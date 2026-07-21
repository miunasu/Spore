"""
安全 Agent - 合并后的统一安全子 Agent

三段能力（由 config.security_agent_mode 控制，off/basic/full）：

1. 风险评估（basic 起）：security_check —— 评估命中高危关键词策略的命令
   （服务/注册表/防火墙/驱动等）的风险等级，返回自然语言风险报告 JSON，
   由 base/security_guard.py 决定放行/确认/阻止。

2. 意图 + 恶意研判（仅 full）：analyze_command_async / analyze_commands_async ——
   对未命中高危关键词的普通命令做异步意图解析（"Agent 正在做什么"），
   同时研判是否恶意（is_malicious / malicious_reason，字段风格与风险报告对齐），
   结果 emit command_intent 事件推前端。

3. 恶意处置（仅 full）：研判为恶意时，因命令已异步放行执行（拦不住），
   直接中断当前会话（后端 bump epoch + 终止子 Agent），emit security_malicious
   通知用户，并记入安全审计日志。

意图分析是异步旁路（后台线程 + 缓存 + 块级批量认领 + 信号量并发限流），
仅桌面模式（有 emit 回调）有意义；CLI 模式 emit=None 直接跳过。
"""
import json
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from base.config import get_config
from base.prompt_loader import load_agent_type_prompt
from base.logger import log_error, log_info


# 全局变量用于存储 IPC 管理器（由 initialize_ipc_system 注入）
_ipc_manager = None


def set_ipc_manager(ipc_manager):
    """设置全局 IPC 管理器"""
    global _ipc_manager
    _ipc_manager = ipc_manager


# ===========================================================================
# 一、风险评估（basic）—— 命中高危关键词策略的命令
# ===========================================================================

# LLM 不可用/解析失败时的保守兜底报告
def _fallback_report(command: str, category: str, reason: str) -> Dict[str, Any]:
    return {
        "risk_level": "high",
        "action": f"检测到{category}类高危操作（AI 评估不可用，采用保守策略）",
        "harm": "无法完成智能风险评估，该命令命中了高危操作策略，可能影响系统配置",
        "reversible": None,
        "rollback_command": None,
        "recommendation": "warn",
        "reason": reason,
        "ai_evaluated": False,
    }


def _parse_report(reply: str) -> Optional[Dict[str, Any]]:
    """从 LLM 回复中提取 JSON 风险报告"""
    if not reply:
        return None
    # 优先提取 ```json ... ``` 代码块，其次提取第一个 {...}
    code_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", reply, re.DOTALL)
    candidates = []
    if code_match:
        candidates.append(code_match.group(1))
    brace_match = re.search(r"\{.*\}", reply, re.DOTALL)
    if brace_match:
        candidates.append(brace_match.group(0))

    for text in candidates:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        level = str(data.get("risk_level", "")).strip().lower()
        if level not in ("low", "medium", "high"):
            continue
        return {
            "risk_level": level,
            "action": str(data.get("action", "")).strip(),
            "harm": str(data.get("harm", "")).strip(),
            "reversible": data.get("reversible"),
            "rollback_command": data.get("rollback_command") or None,
            "recommendation": str(data.get("recommendation", "warn")).strip().lower(),
            "reason": str(data.get("reason", "")).strip(),
            "ai_evaluated": True,
        }
    return None


def security_check(command: str, category: str = "", description: str = "") -> Dict[str, Any]:
    """
    调用安全 Agent 评估命中高危策略的命令的风险。

    Args:
        command: 待评估的 PowerShell 命令
        category: 命中的高危策略类别（关键词匹配阶段产出）
        description: 策略类别的中文说明

    Returns:
        风险报告 dict：risk_level(low/medium/high)、action、harm、
        reversible、rollback_command、recommendation、reason
    """
    if _ipc_manager is None:
        return _fallback_report(command, description or category, "安全 Agent 未初始化")

    config = get_config()
    system_prompt = load_agent_type_prompt("security")
    if not system_prompt:
        return _fallback_report(command, description or category, "安全评估提示词加载失败")

    user_content = (
        f"命中的高危策略类别: {category}（{description}）\n"
        f"待评估命令:\n```powershell\n{command}\n```"
    )

    try:
        request_id = _ipc_manager.send_chat_request(
            messages=[{"role": "user", "content": user_content}],
            model=config.resolve_agent_llm("security")["model"],
            system=system_prompt,
            agent_profile="security",
            tool_calls=False,
        )
        timeout = getattr(config, "security_llm_timeout", 30)
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)

        if response is None or response.get("status") != "success":
            return _fallback_report(command, description or category, "安全 Agent 响应失败或超时")

        reply = (response.get("data") or {}).get("content", "")
        report = _parse_report(reply)
        if report is None:
            return _fallback_report(command, description or category, "风险报告解析失败")

        log_info("SECURITY_AGENT", f"风险评估完成: {report['risk_level']} - {report['action'][:80]}")
        return report

    except Exception as e:
        log_error("SECURITY_AGENT_ERROR", "安全 Agent 评估异常", e,
                  context={"command_preview": command[:120]})
        return _fallback_report(command, description or category, f"评估异常: {e}")


# ===========================================================================
# 二、意图 + 恶意研判（full）—— 未命中高危关键词的普通命令
# ===========================================================================

# 研判结果缓存：规范化命令 -> {"intent","is_malicious","malicious_reason"}
_intent_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = threading.Lock()
_MAX_CACHE_SIZE = 500

# 批量认领：块级批量分析已覆盖的命令（规范化 -> 认领时间），
# 执行期 guard 触发的单条分析据此跳过，避免重复调用
_claimed_commands: Dict[str, float] = {}
_CLAIM_TTL = 600

# 并发限流：避免同时打出多个 LLM 请求（provider 限流重试会把
# 后续请求拖过超时而静默丢失）；批量研判本身只占一个槽位
_analyze_semaphore = threading.BoundedSemaphore(2)
_SEMAPHORE_WAIT_TIMEOUT = 90


def _cache_put(normalized: str, result: Dict[str, Any]) -> None:
    with _cache_lock:
        if len(_intent_cache) >= _MAX_CACHE_SIZE:
            _intent_cache.clear()
        _intent_cache[normalized] = result


def _claim_commands(normalized_list: List[str]) -> None:
    """认领一批命令（含过期清理），后续单条分析跳过它们。"""
    now = time.time()
    with _cache_lock:
        expired = [k for k, ts in _claimed_commands.items() if now - ts > _CLAIM_TTL]
        for k in expired:
            del _claimed_commands[k]
        for norm in normalized_list:
            _claimed_commands[norm] = now


def _is_claimed(normalized: str) -> bool:
    with _cache_lock:
        ts = _claimed_commands.get(normalized)
    return ts is not None and time.time() - ts <= _CLAIM_TTL


def _clean_text(text: str) -> str:
    return (text or "").strip().strip('"\'`').strip()


def _coerce_result(intent: Any, is_malicious: Any, malicious_reason: Any) -> Optional[Dict[str, Any]]:
    """规范化单条研判结果；intent 为空视为无效（返回 None）。"""
    intent_text = _clean_text(str(intent)) if intent is not None else ""
    if not intent_text:
        return None
    # 只有严格 True 才判恶意，解析歧义一律按非恶意（命令已执行，误杀代价高）
    malicious = is_malicious is True or str(is_malicious).strip().lower() == "true"
    reason = _clean_text(str(malicious_reason)) if malicious_reason else ""
    return {
        "intent": intent_text,
        "is_malicious": malicious,
        "malicious_reason": reason if malicious else "",
    }


def _extract_json(reply: str, array: bool = False) -> Optional[Any]:
    """从 LLM 回复中提取 JSON（对象或数组），复用风险报告的宽松提取套路。"""
    if not reply:
        return None
    open_ch, close_ch = ("[", "]") if array else ("{", "}")
    code_match = re.search(r"```(?:json)?\s*(.+?)\s*```", reply, re.DOTALL)
    candidates: List[str] = []
    if code_match:
        candidates.append(code_match.group(1))
    span = re.search(re.escape(open_ch) + r".*" + re.escape(close_ch), reply, re.DOTALL)
    if span:
        candidates.append(span.group(0))
    for text in candidates:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            continue
    return None


def _analyze_intent(command: str) -> Optional[Dict[str, Any]]:
    """调用 LLM 分析单条命令的意图 + 恶意研判，返回结构化结果。"""
    config = get_config()
    system_prompt = load_agent_type_prompt("security_intent")
    if not system_prompt:
        return None

    try:
        request_id = _ipc_manager.send_chat_request(
            messages=[{"role": "user", "content": f"命令:\n```\n{command}\n```"}],
            model=config.resolve_agent_llm("security")["model"],
            system=system_prompt,
            agent_profile="security",
            tool_calls=False,
        )
        timeout = getattr(config, "security_intent_timeout", 45)
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
        if response is None:
            log_info("SECURITY_AGENT", f"命令意图研判超时({timeout}s)，跳过: {command[:80]}")
            return None
        if response.get("status") != "success":
            log_info("SECURITY_AGENT",
                     f"命令意图研判失败(status={response.get('status')})，跳过: {command[:80]}")
            return None
        content = ((response.get("data") or {}).get("content", "") or "").strip()
        data = _extract_json(content, array=False)
        if not isinstance(data, dict):
            return None
        return _coerce_result(
            data.get("intent"), data.get("is_malicious"), data.get("malicious_reason")
        )
    except Exception as e:
        log_error("SECURITY_AGENT_ERROR", "命令意图研判异常", e,
                  context={"command_preview": command[:120]})
        return None


def _analyze_intent_batch(commands: List[str]) -> Dict[int, Dict[str, Any]]:
    """
    一次 LLM 调用批量研判多条命令，返回 {输入序号(1-based): 结果}。

    回复解析为 JSON 数组，按 index 字段对号；缺失/越界/无 intent 的条目跳过。
    """
    config = get_config()
    system_prompt = load_agent_type_prompt("security_intent")
    if not system_prompt:
        return {}

    numbered = "\n".join(f"{i}. {cmd}" for i, cmd in enumerate(commands, 1))
    try:
        request_id = _ipc_manager.send_chat_request(
            messages=[{"role": "user", "content": f"命令列表:\n```\n{numbered}\n```"}],
            model=config.resolve_agent_llm("security")["model"],
            system=system_prompt,
            agent_profile="security",
            tool_calls=False,
        )
        timeout = getattr(config, "security_intent_timeout", 45)
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
        if response is None:
            log_info("SECURITY_AGENT", f"批量意图研判超时({timeout}s)，共{len(commands)}条命令")
            return {}
        if response.get("status") != "success":
            log_info("SECURITY_AGENT",
                     f"批量意图研判失败(status={response.get('status')})，共{len(commands)}条命令")
            return {}

        content = ((response.get("data") or {}).get("content", "") or "").strip()
        data = _extract_json(content, array=True)
        results: Dict[int, Dict[str, Any]] = {}
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                try:
                    index = int(item.get("index"))
                except (TypeError, ValueError):
                    continue
                if not (1 <= index <= len(commands)) or index in results:
                    continue
                result = _coerce_result(
                    item.get("intent"), item.get("is_malicious"), item.get("malicious_reason")
                )
                if result:
                    results[index] = result
        if len(results) < len(commands):
            log_info("SECURITY_AGENT",
                     f"批量意图研判部分缺失: {len(results)}/{len(commands)}")
        return results
    except Exception as e:
        log_error("SECURITY_AGENT_ERROR", "批量命令意图研判异常", e,
                  context={"command_count": len(commands)})
        return {}


# ===========================================================================
# 三、恶意处置（full）—— 中断会话 + 通知 + 审计
# ===========================================================================
def _handle_intent_result(
    emit: Callable[[str, Dict[str, Any]], None],
    command: str,
    result: Dict[str, Any],
    cached: bool,
    session_id: Optional[str],
    interrupt_epoch: Optional[int],
) -> None:
    """推送研判结果；判定恶意时中断会话 + 通知 + 审计。"""
    try:
        emit("command_intent", {
            "command": command[:500],
            "intent": result["intent"],
            "cached": cached,
            "is_malicious": result["is_malicious"],
            "malicious_reason": result.get("malicious_reason") or "",
        })
    except Exception as e:
        log_error("SECURITY_AGENT_EMIT_ERROR", "推送命令意图失败", e)

    if not result.get("is_malicious"):
        return

    reason = result.get("malicious_reason") or ""
    # 审计（命令已执行，无论中断是否成功都留痕）
    try:
        from base.security_guard import audit_log
        audit_log({
            "command": command,
            "decision": "malicious_detected",
            "risk_level": "high",
            "intent": result["intent"],
            "malicious_reason": reason,
            "session_id": session_id,
        })
    except Exception as e:
        log_error("SECURITY_AUDIT_LOG_ERROR", "恶意命令审计写入失败", e)

    # 先中断（越早越好），再通知
    import os
    interrupted = False
    if os.environ.get("SPORE_DESKTOP_MODE") == "1" and session_id:
        try:
            from desktop_app.backend.security_interrupt import interrupt_session_for_malicious
            interrupted = interrupt_session_for_malicious(session_id, interrupt_epoch)
        except Exception as e:
            log_error("SECURITY_MALICIOUS_INTERRUPT_ERROR", "恶意命令中断会话失败", e)

    log_info("SECURITY_AGENT",
             f"检测到恶意命令(interrupted={interrupted}): {command[:100]} - {reason[:80]}")
    try:
        emit("security_malicious", {
            "command": command[:500],
            "intent": result["intent"],
            "malicious_reason": reason,
            "interrupted": interrupted,
        })
    except Exception as e:
        log_error("SECURITY_AGENT_EMIT_ERROR", "推送恶意命令通知失败", e)


def analyze_commands_async(
    commands: List[str],
    emit: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    session_id: Optional[str] = None,
    interrupt_epoch: Optional[int] = None,
) -> None:
    """
    块级批量意图研判：一个 ACTION 块内的多条 shell 命令合并为一次
    LLM 研判，结果仍按条推送（事件名 command_intent）。

    - 命中高危关键词的命令不参与（走 basic 风险评估域，互斥）
    - 缓存命中的命令立即推送（恶意条目命中同样触发中断+通知）
    - 参与批量的命令同步认领，执行期 guard 的单条分析自动跳过
    """
    if emit is None or _ipc_manager is None:
        return
    config = get_config()
    if getattr(config, "security_agent_mode", "full") != "full":
        return

    from base.security_guard import match_high_risk, normalize_command
    guard_active = getattr(config, "security_agent_mode", "full") != "off"

    items: List[Tuple[str, str]] = []  # (command, normalized)
    seen: set = set()
    for command in commands:
        if not command or not isinstance(command, str) or not command.strip():
            continue
        if guard_active and match_high_risk(command) is not None:
            continue
        normalized = normalize_command(command)
        if normalized in seen:
            continue
        seen.add(normalized)
        items.append((command, normalized))
    if not items:
        return

    # 同步认领：guard 在命令执行时触发的单条分析会跳过这些命令
    _claim_commands([norm for _, norm in items])

    # 缓存命中直接推送，只有未命中的进入批量调用
    misses: List[Tuple[str, str]] = []
    for command, normalized in items:
        with _cache_lock:
            cached = _intent_cache.get(normalized)
        if cached is not None:
            _handle_intent_result(emit, command, cached, True, session_id, interrupt_epoch)
        else:
            misses.append((command, normalized))
    if not misses:
        return

    def _worker():
        if not _analyze_semaphore.acquire(timeout=_SEMAPHORE_WAIT_TIMEOUT):
            log_info("SECURITY_AGENT", f"批量意图研判排队超时，跳过{len(misses)}条命令")
            return
        try:
            if len(misses) == 1:
                result = _analyze_intent(misses[0][0])
                results = {1: result} if result else {}
            else:
                results = _analyze_intent_batch([cmd for cmd, _ in misses])
        finally:
            _analyze_semaphore.release()

        for index, (command, normalized) in enumerate(misses, 1):
            result = results.get(index)
            if not result:
                continue
            _cache_put(normalized, result)
            _handle_intent_result(emit, command, result, False, session_id, interrupt_epoch)

    threading.Thread(target=_worker, daemon=True, name="security_agent_batch").start()


def analyze_command_async(
    command: str,
    emit: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    session_id: Optional[str] = None,
    interrupt_epoch: Optional[int] = None,
) -> None:
    """
    异步研判单条命令的意图 + 恶意，并通过 emit 推送到前端（事件名 command_intent）。

    非阻塞：后台线程执行，主流程立即继续。emit 为 None（CLI 无前端）
    或非 full 模式时直接跳过，不产生 LLM 开销。
    """
    if emit is None or _ipc_manager is None:
        return
    config = get_config()
    if getattr(config, "security_agent_mode", "full") != "full":
        return
    if not command or not command.strip():
        return

    from base.security_guard import normalize_command
    normalized = normalize_command(command)

    # 块级批量分析已认领：结果由批量调用推送，这里不再重复分析
    if _is_claimed(normalized):
        return

    # 缓存命中：直接推送（恶意条目同样触发中断+通知）
    with _cache_lock:
        cached = _intent_cache.get(normalized)
    if cached is not None:
        _handle_intent_result(emit, command, cached, True, session_id, interrupt_epoch)
        return

    def _worker():
        if not _analyze_semaphore.acquire(timeout=_SEMAPHORE_WAIT_TIMEOUT):
            log_info("SECURITY_AGENT", f"意图研判排队超时，跳过: {command[:80]}")
            return
        try:
            result = _analyze_intent(command)
        finally:
            _analyze_semaphore.release()
        if not result:
            return
        _cache_put(normalized, result)
        _handle_intent_result(emit, command, result, False, session_id, interrupt_epoch)

    threading.Thread(target=_worker, daemon=True, name="security_agent").start()
