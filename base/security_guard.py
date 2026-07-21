"""
安全守卫系统 (Security Guard)

两阶段检测机制：
1. 第一阶段：关键词匹配（本地快速检测）——识别系统服务、注册表、
   防火墙、驱动、磁盘、安全软件等高危操作。
2. 第二阶段：AI 风险评估——仅命中高危策略的命令才发送给
   Security Agent（AutoAgent/security_agent.py）做深度分析。

根据风险等级与用户配置（strict / balanced / permissive）决定：
- 自动放行（低风险）
- 快速确认（中风险）
- 强制详细确认（高风险）

未命中高危策略的普通命令交给安全 Agent 异步研判意图+恶意（full 模式，不阻塞）。
所有经确认的高风险操作记录到 .spore/security_audit.jsonl，含回滚命令。
"""
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .logger import log_error, log_info
from .utils import terminal

# ---------------------------------------------------------------------------
# 第一阶段：高危操作关键词策略
# ---------------------------------------------------------------------------
# (正则, 类别, 中文说明)
HIGH_RISK_RULES: List[Tuple[str, str, str]] = [
    # 系统服务操作
    (r'\b(set-service|stop-service|start-service|restart-service|new-service|remove-service)\b',
     "service", "系统服务操作"),
    (r'\bsc(\.exe)?\s+(create|delete|config|stop|start)\b',
     "service", "系统服务操作 (sc)"),
    # 注册表操作（HKLM 系统级）
    (r'\b(set-itemproperty|new-itemproperty|remove-itemproperty|new-item|remove-item)\b[^\r\n]*\bhklm:',
     "registry", "系统注册表修改 (HKLM)"),
    (r'\breg(\.exe)?\s+(add|delete|import)\b[^\r\n]*\b(hklm|hkey_local_machine)\b',
     "registry", "系统注册表修改 (reg)"),
    # 防火墙 / 网络配置
    (r'\bnetsh\b', "network", "网络/防火墙配置 (netsh)"),
    (r'\b(new|set|remove|disable|enable)-netfirewallrule\b',
     "firewall", "防火墙规则修改"),
    (r'\bset-netfirewallprofile\b', "firewall", "防火墙配置修改"),
    (r'\b(set|new|remove)-netipaddress\b|\bset-dnsclientserveraddress\b',
     "network", "网络接口配置修改"),
    # 系统功能开关
    (r'\b(disable|enable)-windowsoptionalfeature\b',
     "system_feature", "Windows 系统功能开关"),
    (r'\bdism(\.exe)?\s+/online\b', "system_feature", "系统映像修改 (DISM)"),
    # 驱动安装
    (r'\bpnputil\b', "driver", "驱动程序安装/卸载"),
    # 系统级环境变量
    (r'\[environment\]::setenvironmentvariable\b[^\r\n]*[\'"](machine)[\'"]',
     "env_system", "系统级环境变量修改"),
    (r'\bsetx\b[^\r\n]*\s/m\b', "env_system", "系统级环境变量修改 (setx /M)"),
    # 安全软件（Defender）
    (r'\b(set|add|remove)-mppreference\b', "defender", "Windows Defender 配置修改"),
    # 磁盘操作
    (r'\b(format-volume|clear-disk|initialize-disk|remove-partition|resize-partition)\b',
     "disk", "磁盘分区操作"),
    (r'\bdiskpart\b', "disk", "磁盘分区操作 (diskpart)"),
    (r'\bformat(\.com)?\s+[a-z]:', "disk", "磁盘格式化"),
    (r'\bcipher\s+/w\b', "disk", "磁盘数据擦除"),
    # 启动配置 / 系统还原 / 卷影副本
    (r'\bbcdedit\b', "boot", "系统启动配置修改"),
    (r'\bvssadmin\b[^\r\n]*\bdelete\b', "shadow_copy", "卷影副本删除"),
    (r'\bdisable-computerrestore\b|\bcheckpoint-computer\b',
     "system_restore", "系统还原点操作"),
    # 日志清除
    (r'\bwevtutil\s+cl\b|\bclear-eventlog\b', "log_clear", "系统事件日志清除"),
    # 计划任务
    (r'\bschtasks\b[^\r\n]*/create\b', "scheduled_task", "计划任务创建"),
    (r'\b(register|new)-scheduledtask\b', "scheduled_task", "计划任务创建"),
    # 执行策略 / UAC
    (r'\bset-executionpolicy\b', "execution_policy", "PowerShell 执行策略修改"),
    (r'\benablelua\b', "uac", "UAC 用户账户控制修改"),
    # 账户管理
    (r'\bnet\s+(user|localgroup)\b[^\r\n]*\s/(add|delete|active)\b',
     "account", "用户账户管理"),
    (r'\b(new|remove)-localuser\b|\b(add|remove)-localgroupmember\b',
     "account", "用户账户管理"),
    # 权限修改
    (r'\btakeown\b|\bicacls\b[^\r\n]*/(grant|deny|remove|setowner)\b',
     "acl", "文件权限修改"),
    # 电源操作
    (r'\bshutdown(\.exe)?\s+/(s|r|f)\b|\b(stop|restart)-computer\b',
     "power", "关机/重启操作"),
    # 组策略
    (r'\bsecedit\b|\bgpupdate\s+/force\b', "policy", "系统安全策略修改"),
    # 关键进程终止
    (r'\b(stop-process|taskkill)\b[^\r\n]*\b(winlogon|csrss|lsass|smss|services|svchost|explorer)\b',
     "critical_process", "关键系统进程终止"),
]

_COMPILED_RULES = [(re.compile(p, re.IGNORECASE), cat, desc) for p, cat, desc in HIGH_RISK_RULES]

# 风险评估结果缓存：规范化命令 -> 报告
_risk_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = threading.Lock()

_whitelist_cache: Optional[Dict[str, Any]] = None
_whitelist_lock = threading.Lock()


def match_high_risk(command: str) -> Optional[Tuple[str, str]]:
    """第一阶段：关键词匹配。命中返回 (类别, 说明)，未命中返回 None。"""
    if not command:
        return None
    for pattern, category, description in _COMPILED_RULES:
        if pattern.search(command):
            return category, description
    return None


# 标识符类参数：其后的值只是目标名称/路径，规范化为 <VAR>（用于缓存复用）。
# 刻意不包含风险相关参数（-StartupType/-Action/-Value/-DisableRealtimeMonitoring 等），
# 以免把风险不同的命令归并到同一缓存键。
_IDENTIFIER_PARAMS = (
    "name", "displayname", "path", "literalpath", "servicename",
    "driveletter", "id", "inputobject", "computername", "filepath",
)


def normalize_command(command: str) -> str:
    """
    规范化命令用于缓存与白名单匹配：
    去掉引号内的具体值、数字、路径以及标识符类参数值，只保留命令结构。
    例如 Set-Service -Name XXX -StartupType Disabled 和
        Set-Service -Name YYY -StartupType Disabled 规范化后相同，
    但 -StartupType 的值（Disabled/Automatic）保留，风险不会被错误复用。
    """
    text = command.strip().lower()
    text = re.sub(r'"[^"]*"', '<VAR>', text)
    text = re.sub(r"'[^']*'", '<VAR>', text)
    text = re.sub(r'\b[a-z]:[\\/][^\s;|&]*', '<PATH>', text)
    # 标识符类参数后的值 -> <VAR>
    ident = "|".join(_IDENTIFIER_PARAMS)
    text = re.sub(rf'(-(?:{ident})\s+)(?!-)[^\s;|&]+', r'\1<VAR>', text)
    text = re.sub(r'\b\d+\b', '<N>', text)
    text = re.sub(r'\s+', ' ', text)
    return text


# ---------------------------------------------------------------------------
# 白名单（security_whitelist.json，与 tool_policy.json 同级）
# ---------------------------------------------------------------------------
def _whitelist_path() -> Path:
    try:
        from .config import _PROJECT_ROOT
        return Path(_PROJECT_ROOT) / "security_whitelist.json"
    except Exception:
        return Path.cwd() / "security_whitelist.json"


def load_whitelist(force_reload: bool = False) -> Dict[str, Any]:
    """加载白名单：{"commands": [...精确命令...], "patterns": [...正则...]}"""
    global _whitelist_cache
    with _whitelist_lock:
        if _whitelist_cache is not None and not force_reload:
            return _whitelist_cache
        data: Dict[str, Any] = {"commands": [], "patterns": []}
        path = _whitelist_path()
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    if isinstance(raw.get("commands"), list):
                        data["commands"] = [str(c) for c in raw["commands"]]
                    if isinstance(raw.get("patterns"), list):
                        data["patterns"] = [str(p) for p in raw["patterns"]]
            except Exception as e:
                log_error("SECURITY_WHITELIST_LOAD_ERROR", "加载白名单失败", e)
        _whitelist_cache = data
        return data


def add_to_whitelist(command: str) -> bool:
    """将命令加入白名单并持久化。"""
    global _whitelist_cache
    with _whitelist_lock:
        data = _whitelist_cache or {"commands": [], "patterns": []}
        if command not in data["commands"]:
            data["commands"].append(command)
        try:
            path = _whitelist_path()
            tmp = path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            tmp.replace(path)
            _whitelist_cache = data
            return True
        except Exception as e:
            log_error("SECURITY_WHITELIST_SAVE_ERROR", "保存白名单失败", e)
            return False


def is_whitelisted(command: str) -> bool:
    data = load_whitelist()
    stripped = command.strip()
    norm = normalize_command(command)
    for entry in data.get("commands", []):
        if stripped == entry.strip() or norm == normalize_command(entry):
            return True
    for pattern in data.get("patterns", []):
        try:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


# ---------------------------------------------------------------------------
# 第二阶段：AI 风险评估（带缓存）
# ---------------------------------------------------------------------------
def security_check_cached(command: str, category: str, description: str) -> Dict[str, Any]:
    normalized = normalize_command(command)
    with _cache_lock:
        cached = _risk_cache.get(normalized)
    if cached is not None:
        return cached

    from AutoAgent.security_agent import security_check
    report = security_check(command, category, description)

    # 仅缓存 AI 成功评估的结果（兜底报告不缓存，下次重试）
    if report.get("ai_evaluated"):
        with _cache_lock:
            _risk_cache[normalized] = report
    return report


# ---------------------------------------------------------------------------
# 审计日志
# ---------------------------------------------------------------------------
def audit_log(entry: Dict[str, Any]) -> None:
    try:
        from .backup_manager import get_backup_manager
        path = get_backup_manager().audit_path
        path.parent.mkdir(parents=True, exist_ok=True)
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log_error("SECURITY_AUDIT_LOG_ERROR", "写入安全审计日志失败", e)


# 兼容旧调用名
_audit_log = audit_log


# ---------------------------------------------------------------------------
# 用户确认
# ---------------------------------------------------------------------------
_RISK_LABELS = {"low": "低风险", "medium": "中风险", "high": "高风险"}


def _cli_print(text: str) -> None:
    """CLI 输出，兼容 Windows GBK 控制台（无法编码的字符降级为 ?）。"""
    try:
        print(text)
    except UnicodeEncodeError:
        import sys
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(enc, errors="replace").decode(enc, errors="replace"))


def _build_details(command: str, report: Dict[str, Any]) -> List[str]:
    details = [f"命令: {command}"]
    if report.get("action"):
        details.append(f"功能: {report['action']}")
    if report.get("harm"):
        details.append(f"危害: {report['harm']}")
    reversible = report.get("reversible")
    if reversible is not None:
        details.append(f"可逆: {'是' if reversible else '否'}")
    if report.get("rollback_command"):
        details.append(f"回滚命令: {report['rollback_command']}")
    if report.get("reason"):
        details.append(f"评估: {report['reason']}")
    return details


def _confirm_with_user(command: str, report: Dict[str, Any]) -> bool:
    """根据运行模式（桌面/CLI）请求用户确认。"""
    level = report.get("risk_level", "high")
    label = _RISK_LABELS.get(level, level)
    details = _build_details(command, report)

    is_desktop_mode = os.environ.get("SPORE_DESKTOP_MODE") == "1"
    if is_desktop_mode:
        try:
            from desktop_app.backend.confirm_manager import desktop_confirm
            if level == "high":
                title = "🚨 检测到高风险操作"
                message = f"{report.get('action') or '高风险系统操作'}（建议仔细确认后再执行）"
            else:
                title = "⚡ 检测到系统配置修改"
                message = report.get("action") or "系统配置修改"
            return desktop_confirm(
                action_type=f"security_{level}",
                title=title,
                message=message,
                details=details,
            )
        except Exception as e:
            log_error("SECURITY_CONFIRM_ERROR", "桌面确认请求失败", e)
            return False

    # CLI 模式
    icon = "🚨" if level == "high" else "⚡"
    _cli_print(f"\n{icon} [安全守卫] 检测到{label}操作")
    for line in details:
        _cli_print(f"  {line}")
    try:
        terminal.extra_line += len(details) + 3
    except Exception:
        pass
    if level == "high":
        answer = input("继续执行？输入 yes 确认，其他任意键取消: ").strip().lower()
        return answer in ("yes", "y")
    answer = input("允许执行？(y/n): ").strip().lower()
    return answer == "y"


# ---------------------------------------------------------------------------
# 主入口：execute_command 守卫
# ---------------------------------------------------------------------------
def guard_shell_command(
    args: Dict[str, Any],
    emit: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    session_id: Optional[str] = None,
    interrupt_epoch: Optional[int] = None,
) -> Optional[str]:
    """
    execute_command 执行前的安全守卫。

    返回 None 表示放行；返回字符串表示阻止（该字符串作为错误信息返回给 LLM）。

    - 未命中高危策略：full 模式下交给安全 Agent 异步研判意图+恶意（不阻塞），放行
    - 命中高危策略：调用安全 Agent 评估 -> 按风险等级和配置决定
      自动放行 / 用户确认 / 阻止
    """
    from .config import get_config
    config = get_config()

    command = args.get("command")
    if not command or not isinstance(command, str):
        return None

    def _emit(event: str, data: Dict[str, Any]) -> None:
        if emit is None:
            return
        try:
            emit(event, data)
        except Exception:
            pass

    guard_enabled = getattr(config, "security_guard_enabled", True)
    matched = match_high_risk(command) if guard_enabled else None

    if matched is None:
        # 普通命令：full 模式下安全 Agent 异步研判意图+恶意（与风险评估域互斥）
        try:
            from AutoAgent.security_agent import analyze_command_async
            analyze_command_async(command, emit, session_id=session_id,
                                  interrupt_epoch=interrupt_epoch)
        except Exception as e:
            log_error("SECURITY_AGENT_DISPATCH_ERROR", "安全 Agent 意图研判派发失败", e)
        return None

    category, description = matched

    # 白名单命令直接放行
    if is_whitelisted(command):
        log_info("SECURITY_GUARD", f"白名单放行: [{category}] {command[:100]}")
        _audit_log({
            "command": command, "category": category,
            "decision": "whitelisted", "risk_level": None,
        })
        return None

    _emit("security_checking", {
        "command": command[:500],
        "category": category,
        "description": description,
    })
    if os.environ.get("SPORE_DESKTOP_MODE") != "1":
        _cli_print(f"\n[安全守卫] 检测到{description}，正在进行 AI 风险评估...")

    report = security_check_cached(command, category, description)
    level = report.get("risk_level", "high")

    # 按配置的风险容忍度决定是否需要确认
    # strict: 命中策略一律确认; balanced: low 自动放行; permissive: low/medium 自动放行
    mode = getattr(config, "security_guard_mode", "balanced")
    auto_allow = (
        (mode == "balanced" and level == "low")
        or (mode == "permissive" and level in ("low", "medium"))
    )

    _emit("security_alert", {
        "command": command[:500],
        "category": category,
        "risk_level": level,
        "action": report.get("action", ""),
        "harm": report.get("harm", ""),
        "reversible": report.get("reversible"),
        "rollback_command": report.get("rollback_command"),
        "recommendation": report.get("recommendation", ""),
        "auto_allow": auto_allow,
    })

    if auto_allow:
        if os.environ.get("SPORE_DESKTOP_MODE") != "1":
            _cli_print(f"[安全守卫] {_RISK_LABELS.get(level, level)}，自动放行: {report.get('action', '')}")
        _audit_log({
            "command": command, "category": category, "risk_level": level,
            "decision": "auto_allow", "report": report,
        })
        return None

    confirmed = _confirm_with_user(command, report)

    _audit_log({
        "command": command,
        "category": category,
        "risk_level": level,
        "decision": "user_confirmed" if confirmed else "user_denied",
        "reversible": report.get("reversible"),
        "rollback_command": report.get("rollback_command"),
        "report": report,
    })
    _emit("security_result", {
        "command": command[:500],
        "risk_level": level,
        "confirmed": confirmed,
    })

    if confirmed:
        return None

    return (
        f"安全守卫已阻止该命令（{_RISK_LABELS.get(level, level)}，用户未确认）。\n"
        f"操作: {report.get('action', description)}\n"
        f"危害: {report.get('harm', '未知')}\n"
        f"请换用更安全的方式完成任务，或向用户说明为什么需要此操作。"
    )
