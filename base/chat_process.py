"""
Chat 进程模块 - 独立进程负责与 LLM 通信
支持多线程并发请求，统一中断控制
"""
import multiprocessing as mp
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, Future
import json
import re
import threading
import signal
import time
import uuid

from . import response_health
from .client import load_openai_client, load_anthropic_client
from .logger import log_error, log_info
from .config import get_config
from . import config as _config

try:
    # 收到即记的完整原文通道（由 logger 提供）。容错导入：日志属于旁路能力，
    # 缺了它也不能让整个 chat 进程起不来。
    from .logger import log_raw_received  # type: ignore
except ImportError:  # pragma: no cover - 仅在 logger 尚未提供该接口时走到
    def log_raw_received(payload, conversation_id=None):  # type: ignore
        """logger 未提供 log_raw_received 时的空实现。"""
        return None

if TYPE_CHECKING:
    from openai import OpenAI
    from anthropic import Anthropic

# request_id 格式：{conversation_id}_{uuid}
_REQUEST_ID_CONV_RE = re.compile(
    r"^(?P<cid>.+)_(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)

# 从异常文本里兜底捞 HTTP 状态码（SDK 未暴露 status_code 时，
# 第三方中转的报错串常形如 "Error code: 400 - {...}"）
_HTTP_CODE_IN_TEXT_RE = re.compile(
    r"(?:error\s*code|status(?:[_\s]*code)?)\D{0,4}(\d{3})", re.IGNORECASE
)


def conversation_id_from_request_id(request_id: Optional[str]) -> Optional[str]:
    """从 request_id 反解对话 ID（chat 进程内没有 conversation contextvar）。"""
    if not request_id:
        return None
    match = _REQUEST_ID_CONV_RE.match(request_id)
    if not match:
        return None
    cid = (match.group("cid") or "").strip()
    return cid or None


# 向后兼容的全局变量
_current_conversation_id: Optional[str] = None


def set_current_conversation(conversation_id: str):
    """设置当前活跃的对话 ID"""
    global _current_conversation_id
    _current_conversation_id = conversation_id


class ChatProcess:
    """Chat 进程封装类 - 支持并发LLM请求"""
    
    def __init__(self, request_queue: mp.Queue, response_queue: mp.Queue, stop_event: mp.Event):
        """
        初始化 Chat 进程
        
        Args:
            request_queue: 接收主进程发送的请求
            response_queue: 向主进程发送响应
            stop_event: 全局停止事件
        """
        self.request_queue = request_queue
        self.response_queue = response_queue
        self.stop_event = stop_event
        
        # 主 Agent 客户端
        self.client = None
        self.anthropic_client = None
        
        # 子 Agent 客户端
        self.sub_agent_client = None
        self.sub_agent_anthropic_client = None
        
        # 并发控制
        self.config = get_config()
        self.executor: Optional[ThreadPoolExecutor] = None
        self.active_requests: Dict[str, Future] = {}  # request_id -> Future
        self.active_requests_lock = threading.Lock()

        # AutoAgent 颗粒化基座：按 (sdk, api_key, api_url) 懒加载缓存客户端
        self._profile_clients: Dict[tuple, Any] = {}
        self._profile_clients_lock = threading.Lock()

        # 全局中断标志 - 所有线程共享
        self.global_cancel_flag = threading.Event()

        # Desktop 中断必须精确到 request。Future.cancel() 无法停止已经运行的
        # SDK 调用，因此还要保留 stream 句柄，以便收到 IPC 取消命令时主动 close。
        self._cancelled_request_ids: set[str] = set()
        self._cancelled_requests_lock = threading.Lock()
        self._active_streams: Dict[str, Any] = {}
        self._active_streams_lock = threading.Lock()

        # SDK 类型
        self.llm_sdk = self.config.llm_sdk
        self.sub_agent_llm_sdk = self.config.get_sub_agent_sdk()
        
    def initialize(self):
        """初始化 LLM 客户端和线程池"""
        # 初始化主 Agent 客户端
        if self.llm_sdk == "anthropic":
            self.anthropic_client = load_anthropic_client()
        else:
            self.client = load_openai_client()
        
        # 初始化子 Agent 客户端
        if self.sub_agent_llm_sdk == "anthropic":
            from .client import load_sub_agent_anthropic_client
            self.sub_agent_anthropic_client = load_sub_agent_anthropic_client()
        else:
            from .client import load_sub_agent_openai_client
            self.sub_agent_client = load_sub_agent_openai_client()
        
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.chat_max_workers,
            thread_name_prefix="llm_worker"
        )

        self._log_effective_config()

    def _log_effective_config(self) -> None:
        """启动时落盘生效配置快照。

        运行期配置可能被 config_profiles 覆写，与 .env 不一致（例如 .env 写
        sonnet 实际跑 opus）。出问题时若只能看 .env，会照着错误的前提排查。
        失败静默，不影响启动。
        """
        try:
            cfg = self.config
            snapshot = {
                "llm_sdk": self.llm_sdk,
                "sub_agent_llm_sdk": self.sub_agent_llm_sdk,
                "model": getattr(cfg, "anthropic_model", None) if self.llm_sdk == "anthropic"
                         else getattr(cfg, "openai_model", None),
                "max_output_tokens": cfg.get_max_tokens() if hasattr(cfg, "get_max_tokens") else None,
                "context_max_tokens": getattr(cfg, "context_max_tokens", None),
                "context_warning_threshold": getattr(cfg, "context_warning_threshold", None),
                "thinking_mode": getattr(cfg, "anthropic_thinking_mode", None),
                "thinking_budget_tokens": getattr(cfg, "anthropic_thinking_budget_tokens", None),
                "effort": getattr(cfg, "anthropic_effort", None),
                "use_responses_api": getattr(cfg, "use_responses_api", None),
                "llm_stream_enabled": getattr(cfg, "llm_stream_enabled", None),
                "chat_max_workers": getattr(cfg, "chat_max_workers", None),
                "log_raw_enabled": getattr(cfg, "log_raw_enabled", None),
            }
            log_info("CHAT_PROCESS_CONFIG 生效配置快照", context=snapshot)
        except Exception:
            pass

    def shutdown(self):
        """关闭线程池"""
        if self.executor:
            self.executor.shutdown(wait=False)
            self.executor = None
    
    # API 重试延迟（秒）：立即、5s、15s、25s
    _RETRY_DELAYS = [0, 5, 15, 25]

    # 客户端错误重试没有意义：请求本身不合法（例如历史里混入了空消息），
    # 重发同样的请求必然得到同样的结果，只会白等重试间隔。
    _NON_RETRYABLE_STATUS_CODES = frozenset({400, 401, 403, 404, 405, 413, 414, 415, 422, 501})

    # 空回复最多重试几次。空回复常见于"思考把输出额度吃光、一个正文块都没生成"，
    # 重试一次通常能拿到正文；但它每次都要付全额 token，不能无限试。
    _MAX_EMPTY_ATTEMPTS = 2

    @staticmethod
    def _error_status_code(exc: Optional[Exception], message: str = "") -> Optional[int]:
        """尽力取出 HTTP 状态码；取不到返回 None（按可重试处理）。"""
        for attr in ("status_code", "code"):
            value = getattr(exc, attr, None)
            if isinstance(value, int) and 100 <= value < 600:
                return value
        response = getattr(exc, "response", None)
        value = getattr(response, "status_code", None)
        if isinstance(value, int) and 100 <= value < 600:
            return value
        match = _HTTP_CODE_IN_TEXT_RE.search(message or str(exc or ""))
        if match:
            try:
                code = int(match.group(1))
            except (TypeError, ValueError):
                return None
            if 100 <= code < 600:
                return code
        return None

    @classmethod
    def _is_retryable_error(cls, result: Dict[str, Any]) -> bool:
        """错误是否值得重试。状态码未知时保持重试，不改变既有容错行为。"""
        meta = result.get("error_meta") or {}
        code = meta.get("status_code")
        if not isinstance(code, int):
            return True
        return code not in cls._NON_RETRYABLE_STATUS_CODES

    @classmethod
    def _retry_error_detail(cls, result: Optional[Dict[str, Any]], limit: int = 1000) -> str:
        """从标准化错误结果中提取适合重试进度展示的服务端错误详情。"""
        if not isinstance(result, dict):
            return ""

        def extract(value: Any) -> str:
            if isinstance(value, dict):
                error = value.get("error")
                if error is not None:
                    detail = extract(error)
                    if detail:
                        return detail
                for key in ("message", "detail", "error_description"):
                    if key in value:
                        detail = extract(value[key])
                        if detail:
                            return detail
                for nested in value.values():
                    detail = extract(nested)
                    if detail:
                        return detail
                return ""
            if isinstance(value, (list, tuple)):
                for item in value:
                    detail = extract(item)
                    if detail:
                        return detail
                return ""
            if not isinstance(value, str):
                return ""

            text = value.strip()
            if not text:
                return ""
            if text[:1] in ("{", "["):
                try:
                    parsed = json.loads(text)
                except (TypeError, ValueError):
                    pass
                else:
                    detail = extract(parsed)
                    if detail:
                        return detail
            return text

        raw_payload = result.get("raw_payload")
        candidates = []
        if isinstance(raw_payload, dict):
            candidates.extend([
                raw_payload.get("body"),
                raw_payload.get("response_text"),
                raw_payload.get("message"),
            ])
        candidates.append(result.get("data"))

        for candidate in candidates:
            detail = extract(candidate)
            if not detail:
                continue
            detail = re.sub(r"\s+", " ", detail).strip()
            if len(detail) > limit:
                detail = detail[: max(0, limit - 3)].rstrip() + "..."
            return detail
        return ""

    def _do_llm_call(self, request_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行 LLM 调用（带重试）

        重试策略：立即重试 → 5s → 15s → 25s，共4次机会。

        以下情况不消耗全部机会：
        - cancelled：直接返回
        - refusal：模型明确拒答，重试无意义
        - 4xx 客户端错误：请求本身不合法，重发结果相同
        - empty_response：最多重试 _MAX_EMPTY_ATTEMPTS 次，且**重发前会改生成参数**
          （见 retry_hint / _adjust_*_for_empty_retry）：逐字节相同的请求大概率
          得到同样的空回复，只是多付一次全额 token。
        """
        last_result = None
        total_attempts = len(self._RETRY_DELAYS)
        empty_attempts = 0
        # 只有"上一次是空回复"才携带提示去改参数；普通错误重试保持原参数不变
        retry_hint: Optional[Dict[str, Any]] = None
        for attempt, delay in enumerate(self._RETRY_DELAYS):
            # Cancellation wins before retry progress or another provider attempt.
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            if delay > 0:
                # 第 attempt 次失败后的下一次重试（attempt 从 0 计，展示为第 attempt+1 次重试）
                empty_retry = self._empty_retry_active(retry_hint)
                if empty_retry:
                    progress_attempt = int((retry_hint or {}).get("attempt") or 0) + 1
                    progress_total = self._MAX_EMPTY_ATTEMPTS
                    retry_reason = "empty_response"
                    progress_msg = (
                        f"上次回复没有正文，{delay}秒后进行第 {progress_attempt} 次生成尝试..."
                    )
                else:
                    progress_attempt = attempt + 1
                    progress_total = total_attempts
                    retry_reason = "api_error"
                    error_detail = self._retry_error_detail(last_result)
                    if error_detail:
                        progress_msg = (
                            f"请求失败：{error_detail}；{delay}秒后进行第 "
                            f"{progress_attempt} 次请求尝试..."
                        )
                    else:
                        progress_msg = (
                            f"请求失败，{delay}秒后进行第 {progress_attempt} 次请求尝试..."
                        )
                # 经 IPC 推送进度，供 Desktop 前端 system 日志展示（chat 进程自身 log 到不了主进程 WS）
                try:
                    self.response_queue.put({
                        "request_id": request_id,
                        "status": "progress",
                        "data": {
                            "event": "llm_retry",
                            "attempt": progress_attempt,
                            "total": progress_total,
                            "delay": delay,
                            "message": progress_msg,
                            "retry_reason": retry_reason,
                        },
                    })
                except Exception:
                    # 只有 IPC 投递失败时才由 Chat 子进程兜底落盘；正常路径由
                    # IPCManager 统一记录，避免同一重试进度写两遍。
                    log_error(
                        "LLM_API_RETRY_PROGRESS",
                        progress_msg,
                        context={
                            "request_id": request_id,
                            "conversation_id": conversation_id_from_request_id(request_id),
                            "attempt": progress_attempt,
                            "total": progress_total,
                            "delay": delay,
                            "event": "llm_retry",
                            "retry_reason": retry_reason,
                        },
                    )
                if not self._wait_retry_delay(request_id, delay):
                    return {"request_id": request_id, "status": "cancelled", "data": None}

            if request_data.get("stream"):
                self._emit_stream_event(request_id, "start")
            attempt_request_data = dict(request_data)
            attempt_request_data["_raw_attempt_index"] = attempt + 1
            attempt_request_data["_raw_attempt_id"] = "{0}:attempt-{1}".format(
                request_id, attempt + 1
            )
            result = self._do_single_llm_call(
                request_id, attempt_request_data, retry_hint=retry_hint
            )
            # close(stream) may end iteration normally or surface a transport error.
            # In either case, cancellation must win before error classification/retry.
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            status = result.get("status")

            if status == "cancelled":
                return result

            if status == "success":
                return result

            if status == "refusal":
                return result

            if status == "empty_response":
                empty_attempts += 1
                last_result = result
                if empty_attempts >= self._MAX_EMPTY_ATTEMPTS:
                    log_error(
                        "LLM_EMPTY_RESPONSE",
                        f"Empty response after {empty_attempts} attempt(s), giving up",
                        context=self._health_context(request_id, result),
                    )
                    return result
                # 把上一次的额度消耗情况带给下一次调用：调用路径据此决定压思考
                # 还是抬上限（同样的参数重发几乎必然再空一次）
                retry_hint = self._build_empty_retry_hint(result, empty_attempts)
                log_error(
                    "LLM_EMPTY_RESPONSE_RETRY",
                    f"Empty response (attempt {empty_attempts}/{self._MAX_EMPTY_ATTEMPTS}), retrying",
                    context=self._health_context(request_id, result),
                )
                continue

            last_result = result
            retry_hint = None  # 普通错误重试不改生成参数
            if not self._is_retryable_error(result):
                log_error(
                    "LLM_API_CLIENT_ERROR",
                    f"Non-retryable API error, aborting retries: {result.get('data', '')}",
                    context={
                        "request_id": request_id,
                        "status_code": (result.get("error_meta") or {}).get("status_code"),
                    },
                )
                return result
            log_error(
                "LLM_API_RETRY",
                f"API call failed (attempt {attempt + 1}/{total_attempts}): {result.get('data', '')}",
                context={
                    "request_id": request_id,
                    "conversation_id": conversation_id_from_request_id(request_id),
                    "attempt": attempt + 1,
                    "total": total_attempts,
                },
            )
        return last_result

    @staticmethod
    def _build_empty_retry_hint(result: Dict[str, Any], empty_attempts: int) -> Dict[str, Any]:
        """把上一次空回复的关键数字压成重试提示；构造失败也要给出最小可用提示。"""
        hint: Dict[str, Any] = {
            "reason": "empty_response",
            "attempt": empty_attempts,
            "request_id": result.get("request_id"),
        }
        try:
            health = result.get("health") or {}
            usage = health.get("usage") or {}
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            hint["output_tokens"] = usage.get("output_tokens") or (data.get("usage") or {}).get("output_tokens") or 0
            hint["max_tokens"] = data.get("max_tokens") or 0
            hint["api_stop_reason"] = health.get("api_stop_reason")
        except Exception:
            pass
        return hint

    @staticmethod
    def _health_context(request_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """把健康诊断压成简短的日志上下文。"""
        health = result.get("health") or {}
        return {
            "request_id": request_id,
            "api_stop_reason": health.get("api_stop_reason"),
            "finish_state": health.get("finish_state"),
            "truncated": health.get("truncated"),
            "truncation_source": health.get("truncation_source"),
            "content_blocks": health.get("content_blocks"),
            "usage": health.get("usage"),
        }

    # ------------------------------------------------------------------
    # 收到即记：原文落盘
    #
    # 提取、pause_turn 续调、健康判定都在收到之后发生，任何一步抛异常都会让
    # "收到的东西"彻底消失 —— 而排查中转问题恰恰只能看原文。所以每条响应在
    # 返回的那一行之后立即落盘，落之前不做任何解析。
    # ------------------------------------------------------------------
    def _received_meta(
        self,
        request_id: str,
        api: str,
        model: Optional[str],
        call_meta: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """构造 raw 落盘用的定位信息（只放定位字段，绝不放凭据）。"""
        meta: Dict[str, Any] = {
            "request_id": request_id,
            "conversation_id": conversation_id_from_request_id(request_id),
            "api": api,
            "model": model,
        }
        try:
            if call_meta:
                meta["sub_agent"] = bool(call_meta.get("use_sub_agent_config"))
                meta["agent_profile"] = call_meta.get("agent_profile")
                meta["attempt_id"] = call_meta.get("attempt_id")
                meta["attempt_index"] = call_meta.get("attempt_index")
            if extra:
                meta.update(extra)
        except Exception:
            pass
        return meta

    def _log_received(self, payload: Any, meta: Dict[str, Any]) -> None:
        """收到 provider 响应后立即原样落盘，不等待或附加解析结果。"""
        try:
            agent_profile = (meta or {}).get("agent_profile")
            if agent_profile == "frontend":
                # frontend agent 的 raw 响应落到 frontend_agent.log，不写 raw.log
                from .logger import log_frontend_agent_raw
                log_frontend_agent_raw(payload)
                return
            if not getattr(self.config, "log_raw_enabled", False):
                return
            log_raw_received(
                payload,
                conversation_id=(meta or {}).get("conversation_id"),
            )
        except Exception:
            pass

    @staticmethod
    def _wire_body_text(raw: Any) -> Optional[str]:
        """从 SDK 的 raw response 包装对象里取未经解析的 HTTP 响应体原文。"""
        try:
            text = getattr(raw, "text", None)
            if isinstance(text, str):
                return text
            http_response = getattr(raw, "http_response", None)
            text = getattr(http_response, "text", None)
            if isinstance(text, str):
                return text
            content = getattr(raw, "content", None)
            if isinstance(content, (bytes, bytearray)):
                return bytes(content).decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    # 响应头里值得留档的定位字段（白名单，避免把无关头信息一并落盘）
    _WIRE_HEADER_KEYS = (
        "request-id",
        "x-request-id",
        "anthropic-organization-id",
        "retry-after",
        "content-type",
    )

    @classmethod
    def _wire_meta(cls, raw: Any) -> Dict[str, Any]:
        """取 raw response 的状态码与少量定位响应头；失败返回空 dict。"""
        info: Dict[str, Any] = {}
        try:
            status = getattr(raw, "status_code", None)
            if status is None:
                status = getattr(getattr(raw, "http_response", None), "status_code", None)
            if isinstance(status, int):
                info["http_status"] = status
            headers = getattr(raw, "headers", None)
            if headers is None:
                headers = getattr(getattr(raw, "http_response", None), "headers", None)
            if headers is not None:
                picked = {}
                for key in cls._WIRE_HEADER_KEYS:
                    try:
                        value = headers.get(key)
                    except Exception:
                        value = None
                    if value:
                        picked[key] = str(value)
                if picked:
                    info["headers"] = picked
        except Exception:
            pass
        return info

    def _create_and_log_raw(
        self,
        endpoint: Any,
        request_params: Dict[str, Any],
        meta: Dict[str, Any],
        *,
        compatibility: Optional[str] = None,
    ) -> Any:
        """调用 ``endpoint.create``，在返回的那一刻落盘原文，再返回解析后的响应。

        优先走 SDK 的 ``with_raw_response`` 通道：``model_dump()`` 是 SDK 解析后
        的结构，会把第三方中转返回的非常规字段归一化甚至丢弃 —— 而要排查的正是
        中转把字段搞坏的情况，只有 HTTP wire body 才是可信的原文。

        只在 SDK 不提供 raw 通道时走普通调用。一旦调用了 raw ``create``，任何异常
        都原样交给上层，不能再调用普通 ``create``：异常可能发生在 HTTP 请求已经
        成功之后，自动回退会造成同一轮重复生成和重复计费。

        ``CLEAN_SDK_HEADERS=true`` 会按配置删除 ``X-Stainless-Raw-Response``。
        此时 SDK 可能直接返回已解析模型而非 raw wrapper；这是受支持的配置形态，
        记录 ``parsed_model`` 后直接返回，不尝试恢复或重发请求。
        """
        raw_api = getattr(endpoint, "with_raw_response", None)
        raw_create = getattr(raw_api, "create", None)
        if callable(raw_create):
            raw = self._call_with_compatible_kwargs(
                raw_create, request_params, compatibility=compatibility
            )
            parse = getattr(raw, "parse", None)
            if callable(parse):
                # 先落盘再 parse：parse 失败时（中转返回非标准结构）原文已经在盘上
                wire = self._wire_body_text(raw)
                if wire is not None:
                    self._log_received(
                        wire,
                        {**meta, "payload_kind": "wire_body", **self._wire_meta(raw)},
                    )
                else:
                    self._log_received(
                        self._response_payload(raw),
                        {**meta, "payload_kind": "raw_wrapper_repr", **self._wire_meta(raw)},
                    )
                return parse()

            self._log_received(
                self._response_payload(raw),
                {**meta, "payload_kind": "parsed_model", **self._wire_meta(raw)},
            )
            return raw

        response = self._call_with_compatible_kwargs(
            endpoint.create, request_params, compatibility=compatibility
        )
        payload = self._response_payload(response)
        self._log_received(
            payload,
            {**meta, "payload_kind": "model_dump" if not isinstance(payload, str) else "repr"},
        )
        return response

    @staticmethod
    def _call_with_compatible_kwargs(
        call: Any,
        request_params: Dict[str, Any],
        *,
        compatibility: Optional[str] = None,
    ) -> Any:
        """Call an SDK method, dropping kwargs rejected by older SDK versions.

        Anthropic added parameters such as ``output_config`` after the minimum
        SDK version supported by Spore. A rejected keyword is raised before an
        HTTP request is made, so retrying once without that optional parameter
        is safe and avoids turning a version mismatch into repeated API retries.
        """
        params = dict(request_params)
        while True:
            try:
                return call(**params)
            except TypeError as exc:
                if compatibility != "anthropic":
                    raise
                match = re.search(
                    r"unexpected keyword argument ['\"]([^'\"]+)['\"]", str(exc)
                )
                unsupported = match.group(1) if match else None
                if unsupported is None or unsupported not in params:
                    raise
                params.pop(unsupported)
                log_info(
                    "Anthropic SDK rejected an optional request parameter; retrying without it",
                    context={"parameter": unsupported},
                )

    def _emit_stream_event(self, request_id: str, event: str, content: str = "") -> None:
        """经 IPC 发送非终态流事件；失败不能影响最终响应。"""
        try:
            self.response_queue.put({
                "request_id": request_id,
                "status": "stream",
                "data": {"event": event, "content": content},
            })
        except Exception:
            pass

    def _is_request_cancelled(self, request_id: str) -> bool:
        if self.global_cancel_flag.is_set():
            return True
        with self._cancelled_requests_lock:
            return request_id in self._cancelled_request_ids

    def _wait_retry_delay(self, request_id: str, delay: float) -> bool:
        """Wait for retry backoff; return False if this request is cancelled."""
        deadline = time.monotonic() + max(0.0, delay)
        while True:
            if self._is_request_cancelled(request_id):
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            # Request cancellation uses a guarded set rather than a per-request Event.
            # Poll briefly so Stop does not remain stuck in a 5/15/25-second backoff.
            time.sleep(min(0.05, remaining))

    def _register_stream(self, request_id: str, stream: Any) -> None:
        with self._active_streams_lock:
            self._active_streams[request_id] = stream
        # 取消命令可能先于 SDK 返回 stream 句柄到达。
        if self._is_request_cancelled(request_id):
            self._close_stream(stream)

    def _unregister_stream(self, request_id: str, stream: Any) -> None:
        with self._active_streams_lock:
            if self._active_streams.get(request_id) is stream:
                self._active_streams.pop(request_id, None)

    @staticmethod
    def _close_stream(stream: Any) -> None:
        close = getattr(stream, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    def cancel_request(self, request_id: Optional[str]) -> bool:
        """取消单个请求；运行中的流通过 close() 直接断开传输。"""
        if not request_id:
            return False
        # 与完成回调使用相同的锁顺序，确保 callback 不会先清理、这里再留下
        # 一个永远没有 worker 帮忙移除的过期 tombstone。
        with self.active_requests_lock:
            future = self.active_requests.get(request_id)
            if future is None:
                return False
            with self._cancelled_requests_lock:
                self._cancelled_request_ids.add(request_id)
        if future is not None:
            future.cancel()
        with self._active_streams_lock:
            stream = self._active_streams.get(request_id)
        if stream is not None:
            self._close_stream(stream)
        return True

    @staticmethod
    def _field(value: Any, name: str, default: Any = None) -> Any:
        if isinstance(value, dict):
            return value.get(name, default)
        return getattr(value, name, default)

    def _stream_openai_chat(
        self,
        request_id: str,
        endpoint: Any,
        request_params: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> Any:
        """消费 Chat Completions 分片并重建兼容现有提取器的完整响应。"""
        stream_params = dict(request_params)
        stream_params["stream"] = True
        stream_params["stream_options"] = {"include_usage": True}
        try:
            chunks = endpoint.create(**stream_params)
        except Exception as exc:
            # 一些 OpenAI-compatible 网关支持 SSE，却不认识 stream_options。
            # 仅在错误明确指向该字段时去掉它重试；不能对任意异常重发，避免重复计费。
            if "stream_options" not in str(exc).lower():
                raise
            stream_params.pop("stream_options", None)
            chunks = endpoint.create(**stream_params)

        self._register_stream(request_id, chunks)

        text_parts = []
        response_id = None
        model = stream_params.get("model")
        created = None
        finish_reason = None
        usage = None
        role = "assistant"

        try:
            for chunk in chunks:
                if self._is_request_cancelled(request_id):
                    break
                response_id = response_id or self._field(chunk, "id")
                model = self._field(chunk, "model", model) or model
                created = created or self._field(chunk, "created")
                chunk_usage = self._field(chunk, "usage")
                if chunk_usage is not None:
                    usage = self._response_payload(chunk_usage)

                choices = self._field(chunk, "choices", []) or []
                if not choices:
                    continue
                choice = choices[0]
                finish_reason = self._field(choice, "finish_reason") or finish_reason
                delta = self._field(choice, "delta", {}) or {}
                role = self._field(delta, "role", role) or role
                piece = self._field(delta, "content", "") or ""
                if isinstance(piece, str) and piece:
                    text_parts.append(piece)
                    self._emit_stream_event(request_id, "delta", piece)
        finally:
            self._unregister_stream(request_id, chunks)
            self._close_stream(chunks)

        response = {
            "id": response_id,
            "object": "chat.completion",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "finish_reason": finish_reason,
                "message": {"role": role, "content": "".join(text_parts)},
            }],
            "usage": usage or {},
        }
        self._log_received(response, {**meta, "payload_kind": "stream_aggregate"})
        return response

    def _stream_openai_responses(
        self,
        request_id: str,
        endpoint: Any,
        request_params: Dict[str, Any],
        meta: Dict[str, Any],
    ) -> Any:
        """消费 Responses API 事件，返回服务端最终 Response 或兼容聚合结果。"""
        stream_params = dict(request_params)
        stream_params["stream"] = True
        events = endpoint.create(**stream_params)
        self._register_stream(request_id, events)
        text_parts = []
        final_response = None

        try:
            for event in events:
                if self._is_request_cancelled(request_id):
                    break
                event_type = self._field(event, "type", "") or ""
                if event_type == "response.output_text.delta":
                    piece = self._field(event, "delta", "") or ""
                    if isinstance(piece, str) and piece:
                        text_parts.append(piece)
                        self._emit_stream_event(request_id, "delta", piece)
                elif event_type in ("response.completed", "response.incomplete"):
                    final_response = self._field(event, "response")
        finally:
            self._unregister_stream(request_id, events)
            self._close_stream(events)

        if final_response is None:
            content = "".join(text_parts)
            final_response = {
                "status": "completed",
                "output_text": content,
                "output": [{
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content}],
                }],
                "usage": {},
            }
        self._log_received(
            self._response_payload(final_response),
            {**meta, "payload_kind": "stream_final"},
        )
        return final_response

    def _create_anthropic_message(
        self,
        request_id: str,
        endpoint: Any,
        request_params: Dict[str, Any],
        meta: Dict[str, Any],
        *,
        stream: bool,
    ) -> Any:
        """Anthropic 流式/非流式统一入口，流式结束后返回完整 Message。"""
        if not stream:
            return self._create_and_log_raw(
                endpoint, request_params, meta, compatibility="anthropic"
            )

        stream_factory = getattr(endpoint, "stream", None)
        if not callable(stream_factory):
            raise RuntimeError("当前 Anthropic 客户端不支持 messages.stream")

        with self._call_with_compatible_kwargs(
            stream_factory, request_params, compatibility="anthropic"
        ) as message_stream:
            self._register_stream(request_id, message_stream)
            try:
                for piece in message_stream.text_stream:
                    if self._is_request_cancelled(request_id):
                        break
                    if isinstance(piece, str) and piece:
                        self._emit_stream_event(request_id, "delta", piece)
                if self._is_request_cancelled(request_id):
                    return None
                response = message_stream.get_final_message()
            finally:
                self._unregister_stream(request_id, message_stream)

        self._log_received(
            self._response_payload(response),
            {**meta, "payload_kind": "stream_final"},
        )
        return response

    # ------------------------------------------------------------------
    # 返回契约构造：三条调用路径共用，避免健康判定逻辑三份实现
    # ------------------------------------------------------------------
    @staticmethod
    def _response_payload(response: Any) -> Any:
        """把 provider 响应转成可落盘的结构。任何失败都退化为字符串预览。"""
        if response is None:
            return None
        if isinstance(response, (str, dict, list)):
            return response
        for method in ("model_dump", "dict", "to_dict"):
            fn = getattr(response, method, None)
            if callable(fn):
                try:
                    return fn()
                except Exception:
                    continue
        try:
            return repr(response)
        except Exception:
            return "<unrepresentable response>"

    @classmethod
    def _anthropic_protocol_mismatch(cls, response: Any) -> Optional[Dict[str, Any]]:
        """识别 Anthropic 调用路径收到的 OpenAI Chat Completions 包络。

        不按模型名猜协议，避免误伤支持多种 wire protocol 的中转；只有响应缺少
        Anthropic content 且带明确 OpenAI 标志时才判定为配置错配。
        """
        payload = cls._response_payload(response)
        if not isinstance(payload, dict):
            return None

        content = payload.get("content")
        has_anthropic_content = isinstance(content, list) and bool(content)
        response_id = payload.get("id")
        object_type = payload.get("object")
        openai_marker = (
            isinstance(response_id, str) and response_id.startswith("chatcmpl-")
        ) or object_type == "chat.completion"
        if has_anthropic_content or not openai_marker:
            return None

        return {
            "response_id": response_id,
            "object": object_type,
            "content_type": type(content).__name__,
            "choices_type": type(payload.get("choices")).__name__,
        }

    def _protocol_mismatch_result(
        self,
        request_id: str,
        response: Any,
        model: Optional[str],
        diagnostics: Dict[str, Any],
    ) -> Dict[str, Any]:
        message = (
            "Anthropic Messages 调用收到了 OpenAI Chat Completions 格式的响应。"
            "请将 LLM_SDK 设为 openai，并通过 OPENAI_API_URL / OPENAI_API_KEY / "
            "OPENAI_MODEL 配置该模型；当前响应无法按 Anthropic content[] 解析。"
        )
        context = {
            "request_id": request_id,
            "model": model,
            "expected_api": "anthropic_messages",
            "detected_api": "openai_chat",
            **diagnostics,
        }
        log_error("LLM_API_PROTOCOL_MISMATCH", message, context=context)
        return {
            "request_id": request_id,
            "status": "error",
            "data": message,
            # 使用不可重试的客户端错误码；这是本地协议配置错误，不是 provider 5xx。
            "error_meta": {"status_code": 422, "exception_type": "ProtocolMismatch"},
            "raw_payload": self._response_payload(response),
            "health": {
                "api_stop_reason": None,
                "finish_state": response_health.FINISH_UNKNOWN,
                "truncated": False,
                "empty": True,
                "refusal": False,
                "usage": response_health.extract_usage(response),
                "content_blocks": [],
            },
        }

    def _finalize_result(
        self,
        request_id: str,
        response: Any,
        content: str,
        role: str,
        current_sent: list,
        max_tokens: Optional[int],
        usage_fallback: Optional[Tuple[int, int]] = None,
        extra_context: Optional[Dict[str, Any]] = None,
        pause_rounds: int = 0,
    ) -> Dict[str, Any]:
        """统一构造返回值，并附上健康判定结果。

        状态语义（新增状态都是"过去被误当成 success"的情况）：

        - ``success``        ：有正文。被截断时正文仍然有用，故仍是 success，
                               但 data.truncated=True，由上层决定如何处理。
        - ``empty_response`` ：一个字都没有。过去这种回复照样标 success，空串被写进
                               对话历史，导致后续请求全部被 400 拒掉。
        - ``refusal``        ：模型拒答/被内容过滤且没有正文，重试无意义。

        API 字段全部容错读取：字段缺失只会让 finish_state 退化为 unknown，
        不会根据正文形态猜测传输状态，也不影响非 GPT/Claude 的兼容 API。
        """
        content = content or ""
        try:
            # usage_fallback 在判定之前交给 assess，用于兼容非标准中转的 token
            # 统计结构；它只补齐诊断数据，不参与截断推断。
            health = response_health.assess(
                response, content, max_tokens, usage_fallback=usage_fallback
            )
        except Exception:
            # 健康判定属于旁路增强，绝不能让它挡住正常回复
            health = {
                "api_stop_reason": None,
                "finish_state": response_health.FINISH_UNKNOWN,
                "truncated": False,
                "truncation_source": None,
                "truncation_hint": None,
                "truncation_confidence": None,
                "empty": not content.strip(),
                "refusal": False,
                "paused": False,
                "usage": {},
                "content_blocks": [],
            }

        usage = dict(health.get("usage") or {})
        input_tokens = usage.get("input_tokens") or 0
        api_input_tokens = usage.get("api_input_tokens") or input_tokens
        output_tokens = usage.get("output_tokens") or 0
        # 通用提取拿不到时，用调用路径自己解析出的数字兜底（兼容非标准返回结构）
        if usage_fallback:
            if not input_tokens:
                input_tokens = usage_fallback[0] or 0
            if not output_tokens:
                output_tokens = usage_fallback[1] or 0

        cache_read = usage.get("cache_read_input_tokens") or 0
        cache_write = usage.get("cache_creation_input_tokens") or 0
        # extract_usage 已按 provider 口径处理缓存：OpenAI cached_tokens 是 input
        # 的子集，Anthropic cache_read/cache_creation 才需要加回。这里不能再次推导。
        context_tokens = usage.get("context_tokens") or input_tokens

        # CLI 模式：打印 token 统计（后端自己处理累计）
        if input_tokens > 0 or output_tokens > 0:
            print(f"[Token] {input_tokens} {output_tokens}", flush=True)

        data = {
            "content": content,
            "role": role or "assistant",
            "sent_messages": current_sent,
            "usage": {
                "input_tokens": input_tokens,
                "api_input_tokens": api_input_tokens,
                "output_tokens": output_tokens,
                "prompt_tokens": input_tokens,      # 兼容 OpenAI 格式
                "completion_tokens": output_tokens,  # 兼容 OpenAI 格式
                # 缓存 token 单独给出；input_tokens 已统一为完整上下文，
                # api_input_tokens 保留 provider 主字段原值。
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": cache_write,
                "context_tokens": context_tokens,
            },
            # 传输层终止原因，与协议层 @SPORE:STOP_REASON 完全无关，不参与 break/continue 判定
            "api_stop_reason": health.get("api_stop_reason"),
            "finish_state": health.get("finish_state"),
            "truncated": bool(health.get("truncated")),
            "truncation_source": health.get("truncation_source"),
            "truncation_hint": health.get("truncation_hint"),
            "truncation_confidence": health.get("truncation_confidence"),
            "refusal": bool(health.get("refusal")),
            "paused": bool(health.get("paused")),
            "max_tokens": max_tokens,
            # 正文由几次调用拼成（0 表示单次）。raw 日志靠它说明"这段正文对应
            # 多条原始响应"，否则正文与原文条数对不上。
            "pause_turn_rounds": pause_rounds,
        }

        is_empty = bool(health.get("empty"))
        if is_empty and health.get("refusal"):
            status = "refusal"
        elif is_empty:
            status = "empty_response"
        else:
            status = "success"

        result = {
            "request_id": request_id,
            "status": status,
            "data": data,
            "health": health,
            # 这里刻意不再挂 raw_payload：完整原文已在收到的那一刻由
            # _log_received 落盘（含 pause_turn 每一轮），再留一份只会白占内存。
        }

        if status != "success":
            context = self._health_context(request_id, result)
            context["max_tokens"] = max_tokens
            if extra_context:
                context.update(extra_context)
            log_error(
                "LLM_NO_TEXT_CONTENT",
                "LLM 返回中没有任何正文（status={0}）".format(status),
                context=context,
            )
        elif data["truncated"]:
            log_error(
                "LLM_RESPONSE_TRUNCATED",
                "LLM 回复被截断（source={0}）".format(data["truncation_source"]),
                context=self._health_context(request_id, result),
            )

        return result

    def _error_result(
        self,
        request_id: str,
        exc: Exception,
        message: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """构造错误返回值：附上重试决策所需的状态码，并把响应体原文落盘。

        400 这类失败最需要看原文，但异常字符串通常已被 SDK 摘要过、日志里还会
        被截断。SDK 的 APIStatusError 带 ``.response``（httpx.Response，有 .text）
        与 ``.body``，这里尽力取出来：立刻落 raw（收到即记），同时挂在结果的
        raw_payload 上。取值失败一律忽略，绝不能因为取诊断信息而再抛一次异常。
        """
        status_code = self._error_status_code(exc, message)
        payload = self._exception_payload(exc, message, status_code)
        if meta is not None:
            self._log_received(payload, {**meta, "payload_kind": "exception_body"})
        return {
            "request_id": request_id,
            "status": "error",
            "data": message,
            "error_meta": {
                "status_code": status_code,
                "exception_type": type(exc).__name__,
            },
            "raw_payload": payload,
        }

    @classmethod
    def _exception_payload(
        cls,
        exc: Exception,
        message: str = "",
        status_code: Optional[int] = None,
    ) -> Dict[str, Any]:
        """尽力从异常里挖出 HTTP 响应体原文等诊断信息；全程静默失败。"""
        payload: Dict[str, Any] = {
            "exception_type": type(exc).__name__,
            "message": message or str(exc),
        }
        if status_code is not None:
            payload["status_code"] = status_code
        try:
            response = getattr(exc, "response", None)
            if response is not None:
                # .text 是未经 SDK 解析的响应体原文，第三方中转的错误细节只在这里
                text = getattr(response, "text", None)
                if isinstance(text, str) and text:
                    payload["response_text"] = text
                elif isinstance(getattr(response, "content", None), (bytes, bytearray)):
                    payload["response_text"] = bytes(response.content).decode(
                        "utf-8", errors="replace"
                    )
                payload.update(cls._wire_meta(response))
        except Exception:
            pass
        try:
            body = getattr(exc, "body", None)
            if body is not None:
                payload["body"] = body if isinstance(body, (dict, list, str)) else repr(body)
        except Exception:
            pass
        try:
            request_id = getattr(exc, "request_id", None)
            if request_id:
                payload["provider_request_id"] = str(request_id)
        except Exception:
            pass
        return payload

    def _do_single_llm_call(
        self,
        request_id: str,
        request_data: Dict[str, Any],
        retry_hint: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        执行单个 LLM 调用（在工作线程中运行）

        Args:
            request_id: 请求唯一标识
            request_data: 请求数据
            retry_hint: 重试提示。仅当上一次是空回复时非 None，携带上次的
                output_tokens / max_tokens，供各调用路径自适应下调思考额度、
                抬高输出上限（普通错误重试传 None，参数保持原样）。

        Returns:
            响应字典，包含 request_id
        """
        # 检查是否已被取消
        if self._is_request_cancelled(request_id):
            return {"request_id": request_id, "status": "cancelled", "data": None}

        messages = request_data.get("messages", [])
        model = request_data.get("model")
        system = request_data.get("system")
        use_sub_agent_config = request_data.get("use_sub_agent_config", False)
        agent_profile = request_data.get("agent_profile")
        stream = bool(request_data.get("stream"))

        # 优先级：颗粒化 profile 基座 > 子 Agent 基座 > 主 Agent 基座
        overrides = None
        if agent_profile:
            resolved = self.config.resolve_agent_llm(agent_profile)
            sdk = resolved["sdk"]
            client = self._client_for(sdk, resolved["api_key"], resolved["api_url"])
            # profile 配置的 model 优先；未配置时用调用方传入的 model 兜底
            model = resolved["model"] or model
            overrides = resolved  # 含高级参数（effort/thinking/responses）
        elif use_sub_agent_config:
            # 子 Agent 派发：沿用预初始化的子 Agent 客户端，
            # 但高级参数按 sub_agent 层解析（SUB_AGENT_* → 主）
            sdk = self.sub_agent_llm_sdk
            client = self.sub_agent_client if sdk == "openai" else self.sub_agent_anthropic_client
            overrides = self.config.resolve_agent_llm("sub_agent")
        else:
            # 使用主 agent 配置
            sdk = self.llm_sdk
            client = self.client if sdk == "openai" else self.anthropic_client

        # 只放定位用的字段（不含任何凭据），供 raw 落盘时标明这条属于谁
        call_meta = {
            "use_sub_agent_config": bool(use_sub_agent_config),
            "agent_profile": agent_profile,
            "attempt_id": request_data.get("_raw_attempt_id"),
            "attempt_index": request_data.get("_raw_attempt_index"),
        }

        # 根据 SDK 类型选择不同的调用方式
        if sdk == "anthropic":
            return self._do_anthropic_call(
                request_id, messages, model, system, client, overrides,
                retry_hint=retry_hint, call_meta=call_meta, stream=stream,
            )
        else:
            return self._do_openai_call(
                request_id, messages, model, system, client, overrides,
                retry_hint=retry_hint, call_meta=call_meta, stream=stream,
            )

    # effort 类参数的显式关闭哨兵：配置 none/off 表示"该层明确不传此参数"，
    # 与"留空 → 继承下层配置"区分开（例如主 Agent 开 effort、某个 AutoAgent 关掉）
    _EFFORT_NONE_SENTINELS = ("none", "off")

    def _adv(self, overrides: Optional[Dict[str, Any]], key: str, config_attr: str):
        """取有效高级参数：overrides 命中（非 None）则用之，否则回退全局 config。"""
        if overrides is not None:
            val = overrides.get(key)
            if val is not None:
                return val
        return getattr(self.config, config_attr, None)

    def _adv_effort(self, overrides: Optional[Dict[str, Any]], key: str, config_attr: str):
        """取 effort 类参数：在 _adv 基础上把显式关闭哨兵（none/off）消化为不传。"""
        val = self._adv(overrides, key, config_attr)
        if isinstance(val, str) and val.strip().lower() in self._EFFORT_NONE_SENTINELS:
            return None
        return val

    # ------------------------------------------------------------------
    # 空回复的自适应重试参数
    #
    # 空回复的典型成因是"思考/推理把输出额度吃光，一个正文块都没产出"（现场
    # 案例：output_tokens 用掉 7958，正文 0 字符）。用逐字节相同的参数重发，
    # 极可能复现同一个空回复，只是多付一次全额 token。所以重试前必须动参数：
    # 先给正文腾额度（压思考），不够再抬上限。
    # ------------------------------------------------------------------

    # 重试时抬高输出上限的目标值。取 16000 的两条理由：
    # 1) 与 _THINKING_MIN_SAFE_MAX_TOKENS 一致 —— 低于这个值时，思考本身就容易
    #    把额度吃满，抬到它才算真正解除瓶颈；
    # 2) 它落在所有"支持思考/推理"的模型的输出上限之内（Claude 3.7+ ≥ 32K、
    #    gpt-4o 16384、o 系列 ≥ 32K），抬到这里不会反过来引发
    #    "max_tokens 超过模型上限"的 400 —— 把软失败换成硬失败是更坏的结果。
    _EMPTY_RETRY_MAX_TOKENS_TARGET = 16000

    # 上一次的 output_tokens 占满上限的这个比例以上，就认定"额度是瓶颈"。
    # 一个正文字都没有却烧掉半个额度，只可能是被思考/推理消耗掉了。
    _EMPTY_RETRY_BURN_RATIO = 0.5

    # 推理档位下调阶梯。只有一次重试机会，所以一步降到 low 而不是逐档下调；
    # 不降到 minimal（仅 gpt-5 系支持，其他模型会 400），也不整个删掉
    # reasoning（删掉等于回到服务端默认档位，通常是 medium，可能更糟）。
    _OPENAI_EFFORT_DOWNGRADE = {"high": "low", "medium": "low", "low": "low", "minimal": "minimal", "disable": "disable"}

    @staticmethod
    def _empty_retry_active(retry_hint: Optional[Dict[str, Any]]) -> bool:
        """本次是否为"上一次空回复"触发的重试（普通错误重试不动参数）。"""
        try:
            return bool(retry_hint) and retry_hint.get("reason") == "empty_response"
        except Exception:
            return False

    @classmethod
    def _prev_burned_output_budget(cls, retry_hint: Optional[Dict[str, Any]]) -> bool:
        """上一次空回复是不是把输出额度大量烧掉了（说明额度本身就是瓶颈）。"""
        try:
            prev_out = int((retry_hint or {}).get("output_tokens") or 0)
            prev_cap = int((retry_hint or {}).get("max_tokens") or 0)
            return prev_cap > 0 and prev_out >= prev_cap * cls._EMPTY_RETRY_BURN_RATIO
        except Exception:
            return False

    def _adjust_anthropic_for_empty_retry(
        self,
        retry_hint: Optional[Dict[str, Any]],
        max_tokens: int,
        thinking_mode: Optional[str],
        budget_tokens: Optional[int],
        effort: Optional[str],
    ) -> Tuple[int, Optional[str], Optional[int], Optional[str], Optional[Dict[str, Any]]]:
        """空回复重试：优先压缩思考额度，把输出额度让给正文。

        Returns:
            (max_tokens, thinking_mode, budget_tokens, effort, adjust)。
            adjust 为 None 表示这次没动任何参数（非空回复重试，或无旋钮可调）。
        """
        if not self._empty_retry_active(retry_hint):
            return max_tokens, thinking_mode, budget_tokens, effort, None
        before = {
            "max_tokens": max_tokens,
            "thinking_mode": thinking_mode,
            "thinking_budget_tokens": budget_tokens,
            "effort": effort,
        }
        action = "none"
        try:
            if thinking_mode == "adaptive":
                # adaptive 没有可调的 budget 旋钮，唯一有效手段是整个关掉思考：
                # 关掉后整份 max_tokens 都归正文，也不必抬上限（零 400 风险）。
                thinking_mode = "disabled"
                # effort 会被重新推断成 adaptive thinking，必须一起撤掉，
                # 否则等于什么都没改。
                effort = None
                action = "thinking_adaptive_to_disabled"
            elif thinking_mode == "enabled":
                # 手动预算：腰斩（不低于 API 要求的 1024），并保证正文能拿到不少于
                # 思考的额度；上限不够就抬到 16000（能开思考的模型都容得下）。
                new_budget = max(1024, int(budget_tokens or 0) // 2)
                if max_tokens - new_budget < new_budget:
                    max_tokens = max(max_tokens, self._EMPTY_RETRY_MAX_TOKENS_TARGET)
                budget_tokens = new_budget
                action = "thinking_budget_halved"
            elif self._prev_burned_output_budget(retry_hint):
                # 思考按配置是关的，额度却照样被烧光 —— 常见于第三方中转把推理
                # 内容计进 output_tokens 却不回传对应内容块。此时只剩抬上限一招。
                max_tokens = max(max_tokens, self._EMPTY_RETRY_MAX_TOKENS_TARGET)
                action = "max_tokens_raised"
        except Exception:
            # 参数自适应属于旁路优化，出错就按原参数重试，绝不能挡住调用
            return before["max_tokens"], before["thinking_mode"], before["thinking_budget_tokens"], \
                before["effort"], None
        adjust = {
            "reason": "empty_response_retry",
            "request_id": (retry_hint or {}).get("request_id"),
            "attempt": (retry_hint or {}).get("attempt"),
            "prev_output_tokens": (retry_hint or {}).get("output_tokens"),
            "prev_max_tokens": (retry_hint or {}).get("max_tokens"),
            "action": action,
            "before": before,
            "after": {
                "max_tokens": max_tokens,
                "thinking_mode": thinking_mode,
                "thinking_budget_tokens": budget_tokens,
                "effort": effort,
            },
        }
        self._log_empty_retry_adjust(adjust)
        return max_tokens, thinking_mode, budget_tokens, effort, adjust

    def _adjust_openai_for_empty_retry(
        self,
        retry_hint: Optional[Dict[str, Any]],
        max_tokens: int,
        effort: Optional[str],
    ) -> Tuple[int, Optional[str], Optional[Dict[str, Any]]]:
        """空回复重试：下调 reasoning_effort 并抬高输出上限，给正文腾额度。"""
        if not self._empty_retry_active(retry_hint):
            return max_tokens, effort, None
        before = {"max_tokens": max_tokens, "reasoning_effort": effort}
        action = "none"
        try:
            if effort:
                key = str(effort).strip().lower()
                # 未知档位（中转自造值）一律降到 low，这是各家都认的最低有效档
                lowered = self._OPENAI_EFFORT_DOWNGRADE.get(key, "low")
                # 推理仍会占额度，所以下调档位的同时把上限抬到安全值
                max_tokens = max(max_tokens, self._EMPTY_RETRY_MAX_TOKENS_TARGET)
                action = "effort_downgraded" if lowered != key else "max_tokens_raised"
                effort = lowered
            elif self._prev_burned_output_budget(retry_hint):
                # 没配 effort 却把额度烧光（中转默认开了推理）：只能抬上限
                max_tokens = max(max_tokens, self._EMPTY_RETRY_MAX_TOKENS_TARGET)
                action = "max_tokens_raised"
        except Exception:
            return before["max_tokens"], before["reasoning_effort"], None
        adjust = {
            "reason": "empty_response_retry",
            "request_id": (retry_hint or {}).get("request_id"),
            "attempt": (retry_hint or {}).get("attempt"),
            "prev_output_tokens": (retry_hint or {}).get("output_tokens"),
            "prev_max_tokens": (retry_hint or {}).get("max_tokens"),
            "action": action,
            "before": before,
            "after": {"max_tokens": max_tokens, "reasoning_effort": effort},
        }
        self._log_empty_retry_adjust(adjust)
        return max_tokens, effort, adjust

    @staticmethod
    def _log_empty_retry_adjust(adjust: Dict[str, Any]) -> None:
        """把调整后的实际参数落进日志。

        不落的话，日志里这次重试和上一次长得一模一样，排查时看不出到底改了什么、
        改了有没有用。用 log_error 落是刻意的：它会进 error.log 与日志监控，
        和触发它的 LLM_EMPTY_RESPONSE_RETRY 挨在一起，不必翻两个文件对时间戳。
        """
        try:
            log_error(
                "LLM_EMPTY_RETRY_ADJUST",
                "空回复重试：已调整生成参数（action={0}）".format(adjust.get("action")),
                context=adjust,
            )
        except Exception:
            pass


    def _client_for(self, sdk: str, api_key: str, api_url: Optional[str]):
        """按 (sdk, api_key, api_url) 懒加载并缓存客户端，供颗粒化 Agent 基座复用。"""
        cache_key = (sdk, api_key or "", api_url or "")
        with self._profile_clients_lock:
            cached = self._profile_clients.get(cache_key)
            if cached is not None:
                return cached
            from .client import build_openai_client, build_anthropic_client
            if sdk == "anthropic":
                client = build_anthropic_client(api_key, api_url)
            else:
                client = build_openai_client(api_key, api_url)
            self._profile_clients[cache_key] = client
            return client


    @staticmethod
    def _extract_openai_responses_text(response: Any) -> str:
        """从 Responses API 返回值中提取文本。

        官方 SDK 返回带 output_text 的对象；部分代理/兼容网关可能返回 str、dict，
        或只有 output 列表。这里做兜底，避免 AttributeError。
        """
        if response is None:
            return ""

        if isinstance(response, str):
            return response

        if isinstance(response, dict):
            # 直接文本字段
            for key in ("output_text", "text", "content"):
                val = response.get(key)
                if isinstance(val, str) and val:
                    return val
            output = response.get("output") or []
            parts: list[str] = []
            for item in output:
                if isinstance(item, str):
                    parts.append(item)
                    continue
                if not isinstance(item, dict):
                    continue
                # message item: content: [{type: output_text, text: ...}]
                content = item.get("content")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict):
                            block_type = block.get("type")
                            if block_type in ("output_text", "text") and block.get("text"):
                                parts.append(str(block.get("text")))
                            elif isinstance(block.get("text"), str):
                                parts.append(block["text"])
                        elif isinstance(block, str):
                            parts.append(block)
                elif item.get("type") in ("output_text", "text") and item.get("text"):
                    parts.append(str(item.get("text")))
            return "".join(parts)

        # 官方 SDK Response 对象
        output_text = getattr(response, "output_text", None)
        if isinstance(output_text, str):
            return output_text
        if output_text is not None and not callable(output_text):
            # 极少数实现里 output_text 可能不是 str
            try:
                return str(output_text)
            except Exception:
                pass

        # 回退：遍历 output 消息块
        parts: list[str] = []
        output = getattr(response, "output", None) or []
        for item in output:
            content = getattr(item, "content", None)
            if content is None and isinstance(item, dict):
                content = item.get("content")
            if isinstance(content, str):
                parts.append(content)
                continue
            if not content:
                # 有些 item 本身就是 output_text
                text_val = getattr(item, "text", None)
                if text_val is None and isinstance(item, dict):
                    text_val = item.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
                continue
            for block in content:
                block_type = getattr(block, "type", None)
                if block_type is None and isinstance(block, dict):
                    block_type = block.get("type")
                text_val = getattr(block, "text", None)
                if text_val is None and isinstance(block, dict):
                    text_val = block.get("text")
                if block_type in ("output_text", "text", None) and isinstance(text_val, str):
                    parts.append(text_val)
                elif isinstance(block, str):
                    parts.append(block)
        return "".join(parts)



    @staticmethod
    def _extract_openai_chat_completion(completion: Any) -> tuple[str, str, int, int]:
        """从 Chat Completions 返回值提取 (content, role, prompt_tokens, completion_tokens)。

        官方 SDK 返回 ChatCompletion 对象；部分代理可能返回 dict，
        甚至直接返回纯文本 str（非标准）。
        """
        if completion is None:
            return "", "assistant", 0, 0

        # 非标准：API 直接返回字符串内容
        if isinstance(completion, str):
            return completion, "assistant", 0, 0

        def _usage_from(obj: Any) -> tuple[int, int]:
            usage = None
            if isinstance(obj, dict):
                usage = obj.get("usage") or {}
                if isinstance(usage, dict):
                    return (
                        int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0),
                        int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
                    )
                return 0, 0
            usage = getattr(obj, "usage", None)
            if usage is None:
                return 0, 0
            return (
                int(getattr(usage, "prompt_tokens", 0) or getattr(usage, "input_tokens", 0) or 0),
                int(getattr(usage, "completion_tokens", 0) or getattr(usage, "output_tokens", 0) or 0),
            )

        def _content_from_message(message: Any) -> tuple[str, str]:
            if message is None:
                return "", "assistant"
            if isinstance(message, str):
                return message, "assistant"
            if isinstance(message, dict):
                content = message.get("content")
                role = message.get("role") or "assistant"
            else:
                content = getattr(message, "content", None)
                role = getattr(message, "role", None) or "assistant"

            if content is None:
                return "", str(role)
            if isinstance(content, str):
                return content, str(role)
            # content 可能是多段 list: [{type:text,text:...}]
            if isinstance(content, list):
                parts: list[str] = []
                for block in content:
                    if isinstance(block, str):
                        parts.append(block)
                    elif isinstance(block, dict):
                        if block.get("type") in ("text", "output_text", None) and block.get("text"):
                            parts.append(str(block.get("text")))
                        elif isinstance(block.get("content"), str):
                            parts.append(block["content"])
                    else:
                        text_val = getattr(block, "text", None)
                        if isinstance(text_val, str):
                            parts.append(text_val)
                return "".join(parts), str(role)
            return str(content), str(role)

        # dict 形态
        if isinstance(completion, dict):
            choices = completion.get("choices") or []
            if choices:
                first = choices[0] or {}
                if isinstance(first, dict):
                    # 常见: choices[0].message.content
                    if "message" in first:
                        content, role = _content_from_message(first.get("message"))
                        p, c = _usage_from(completion)
                        return content, role, p, c
                    # 部分兼容实现: choices[0].text
                    if isinstance(first.get("text"), str):
                        p, c = _usage_from(completion)
                        return first["text"], "assistant", p, c
                    if isinstance(first.get("content"), str):
                        p, c = _usage_from(completion)
                        return first["content"], "assistant", p, c
            # 无 choices 时尝试顶层 content/text
            for key in ("content", "text", "output_text", "response"):
                val = completion.get(key)
                if isinstance(val, str) and val:
                    p, c = _usage_from(completion)
                    return val, "assistant", p, c
            raise TypeError(
                "OpenAI Chat Completions returned a dict without recognizable choices/message. "
                f"keys={list(completion.keys())[:20]}"
            )

        # 官方对象形态
        choices = getattr(completion, "choices", None)
        if choices:
            first = choices[0]
            message = getattr(first, "message", None)
            if message is None and isinstance(first, dict):
                message = first.get("message")
            if message is not None:
                content, role = _content_from_message(message)
                p, c = _usage_from(completion)
                return content, role, p, c
            text_val = getattr(first, "text", None)
            if text_val is None and isinstance(first, dict):
                text_val = first.get("text")
            if isinstance(text_val, str):
                p, c = _usage_from(completion)
                return text_val, "assistant", p, c

        raise TypeError(
            "OpenAI Chat Completions returned an unexpected object without choices: "
            f"type={type(completion).__name__}, preview={str(completion)[:300]}"
        )


    def _do_openai_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI",
        overrides: Optional[Dict[str, Any]] = None,
        retry_hint: Optional[Dict[str, Any]] = None,
        call_meta: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """使用 OpenAI SDK 调用 LLM（自动选择 Chat Completions 或 Responses API）"""
        if self._adv(overrides, "use_responses_api", "use_responses_api"):
            return self._do_openai_responses_call(
                request_id, messages, model, system, client, overrides,
                retry_hint=retry_hint, call_meta=call_meta, stream=stream,
            )
        return self._do_openai_chat_call(
            request_id, messages, model, system, client, overrides,
            retry_hint=retry_hint, call_meta=call_meta, stream=stream,
        )

    def _do_openai_chat_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI",
        overrides: Optional[Dict[str, Any]] = None,
        retry_hint: Optional[Dict[str, Any]] = None,
        call_meta: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """使用 OpenAI Chat Completions API"""
        # 构建最终消息列表
        final_messages = []
        if system:
            if self.config.system_as_user:
                # 兼容模式：将 system prompt 作为第一条 user 消息
                if _config.memory_continued:
                    # 继承记忆模式：将 prompt 拼接到第一条 user 消息前面
                    _config.memory_continued = False  # 重置标志
                    if messages and messages[0].get("role") == "user":
                        # 拼接 prompt 到第一条 user 消息
                        messages[0]["content"] = system + "\n\n" + messages[0]["content"]
                    else:
                        # 没有 user 消息，直接添加 prompt
                        final_messages.append({"role": "user", "content": system})
                else:
                    # 正常模式：添加 system prompt 作为第一条 user 消息
                    if system:
                        final_messages.append({"role": "user", "content": system})
            else:
                final_messages.append({"role": "system", "content": system})
        final_messages.extend(messages)
        
        # 在 system_as_user 模式下，合并连续的同角色消息（避免连续的 user 消息）
        if self.config.system_as_user:
            final_messages = self._merge_consecutive_messages(final_messages)
        else:
            # 标准模式不合并，但空消息一律要清掉：历史里混入空 assistant 消息
            # 会让整轮请求被 400 拒掉，且后续每一轮都失败
            final_messages = self._drop_blank_messages(final_messages)

        try:
            timeout = self.config.api_timeout
            max_tokens = self._adv(overrides, "max_output_tokens", "max_output_tokens") or self.config.get_max_tokens()

            # 如果配置了 reasoning_effort，添加到请求中（none/off 表示明确不传）
            eff = self._adv_effort(overrides, "reasoning_effort", "openai_reasoning_effort")
            # 上一次是空回复时才会真正改动参数（降推理档位 / 抬输出上限）
            max_tokens, eff, retry_adjust = self._adjust_openai_for_empty_retry(
                retry_hint, max_tokens, eff
            )

            # 构建请求参数
            request_params = {
                "model": model,
                "messages": final_messages,
                "max_tokens": max_tokens,
                "timeout": timeout,
            }

            if eff == "disable":
                # 非 Responses 路径的显式关闭格式与 Claude 相同
                request_params["extra_body"] = {"thinking": {"type": "disabled"}}
            elif eff:
                request_params["extra_body"] = {"reasoning_effort": eff}

            received_meta = self._received_meta(
                request_id, "openai_chat", model, call_meta,
                extra={"retry_adjust": retry_adjust} if retry_adjust else None,
            )
            # 收到即落盘：提取/判定之前先把原文写进 raw
            if stream:
                completion = self._stream_openai_chat(
                    request_id, client.chat.completions, request_params, received_meta
                )
            else:
                completion = self._create_and_log_raw(
                    client.chat.completions, request_params, received_meta
                )

            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            # 兼容官方 ChatCompletion 对象 / dict / 部分代理返回的纯文本 str
            if isinstance(completion, str):
                log_error(
                    "LLM_API_CALL_ERROR",
                    "OpenAI Chat Completions returned a plain string instead of a ChatCompletion object. "
                    "This usually means OPENAI_API_URL is not a standard OpenAI-compatible /chat/completions endpoint, "
                    "or the proxy returns raw text. Check LLM_SDK/OPENAI_API_URL/OPENAI_MODEL.",
                    context={
                        "request_id": request_id,
                        "model": model,
                        "response_type": "str",
                        "response_preview": completion[:500],
                        "openai_api_url": getattr(self.config, "openai_api_url", None),
                        "use_responses_api": getattr(self.config, "use_responses_api", False),
                    },
                )

            reply_content, reply_role, input_tokens, output_tokens = self._extract_openai_chat_completion(completion)

            # 构建本次发送的消息（不包含历史记忆）
            current_sent = []
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            if is_first_conversation and system:
                if self.config.system_as_user:
                    current_sent.append({"role": "user", "content": system})
                else:
                    current_sent.append({"role": "system", "content": system})
            tail_msgs_chat: list = []
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    if self.config.system_as_user and system and msg.get("content") == system:
                        break
                    tail_msgs_chat.append(msg)
                else:
                    break
            current_sent.extend(reversed(tail_msgs_chat))

            return self._finalize_result(
                request_id,
                completion,
                reply_content,
                reply_role or "assistant",
                current_sent,
                max_tokens,
                usage_fallback=(input_tokens, output_tokens),
                extra_context={
                    "api": "openai_chat",
                    "model": model,
                    "reasoning_effort": eff,
                    "retry_adjust": retry_adjust,
                },
            )

        except Exception as exc:
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            error_context = {
                "request_id": request_id,
                "model": model,
                "openai_api_url": getattr(self.config, "openai_api_url", None),
                "use_responses_api": getattr(self.config, "use_responses_api", False),
                "llm_sdk": getattr(self, "llm_sdk", None),
            }
            if 'completion' in locals() and completion is not None:
                error_context["response_type"] = type(completion).__name__
                error_context["response"] = str(completion)[:1000]
            log_error(
                "LLM_API_CALL_ERROR",
                f"OpenAI Chat API call error: {str(exc)}",
                exc,
                context=error_context
            )
            # 异常携带的响应体原文同样"收到即记"：400 这类失败最需要看原文
            return self._error_result(
                request_id, exc, str(exc),
                meta=self._received_meta(request_id, "openai_chat", model, call_meta),
            )

    def _do_openai_responses_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI",
        overrides: Optional[Dict[str, Any]] = None,
        retry_hint: Optional[Dict[str, Any]] = None,
        call_meta: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """使用 OpenAI Responses API（client.responses.create）"""
        # Responses API 使用 `input` 字段传消息，`instructions` 传 system prompt
        # 消息格式与 Chat Completions 相同（role + content）
        input_messages = []

        if system and self.config.system_as_user:
            # system_as_user 模式：将 system 拼入第一条 user 消息
            if _config.memory_continued:
                _config.memory_continued = False
                if messages and messages[0].get("role") == "user":
                    messages[0]["content"] = system + "\n\n" + messages[0]["content"]
                else:
                    input_messages.append({"role": "user", "content": system})
            else:
                input_messages.append({"role": "user", "content": system})

        input_messages.extend(messages)

        if self.config.system_as_user:
            input_messages = self._merge_consecutive_messages(input_messages)
        else:
            input_messages = self._drop_blank_messages(input_messages)

        try:
            # 构建请求参数
            # Responses API 不支持 temperature，instructions 对应 system prompt
            max_tokens = self._adv(overrides, "max_output_tokens", "max_output_tokens") or self.config.get_max_tokens()

            # 如果配置了 reasoning_effort，添加到请求中（none/off 表示明确不传）
            eff = self._adv_effort(overrides, "reasoning_effort", "openai_reasoning_effort")
            # 上一次是空回复时才会真正改动参数（降推理档位 / 抬输出上限）
            max_tokens, eff, retry_adjust = self._adjust_openai_for_empty_retry(
                retry_hint, max_tokens, eff
            )

            request_params: Dict[str, Any] = {
                "model": model,
                "input": input_messages,
                "max_output_tokens": max_tokens,
            }
            if system and not self.config.system_as_user:
                request_params["instructions"] = system

            if eff == "disable":
                # Responses API 用 effort="none" 显式关闭推理，不同于内部 none sentinel（不传）
                request_params["reasoning"] = {"effort": "none"}
            elif eff:
                request_params["reasoning"] = {"effort": eff}

            received_meta = self._received_meta(
                request_id, "openai_responses", model, call_meta,
                extra={"retry_adjust": retry_adjust} if retry_adjust else None,
            )
            # 收到即落盘：提取/判定之前先把原文写进 raw
            if stream:
                response = self._stream_openai_responses(
                    request_id, client.responses, request_params, received_meta
                )
            else:
                response = self._create_and_log_raw(client.responses, request_params, received_meta)

            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            # 兼容官方 SDK 对象 / dict / 部分代理返回的 str
            if isinstance(response, str):
                # 网关未返回标准 Responses 对象时给出更明确的错误上下文
                log_error(
                    "LLM_API_CALL_ERROR",
                    "OpenAI Responses API returned a plain string instead of a Response object. "
                    "This usually means the API base URL is not a full Responses-compatible endpoint. "
                    "Try setting USE_RESPONSES_API=false, or use an official OpenAI Responses endpoint.",
                    context={
                        "request_id": request_id,
                        "model": model,
                        "response_preview": response[:500],
                    },
                )
            reply_content = self._extract_openai_responses_text(response)

            # 构建本次发送的消息记录
            current_sent = []
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            if is_first_conversation and system and not self.config.system_as_user:
                current_sent.append({"role": "system", "content": system})
            tail_msgs_resp: list = []
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    if self.config.system_as_user and system and msg.get("content") == system:
                        break
                    tail_msgs_resp.append(msg)
                else:
                    break
            current_sent.extend(reversed(tail_msgs_resp))

            # usage / status / incomplete_details 全部走容错提取：
            # Responses API 的截断信号在 status="incomplete" + incomplete_details.reason，
            # 字段缺失时保持 unknown，由协议层独立校验回复结构
            return self._finalize_result(
                request_id,
                response,
                reply_content,
                "assistant",
                current_sent,
                max_tokens,
                extra_context={
                    "api": "openai_responses",
                    "model": model,
                    "reasoning_effort": eff,
                    "retry_adjust": retry_adjust,
                },
            )

        except Exception as exc:
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            error_context = {"request_id": request_id, "model": model}
            if 'response' in locals() and response is not None:
                error_context["response"] = str(response)
            log_error(
                "LLM_API_CALL_ERROR",
                f"OpenAI Responses API call error: {str(exc)}",
                exc,
                context=error_context
            )
            # 异常携带的响应体原文同样"收到即记"
            return self._error_result(
                request_id, exc, str(exc),
                meta=self._received_meta(request_id, "openai_responses", model, call_meta),
            )
    
    def _do_anthropic_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "Anthropic",
        overrides: Optional[Dict[str, Any]] = None,
        retry_hint: Optional[Dict[str, Any]] = None,
        call_meta: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Dict[str, Any]:
        """使用 Anthropic SDK 调用 LLM"""
        # Anthropic 消息格式转换
        # 1. 如果 system_as_user=true，system 作为第一条 user 消息
        # 2. 否则 system 作为单独参数传递
        # 3. 消息必须是 user/assistant 交替，不能有连续的同角色消息
        
        anthropic_messages = []
        anthropic_system = None  # 实际传给 API 的 system 参数
        
        # 根据配置决定 system 的处理方式
        if self.config.system_as_user:
            # system_as_user 模式：system 作为第一条 user 消息
            if _config.memory_continued:
                # 继承记忆模式：将 prompt 拼接到第一条 user 消息前面
                _config.memory_continued = False  # 重置标志
                if messages and messages[0].get("role") == "user":
                    # 拼接 prompt 到第一条 user 消息
                    messages[0]["content"] = system + "\n\n" + messages[0]["content"]
                elif system:
                    # 没有 user 消息，直接添加 prompt
                    anthropic_messages.append({"role": "user", "content": system})
            else:
                # 正常模式：添加 prompt 作为第一条 user 消息
                if system:
                    anthropic_messages.append({"role": "user", "content": system})
        else:
            # 标准模式：system 作为单独参数
            anthropic_system = system
        
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            
            # 跳过 system 消息（已处理）
            if role == "system":
                if not anthropic_system and not self.config.system_as_user:
                    anthropic_system = content
                continue
            
            # 转换角色名
            if role == "assistant":
                anthropic_messages.append({"role": "assistant", "content": content})
            else:
                # user 或其他角色都当作 user
                anthropic_messages.append({"role": "user", "content": content})
        
        # 合并连续的同角色消息（同时丢弃空消息）
        anthropic_messages = self._merge_consecutive_messages(anthropic_messages)

        # 确保第一条消息是 user
        if anthropic_messages and anthropic_messages[0]["role"] != "user":
            anthropic_messages.insert(0, {"role": "user", "content": "[系统初始化]"})

        if not anthropic_messages:
            # 清理后一条消息都不剩，说明上游传来的历史全是空内容。
            # 直接返回错误比发出必然被 400 拒掉的请求更清晰，也不会白等四次重试。
            message = "请求消息为空（清理空消息后无有效内容），未发起 API 调用"
            # 光知道"消息为空"没法定位是谁传来的空历史，必须留下清理前的形状：
            # 每条消息的角色与内容长度（不落内容本身，避免把整段历史复制进日志）。
            diagnostics: Dict[str, Any] = {
                "reason": "empty_request_after_cleanup",
                "raw_message_count": len(messages or []),
                "system_length": len(system or ""),
                "system_as_user": bool(getattr(self.config, "system_as_user", False)),
                "model": model,
            }
            try:
                diagnostics["raw_messages"] = [
                    {
                        "role": m.get("role") if isinstance(m, dict) else type(m).__name__,
                        "content_type": type(m.get("content")).__name__ if isinstance(m, dict) else None,
                        "content_length": len(str(m.get("content") or "")) if isinstance(m, dict) else 0,
                    }
                    for m in (messages or [])
                ]
            except Exception:
                pass
            log_error(
                "LLM_EMPTY_REQUEST",
                message,
                context={"request_id": request_id, **diagnostics},
            )
            return {
                "request_id": request_id,
                "status": "error",
                "data": message,
                "error_meta": {"status_code": 400, "exception_type": "EmptyRequest"},
                "raw_payload": diagnostics,
            }

        try:
            max_tokens = self._adv(overrides, "max_output_tokens", "max_output_tokens") or self.config.get_max_tokens()

            # 构建请求参数
            request_params = {
                "model": model or self.config.get_model(),
                "messages": anthropic_messages,
                "max_tokens": max_tokens,
                "timeout": self.config.api_timeout,
            }
            
            # system 参数（仅在非 system_as_user 模式下使用）
            if anthropic_system:
                request_params["system"] = anthropic_system

            # Claude thinking / effort：
            # - 现代模型：thinking={"type":"adaptive"} + output_config={"effort":...}
            # - 旧模型手动扩展思考：thinking={"type":"enabled","budget_tokens":N}
            thinking_mode = self._adv(overrides, "thinking_mode", "anthropic_thinking_mode")
            # none/off 哨兵 → 明确不传 effort（且不会触发 adaptive thinking 的自动推断）
            effort = self._adv_effort(overrides, "effort", "anthropic_effort")
            budget_tokens = self._adv(overrides, "thinking_budget_tokens", "anthropic_thinking_budget_tokens")

            # 'disable' 哨兵：明确关闭思考（不论是否已有 thinking_mode 配置均强制覆盖）
            if effort == "disable":
                thinking_mode = "disabled"
                effort = None

            if thinking_mode is None:
                if effort:
                    thinking_mode = "adaptive"
                elif budget_tokens:
                    thinking_mode = "enabled"

            # 上一次是空回复时才会真正改动参数：先压思考给正文腾额度，必要时提高输出上限。
            # 放在推断之后，是为了让"由 effort 推断出的 adaptive"也能被压下去。
            max_tokens, thinking_mode, budget_tokens, effort, retry_adjust = \
                self._adjust_anthropic_for_empty_retry(
                    retry_hint, max_tokens, thinking_mode, budget_tokens, effort
                )
            request_params["max_tokens"] = max_tokens

            if thinking_mode == "disabled":
                request_params["thinking"] = {"type": "disabled"}
            elif thinking_mode == "adaptive":
                request_params["thinking"] = {"type": "adaptive"}
            elif thinking_mode == "enabled":
                # budget_tokens 必须 >= 1024 且 < max_tokens
                resolved_budget = budget_tokens if budget_tokens is not None else min(10000, max(1024, max_tokens // 2))
                if resolved_budget >= max_tokens:
                    resolved_budget = max(1024, max_tokens - 1)
                if resolved_budget >= 1024 and resolved_budget < max_tokens:
                    request_params["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": resolved_budget,
                    }

            if effort:
                request_params["output_config"] = {"effort": effort}

            # 思考 token 也计入 output_tokens：max_tokens 太小时，额度可能被思考吃光，
            # 一个正文块都产不出来 —— 表现就是"空回复"。这里提前告警，避免只在
            # 现象层反复排查。
            self._warn_thinking_budget(request_params.get("thinking"), max_tokens, model)

            received_meta = self._received_meta(
                request_id, "anthropic_messages", request_params.get("model"), call_meta,
                extra={"retry_adjust": retry_adjust} if retry_adjust else None,
            )
            # 收到即落盘：提取 / 续调 / 判定之前先把原文写进 raw
            response = self._create_anthropic_message(
                request_id, client.messages, request_params, received_meta, stream=stream
            )

            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            mismatch = self._anthropic_protocol_mismatch(response)
            if mismatch is not None:
                return self._protocol_mismatch_result(
                    request_id, response, request_params.get("model"), mismatch
                )

            # 提取响应内容：排除式判定（排除 thinking / 工具类块，其余凡有文本即为正文），
            # 同时兼容 dict 形态的块。旧实现只认 type == "text"，模型新增块类型或
            # 第三方中转自造类型名时会把整条回复静默丢成空串。
            content = response_health.extract_text(response)

            # pause_turn：长任务被服务端暂停，需要把已产出的部分回传后续调，
            # 否则这一轮会被当成"提前结束"，正文只有一半。
            response, content, pause_rounds = self._continue_paused_turn(
                request_id, client, request_params, response, content, received_meta,
                stream=stream,
            )
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            # 构建本次发送的消息（不包含历史记忆）
            current_sent = []
            
            # 判断是否是第一次对话（messages 中只有一条用户消息）
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            
            # 只在第一次对话时添加 system prompt
            if is_first_conversation:
                if anthropic_system and not self.config.system_as_user:
                    current_sent.append({"role": "system", "content": anthropic_system})
                elif self.config.system_as_user and anthropic_messages and anthropic_messages[0].get("role") == "user":
                    # system_as_user 模式：第一条 user 消息就是 system prompt
                    current_sent.append(anthropic_messages[0])
            
            # 添加本轮所有连续的用户消息（多工具结果 + 最后一条用户输入）
            start_index = 1 if self.config.system_as_user else 0
            tail_msgs: list = []
            for msg in reversed(anthropic_messages[start_index:]):
                if msg.get("role") == "user":
                    tail_msgs.append(msg)
                else:
                    break
            current_sent.extend(reversed(tail_msgs))
            
            return self._finalize_result(
                request_id,
                response,
                content,
                "assistant",
                current_sent,
                max_tokens,
                extra_context={
                    "api": "anthropic_messages",
                    "model": request_params.get("model"),
                    "thinking": request_params.get("thinking"),
                    "output_config": request_params.get("output_config"),
                    "retry_adjust": retry_adjust,
                },
                pause_rounds=pause_rounds,
            )

        except Exception as exc:
            if self._is_request_cancelled(request_id):
                return {"request_id": request_id, "status": "cancelled", "data": None}

            error_context = {"request_id": request_id, "model": model}
            if 'response' in locals() and response is not None:
                error_context["response"] = str(response)
            log_error(
                "LLM_API_CALL_ERROR",
                f"Anthropic API call error: {str(exc)}",
                exc,
                context=error_context
            )
            # 异常携带的响应体原文同样"收到即记"
            return self._error_result(
                request_id, exc, str(exc),
                meta=self._received_meta(request_id, "anthropic_messages", model, call_meta),
            )

    # pause_turn 续调上限：防止服务端反复 pause 时无限续调
    _MAX_PAUSE_CONTINUATIONS = 2

    # 开启思考时，输出上限低于此值就容易被思考吃光额度
    _THINKING_MIN_SAFE_MAX_TOKENS = 16000

    def _warn_thinking_budget(
        self, thinking: Optional[Dict[str, Any]], max_tokens: int, model: Optional[str]
    ) -> None:
        """思考额度与输出上限明显不匹配时告警（只记日志，不改变行为）。"""
        try:
            if not isinstance(thinking, dict):
                return
            mode = thinking.get("type")
            if mode not in ("adaptive", "enabled"):
                return
            budget = thinking.get("budget_tokens")
            risky = False
            reason = None
            if isinstance(budget, int) and budget > 0:
                # 留给正文的额度不足思考额度的一半时，正文极可能写不完
                if max_tokens - budget < max(1024, budget // 2):
                    risky = True
                    reason = "budget_leaves_too_little_for_text"
            elif max_tokens < self._THINKING_MIN_SAFE_MAX_TOKENS:
                risky = True
                reason = "max_tokens_too_small_for_thinking"
            if not risky:
                return
            log_error(
                "LLM_THINKING_BUDGET_RISK",
                "思考已开启但输出上限偏小，正文可能被截断甚至为空；建议提高 MAX_OUTPUT_TOKENS "
                "或降低 thinking 预算。",
                context={
                    "model": model,
                    "max_tokens": max_tokens,
                    "thinking": thinking,
                    "reason": reason,
                },
            )
        except Exception:
            pass

    def _continue_paused_turn(
        self,
        request_id: str,
        client: "Anthropic",
        request_params: Dict[str, Any],
        response: Any,
        content: str,
        received_meta: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Tuple[Any, str, int]:
        """pause_turn 续调：把已产出的助手轮回传，继续这一轮生成。

        每一轮的响应都在返回的那一刻单独落一条 raw（带 pause_turn_round 序号）：
        正文是跨轮累加的，而 response 只保留最后一轮，只落最后一次的话，日志里
        的正文和原文会互相矛盾。

        续调次数有上限；任何异常都直接返回已拿到的内容，不让续调把正常回复带崩。

        Returns:
            (最后一轮的响应, 累加后的正文, 实际续调轮数)
        """
        rounds = 0
        try:
            while rounds < self._MAX_PAUSE_CONTINUATIONS:
                _raw, finish_state = response_health.extract_finish_reason(response)
                if finish_state != response_health.FINISH_PAUSED:
                    break
                if self._is_request_cancelled(request_id):
                    break
                blocks = self._serialize_content_blocks(response)
                if not blocks:
                    break
                params = dict(request_params)
                params["messages"] = list(params.get("messages") or []) + [
                    {"role": "assistant", "content": blocks}
                ]
                log_info(
                    "LLM 返回 pause_turn，续调以取回剩余内容",
                    context={"request_id": request_id, "round": rounds + 1},
                )
                round_meta = dict(received_meta or {"request_id": request_id})
                round_meta["pause_turn_round"] = rounds + 1
                response = self._create_anthropic_message(
                    request_id, client.messages, params, round_meta, stream=stream
                )
                content = (content or "") + response_health.extract_text(response)
                request_params = params
                rounds += 1
        except Exception as exc:
            log_error(
                "LLM_PAUSE_CONTINUATION_FAILED",
                "pause_turn 续调失败，返回已获取的部分内容: {0}".format(exc),
                exc,
                context={"request_id": request_id, "round": rounds},
            )
        return response, content, rounds

    @staticmethod
    def _serialize_content_blocks(response: Any) -> list:
        """把响应的内容块转成可回传的结构；失败返回空列表。"""
        blocks = []
        for block in response_health.iter_content_blocks(response):
            if isinstance(block, dict):
                blocks.append(block)
                continue
            for method in ("model_dump", "dict", "to_dict"):
                fn = getattr(block, method, None)
                if callable(fn):
                    try:
                        blocks.append(fn())
                        break
                    except Exception:
                        continue
            else:
                return []
        return blocks

    @staticmethod
    def _drop_blank_messages(messages: list) -> list:
        """清掉内容为空/纯空白的消息，保留原有顺序与角色，不做合并。"""
        cleaned = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                if not content.strip():
                    continue
            elif isinstance(content, (list, tuple)) and not content:
                continue
            cleaned.append(msg)
        return cleaned

    def _merge_consecutive_messages(self, messages: list) -> list:
        """
        合并连续的同角色消息（Anthropic 要求 user/assistant 交替）

        额外做两件事，防止把历史里的脏数据继续往 API 送：
        - 丢弃 content 为空/纯空白的消息（空消息会让整个请求被 400 拒掉）
        - 非字符串 content 统一转成字符串再拼接（拼接 None 会直接抛 TypeError）
        """
        if not messages:
            return []

        merged: list = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role") or "user"
            content = msg.get("content")
            if content is None:
                continue
            if not isinstance(content, str):
                # 结构化 content（多段块）保持原样，不做拼接
                if isinstance(content, (list, tuple)):
                    if not content:
                        continue
                    merged.append({"role": role, "content": list(content)})
                    continue
                content = str(content)
            if not content.strip():
                # 空消息一定是上游出了问题，这里拦住，避免整轮请求被拒
                continue
            if merged and merged[-1]["role"] == role and isinstance(merged[-1]["content"], str):
                merged[-1]["content"] += "\n\n" + content
            else:
                merged.append({"role": role, "content": content})

        return merged
    
    @staticmethod
    def _strip_ipc_payload(result: Any) -> Any:
        """过 IPC 前去掉只服务于本进程日志的重字段。

        raw_payload（现在只有错误分支会挂：异常里带出来的响应体原文）可能有几十万
        字符，且已在本进程落盘；health 的关键字段也已平铺进 data。两者都没必要
        再序列化一遍穿过队列。
        """
        if not isinstance(result, dict):
            return result
        if "raw_payload" not in result and "health" not in result:
            return result
        slim = dict(result)
        slim.pop("raw_payload", None)
        slim.pop("health", None)
        return slim

    def _on_request_complete(self, request_id: str, future: Future):
        """请求完成回调 - 将结果放入响应队列"""
        # 从活跃请求中移除
        with self.active_requests_lock:
            self.active_requests.pop(request_id, None)
        with self._cancelled_requests_lock:
            self._cancelled_request_ids.discard(request_id)
        
        try:
            result = self._strip_ipc_payload(future.result())
            # 如果被取消，不发送响应（或发送取消状态）
            if result.get("status") != "cancelled":
                self.response_queue.put(result)
            else:
                # 可选：发送取消确认
                self.response_queue.put(result)
        except Exception as e:
            log_error("CHAT_CALLBACK_ERROR", f"Error in request callback: {e}", e)
            self.response_queue.put({
                "request_id": request_id,
                "status": "error",
                "data": str(e)
            })
    
    def submit_request(self, request_id: str, request_data: Dict[str, Any]):
        """
        提交一个 LLM 请求到线程池
        
        Args:
            request_id: 请求唯一标识
            request_data: 请求数据
        """
        future = self.executor.submit(self._do_llm_call, request_id, request_data)
        
        with self.active_requests_lock:
            self.active_requests[request_id] = future
        
        # 添加完成回调
        future.add_done_callback(lambda f: self._on_request_complete(request_id, f))
    
    def cancel_all_requests(self):
        """取消所有正在进行的请求"""
        # 设置全局取消标志
        self.global_cancel_flag.set()
        
        # 尝试取消所有 Future（对于尚未开始的任务有效）
        with self.active_requests_lock:
            request_ids = list(self.active_requests)
        for request_id in request_ids:
            self.cancel_request(request_id)
        cancelled_count = len(request_ids)
        
        # 发送中断确认
        self.response_queue.put({"status": "interrupted", "cancelled_count": cancelled_count})
        
        # 短暂延迟后重置取消标志，允许新请求
        time.sleep(0.1)
        self.global_cancel_flag.clear()
    
    def run(self):
        """主循环 - 持续等待并处理请求"""
        self.initialize()
        
        while True:
            try:
                # 非阻塞方式检查队列
                if not self.request_queue.empty():
                    request_data = self.request_queue.get()
                    
                    # 退出命令
                    if request_data.get("command") == "exit":
                        self.shutdown()
                        break
                    
                    # 中断命令 - 取消所有请求
                    if request_data.get("command") == "interrupt":
                        self.cancel_all_requests()
                        continue

                    # 精确中断：只关闭指定会话当前的 provider 请求，不影响并发会话。
                    if request_data.get("command") == "cancel":
                        self.cancel_request(request_data.get("request_id"))
                        continue
                    
                    # 正常请求 - 提取或生成 request_id
                    request_id = request_data.get("request_id")
                    if not request_id:
                        request_id = str(uuid.uuid4())
                    
                    # 提交到线程池
                    self.submit_request(request_id, request_data)
                
                # 检查全局停止事件
                if self.stop_event.is_set():
                    self.cancel_all_requests()
                    self.stop_event.clear()
                
                # 短暂休眠
                time.sleep(0.01)
                
            except KeyboardInterrupt:
                self.cancel_all_requests()
                continue
            except Exception as e:
                log_error("CHAT_PROCESS_ERROR", "Error in chat process main loop", e)
                continue


def chat_process_worker(request_queue: mp.Queue, response_queue: mp.Queue, stop_event: mp.Event):
    """
    Chat 进程的工作函数 - 多进程启动入口
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    chat_proc = ChatProcess(request_queue, response_queue, stop_event)
    chat_proc.run()


class ReplyMessage:
    """LLM 响应消息对象（纯文本协议模式）"""
    def __init__(self, data):
        self.content = data.get("content")
        self.role = data.get("role")
