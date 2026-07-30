"""
Chat 进程模块 - 独立进程负责与 LLM 通信
支持多线程并发请求，统一中断控制
"""
import multiprocessing as mp
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, Future
import re
import threading
import signal
import time
import uuid

from .client import load_openai_client, load_anthropic_client
from .logger import log_error, log_raw_response
from .config import get_config
from . import config as _config

if TYPE_CHECKING:
    from openai import OpenAI
    from anthropic import Anthropic

# request_id 格式：{conversation_id}_{uuid}
_REQUEST_ID_CONV_RE = re.compile(
    r"^(?P<cid>.+)_(?P<uuid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
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
        
    def shutdown(self):
        """关闭线程池"""
        if self.executor:
            self.executor.shutdown(wait=False)
            self.executor = None
    
    # API 重试延迟（秒）：立即、5s、15s、25s
    _RETRY_DELAYS = [0, 5, 15, 25]

    def _do_llm_call(self, request_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行 LLM 调用（带重试）
        
        重试策略：立即重试 → 5s → 15s → 25s，共4次机会。
        全部失败后返回最后一次的错误。
        """
        last_result = None
        total_attempts = len(self._RETRY_DELAYS)
        for attempt, delay in enumerate(self._RETRY_DELAYS):
            if delay > 0:
                # 第 attempt 次失败后的下一次重试（attempt 从 0 计，展示为第 attempt+1 次重试）
                progress_msg = f"请求失败，{delay}秒后进行第 {attempt + 1} 次重试..."
                log_error("LLM_API_RETRY_PROGRESS", progress_msg)
                # 经 IPC 推送进度，供 Desktop 前端 system 日志展示（chat 进程自身 log 到不了主进程 WS）
                try:
                    self.response_queue.put({
                        "request_id": request_id,
                        "status": "progress",
                        "data": {
                            "event": "llm_retry",
                            "attempt": attempt + 1,
                            "total": total_attempts,
                            "delay": delay,
                            "message": progress_msg,
                        },
                    })
                except Exception:
                    pass
                time.sleep(delay)
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            result = self._do_single_llm_call(request_id, request_data)
            if result["status"] != "error":
                self._log_raw_response(request_id, request_data, result)
                return result
            last_result = result
            # 如果是被取消的，不重试
            if result["status"] == "cancelled":
                return result
            log_error(
                "LLM_API_RETRY",
                f"API call failed (attempt {attempt + 1}/{total_attempts}): {result.get('data', '')}"
            )
        return last_result

    def _log_raw_response(self, request_id: str, request_data: Dict[str, Any], result: Dict[str, Any]) -> None:
        """收到 LLM 回复后立即把原文完整写入对应会话的 raw 日志（仅落盘）。

        由 LOG_RAW_ENABLED 控制；失败静默，绝不影响正常回复流程。
        """
        try:
            if not getattr(self.config, "log_raw_enabled", False):
                return
            if result.get("status") != "success":
                return
            data = result.get("data")
            if not isinstance(data, dict):
                return
            metadata = {
                "request_id": request_id,
                "conversation_id": conversation_id_from_request_id(request_id),
                "model": request_data.get("model"),
                "role": data.get("role"),
                "sub_agent": bool(request_data.get("use_sub_agent_config")),
                "agent_profile": request_data.get("agent_profile"),
                "usage": data.get("usage"),
            }
            log_raw_response(
                data.get("content") or "",
                conversation_id=conversation_id_from_request_id(request_id),
                metadata=metadata,
            )
        except Exception:
            pass

    def _do_single_llm_call(self, request_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行单个 LLM 调用（在工作线程中运行）
        
        Args:
            request_id: 请求唯一标识
            request_data: 请求数据
            
        Returns:
            响应字典，包含 request_id
        """
        # 检查是否已被取消
        if self.global_cancel_flag.is_set():
            return {"request_id": request_id, "status": "cancelled", "data": None}
        
        messages = request_data.get("messages", [])
        model = request_data.get("model")
        system = request_data.get("system")
        use_sub_agent_config = request_data.get("use_sub_agent_config", False)
        agent_profile = request_data.get("agent_profile")

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

        # 根据 SDK 类型选择不同的调用方式
        if sdk == "anthropic":
            return self._do_anthropic_call(request_id, messages, model, system, client, overrides)
        else:
            return self._do_openai_call(request_id, messages, model, system, client, overrides)

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
    ) -> Dict[str, Any]:
        """使用 OpenAI SDK 调用 LLM（自动选择 Chat Completions 或 Responses API）"""
        if self._adv(overrides, "use_responses_api", "use_responses_api"):
            return self._do_openai_responses_call(request_id, messages, model, system, client, overrides)
        return self._do_openai_chat_call(request_id, messages, model, system, client, overrides)

    def _do_openai_chat_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI",
        overrides: Optional[Dict[str, Any]] = None,
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
        
        try:
            timeout = self.config.api_timeout
            max_tokens = self.config.get_max_tokens()
            
            # 获取 conversation_id（从 request_data 传递）
            conversation_id = request_id.split("_")[0] if "_" in request_id else None

            # 构建请求参数
            request_params = {
                "model": model,
                "messages": final_messages,
                "max_tokens": max_tokens,
                "timeout": timeout,
            }
            
            # 如果配置了 reasoning_effort，添加到请求中（none/off 表示明确不传）
            eff = self._adv_effort(overrides, "reasoning_effort", "openai_reasoning_effort")
            if eff:
                request_params["extra_body"] = {"reasoning_effort": eff}

            completion = client.chat.completions.create(**request_params)
            
            if self.global_cancel_flag.is_set():
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
            
            # CLI 模式：打印 token 统计（后端自己处理累计）
            if input_tokens > 0 or output_tokens > 0:
                print(f"[Token] {input_tokens} {output_tokens}", flush=True)
            
            # 构建本次发送的消息（不包含历史记忆）
            current_sent = []
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            if is_first_conversation and system:
                if self.config.system_as_user:
                    current_sent.append({"role": "user", "content": system})
                else:
                    current_sent.append({"role": "system", "content": system})
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    if self.config.system_as_user and system and msg.get("content") == system:
                        continue
                    current_sent.append(msg)
                    break
            
            result = {
                "content": reply_content,
                "role": reply_role or "assistant",
                "sent_messages": current_sent,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "prompt_tokens": input_tokens,  # 兼容 OpenAI 格式
                    "completion_tokens": output_tokens  # 兼容 OpenAI 格式
                }
            }
            
            return {"request_id": request_id, "status": "success", "data": result}
            
        except Exception as exc:
            if self.global_cancel_flag.is_set():
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
            return {"request_id": request_id, "status": "error", "data": str(exc)}

    def _do_openai_responses_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI",
        overrides: Optional[Dict[str, Any]] = None,
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

        try:
            # 获取 conversation_id
            conversation_id = request_id.split("_")[0] if "_" in request_id else None

            # 构建请求参数
            # Responses API 不支持 temperature，instructions 对应 system prompt
            request_params: Dict[str, Any] = {
                "model": model,
                "input": input_messages,
                "max_output_tokens": self.config.get_max_tokens(),
            }
            if system and not self.config.system_as_user:
                request_params["instructions"] = system

            # 如果配置了 reasoning_effort，添加到请求中（none/off 表示明确不传）
            eff = self._adv_effort(overrides, "reasoning_effort", "openai_reasoning_effort")
            if eff:
                request_params["reasoning"] = {"effort": eff}

            response = client.responses.create(**request_params)

            if self.global_cancel_flag.is_set():
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

            # 从 API 响应中获取 token 统计（如果有）
            input_tokens = 0
            output_tokens = 0
            if hasattr(response, 'usage') and response.usage:
                input_tokens = getattr(response.usage, 'input_tokens', 0) or getattr(response.usage, 'prompt_tokens', 0)
                output_tokens = getattr(response.usage, 'output_tokens', 0) or getattr(response.usage, 'completion_tokens', 0)
            
            # CLI 模式：打印 token 统计（后端自己处理累计）
            if input_tokens > 0 or output_tokens > 0:
                print(f"[Token] {input_tokens} {output_tokens}", flush=True)

            # 构建本次发送的消息记录
            current_sent = []
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            if is_first_conversation and system and not self.config.system_as_user:
                current_sent.append({"role": "system", "content": system})
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    if self.config.system_as_user and system and msg.get("content") == system:
                        continue
                    current_sent.append(msg)
                    break

            result = {
                "content": reply_content,
                "role": "assistant",
                "sent_messages": current_sent,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "prompt_tokens": input_tokens,  # 兼容 OpenAI 格式
                    "completion_tokens": output_tokens  # 兼容 OpenAI 格式
                }
            }

            return {"request_id": request_id, "status": "success", "data": result}

        except Exception as exc:
            if self.global_cancel_flag.is_set():
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
            return {"request_id": request_id, "status": "error", "data": str(exc)}
    
    def _do_anthropic_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "Anthropic",
        overrides: Optional[Dict[str, Any]] = None,
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
        
        # 合并连续的同角色消息
        anthropic_messages = self._merge_consecutive_messages(anthropic_messages)
        
        # 确保第一条消息是 user
        if anthropic_messages and anthropic_messages[0]["role"] != "user":
            anthropic_messages.insert(0, {"role": "user", "content": "[系统初始化]"})
        
        try:
            max_tokens = self.config.get_max_tokens()
            
            # 获取 conversation_id
            conversation_id = request_id.split("_")[0] if "_" in request_id else None

            # 构建请求参数
            request_params = {
                "model": model or self.config.get_model(),
                "messages": anthropic_messages,
                "max_tokens": max_tokens,
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

            if thinking_mode is None:
                if effort:
                    thinking_mode = "adaptive"
                elif budget_tokens:
                    thinking_mode = "enabled"

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
            
            response = client.messages.create(**request_params)
            
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            # 从 API 响应中获取 token 统计（最准确）
            input_tokens = 0
            output_tokens = 0
            if hasattr(response, 'usage'):
                input_tokens = getattr(response.usage, 'input_tokens', 0)
                output_tokens = getattr(response.usage, 'output_tokens', 0)
            
            # 提取响应内容（忽略 thinking / redacted_thinking 块）
            content = ""
            if response.content:
                for block in response.content:
                    block_type = getattr(block, "type", None)
                    if block_type == "text" or (block_type is None and hasattr(block, "text") and not hasattr(block, "thinking")):
                        content += getattr(block, "text", "") or ""
            
            # CLI 模式：打印 token 统计（后端自己处理累计）
            if input_tokens > 0 or output_tokens > 0:
                print(f"[Token] {input_tokens} {output_tokens}", flush=True)
            
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
            
            # 添加最后一条真正的用户消息（跳过第一条 system prompt）
            start_index = 1 if self.config.system_as_user else 0
            for msg in reversed(anthropic_messages[start_index:]):
                if msg.get("role") == "user":
                    current_sent.append(msg)
                    break
            
            result = {
                "content": content,
                "role": "assistant",
                "sent_messages": current_sent,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "prompt_tokens": input_tokens,  # 兼容 OpenAI 格式
                    "completion_tokens": output_tokens  # 兼容 OpenAI 格式
                }
            }
            
            return {"request_id": request_id, "status": "success", "data": result}
            
        except Exception as exc:
            if self.global_cancel_flag.is_set():
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
            return {"request_id": request_id, "status": "error", "data": str(exc)}
    
    def _merge_consecutive_messages(self, messages: list) -> list:
        """
        合并连续的同角色消息（Anthropic 要求 user/assistant 交替）
        """
        if not messages:
            return []
        
        merged = []
        for msg in messages:
            if merged and merged[-1]["role"] == msg["role"]:
                # 合并内容
                merged[-1]["content"] += "\n\n" + msg["content"]
            else:
                merged.append({"role": msg["role"], "content": msg["content"]})
        
        return merged
    
    def _on_request_complete(self, request_id: str, future: Future):
        """请求完成回调 - 将结果放入响应队列"""
        # 从活跃请求中移除
        with self.active_requests_lock:
            self.active_requests.pop(request_id, None)
        
        try:
            result = future.result()
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
            for request_id, future in self.active_requests.items():
                future.cancel()
            # 清空活跃请求
            cancelled_count = len(self.active_requests)
            self.active_requests.clear()
        
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
