"""
Chat 进程模块 - 独立进程负责与 LLM 通信
支持多线程并发请求，统一中断控制
"""
import multiprocessing as mp
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, Future
import threading
import signal
import time
import uuid

from .client import load_openai_client, load_anthropic_client
from .logger import log_error
from .config import get_config
from . import config as _config

if TYPE_CHECKING:
    from openai import OpenAI
    from anthropic import Anthropic

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
        for attempt, delay in enumerate(self._RETRY_DELAYS):
            if delay > 0:
                time.sleep(delay)
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            result = self._do_single_llm_call(request_id, request_data)
            if result["status"] != "error":
                return result
            last_result = result
            # 如果是被取消的，不重试
            if result["status"] == "cancelled":
                return result
            log_error(
                "LLM_API_RETRY",
                f"API call failed (attempt {attempt + 1}/{len(self._RETRY_DELAYS)}): {result.get('data', '')}"
            )
        return last_result

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
        
        # 根据是否使用子 agent 配置选择 SDK 和客户端
        if use_sub_agent_config:
            # 使用子 agent 配置
            sdk = self.sub_agent_llm_sdk
            client = self.sub_agent_client if sdk == "openai" else self.sub_agent_anthropic_client
        else:
            # 使用主 agent 配置
            sdk = self.llm_sdk
            client = self.client if sdk == "openai" else self.anthropic_client
        
        # 根据 SDK 类型选择不同的调用方式
        if sdk == "anthropic":
            return self._do_anthropic_call(request_id, messages, model, system, client)
        else:
            return self._do_openai_call(request_id, messages, model, system, client)
    
    def _do_openai_call(
        self, 
        request_id: str, 
        messages: list, 
        model: str, 
        system: Optional[str],
        client: "OpenAI"
    ) -> Dict[str, Any]:
        """使用 OpenAI SDK 调用 LLM（自动选择 Chat Completions 或 Responses API）"""
        if self.config.use_responses_api:
            return self._do_openai_responses_call(request_id, messages, model, system, client)
        return self._do_openai_chat_call(request_id, messages, model, system, client)

    def _do_openai_chat_call(
        self,
        request_id: str,
        messages: list,
        model: str,
        system: Optional[str],
        client: "OpenAI"
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
            
            # 如果配置了 reasoning_effort，添加到请求中
            if self.config.openai_reasoning_effort:
                request_params["extra_body"] = {"reasoning_effort": self.config.openai_reasoning_effort}
            
            completion = client.chat.completions.create(**request_params)
            
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            message = completion.choices[0].message
            reply_content = message.content or ""
            
            # 从 API 响应中获取 token 统计（最准确）
            input_tokens = 0
            output_tokens = 0
            if hasattr(completion, 'usage') and completion.usage:
                input_tokens = getattr(completion.usage, 'prompt_tokens', 0)
                output_tokens = getattr(completion.usage, 'completion_tokens', 0)
            
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
                "content": message.content,
                "role": message.role,
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
            if 'completion' in locals() and completion is not None:
                error_context["response"] = str(completion)
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
        client: "OpenAI"
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

            # 如果配置了 reasoning_effort，添加到请求中
            if self.config.openai_reasoning_effort:
                request_params["reasoning"] = {"effort": self.config.openai_reasoning_effort}

            response = client.responses.create(**request_params)

            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}

            reply_content = response.output_text or ""

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
        client: "Anthropic"
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
            
            response = client.messages.create(**request_params)
            
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            # 从 API 响应中获取 token 统计（最准确）
            input_tokens = 0
            output_tokens = 0
            if hasattr(response, 'usage'):
                input_tokens = getattr(response.usage, 'input_tokens', 0)
                output_tokens = getattr(response.usage, 'output_tokens', 0)
            
            # 提取响应内容
            content = ""
            if response.content:
                for block in response.content:
                    if hasattr(block, "text"):
                        content += block.text
            
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
