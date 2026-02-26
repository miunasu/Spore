"""
Chat 进程模块 - 独立进程负责与 LLM 通信
支持多线程并发请求，统一中断控制
"""
import multiprocessing as mp
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, Future
import threading
import signal
import time
import uuid

from .client import load_openai_client, load_anthropic_client
from .logger import log_error
from .config import get_config
from . import config as _config

# 每个对话的 token 计数（conversation_id -> token_count）
_conversation_tokens: Dict[str, int] = {}
_current_conversation_id: Optional[str] = None
_token_count_lock = threading.Lock()


def get_current_token_count(conversation_id: Optional[str] = None) -> int:
    """获取指定对话的 token 数"""
    with _token_count_lock:
        cid = conversation_id or _current_conversation_id
        if cid:
            return _conversation_tokens.get(cid, 0)
        return 0


def set_current_token_count(count: int, conversation_id: Optional[str] = None):
    """设置指定对话的 token 数"""
    with _token_count_lock:
        cid = conversation_id or _current_conversation_id
        if cid:
            _conversation_tokens[cid] = count


def add_to_token_count(additional_tokens: int, conversation_id: Optional[str] = None):
    """累加 token 数到指定对话"""
    with _token_count_lock:
        cid = conversation_id or _current_conversation_id
        if cid:
            current = _conversation_tokens.get(cid, 0)
            _conversation_tokens[cid] = current + additional_tokens


def set_current_conversation(conversation_id: str):
    """设置当前活跃的对话 ID"""
    global _current_conversation_id
    with _token_count_lock:
        _current_conversation_id = conversation_id
        # 如果是新对话，初始化 token 计数
        if conversation_id not in _conversation_tokens:
            _conversation_tokens[conversation_id] = 0


def reset_token_count(conversation_id: Optional[str] = None):
    """重置指定对话的 token 计数"""
    with _token_count_lock:
        cid = conversation_id or _current_conversation_id
        if cid:
            _conversation_tokens[cid] = 0


def remove_conversation_tokens(conversation_id: str):
    """移除对话的 token 记录（关闭对话时调用）"""
    with _token_count_lock:
        _conversation_tokens.pop(conversation_id, None)


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
        self.client = None
        self.anthropic_client = None
        
        # 并发控制
        self.config = get_config()
        self.executor: Optional[ThreadPoolExecutor] = None
        self.active_requests: Dict[str, Future] = {}  # request_id -> Future
        self.active_requests_lock = threading.Lock()
        
        # 全局中断标志 - 所有线程共享
        self.global_cancel_flag = threading.Event()
        
        # SDK 类型
        self.llm_sdk = self.config.llm_sdk
        
    def initialize(self):
        """初始化 LLM 客户端和线程池"""
        if self.llm_sdk == "anthropic":
            self.anthropic_client = load_anthropic_client()
        else:
            self.client = load_openai_client()
        
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.chat_max_workers,
            thread_name_prefix="llm_worker"
        )
        
    def shutdown(self):
        """关闭线程池"""
        if self.executor:
            self.executor.shutdown(wait=False)
            self.executor = None
    
    def _do_llm_call(self, request_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
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
        temperature = request_data.get("temperature", 0.7)
        system = request_data.get("system")
        
        # 根据 SDK 类型选择不同的调用方式
        if self.llm_sdk == "anthropic":
            return self._do_anthropic_call(request_id, messages, model, temperature, system)
        else:
            return self._do_openai_call(request_id, messages, model, temperature, system)
    
    def _do_openai_call(
        self, 
        request_id: str, 
        messages: list, 
        model: str, 
        temperature: float, 
        system: Optional[str]
    ) -> Dict[str, Any]:
        """使用 OpenAI SDK 调用 LLM"""
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
            
            # 计算发送消息的 token 数
            from .utils.token_counter import count_tokens
            token_count = count_tokens(final_messages)
            set_current_token_count(token_count)
            
            # message debug
            # from .logger import log_info
            # log_info("OPENAI_MESSAGES_DEBUG", f"final_messages: {final_messages}")

            completion = self.client.chat.completions.create(
                model=model,
                messages=final_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout
            )
            
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            message = completion.choices[0].message
            
            # 计算接收到的回复的 token 数，并累加到总计数
            reply_content = message.content or ""
            reply_tokens = count_tokens(reply_content)
            current_total = get_current_token_count()
            set_current_token_count(current_total + reply_tokens)
            
            # 构建本次发送的消息（不包含历史记忆）
            # 只包含：system prompt（仅第一次对话） + 最后一条用户消息
            current_sent = []
            
            # 判断是否是第一次对话（messages 中只有一条用户消息）
            is_first_conversation = len([m for m in messages if m.get("role") == "user"]) == 1
            
            # 只在第一次对话时添加 system prompt
            if is_first_conversation and system:
                if self.config.system_as_user:
                    current_sent.append({"role": "user", "content": system})
                else:
                    current_sent.append({"role": "system", "content": system})
            
            # 添加最后一条真正的用户消息
            # 在 system_as_user 模式下，需要跳过可能已经包含 system 的第一条消息
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    # 检查是否是 system prompt（避免重复）
                    if self.config.system_as_user and system and msg.get("content") == system:
                        continue
                    current_sent.append(msg)
                    break
            
            result = {
                "content": message.content,
                "role": message.role,
                "sent_messages": current_sent,  # 只包含本次发送的内容
            }
            
            return {"request_id": request_id, "status": "success", "data": result}
            
        except Exception as exc:
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            log_error(
                "LLM_API_CALL_ERROR",
                f"OpenAI API call error: {str(exc)}",
                exc,
                context={"request_id": request_id, "model": model}
            )
            return {"request_id": request_id, "status": "error", "data": str(exc)}
    
    def _do_anthropic_call(
        self, 
        request_id: str, 
        messages: list, 
        model: str, 
        temperature: float, 
        system: Optional[str]
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
            
            # 计算发送消息的 token 数
            from .utils.token_counter import count_tokens
            token_count = count_tokens(anthropic_messages)
            set_current_token_count(token_count)
            
            # 调试日志：记录发送给 Anthropic 的消息
            # from .logger import log_info
            # log_info("ANTHROPIC_MESSAGES_DEBUG", f"anthropic_messages: {anthropic_messages}")

            # 构建请求参数
            request_params = {
                "model": model or self.config.get_model(),
                "messages": anthropic_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
            
            # system 参数（仅在非 system_as_user 模式下使用）
            if anthropic_system:
                request_params["system"] = anthropic_system
            
            response = self.anthropic_client.messages.create(**request_params)
            
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            # 提取响应内容
            content = ""
            if response.content:
                for block in response.content:
                    if hasattr(block, "text"):
                        content += block.text
            
            # 计算接收到的回复的 token 数，并累加到总计数
            reply_tokens = count_tokens(content)
            current_total = get_current_token_count()
            set_current_token_count(current_total + reply_tokens)
            
            # 构建本次发送的消息（不包含历史记忆）
            # 只包含：system prompt（仅第一次对话） + 最后一条用户消息
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
                "sent_messages": current_sent,  # 只包含本次发送的内容
            }
            
            return {"request_id": request_id, "status": "success", "data": result}
            
        except Exception as exc:
            if self.global_cancel_flag.is_set():
                return {"request_id": request_id, "status": "cancelled", "data": None}
            
            log_error(
                "LLM_API_CALL_ERROR",
                f"Anthropic API call error: {str(exc)}",
                exc,
                context={"request_id": request_id, "model": model}
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
