"""
IPC 管理器 - 负责主进程和 Chat 进程之间的通信
支持并发请求，通过 request_id 匹配响应
"""
import json
import multiprocessing as mp
import os
import threading
import time
import uuid
from typing import Optional, Dict, Any, List, Callable

from .chat_process import chat_process_worker, conversation_id_from_request_id
from .logger import log_error
from .config import get_config


class IPCManager:
    """进程间通信管理器 - 支持并发请求"""
    
    def __init__(self):
        """初始化 IPC 管理器"""
        self.request_queue = mp.Queue()
        self.response_queue = mp.Queue()
        self.stop_event = mp.Event()
        self.chat_process = None
        self.process_started = False
        
        # 响应缓存：request_id -> (response, timestamp)
        self._response_cache: Dict[str, tuple] = {}
        self._cache_lock = threading.Lock()
        self._cancelled_request_ids: set[str] = set()
        self._cancelled_request_times: Dict[str, float] = {}
        
        # 响应分发线程
        self._dispatcher_thread: Optional[threading.Thread] = None
        self._dispatcher_stop = threading.Event()
        
        # 等待特定响应的条件变量
        self._response_conditions: Dict[str, threading.Condition] = {}
        self._conditions_lock = threading.Lock()

        # 流式分片是非终态旁路，不进入响应缓存；回调只存在于发起请求的主进程。
        self._stream_callbacks: Dict[str, Callable[[Dict[str, Any]], None]] = {}
        self._stream_buffers: Dict[str, str] = {}
        self._stream_lock = threading.Lock()
        
        # 配置
        self._config = get_config()
        
    def start_chat_process(self):
        """启动 Chat 进程和响应分发线程"""
        if self.process_started:
            return

        self.stop_event.clear()
        
        # 启动 Chat 进程
        self.chat_process = mp.Process(
            target=chat_process_worker,
            args=(self.request_queue, self.response_queue, self.stop_event),
            daemon=False
        )
        self.chat_process.start()
        
        # 启动响应分发线程
        self._dispatcher_stop.clear()
        self._dispatcher_thread = threading.Thread(
            target=self._response_dispatcher,
            name="ipc_dispatcher",
            daemon=True
        )
        self._dispatcher_thread.start()
        
        self.process_started = True
        
    def stop_chat_process(self):
        """停止 Chat 进程和分发线程"""
        if not self.process_started:
            return
        
        # 停止分发线程
        self._dispatcher_stop.set()
        if self._dispatcher_thread and self._dispatcher_thread.is_alive():
            self._dispatcher_thread.join(timeout=2)
        
        # 发送退出命令
        try:
            self.request_queue.put({"command": "exit"}, timeout=1)
        except Exception as e:
            log_error("IPC_QUEUE_ERROR", "Failed to send exit command", e)
        
        # 等待进程结束
        if self.chat_process and self.chat_process.is_alive():
            self.chat_process.join(timeout=5)
            if self.chat_process.is_alive():
                self.chat_process.terminate()
                self.chat_process.join(timeout=2)
        
        # 清理
        self._clear_queue(self.request_queue)
        self._clear_queue(self.response_queue)
        self._response_cache.clear()
        self._cancelled_request_ids.clear()
        self._cancelled_request_times.clear()
        with self._stream_lock:
            self._stream_callbacks.clear()
            self._stream_buffers.clear()

        self.process_started = False
    
    def _clear_queue(self, queue):
        """清空队列"""
        try:
            while not queue.empty():
                try:
                    queue.get_nowait()
                except:
                    break
        except:
            pass
    
    def _response_dispatcher(self):
        """响应分发线程 - 从响应队列读取并分发到对应的等待者"""
        while not self._dispatcher_stop.is_set():
            try:
                # 非阻塞检查队列
                if not self.response_queue.empty():
                    response = self.response_queue.get_nowait()
                    
                    # 处理中断确认（无 request_id）
                    if response.get("status") == "interrupted":
                        self._handle_interrupt_response(response)
                        continue

                    # 进度事件（如 LLM 重试）：非终态，推送前端后继续等待真实响应
                    if response.get("status") == "progress":
                        self._handle_progress_response(response)
                        continue

                    if response.get("status") == "stream":
                        self._handle_stream_response(response)
                        continue
                    
                    request_id = response.get("request_id")
                    if not request_id:
                        # 兼容：无 request_id 的响应放入默认位置
                        request_id = "__default__"
                        response["request_id"] = request_id

                    with self._cache_lock:
                        if request_id in self._cancelled_request_ids:
                            # 精确取消后的真实 provider 响应无论成功失败都只能被丢弃。
                            if response.get("status") != "cancelled":
                                self._cancelled_request_ids.discard(request_id)
                                self._cancelled_request_times.pop(request_id, None)
                            continue

                        # 存入缓存
                        self._response_cache[request_id] = (response, time.time())

                    self._clear_stream_state(request_id)
                    
                    # 通知等待者
                    self._notify_waiter(request_id)
                
                # 定期清理过期响应
                self._cleanup_expired_responses()
                
                time.sleep(0.01)
                
            except Exception as e:
                if not self._dispatcher_stop.is_set():
                    log_error("IPC_DISPATCHER_ERROR", "Error in response dispatcher", e)
                time.sleep(0.1)
    
    def _handle_interrupt_response(self, response):
        """兼容旧的无 request_id 中断确认，将当前 waiter 逐个逻辑取消。"""
        with self._conditions_lock:
            request_ids = list(self._response_conditions)
        for request_id in request_ids:
            self.cancel_request(request_id)

    @staticmethod
    def _conversation_id_from_request_id(request_id: Optional[str]) -> Optional[str]:
        return conversation_id_from_request_id(request_id)

    def _handle_progress_response(self, response: Dict[str, Any]) -> None:
        """
        处理 Chat 进程推送的非终态进度（当前主要用于 LLM 重试提醒）。

        chat 子进程的 log_error 无法直接打到主进程 WebSocket；因此经 IPC 转发，
        由主进程写日志并推送到 Desktop 前端 system 日志面板。
        """
        data = response.get("data") if isinstance(response.get("data"), dict) else {}
        message = data.get("message") or "LLM request progress"
        request_id = response.get("request_id")
        conversation_id = self._conversation_id_from_request_id(request_id)

        log_entry = {
            "error_type": "LLM_API_RETRY_PROGRESS",
            "message": message,
            "context": {
                "request_id": request_id,
                "attempt": data.get("attempt"),
                "total": data.get("total"),
                "delay": data.get("delay"),
                "event": data.get("event") or "llm_retry",
            },
        }
        try:
            log_error(
                "LLM_API_RETRY_PROGRESS",
                message,
                context=log_entry["context"],
            )
        except Exception:
            pass

        # Desktop：直推 WS。IPC 分发线程没有 conversation_context，必须显式带 conversation_id。
        if os.environ.get("SPORE_DESKTOP_MODE") == "1":
            try:
                from desktop_app.backend.websocket.ipc_bridge import send_ws_message
                send_ws_message({
                    "type": "log",
                    "data": {
                        "log_type": "error",
                        "content": json.dumps(log_entry, ensure_ascii=False, indent=2),
                        "timestamp": time.time(),
                        "conversation_id": conversation_id,
                    },
                })
            except Exception as e:
                log_error("IPC_PROGRESS_WS_ERROR", f"Failed to push retry progress to WS: {e}", e)

    def _handle_stream_response(self, response: Dict[str, Any]) -> None:
        """聚合单个 request 的 delta，并交给其会话级回调。"""
        request_id = response.get("request_id")
        if not request_id:
            return
        with self._cache_lock:
            if request_id in self._cancelled_request_ids:
                return

        data = response.get("data") if isinstance(response.get("data"), dict) else {}
        event = data.get("event") or "delta"
        piece = data.get("content") if isinstance(data.get("content"), str) else ""
        with self._stream_lock:
            callback = self._stream_callbacks.get(request_id)
            if callback is None:
                return
            if event == "start":
                self._stream_buffers[request_id] = ""
            elif event == "delta":
                self._stream_buffers[request_id] = self._stream_buffers.get(request_id, "") + piece
            content = self._stream_buffers.get(request_id, "")

        try:
            callback({"event": event, "delta": piece, "content": content})
        except Exception as e:
            log_error("IPC_STREAM_CALLBACK_ERROR", f"Stream callback failed: {e}", e)

    def _clear_stream_state(self, request_id: str) -> None:
        with self._stream_lock:
            self._stream_callbacks.pop(request_id, None)
            self._stream_buffers.pop(request_id, None)
    
    def _notify_waiter(self, request_id: str):
        """通知等待特定 request_id 的线程"""
        with self._conditions_lock:
            condition = self._response_conditions.get(request_id)
            if condition:
                with condition:
                    condition.notify_all()
    
    def _cleanup_expired_responses(self):
        """清理过期的响应缓存"""
        now = time.time()
        expire_time = self._config.chat_response_expire
        
        with self._cache_lock:
            expired_keys = [
                k for k, (_, ts) in self._response_cache.items()
                if now - ts > expire_time
            ]
            for k in expired_keys:
                del self._response_cache[k]

            expired_cancelled = [
                request_id for request_id, cancelled_at in self._cancelled_request_times.items()
                if now - cancelled_at > expire_time
            ]
            for request_id in expired_cancelled:
                self._cancelled_request_ids.discard(request_id)
                self._cancelled_request_times.pop(request_id, None)
    
    def send_chat_request(
        self,
        messages: List[Dict[str, str]],
        model: str,
        system: Optional[str] = None,
        request_id: Optional[str] = None,
        use_sub_agent_config: bool = False,
        agent_profile: Optional[str] = None,
        stream: bool = False,
        stream_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs  # 兼容旧调用，忽略 tool_calls, tools 等参数
    ) -> str:
        """
        向 Chat 进程发送聊天请求（纯文本协议模式）

        Args:
            messages: 消息列表
            model: 模型名称
            system: 系统提示
            request_id: 请求ID（可选，不提供则自动生成）
            use_sub_agent_config: 是否使用子 Agent 配置（默认 False）
            agent_profile: AutoAgent 颗粒化基座 profile（supervisor/mode_selector/
                security/assistant），优先级高于 use_sub_agent_config

        Returns:
            request_id: 请求的唯一标识，用于获取响应
        """
        if not self.process_started:
            raise RuntimeError("Chat 进程未启动")

        if request_id is None:
            request_id = str(uuid.uuid4())

        request_data = {
            "request_id": request_id,
            "messages": messages,
            "model": model,
            "system": system,
            "use_sub_agent_config": use_sub_agent_config,
            "agent_profile": agent_profile,
            "stream": bool(stream and stream_callback is not None),
        }
        
        # 预先创建条件变量。若 interrupt 已先一步为该 ID 写入 tombstone，
        # 不再把请求送入 provider；等待方会立即读到合成的 cancelled。
        with self._conditions_lock:
            self._response_conditions[request_id] = threading.Condition()
        if request_data["stream"]:
            with self._stream_lock:
                self._stream_callbacks[request_id] = stream_callback
                self._stream_buffers[request_id] = ""
        with self._cache_lock:
            cancelled = request_id in self._cancelled_request_ids

        if not cancelled:
            self.request_queue.put(request_data)
        return request_id
        
    def get_chat_response(
        self, 
        request_id: Optional[str] = None,
        timeout: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        获取 Chat 进程的响应
        
        Args:
            request_id: 请求ID，None 表示获取任意响应（兼容旧接口）
            timeout: 超时时间（秒），None 表示无限等待
            
        Returns:
            响应数据字典，如果超时则返回 None
        """
        if request_id is None:
            request_id = "__default__"
        
        check_interval = self._config.ipc_check_interval
        start_time = time.time()
        
        # 获取或创建条件变量
        with self._conditions_lock:
            if request_id not in self._response_conditions:
                self._response_conditions[request_id] = threading.Condition()
            condition = self._response_conditions[request_id]
        
        try:
            while True:
                # 检查缓存
                with self._cache_lock:
                    if request_id in self._response_cache:
                        response, _ = self._response_cache.pop(request_id)
                        return response
                
                # 检查超时
                if timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= timeout:
                        return None
                    wait_time = min(check_interval, timeout - elapsed)
                else:
                    wait_time = check_interval
                
                # 等待通知（使用较短的超时避免死锁）
                with condition:
                    condition.wait(timeout=wait_time)
                
                # 再次检查缓存（可能在 wait 期间被唤醒）
                with self._cache_lock:
                    if request_id in self._response_cache:
                        response, _ = self._response_cache.pop(request_id)
                        return response
                    
        except KeyboardInterrupt:
            raise
        finally:
            # 清理条件变量
            with self._conditions_lock:
                self._response_conditions.pop(request_id, None)
            self._clear_stream_state(request_id)
    
    def cancel_request(self, request_id: Optional[str]) -> bool:
        """逻辑取消一个精确请求：立即唤醒 waiter，并丢弃迟到的 provider 响应。"""
        if not request_id:
            return False

        cancelled_response = {
            "request_id": request_id,
            "status": "cancelled",
            "data": None,
        }
        now = time.time()
        with self._cache_lock:
            self._cancelled_request_ids.add(request_id)
            self._cancelled_request_times[request_id] = now
            self._response_cache[request_id] = (cancelled_response, now)
        self._clear_stream_state(request_id)
        self._notify_waiter(request_id)
        return True

    def interrupt_current_request(self):
        """兼容 CLI 的全局逻辑中断；不再设置 stop_event 或等待 Chat 进程。"""
        if not self.process_started:
            return

        with self._conditions_lock:
            request_ids = list(self._response_conditions)
        for request_id in request_ids:
            self.cancel_request(request_id)

    def is_chat_process_alive(self) -> bool:
        """检查 Chat 进程是否存活"""
        if not self.process_started or not self.chat_process:
            return False
        return self.chat_process.is_alive()
    
    def clear_queues(self):
        """清空队列和缓存"""
        cleared_count = 0
        
        while True:
            try:
                self.request_queue.get_nowait()
                cleared_count += 1
            except:
                break
        
        while True:
            try:
                self.response_queue.get_nowait()
                cleared_count += 1
            except:
                break
        
        with self._cache_lock:
            cleared_count += len(self._response_cache)
            self._response_cache.clear()
        
        return cleared_count
    
    def setup_all_modules(self) -> Dict[str, Any]:
        """为所有需要使用 IPC 的模块设置 IPC 管理器
        
        注意：supervisor 在主对话循环中自动触发，
        需要通过全局变量获取 IPC 管理器
        """
        results = {"success": [], "failed": []}
        
        modules = [
            ("tools", "base.tools", "set_ipc_manager"),
            ("agent_process", "base.agent_process", "set_ipc_manager"),
            ("supervisor", "AutoAgent.supervisor", "set_ipc_manager"),
            ("security_agent", "AutoAgent.security_agent", "set_ipc_manager"),
        ]
        
        for name, module_path, func_name in modules:
            try:
                module = __import__(module_path, fromlist=[func_name])
                set_func = getattr(module, func_name)
                set_func(self)
                results["success"].append(name)
            except Exception as e:
                results["failed"].append((name, str(e)))
        
        return results
    
    def __del__(self):
        """析构函数"""
        self.stop_chat_process()


def initialize_ipc_system() -> IPCManager:
    """
    初始化完整的 IPC 系统
    
    Returns:
        IPCManager: 已启动的 IPC 管理器实例
    """
    ipc_manager = IPCManager()
    ipc_manager.start_chat_process()
    results = ipc_manager.setup_all_modules()
    
    if results["failed"]:
        print(f"[警告] 部分模块 IPC 设置失败: {[name for name, _ in results['failed']]}")
    
    return ipc_manager
