"""
确认请求管理器

通过 WebSocket 双向通信处理确认请求。
- 发送确认请求到前端（通过 WebSocket）
- 接收前端响应（通过 WebSocket 响应队列）
"""
import threading
import time
from typing import Optional, Dict, Any


# 待处理的确认请求
_pending_requests: Dict[str, threading.Event] = {}
_pending_results: Dict[str, bool] = {}
_lock = threading.Lock()
_counter = 0

# 响应监听线程
_listener_thread: Optional[threading.Thread] = None
_listener_running = False


def _response_listener():
    """监听 WebSocket 响应队列"""
    global _listener_running
    
    from .websocket.ws_process import get_response_queue
    
    while _listener_running:
        response_queue = get_response_queue()
        if not response_queue:
            time.sleep(0.1)
            continue
        
        try:
            while not response_queue.empty():
                try:
                    msg = response_queue.get_nowait()
                    
                    # 处理确认响应
                    if msg.get("type") == "confirm_response":
                        request_id = msg.get("request_id")
                        confirmed = msg.get("confirmed", False)
                        
                        with _lock:
                            if request_id in _pending_requests:
                                _pending_results[request_id] = confirmed
                                _pending_requests[request_id].set()
                                
                except Exception:
                    break
        except Exception:
            pass
        
        time.sleep(0.01)


def start_response_listener():
    """启动响应监听线程"""
    global _listener_thread, _listener_running
    
    if _listener_thread and _listener_thread.is_alive():
        return
    
    _listener_running = True
    _listener_thread = threading.Thread(target=_response_listener, daemon=True)
    _listener_thread.start()


def stop_response_listener():
    """停止响应监听线程"""
    global _listener_running
    _listener_running = False


def desktop_confirm(
    action_type: str,
    title: str,
    message: str,
    details: list = None,
    timeout: float = 300
) -> bool:
    """
    桌面模式确认函数
    
    通过 WebSocket 发送确认请求，等待前端响应。
    
    Args:
        action_type: 操作类型
        title: 标题
        message: 消息
        details: 详细信息列表
        timeout: 超时时间
        
    Returns:
        用户是否确认
    """
    global _counter
    
    # 生成请求 ID
    with _lock:
        _counter += 1
        request_id = f"confirm_{_counter}_{int(time.time() * 1000)}"
        
        # 创建等待事件
        event = threading.Event()
        _pending_requests[request_id] = event
    
    # 发送确认请求到前端
    try:
        from .websocket.ipc_bridge import send_ws_message
        send_ws_message({
            "type": "confirm_request",
            "data": {
                "request_id": request_id,
                "action_type": action_type,
                "title": title,
                "message": message,
                "details": details or [],
                "timestamp": time.time()
            }
        })
    except Exception:
        with _lock:
            _pending_requests.pop(request_id, None)
        return False
    
    # 等待响应
    responded = event.wait(timeout=timeout)
    
    # 获取结果并清理
    with _lock:
        result = _pending_results.pop(request_id, False)
        _pending_requests.pop(request_id, None)
    
    if not responded:
        # 超时，通知前端取消
        try:
            from .websocket.ipc_bridge import send_ws_message
            send_ws_message({
                "type": "confirm_cancel",
                "data": {
                    "request_id": request_id,
                    "reason": "timeout"
                }
            })
        except Exception:
            pass
        return False
    
    return result
