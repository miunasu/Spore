"""
事件信号管理器模块

负责响应路由和线程唤醒，实现事件驱动的IPC通信。
"""
import threading
from typing import Dict, Any, Optional
import time


class EventSignalManager:
    """
    事件信号管理器
    
    管理多个Agent的事件信号，实现响应路由和线程唤醒。
    每个Agent通过唯一的conversation_id注册，当响应到达时，
    对应的Agent线程会被事件信号唤醒。
    """
    
    def __init__(self):
        """初始化事件信号管理器"""
        # conversation_id -> threading.Event
        self._events: Dict[str, threading.Event] = {}
        # conversation_id -> response data
        self._responses: Dict[str, Dict[str, Any]] = {}
        # 保护共享数据的锁
        self._lock = threading.Lock()
        # 全局终止事件
        self._global_termination = threading.Event()
    
    def register_agent(self, conversation_id: str) -> threading.Event:
        """
        注册Agent并返回其事件对象
        
        Args:
            conversation_id: Agent的唯一对话ID
        
        Returns:
            threading.Event: 该Agent的事件对象，用于等待响应
        """
        with self._lock:
            if conversation_id in self._events:
                # 已存在，返回现有事件
                return self._events[conversation_id]
            
            event = threading.Event()
            self._events[conversation_id] = event
            return event
    
    def unregister_agent(self, conversation_id: str) -> None:
        """
        注销Agent
        
        Args:
            conversation_id: Agent的唯一对话ID
        """
        with self._lock:
            self._events.pop(conversation_id, None)
            self._responses.pop(conversation_id, None)
    
    def signal_response(self, conversation_id: str, response: Dict[str, Any]) -> bool:
        """
        收到响应时发送信号唤醒对应Agent
        
        Args:
            conversation_id: Agent的唯一对话ID
            response: 响应数据
        
        Returns:
            bool: 是否成功发送信号（Agent是否已注册）
        """
        with self._lock:
            if conversation_id not in self._events:
                return False
            
            # 存储响应数据
            self._responses[conversation_id] = response
            # 发送信号唤醒等待的线程
            self._events[conversation_id].set()
            return True
    
    def wait_for_response(
        self,
        conversation_id: str,
        timeout: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """
        等待响应（阻塞直到事件信号或超时）
        
        Args:
            conversation_id: Agent的唯一对话ID
            timeout: 超时时间（秒），None表示无限等待
        
        Returns:
            Dict: 响应数据，如果超时或被终止返回None
        """
        with self._lock:
            event = self._events.get(conversation_id)
            if event is None:
                return None
        
        # 等待事件信号
        # 使用循环检查，以便能够响应全局终止信号
        start_time = time.time()
        while True:
            # 检查全局终止信号
            if self._global_termination.is_set():
                return None
            
            # 计算剩余等待时间
            if timeout is not None:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed
                if remaining <= 0:
                    return None
                wait_time = min(remaining, 0.1)  # 最多等待0.1秒
            else:
                wait_time = 0.1
            
            # 等待事件
            signaled = event.wait(timeout=wait_time)
            
            if signaled:
                # 事件被触发，获取响应
                with self._lock:
                    response = self._responses.pop(conversation_id, None)
                    # 重置事件以便下次使用
                    event.clear()
                return response
    
    def signal_termination(self) -> int:
        """
        发送全局终止信号，唤醒所有等待的Agent
        
        Returns:
            int: 被唤醒的Agent数量
        """
        with self._lock:
            # 设置全局终止标志
            self._global_termination.set()
            
            # 唤醒所有等待的Agent
            count = 0
            for conversation_id, event in self._events.items():
                # 设置终止响应
                self._responses[conversation_id] = {
                    "status": "terminated",
                    "conversation_id": conversation_id
                }
                event.set()
                count += 1
            
            return count
    
    def reset_termination(self) -> None:
        """重置全局终止信号"""
        self._global_termination.clear()
    
    def is_terminated(self) -> bool:
        """检查是否已发送终止信号"""
        return self._global_termination.is_set()
    
    def get_registered_count(self) -> int:
        """获取已注册的Agent数量"""
        with self._lock:
            return len(self._events)
    
    def get_pending_responses(self) -> int:
        """获取待处理的响应数量"""
        with self._lock:
            return len(self._responses)
    
    def clear_all(self) -> None:
        """清除所有注册和响应"""
        with self._lock:
            # 先唤醒所有等待的线程
            for event in self._events.values():
                event.set()
            
            self._events.clear()
            self._responses.clear()
            self._global_termination.clear()


# 全局事件信号管理器实例
_event_signal_manager: Optional[EventSignalManager] = None


def get_event_signal_manager() -> EventSignalManager:
    """获取全局事件信号管理器实例"""
    global _event_signal_manager
    if _event_signal_manager is None:
        _event_signal_manager = EventSignalManager()
    return _event_signal_manager


def reset_event_signal_manager() -> None:
    """重置全局事件信号管理器"""
    global _event_signal_manager
    if _event_signal_manager is not None:
        _event_signal_manager.clear_all()
    _event_signal_manager = EventSignalManager()
