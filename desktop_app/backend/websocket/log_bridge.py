"""
日志推送桥接

将 base/logger.py 和 base/multi_agent_monitor.py 的日志
通过 IPC 队列推送到独立的 WebSocket 进程。
"""
import time
from typing import Dict, List

from .ipc_bridge import send_ws_message
from base.logger import get_logger
from base.todo_manager import set_todo_update_callback

try:
    from base.multi_agent_monitor import set_agent_log_callback
    AGENT_MONITOR_AVAILABLE = True
except ImportError:
    AGENT_MONITOR_AVAILABLE = False


def setup_log_callbacks():
    """
    设置日志推送回调
    
    增强 SporeLogger._send_to_monitor，添加 WebSocket 推送
    """
    logger = get_logger()
    original_send = logger._send_to_monitor
    
    def enhanced_send(log_type: str, content: str):
        """增强的日志发送方法"""
        # 调用原始方法（推送到日志监控终端）
        original_send(log_type, content)
        
        # 获取当前会话 ID
        conversation_id = None
        try:
            from ..core import get_session_manager
            manager = get_session_manager()
            if manager:
                conversation_id = manager.current_session_id
        except:
            pass
        
        # 通过 IPC 队列推送到 WebSocket
        send_ws_message({
            "type": "log",
            "data": {
                "log_type": log_type,
                "content": content,
                "timestamp": time.time(),
                "conversation_id": conversation_id  # 添加会话 ID
            }
        })
    
    logger._send_to_monitor = enhanced_send


def setup_todo_callbacks():
    """
    设置 Todo 推送回调
    
    当 todo_write 被调用时，推送到 WebSocket
    """
    def todo_update_callback(todos: List[Dict]):
        """Todo 更新回调"""
        # 获取当前会话 ID
        conversation_id = None
        try:
            from ..core import get_session_manager
            manager = get_session_manager()
            if manager:
                conversation_id = manager.current_session_id
        except:
            pass
        
        send_ws_message({
            "type": "todo_update",
            "data": {
                "todos": todos,
                "timestamp": time.time(),
                "conversation_id": conversation_id  # 添加会话 ID
            }
        })
    
    set_todo_update_callback(todo_update_callback)


def setup_agent_monitor_callbacks():
    """
    设置 Agent 监控推送回调
    
    将 Agent 日志通过 IPC 队列推送到 WebSocket
    """
    if not AGENT_MONITOR_AVAILABLE:
        return
    
    from ..routes.agents import register_agent, update_agent_status
    
    _registered_agents = set()
    
    def agent_log_callback(agent_id: str, agent_name: str, message: str, level: str = "INFO"):
        """Agent 日志回调"""
        nonlocal _registered_agents
        
        # 获取当前会话 ID
        conversation_id = None
        try:
            from ..core import get_session_manager
            manager = get_session_manager()
            if manager:
                conversation_id = manager.current_session_id
        except:
            pass
        
        # 注册新 Agent
        is_new = agent_id not in _registered_agents
        register_agent(agent_id, agent_name, "running")
        
        if is_new:
            _registered_agents.add(agent_id)
            send_ws_message({
                "type": "agent_register",
                "data": {
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "status": "running",
                    "conversation_id": conversation_id  # 添加会话 ID
                }
            })
        
        # 处理完成/中断信号
        if level == "SYSTEM":
            if message == "__COMPLETE__":
                update_agent_status(agent_id, "completed")
                _registered_agents.discard(agent_id)
                send_ws_message({
                    "type": "agent_status",
                    "data": {
                        "agent_id": agent_id,
                        "status": "completed",
                        "conversation_id": conversation_id  # 添加会话 ID
                    }
                })
                return
            elif message == "__INTERRUPT__":
                update_agent_status(agent_id, "interrupted")
                _registered_agents.discard(agent_id)
                send_ws_message({
                    "type": "agent_status",
                    "data": {
                        "agent_id": agent_id,
                        "status": "interrupted",
                        "conversation_id": conversation_id  # 添加会话 ID
                    }
                })
                return
        
        # 推送日志
        send_ws_message({
            "type": "agent_output",
            "data": {
                "agent_id": agent_id,
                "agent_name": agent_name,
                "message": message,
                "level": level,
                "timestamp": time.time(),
                "conversation_id": conversation_id  # 添加会话 ID
            }
        })
    
    set_agent_log_callback(agent_log_callback)
