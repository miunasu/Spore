"""
日志推送桥接

将 base/logger.py 和 base/multi_agent_monitor.py 的日志
通过 IPC 队列推送到独立的 WebSocket 进程。
"""
import time
from typing import Dict, List
from .ipc_bridge import send_ws_message


def setup_log_callbacks():
    """
    设置日志推送回调
    
    增强 SporeLogger._send_to_monitor，添加 WebSocket 推送
    """
    from base.logger import get_logger
    
    logger = get_logger()
    original_send = logger._send_to_monitor
    
    def enhanced_send(log_type: str, content: str):
        """增强的日志发送方法"""
        # 调用原始方法（推送到日志监控终端）
        original_send(log_type, content)
        
        # 通过 IPC 队列推送到 WebSocket
        send_ws_message({
            "type": "log",
            "data": {
                "log_type": log_type,
                "content": content,
                "timestamp": time.time()
            }
        })
    
    logger._send_to_monitor = enhanced_send


def setup_todo_callbacks():
    """
    设置 Todo 推送回调
    
    当 todo_write 被调用时，推送到 WebSocket
    """
    from base.todo_manager import set_todo_update_callback
    
    def todo_update_callback(todos: List[Dict]):
        """Todo 更新回调"""
        send_ws_message({
            "type": "todo_update",
            "data": {
                "todos": todos,
                "timestamp": time.time()
            }
        })
    
    set_todo_update_callback(todo_update_callback)


def setup_agent_monitor_callbacks():
    """
    设置 Agent 监控推送回调
    
    将 Agent 日志通过 IPC 队列推送到 WebSocket
    """
    try:
        from base.multi_agent_monitor import set_agent_log_callback
        from ..routes.agents import register_agent, update_agent_status
        
        _registered_agents = set()
        
        def agent_log_callback(agent_id: str, agent_name: str, message: str, level: str = "INFO"):
            """Agent 日志回调"""
            nonlocal _registered_agents
            
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
                        "status": "running"
                    }
                })
            
            # 处理完成/中断信号
            if level == "SYSTEM":
                if message == "__COMPLETE__":
                    update_agent_status(agent_id, "completed")
                    _registered_agents.discard(agent_id)
                    send_ws_message({
                        "type": "agent_status",
                        "data": {"agent_id": agent_id, "status": "completed"}
                    })
                    return
                elif message == "__INTERRUPT__":
                    update_agent_status(agent_id, "interrupted")
                    _registered_agents.discard(agent_id)
                    send_ws_message({
                        "type": "agent_status",
                        "data": {"agent_id": agent_id, "status": "interrupted"}
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
                    "timestamp": time.time()
                }
            })
        
        set_agent_log_callback(agent_log_callback)
    except ImportError:
        pass
