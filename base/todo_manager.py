"""
TODO管理器 - 声明式管理任务步骤列表

支持多会话独立管理：
- 每个会话的TODO列表存储在 ConversationState.todos 中
- TodoManager 通过 session_manager 访问当前会话的TODO列表
"""
import json
import os
from typing import Dict, List, Optional, Callable
from datetime import datetime
from .logger import log_tool_error
from .session_context import get_current_conversation_id

# Todo 更新回调
_todo_update_callback: Optional[Callable[[str, List[Dict]], None]] = None

def set_todo_update_callback(callback: Callable[[str, List[Dict]], None]) -> None:
    """设置 todo 更新回调函数
    
    Args:
        callback: 回调函数，接收 (session_id, todos) 参数
    """
    global _todo_update_callback
    _todo_update_callback = callback

class TodoManager:
    """TODO管理器 - 声明式管理任务步骤列表
    
    现在支持多会话独立管理，每个会话的TODO列表存储在对应的 ConversationState 中
    """
    
    def __init__(self, session_manager=None):
        """
        Args:
            session_manager: MultiSessionManager 实例，用于访问当前会话状态
        """
        self.session_manager = session_manager
    
    def _resolve_session_id(self, session_id: Optional[str] = None) -> str:
        if session_id:
            return session_id
        context_session_id = get_current_conversation_id()
        if context_session_id:
            return context_session_id
        return self._get_current_session_id()
    
    def _get_session_state(self, session_id: Optional[str] = None):
        if not self.session_manager:
            return None
        resolved_session_id = self._resolve_session_id(session_id)
        state = self.session_manager.get_session(resolved_session_id)
        if state is None:
            state = self.session_manager.create_session(resolved_session_id)
        return state

    def _get_current_todos(self, session_id: Optional[str] = None) -> List[Dict]:
        """获取指定会话的TODO列表"""
        state = self._get_session_state(session_id)
        return state.todos if state else []

    def _set_current_todos(self, todos: List[Dict], session_id: Optional[str] = None) -> None:
        """设置指定会话的TODO列表"""
        state = self._get_session_state(session_id)
        if state:
            state.todos = todos
    
    def _get_current_session_id(self) -> str:
        """获取当前会话ID"""
        if self.session_manager:
            return self.session_manager.current_session_id
        return "default"
    
    def write_todos(self, tasks: List[Dict], session_id: Optional[str] = None) -> List[Dict]:
        """写入完整的TODO列表（声明式更新）
        
        Args:
            tasks: 任务列表，每个任务包含 content 和 status
                   status 可以是: pending, completed, failed
        
        Returns:
            写入后的完整TODO列表
        """
        todos = []
        
        for i, task in enumerate(tasks, 1):
            # 严格要求使用 content 字段
            if "content" not in task:
                raise ValueError(f"任务 {i} 缺少必需的 'content' 字段。正确格式: {{\"content\": \"任务描述\", \"status\": \"pending\"}}")
            
            content = task.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ValueError(f"任务 {i} 的 'content' 字段必须是非空字符串")
            
            content = content.strip()
            
            status = task.get("status", "pending").lower()
            if status not in ["pending", "completed", "failed"]:
                status = "pending"
            
            todo = {
                "id": str(i),
                "content": content,
                "status": status,
                "updated_at": datetime.now().isoformat()
            }
            todos.append(todo)
        
        # 保存到当前会话
        resolved_session_id = self._resolve_session_id(session_id)
        self._set_current_todos(todos, resolved_session_id)
        
        # 触发回调（传递会话ID）
        if _todo_update_callback:
            try:
                _todo_update_callback(resolved_session_id, todos)
            except Exception:
                pass
        
        return todos
    
    def get_todos(self, session_id: Optional[str] = None) -> List[Dict]:
        """获取当前会话的TODO列表"""
        return self._get_current_todos(session_id).copy()
    
    def format_for_prompt(self) -> str:
        """格式化TODO列表用于prompt显示"""
        todos = self._get_current_todos()
        if not todos:
            return "当前没有任务规划"
        
        lines = []
        for todo in todos:
            status = todo["status"]
            status_icon = {
                "pending": "[ ]",
                "completed": "[√]",
                "failed": "[x]"
            }.get(status, "[?]")
            
            lines.append(f"{todo['id']}.{todo['content']}  {status_icon}")
        
        return "\n".join(lines)

# 全局TODO管理器实例（需要在初始化时设置 session_manager）
_todo_manager: Optional[TodoManager] = None

def initialize_todo_manager(session_manager) -> TodoManager:
    """初始化全局TODO管理器
    
    Args:
        session_manager: MultiSessionManager 实例
    
    Returns:
        TodoManager 实例
    """
    global _todo_manager
    _todo_manager = TodoManager(session_manager)
    return _todo_manager

def get_todo_manager() -> Optional[TodoManager]:
    """获取全局TODO管理器实例"""
    return _todo_manager

def todo_write(tasks: List[Dict], session_id: Optional[str] = None) -> Dict:
    """
    TODO写入函数 - 供LLM通过function call调用
    声明式更新整个任务列表
    
    参数:
        tasks: 任务列表，每个任务包含:
               - content: 任务内容 (必需)
               - status: 任务状态 (可选，默认pending)
                        可选值: pending(待执行), completed(已完成), failed(失败)
    
    返回:
        操作结果的字典
    """
    global _todo_manager

    if not _todo_manager:
        error_msg = "TODO管理器未初始化"
        log_tool_error("todo_write", error_msg, {})
        return {"success": False, "error": error_msg}

    try:
        if not isinstance(tasks, list):
            error_msg = "tasks必须是列表"
            log_tool_error("todo_write", error_msg, {"tasks": str(type(tasks))})
            return {"success": False, "error": error_msg}
        
        # 写入TODO列表
        todos = _todo_manager.write_todos(tasks, session_id=session_id)
        
        # 统计各状态数量
        status_count = {"pending": 0, "completed": 0, "failed": 0}
        for todo in todos:
            status_count[todo["status"]] = status_count.get(todo["status"], 0) + 1
        
        return {
            "success": True,
            "todos": todos,
            "count": len(todos),
            "status_count": status_count,
            "message": f"已更新任务列表，共 {len(todos)} 个步骤 (待执行:{status_count['pending']}, 已完成:{status_count['completed']}, 失败:{status_count['failed']})"
        }
    
    except Exception as e:
        error_msg = f"操作失败: {str(e)}"
        log_tool_error("todo_write", error_msg, {"tasks": tasks[:3] if isinstance(tasks, list) else tasks}, e)
        return {"success": False, "error": error_msg}

def get_current_todos_for_prompt() -> str:
    """获取当前会话的TODO列表用于prompt替换"""
    global _todo_manager
    if not _todo_manager:
        return "当前没有任务规划"
    return _todo_manager.format_for_prompt()

