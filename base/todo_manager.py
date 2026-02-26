import json
import os
from typing import Dict, List, Optional, Callable
from datetime import datetime
from .logger import log_tool_error

# Todo 更新回调
_todo_update_callback: Optional[Callable[[List[Dict]], None]] = None

def set_todo_update_callback(callback: Callable[[List[Dict]], None]) -> None:
    """设置 todo 更新回调函数"""
    global _todo_update_callback
    _todo_update_callback = callback

class TodoManager:
    """TODO管理器 - 声明式管理任务步骤列表"""
    
    def __init__(self):
        self.todos: List[Dict] = []
    
    def write_todos(self, tasks: List[Dict]) -> List[Dict]:
        """写入完整的TODO列表（声明式更新）
        
        Args:
            tasks: 任务列表，每个任务包含 content 和 status
                   status 可以是: pending, completed, failed
        
        Returns:
            写入后的完整TODO列表
        """
        self.todos = []
        
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
            self.todos.append(todo)
        
        # 触发回调
        if _todo_update_callback:
            try:
                _todo_update_callback(self.todos)
            except Exception:
                pass
        
        return self.todos
    
    def get_todos(self) -> List[Dict]:
        """获取当前TODO列表"""
        return self.todos.copy()
    
    def format_for_prompt(self) -> str:
        """格式化TODO列表用于prompt显示"""
        if not self.todos:
            return "当前没有任务规划"
        
        lines = []
        for todo in self.todos:
            status = todo["status"]
            status_icon = {
                "pending": "[ ]",
                "completed": "[√]",
                "failed": "[x]"
            }.get(status, "[?]")
            
            lines.append(f"{todo['id']}.{todo['content']}  {status_icon}")
        
        return "\n".join(lines)

# 全局TODO管理器实例
_todo_manager = TodoManager()

def todo_write(tasks: List[Dict]) -> Dict:
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

    try:
        if not isinstance(tasks, list):
            error_msg = "tasks必须是列表"
            log_tool_error("todo_write", error_msg, {"tasks": str(type(tasks))})
            return {"success": False, "error": error_msg}
        
        # 写入TODO列表
        todos = _todo_manager.write_todos(tasks)
        
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
    """获取当前TODO列表用于prompt替换"""
    global _todo_manager
    return _todo_manager.format_for_prompt()

