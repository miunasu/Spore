"""
RESULT 块格式化器

将工具执行结果格式化为 RESULT 块文本。
"""
import json
from typing import Any, Optional


class ResultFormatter:
    """RESULT 块格式化器"""
    
    RESULT_MARKER = "@SPORE:RESULT"
    TODO_MARKER = "@SPORE:TODO"
    
    def _get_todo_block(self) -> str:
        """获取当前 TODO 内容块（只在有实际任务时注入）"""
        try:
            from ..todo_manager import get_current_todos_for_prompt
            todo_content = get_current_todos_for_prompt()
            # 只在有实际任务时才注入，跳过"当前没有任务规划"
            if todo_content and todo_content.strip() and todo_content != "当前没有任务规划":
                return f"\n\n{self.TODO_MARKER}\n{todo_content}"
        except Exception:
            pass
        return ""
    
    def format(self, result: Any, tool_name: Optional[str] = None) -> str:
        """
        格式化工具结果为 RESULT 块
        
        Args:
            result: 工具执行结果（可以是字符串、字典、列表等）
            tool_name: 工具名称（可选，用于错误信息）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        # 将结果转换为字符串
        if result is None:
            result_str = ""
        elif isinstance(result, str):
            result_str = result
        elif isinstance(result, (dict, list)):
            try:
                result_str = json.dumps(result, ensure_ascii=False, indent=2)
            except (TypeError, ValueError):
                result_str = str(result)
        else:
            result_str = str(result)
        
        return f"{self.RESULT_MARKER}\n{result_str}{self._get_todo_block()}"
    
    def format_error(self, error_message: str, tool_name: Optional[str] = None) -> str:
        """
        格式化错误信息为 RESULT 块
        
        Args:
            error_message: 错误信息
            tool_name: 工具名称（可选）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        if tool_name:
            error_content = f"[错误] 工具 {tool_name} 执行失败: {error_message}"
        else:
            error_content = f"[错误] {error_message}"
        
        return f"{self.RESULT_MARKER}\n{error_content}{self._get_todo_block()}"
    
    def format_interrupt(self, tool_name: Optional[str] = None) -> str:
        """
        格式化中断信息为 RESULT 块
        
        Args:
            tool_name: 被中断的工具名称（可选）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        if tool_name:
            interrupt_content = f"[中断] 工具 {tool_name} 执行被用户中断"
        else:
            interrupt_content = "[中断] 工具执行被用户中断"
        
        return f"{self.RESULT_MARKER}\n{interrupt_content}{self._get_todo_block()}"
    
    def format_timeout(self, tool_name: Optional[str] = None, timeout_seconds: Optional[int] = None) -> str:
        """
        格式化超时信息为 RESULT 块
        
        Args:
            tool_name: 超时的工具名称（可选）
            timeout_seconds: 超时时间（秒）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        if tool_name and timeout_seconds:
            timeout_content = f"[超时] 工具 {tool_name} 执行超时（{timeout_seconds}秒）"
        elif tool_name:
            timeout_content = f"[超时] 工具 {tool_name} 执行超时"
        elif timeout_seconds:
            timeout_content = f"[超时] 工具执行超时（{timeout_seconds}秒）"
        else:
            timeout_content = "[超时] 工具执行超时"
        
        return f"{self.RESULT_MARKER}\n{timeout_content}{self._get_todo_block()}"
    
    def format_not_found(self, tool_name: str) -> str:
        """
        格式化工具未找到错误为 RESULT 块
        
        Args:
            tool_name: 未找到的工具名称
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return f"{self.RESULT_MARKER}\n[错误] 未找到工具: {tool_name}{self._get_todo_block()}"
    
    def format_parse_error(self, error_message: str) -> str:
        """
        格式化解析错误为 RESULT 块
        
        Args:
            error_message: 解析错误信息
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return f"{self.RESULT_MARKER}\n[解析错误] {error_message}{self._get_todo_block()}"
