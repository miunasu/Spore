"""Format tool and protocol results as Spore RESULT messages."""
import json
from typing import Any, Optional


class ResultFormatter:
    """RESULT block formatter."""

    RESULT_MARKER = "@SPORE:RESULT"
    TODO_MARKER = "@SPORE:TODO_START"
    TODO_END_MARKER = "@SPORE:TODO_END"

    def _get_todo_block(self) -> str:
        """Append current TODO state only when there are actual tasks."""
        try:
            from ..todo_manager import get_current_todos_for_prompt

            todo_content = get_current_todos_for_prompt()
            if todo_content and todo_content.strip() and todo_content != "当前没有任务规划":
                return f"\n\n{self.TODO_MARKER}\n{todo_content}\n{self.TODO_END_MARKER}"
        except Exception:
            pass
        return ""

    def format(self, result: Any, tool_name: Optional[str] = None) -> str:
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
        if tool_name:
            error_content = f"[错误] 工具 {tool_name} 执行失败: {error_message}"
        else:
            error_content = f"[错误] {error_message}"

        return f"{self.RESULT_MARKER}\n{error_content}{self._get_todo_block()}"

    def format_interrupt(self, tool_name: Optional[str] = None) -> str:
        if tool_name:
            interrupt_content = f"[中断] 工具 {tool_name} 执行被用户中断"
        else:
            interrupt_content = "[中断] 工具执行被用户中断"

        return f"{self.RESULT_MARKER}\n{interrupt_content}{self._get_todo_block()}"

    def format_timeout(self, tool_name: Optional[str] = None, timeout_seconds: Optional[int] = None) -> str:
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
        return f"{self.RESULT_MARKER}\n[错误] 未找到工具 {tool_name}{self._get_todo_block()}"

    def format_parse_error(self, error_message: str) -> str:
        return f"{self.RESULT_MARKER}\n[解析错误] {error_message}{self._get_todo_block()}"

    def format_protocol_error(self, code: str, message: str) -> str:
        payload = {
            "Status": "ProtocolError",
            "code": code,
            "message": message,
            "required_frameworks": {
                "REPLY_ONLY": "REPLY_START/END, optional TODO_START/END, no ACTION block.",
                "ACTION_ONLY": "Optional REPLY/TODO, exactly one ACTION_SINGLE/SEQUENCE/PARALLEL block, no STOP_REASON.",
                "FINAL_ONLY": "@SPORE:STOP_REASON=<natural language reason> (optional CONTENT multi-line), no REPLY/ACTION.",
            },
            "valid_action_blocks": [
                "ACTION_SINGLE",
                "ACTION_SEQUENCE",
                "ACTION_PARALLEL",
            ],
        }
        return f"{self.RESULT_MARKER}\n{json.dumps(payload, ensure_ascii=False, indent=2)}{self._get_todo_block()}"
