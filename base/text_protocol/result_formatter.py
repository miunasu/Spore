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

    def format_truncated(
        self,
        message: str,
        attempt: int = 1,
        api_stop_reason: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
    ) -> str:
        """回复被输出上限截断时给 LLM 的反馈。

        与 ProtocolError 区分开：截断不是模型写错了协议，反馈成协议错误会让模型
        原样重发同一份超长内容，再次撞上限，形成死循环。这里明确要求缩小单次
        输出规模，并随重试次数升级措辞。
        """
        payload = {
            "Status": "OutputTruncated",
            "code": "truncated_output",
            "message": message,
            "attempt": attempt,
            "api_stop_reason": api_stop_reason,
            "max_output_tokens": max_output_tokens,
            "how_to_recover": [
                "不要重复输出上一轮已经产出的部分",
                "把内容拆成多次输出：先写入第一部分，再用追加方式补齐后续部分",
                "单次输出的规模要明显小于上一轮",
            ],
        }
        if attempt >= 2:
            payload["how_to_recover"].insert(
                0,
                "已经连续被截断，必须换策略：把本次输出量至少减半，或改为先只输出目录/大纲",
            )
        return f"{self.RESULT_MARKER}\n{json.dumps(payload, ensure_ascii=False, indent=2)}{self._get_todo_block()}"

    def format_empty_response(self, attempt: int = 1) -> str:
        """模型一个字都没返回时给出的反馈（不写入对话历史的替代品）。"""
        payload = {
            "Status": "EmptyResponse",
            "code": "empty_response",
            "message": "上一轮没有收到任何正文内容，请重新输出完整的协议块回复。",
            "attempt": attempt,
            "how_to_recover": [
                "直接重新输出这一轮的回复，使用完整的 Spore 协议块",
                "先输出较短的内容确保能正常返回，再逐步补齐细节",
            ],
        }
        return f"{self.RESULT_MARKER}\n{json.dumps(payload, ensure_ascii=False, indent=2)}{self._get_todo_block()}"

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
