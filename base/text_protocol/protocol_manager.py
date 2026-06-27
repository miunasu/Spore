"""
Spore text protocol manager.

This module injects protocol instructions, validates LLM responses, extracts
user-visible blocks, and formats tool results.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional
import re

from .action_parser import ActionMode, ActionParser, ParsedAction, ParsedActionBlock
from .result_formatter import ResultFormatter
from .tool_doc_generator import ToolDocGenerator


def find_standalone_marker(text: str, marker: str) -> int:
    """Find a marker that appears on its own line."""
    pos = 0
    while pos < len(text):
        found = text.find(marker, pos)
        if found == -1:
            return -1
        if found > 0 and text[found - 1] != "\n":
            pos = found + len(marker)
            continue

        end_pos = found + len(marker)
        if end_pos >= len(text):
            return found

        next_char = text[end_pos]
        if next_char == "\n":
            return found
        if next_char in " \t":
            i = end_pos
            while i < len(text) and text[i] in " \t":
                i += 1
            if i >= len(text) or text[i] == "\n":
                return found
        pos = end_pos
    return -1


def is_standalone_marker(text: str, marker: str) -> bool:
    return find_standalone_marker(text, marker) >= 0


@dataclass
class ProtocolError:
    code: str
    message: str


@dataclass
class ParsedResponse:
    """Parsed LLM response."""

    response_type: Literal["action", "final", "continue", "protocol_error"]
    prefix_text: Optional[str] = None
    reply_content: Optional[str] = None
    action: Optional[ParsedAction] = None
    action_block: Optional[ParsedActionBlock] = None
    final_content: Optional[str] = None
    raw_response: str = ""
    protocol_error: Optional[ProtocolError] = None


PROTOCOL_TEMPLATE = """
---

## [IMPORTANT] Spore 回复协议（最高优先级）

你必须使用 Spore 文本 DSL 协议回复。协议块标识符必须独占一行。

### 可用协议块

回复用户可见内容：

```text
@SPORE:REPLY_START
给用户看的自然语言内容
@SPORE:REPLY_END
```

任务进度：

```text
@SPORE:TODO_START
1. [pending] 步骤一
2. [completed] 步骤二
@SPORE:TODO_END
```


**CONTENT块（原始内容语法）**

当参数值包含多行文本、代码、特殊字符时，使用CONTENT块传递。块内的所有内容原样保留，不会被解析器识别为协议指令或进行转义处理。类似于Python的raw string（`r""`），解决参数的转义问题。

格式：

```text
param=@SPORE:CONTENT_START
任意内容，包括换行、引号、特殊字符
都不会被转义或解析
@SPORE:CONTENT_END
```


任务完成标记：

```text
@SPORE:FINAL@
```

工具调用只能选择其中一种 ACTION 块。

单个工具：

```text
@SPORE:ACTION_SINGLE_START
file type=read file_path="C:/test.txt"
@SPORE:ACTION_SINGLE_END
```

顺序执行多个工具，前一步失败时系统默认停止后续步骤：

```text
@SPORE:ACTION_SEQUENCE_START
1. execute_command command="New-Item -ItemType Directory -Force output" working_dir="C:/project" timeout=30
2. file type=write file_path="C:/project/output/a.txt" content=@SPORE:CONTENT_START
hello
@SPORE:CONTENT_END
3. file type=read file_path="C:/project/output/a.txt"
@SPORE:ACTION_SEQUENCE_END
```

{parallel_action_docs}

### 隐形回复框架

不要输出 REPLY_ONLY、ACTION_ONLY、FINAL_ONLY 这些框架名，它们只是系统内部概念。

REPLY_ONLY：
- 允许 REPLY 块
- 可选 TODO 块
- 禁止任意 ACTION 块

ACTION_ONLY：
- 可选简短 REPLY 块
- 可选 TODO 块
- 必须包含且只包含一个 {action_block_names} 块
- 禁止包含 @SPORE:FINAL@
- ACTION 块结束后立即停止输出

FINAL_ONLY：
- 必须包含 REPLY 块
- 必须包含 @SPORE:FINAL@
- 禁止任意 ACTION 块

### 严格校验规则

- 协议块外禁止出现非空内容
- 所有 START/END 标记必须成对
- 禁止未知 @SPORE: 标识符
- 同一轮禁止出现多个 ACTION 块
- ACTION 回复中禁止出现 @SPORE:FINAL@
- 调用工具后不要自行输出 RESULT，系统会自动返回工具结果
- 多行参数继续使用 `@SPORE:CONTENT_START ... @SPORE:CONTENT_END`

### 可用工具

{tool_docs}
"""


PARALLEL_ACTION_DOCS = """并行执行多个工具，每个子操作必须有唯一 task_id：

```text
@SPORE:ACTION_PARALLEL_START
task_id=read_readme tool=file type=read file_path="C:/project/README.md"
task_id=grep_todos tool=Grep pattern="TODO" path="C:/project" output_mode=content -n=true head_limit=50
@SPORE:ACTION_PARALLEL_END
```
"""


class ProtocolManager:
    """Text protocol manager."""

    BLOCK_MARKERS = {
        "REPLY": ("@SPORE:REPLY_START", "@SPORE:REPLY_END"),
        "TODO": ("@SPORE:TODO_START", "@SPORE:TODO_END"),
        "ACTION_SINGLE": ("@SPORE:ACTION_SINGLE_START", "@SPORE:ACTION_SINGLE_END"),
        "ACTION_SEQUENCE": ("@SPORE:ACTION_SEQUENCE_START", "@SPORE:ACTION_SEQUENCE_END"),
        "ACTION_PARALLEL": ("@SPORE:ACTION_PARALLEL_START", "@SPORE:ACTION_PARALLEL_END"),
    }
    ACTION_BLOCK_NAMES = {"ACTION_SINGLE", "ACTION_SEQUENCE", "ACTION_PARALLEL"}
    VALID_MARKERS = {
        "@SPORE:REPLY_START",
        "@SPORE:REPLY_END",
        "@SPORE:TODO_START",
        "@SPORE:TODO_END",
        "@SPORE:ACTION_SINGLE_START",
        "@SPORE:ACTION_SINGLE_END",
        "@SPORE:ACTION_SEQUENCE_START",
        "@SPORE:ACTION_SEQUENCE_END",
        "@SPORE:ACTION_PARALLEL_START",
        "@SPORE:ACTION_PARALLEL_END",
        "@SPORE:FINAL@",
        "@SPORE:CONTENT_START",
        "@SPORE:CONTENT_END",
    }
    CONTENT_MARKERS = {"@SPORE:CONTENT_START", "@SPORE:CONTENT_END"}

    def __init__(self):
        self.action_parser = ActionParser()
        self.result_formatter = ResultFormatter()
        self.tool_doc_generator = ToolDocGenerator()

    def _has_multi_agent_dispatch(self, tool_definitions: Dict[str, Dict[str, Any]]) -> bool:
        return "multi_agent_dispatch" in tool_definitions

    def _visibility_for_tools(self, tool_definitions: Dict[str, Dict[str, Any]]) -> tuple[bool, bool]:
        has_multi_agent = self._has_multi_agent_dispatch(tool_definitions)
        return not has_multi_agent, has_multi_agent

    def _filter_prompt_for_tools(
        self,
        original_prompt: str,
        tool_definitions: Dict[str, Dict[str, Any]],
    ) -> str:
        if not original_prompt:
            return original_prompt

        show_parallel, show_multi_agent = self._visibility_for_tools(tool_definitions)
        prompt = original_prompt

        if not show_parallel:
            prompt = re.sub(
                r"\n并行工具调用：\n\n@SPORE:ACTION_PARALLEL_START\n.*?@SPORE:ACTION_PARALLEL_END\n",
                "\n",
                prompt,
                flags=re.S,
            )
        else:
            prompt = prompt.replace(
                "- 无依赖的步骤可并发派发给子 Agent",
                "- 无依赖的工具操作可使用 ACTION_PARALLEL 并发执行",
            )

        if not show_multi_agent:
            prompt = re.sub(
                r"\n---\n\n## 多 Agent 系统\n.*?(?=\n---\n\n## Skills 系统)",
                "",
                prompt,
                flags=re.S,
            )

        return prompt

    def generate_protocol_instructions(
        self,
        tool_definitions: Dict[str, Dict[str, Any]],
    ) -> str:
        show_parallel, show_multi_agent = self._visibility_for_tools(tool_definitions)
        visible_tool_definitions = dict(tool_definitions)
        if not show_multi_agent:
            visible_tool_definitions.pop("multi_agent_dispatch", None)

        tool_docs = self.tool_doc_generator.generate(visible_tool_definitions)
        return PROTOCOL_TEMPLATE.format(
            action_block_names="ACTION_SINGLE、ACTION_SEQUENCE 或 ACTION_PARALLEL" if show_parallel else "ACTION_SINGLE 或 ACTION_SEQUENCE",
            parallel_action_docs=PARALLEL_ACTION_DOCS if show_parallel else "",
            tool_docs=tool_docs,
        )

    def inject_protocol(
        self,
        original_prompt: str,
        tool_definitions: Dict[str, Dict[str, Any]],
    ) -> str:
        return (
            self._filter_prompt_for_tools(original_prompt, tool_definitions)
            + self.generate_protocol_instructions(tool_definitions)
        )

    def _find_standalone_marker(self, response: str, marker: str) -> int:
        return find_standalone_marker(response, marker)

    def _extract_block_content(self, response: str, block_name: str) -> Optional[str]:
        start_marker, end_marker = self.BLOCK_MARKERS[block_name]
        start = self._find_standalone_marker(response, start_marker)
        if start < 0:
            return None
        content_start = start + len(start_marker)
        end = self._find_standalone_marker(response[content_start:], end_marker)
        if end < 0:
            return None
        return response[content_start:content_start + end].strip() or None

    def _scan_protocol(self, response: str) -> tuple[List[Dict[str, Any]], Optional[ProtocolError]]:
        blocks: List[Dict[str, Any]] = []
        stack: List[Dict[str, Any]] = []
        content_spans: List[tuple[int, int]] = []
        final_spans: List[tuple[int, int]] = []

        marker_regex = re.compile(r"(?m)^[ \t]*(@SPORE:[A-Z_]+(?:_START|_END)?@?)[ \t]*(?:\r?\n|$)")
        markers = list(marker_regex.finditer(response))
        in_content = False

        for match in markers:
            marker = match.group(1)

            if not in_content and stack and stack[-1]["name"] in self.ACTION_BLOCK_NAMES:
                action_content_so_far = response[stack[-1]["content_start"]:match.start()]
                if action_content_so_far.rfind("@SPORE:CONTENT_START") > action_content_so_far.rfind("@SPORE:CONTENT_END"):
                    in_content = True

            if in_content:
                if marker == "@SPORE:CONTENT_END":
                    in_content = False
                continue

            if marker not in self.VALID_MARKERS:
                return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 标识符: {marker}")

            if marker in self.CONTENT_MARKERS:
                if not stack or stack[-1]["name"] not in self.ACTION_BLOCK_NAMES:
                    return blocks, ProtocolError("unknown_protocol_block", f"{marker} 只能出现在 ACTION 参数内容中")
                if marker == "@SPORE:CONTENT_START":
                    in_content = True
                else:
                    return blocks, ProtocolError("mismatched_end_marker", "@SPORE:CONTENT_END 缺少对应的 @SPORE:CONTENT_START")
                continue

            if marker == "@SPORE:FINAL@":
                final_spans.append((match.start(), match.end()))
                blocks.append({
                    "name": "FINAL",
                    "start": match.start(),
                    "end": match.end(),
                    "content_start": match.start(),
                    "content_end": match.end(),
                    "content": "",
                    "raw": match.group(0),
                })
                continue

            if marker.endswith("_START"):
                block_name = marker[len("@SPORE:"):-len("_START")]
                if block_name not in self.BLOCK_MARKERS:
                    return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 协议块: {marker}")
                if stack:
                    return blocks, ProtocolError("mismatched_end_marker", f"协议块不允许嵌套: {marker}")
                stack.append({"name": block_name, "start_marker": marker, "start": match.start(), "content_start": match.end()})
                continue

            if marker.endswith("_END"):
                block_name = marker[len("@SPORE:"):-len("_END")]
                if block_name not in self.BLOCK_MARKERS:
                    return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 协议块: {marker}")
                if not stack:
                    return blocks, ProtocolError("mismatched_end_marker", f"缺少开始标识符: {marker}")
                open_block = stack.pop()
                if open_block["name"] != block_name:
                    return blocks, ProtocolError(
                        "mismatched_end_marker",
                        f"开始标识符 {open_block['start_marker']} 与结束标识符 {marker} 不匹配",
                    )
                blocks.append({
                    "name": block_name,
                    "start": open_block["start"],
                    "end": match.end(),
                    "content_start": open_block["content_start"],
                    "content_end": match.start(),
                    "content": response[open_block["content_start"]:match.start()].strip(),
                    "raw": response[open_block["start"]:match.end()],
                })
                content_spans.append((open_block["start"], match.end()))

        if in_content:
            return blocks, ProtocolError("missing_end_marker", "缺少结束标识符: @SPORE:CONTENT_END")

        if stack:
            open_block = stack[-1]
            return blocks, ProtocolError("missing_end_marker", f"缺少结束标识符: @SPORE:{open_block['name']}_END")

        if len(final_spans) > 1:
            return blocks, ProtocolError("multiple_final_markers", "同一轮回复中只能包含一个 @SPORE:FINAL@")
        if final_spans:
            content_spans.append(final_spans[0])

        uncovered = self._content_outside_spans(response, content_spans)
        if uncovered:
            return blocks, ProtocolError("content_outside_block", "协议块外存在非空内容")

        return blocks, None

    def _content_outside_spans(self, response: str, spans: List[tuple[int, int]]) -> str:
        if not response.strip():
            return ""

        spans = sorted(spans)
        parts: List[str] = []
        cursor = 0
        for start, end in spans:
            if start > cursor:
                parts.append(response[cursor:start])
            cursor = max(cursor, end)
        if cursor < len(response):
            parts.append(response[cursor:])

        return "".join(parts).strip()

    def parse_response(self, response: str) -> ParsedResponse:
        if not response:
            return ParsedResponse(response_type="continue", raw_response="")

        blocks, error = self._scan_protocol(response)
        if error:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=error,
            )

        final_blocks = [block for block in blocks if block["name"] == "FINAL"]
        final_pos = final_blocks[0]["start"] if final_blocks else -1
        has_final = bool(final_blocks)
        action_blocks = [block for block in blocks if block["name"] in self.ACTION_BLOCK_NAMES]
        reply_blocks = [block for block in blocks if block["name"] == "REPLY"]
        todo_blocks = [block for block in blocks if block["name"] == "TODO"]

        if len(reply_blocks) > 1:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("multiple_reply_blocks", "同一轮回复中只能包含一个 REPLY 块"),
            )

        if len(todo_blocks) > 1:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("multiple_todo_blocks", "同一轮回复中只能包含一个 TODO 块"),
            )

        if len(action_blocks) > 1:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("multiple_action_blocks", "同一轮回复中只能包含一个 ACTION 块"),
            )

        if action_blocks and has_final:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("action_with_final", "ACTION 回复中禁止出现 @SPORE:FINAL@"),
            )

        reply_content = reply_blocks[0]["content"] if reply_blocks else None

        if action_blocks:
            action_block_info = action_blocks[0]
            mode = self._action_name_to_mode(action_block_info["name"])
            parsed_block = self.action_parser.parse_block(
                response,
                mode=mode,
                content=action_block_info["content"],
                raw_text=action_block_info["raw"],
            )
            if parsed_block is None:
                return ParsedResponse(
                    response_type="protocol_error",
                    raw_response=response,
                    protocol_error=ProtocolError("invalid_action_block", self._invalid_action_message(mode)),
                )

            return ParsedResponse(
                response_type="action",
                prefix_text=reply_content,
                reply_content=reply_content,
                action=parsed_block.first_action,
                action_block=parsed_block,
                raw_response=response,
            )

        if has_final:
            if not reply_content:
                return ParsedResponse(
                    response_type="protocol_error",
                    raw_response=response,
                    protocol_error=ProtocolError("missing_reply_block", "FINAL_ONLY 回复必须包含 REPLY 块"),
                )
            final_content = response[final_pos + len(self.action_parser.FINAL_MARKER):].strip() or None
            return ParsedResponse(
                response_type="final",
                prefix_text=reply_content,
                reply_content=reply_content,
                final_content=final_content,
                raw_response=response,
            )

        return ParsedResponse(
            response_type="continue",
            prefix_text=reply_content,
            reply_content=reply_content,
            raw_response=response,
        )

    def _action_name_to_mode(self, name: str) -> ActionMode:
        if name == "ACTION_SEQUENCE":
            return "sequence"
        if name == "ACTION_PARALLEL":
            return "parallel"
        return "single"

    def _invalid_action_message(self, mode: ActionMode) -> str:
        if mode == "sequence":
            return "ACTION_SEQUENCE 必须包含按顺序编号的工具调用，例如 `1. file type=read ...`"
        if mode == "parallel":
            return "ACTION_PARALLEL 的每个子操作必须包含唯一 task_id，例如 `task_id=readme tool=file type=read ...`"
        return "ACTION_SINGLE 必须包含且只包含一个有效工具调用"

    def format_result(self, result: Any, tool_name: Optional[str] = None) -> str:
        return self.result_formatter.format(result, tool_name)

    def format_error(self, error_message: str, tool_name: Optional[str] = None) -> str:
        return self.result_formatter.format_error(error_message, tool_name)

    def format_interrupt(self, tool_name: Optional[str] = None) -> str:
        return self.result_formatter.format_interrupt(tool_name)

    def format_not_found(self, tool_name: str) -> str:
        return self.result_formatter.format_not_found(tool_name)

    def format_parse_error(self, error_message: str) -> str:
        return self.result_formatter.format_parse_error(error_message)

    def format_protocol_error(self, error: ProtocolError) -> str:
        return self.result_formatter.format_protocol_error(error.code, error.message)

    def parse_todo_from_response(self, response: str) -> Optional[List[Dict[str, str]]]:
        todo_content = self._extract_block_content(response, "TODO")
        if not todo_content:
            return None

        tasks: List[Dict[str, str]] = []
        for line in todo_content.split("\n"):
            line = line.strip()
            if not line:
                continue

            if line[0].isdigit():
                i = 0
                while i < len(line) and (line[i].isdigit() or line[i] == "."):
                    i += 1
                line = line[i:].strip()
            elif line.startswith("-"):
                line = line[1:].strip()

            status = "pending"
            content = line

            if line.startswith("["):
                bracket_end = line.find("]")
                if bracket_end > 0:
                    status = self._parse_status(line[1:bracket_end].strip().lower())
                    content = line[bracket_end + 1:].strip()
            else:
                match = re.search(r"\[([^\]]*)\]\s*$", line)
                if match:
                    status = self._parse_status(match.group(1).strip().lower())
                    content = line[:match.start()].strip()

            if content:
                tasks.append({"content": content, "status": status})

        return tasks if tasks else None

    def _parse_status(self, status_str: str) -> str:
        if status_str in {"completed", "done", "完成", "已完成", "v", "x"}:
            return "completed"
        if status_str in {"failed", "fail", "失败", "已失败"}:
            return "failed"
        return "pending"
