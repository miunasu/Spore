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


# 终止符：纯粹的标记，无参数
STOP_MARKER = "@SPORE:STOP"
CONTENT_START_MARKER = "@SPORE:CONTENT_START"
CONTENT_END_MARKER = "@SPORE:CONTENT_END"


def _strip_content_wrapper_padding(content: str) -> str:
    if content.startswith("\r\n"):
        content = content[2:]
    elif content.startswith("\n"):
        content = content[1:]
    return content.rstrip("\r\n \t")


def extract_stop_blocks(text: str) -> tuple[List[Dict[str, Any]], Optional[str]]:
    """Extract all STOP markers from response text.

    Returns (blocks, error_message).
    """
    text = text or ""
    blocks: List[Dict[str, Any]] = []

    # @SPORE:STOP (纯终止符，无参数)
    stop_pos = find_standalone_marker(text, STOP_MARKER)
    if stop_pos >= 0:
        end_pos = stop_pos + len(STOP_MARKER)
        # 跳过行尾空白到换行符
        while end_pos < len(text) and text[end_pos] in " \t":
            end_pos += 1
        if end_pos < len(text) and text[end_pos] in "\r\n":
            if text[end_pos] == "\r" and end_pos + 1 < len(text) and text[end_pos + 1] == "\n":
                end_pos += 2
            else:
                end_pos += 1
        blocks.append({
            "name": "STOP",
            "start": stop_pos,
            "end": end_pos,
            "content_start": stop_pos,
            "content_end": end_pos,
            "raw": text[stop_pos:end_pos],
        })
    return blocks, None


def find_stop_marker(text: str) -> Optional[tuple[int, int, str]]:
    """Find first @SPORE:STOP terminator.

    Returns (start, end, content) or None. Content is always empty for STOP.
    """
    blocks, err = extract_stop_blocks(text or "")
    if err or not blocks:
        return None
    b = blocks[0]
    return b["start"], b["end"], ""


def has_stop_marker(text: str) -> bool:
    return find_stop_marker(text) is not None


def is_stop_line(line: str) -> bool:
    """True if line is @SPORE:STOP."""
    return (line or "").strip() == STOP_MARKER


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
    raw_response: str = ""
    protocol_error: Optional[ProtocolError] = None
    # Soft protocol notice (e.g. content outside blocks). Not a hard failure.
    protocol_warning: Optional[str] = None
    # True when the reply was cut off by the output cap rather than mis-written.
    # Callers must not treat a truncated reply as a normal turn.
    truncated: bool = False


PROTOCOL_TEMPLATE = """
---

## [IMPORTANT] Spore 回复协议（最高优先级）

你必须使用 Spore 文本 DSL 协议回复。协议块标识符必须独占一行。

当前没有任何隐藏工具可直接调用；所有工具调用都必须使用 ACTION 协议块（{action_block_names_slash}）输出，由用户侧系统执行。
所有输出内容必须被包裹在协议块内，协议块外不得出现任何非空内容。


### 可用协议块

回复用户可见内容（同一轮可出现多个 REPLY 块，内容会按顺序全部展示给用户）：

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


**最终回复（任务完成）**

所有回复内容（包括最终总结）都必须放在 REPLY 块中。任务完成后，输出 `@SPORE:STOP` 终止符。

格式：

```text
@SPORE:REPLY_START
最终总结性回复
@SPORE:REPLY_END

@SPORE:STOP
```

说明：
- `@SPORE:STOP` 是纯粹的终止符，不带任何参数
- 最终回复内容必须放在 REPLY 块中


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
- ACTION 块结束后立即停止输出

FINAL_ONLY：
- 必须包含 REPLY 块（放置最终总结内容）
- 必须包含 @SPORE:STOP 终止符
- 禁止任意 ACTION 块

### 严格校验规则

- 协议块外禁止出现非空内容
- 所有 START/END 标记必须成对
- 禁止未知 @SPORE: 标识符
- 同一轮禁止出现多个 ACTION 块
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

    # Soft warning when non-empty text appears outside protocol blocks.
    # Actions still execute; warning is returned to the LLM with tool results.
    CONTENT_OUTSIDE_WARNING = (
        "协议块外存在非空内容。所有输出必须在协议块内(本次协议块外内容已兼容，合法协议块内操作已执行，不必再次输出本轮相同操作)：\n"
        "- 用户可见内容使用 @SPORE:REPLY_START / @SPORE:REPLY_END\n"
        "- 工具调用使用 @SPORE:ACTION_*_START / @SPORE:ACTION_*_END\n"
        "- 任务完成在 REPLY 块中输出总结，然后输出 @SPORE:STOP\n"
    )

    # 兜底：匹配连续重复的协议边界标记（中间仅有空白行或无内容）
    # 捕获组：(1)首个标记全行, (2)标记token, (3)首个标记的换行, (4)中间空白行, (5)重复标记行
    _DEDUP_BOUNDARY_RE = re.compile(
        r'(?m)^([ \t]*(@SPORE:[A-Z_]+_(?:START|END))[ \t]*)(\r?\n)'
        r'((?:[ \t]*\r?\n)*)'
        r'([ \t]*\2[ \t]*(?:\r?\n|$))'
    )


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
        "@SPORE:STOP",  # 终止符
        "@SPORE:CONTENT_START",
        "@SPORE:CONTENT_END",
    }
    CONTENT_MARKERS = {"@SPORE:CONTENT_START", "@SPORE:CONTENT_END"}

    @staticmethod
    def _deduplicate_boundary_markers(text: str) -> str:
        """兜底：将连续重复的协议边界标记合并为一个。

        模型偶尔输出同一边界标记两次（中间可能是换行、空格行或无内容），
        导致解析器报 mismatched_end_marker 等协议错误。此预处理在解析前
        将简单重复合并，使响应顺利通过校验。支持三连及以上重复（循环处理）。
        """
        prev = None
        while prev != text:
            prev = text
            text = ProtocolManager._DEDUP_BOUNDARY_RE.sub(r'\1\3', text)
        return text

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
        if show_parallel:
            action_block_names = "ACTION_SINGLE、ACTION_SEQUENCE 或 ACTION_PARALLEL"
            action_block_names_slash = "ACTION_SINGLE/ACTION_SEQUENCE/ACTION_PARALLEL"
        else:
            action_block_names = "ACTION_SINGLE 或 ACTION_SEQUENCE"
            action_block_names_slash = "ACTION_SINGLE/ACTION_SEQUENCE"
        return PROTOCOL_TEMPLATE.format(
            action_block_names=action_block_names,
            action_block_names_slash=action_block_names_slash,
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

    def _scan_protocol(self, response: str) -> tuple[List[Dict[str, Any]], Optional[ProtocolError], str]:
        blocks: List[Dict[str, Any]] = []
        stack: List[Dict[str, Any]] = []
        content_spans: List[tuple[int, int]] = []
        final_spans: List[tuple[int, int]] = []

        # Pre-parse STOP markers
        stop_blocks, stop_err = extract_stop_blocks(response)
        if stop_err:
            return blocks, ProtocolError("invalid_stop", stop_err), ""
        for stop_block in stop_blocks:
            blocks.append(stop_block)
            final_spans.append((stop_block["start"], stop_block["end"]))
        stop_spans = list(final_spans)

        # 新协议 STOP 是纯终止符（无参数），只需检测第一个即可。
        # content_after_stop 检查：STOP 之后不应有其他内容。
        if final_spans and response[final_spans[-1][1]:].strip():
            return blocks, ProtocolError(
                "content_after_stop",
                "@SPORE:STOP 之后不应有其他内容",
            ), ""

        # Standard block markers only; STOP spans are handled above.
        marker_regex = re.compile(r"(?m)^[ \t]*(@SPORE:[A-Z_]+(?:_START|_END)?@?)[ \t]*(?:\r?\n|$)")
        markers = list(marker_regex.finditer(response))
        in_content = False

        def _in_stop_span(pos: int) -> bool:
            return any(start <= pos < end for start, end in stop_spans)

        for match in markers:
            if _in_stop_span(match.start()):
                continue

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
                return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 标识符: {marker}"), ""

            if marker in self.CONTENT_MARKERS:
                if not stack or stack[-1]["name"] not in self.ACTION_BLOCK_NAMES:
                    return blocks, ProtocolError("unknown_protocol_block", f"{marker} 只能出现在 ACTION 参数内容中"), ""
                if marker == "@SPORE:CONTENT_START":
                    in_content = True
                else:
                    return blocks, ProtocolError("mismatched_end_marker", "@SPORE:CONTENT_END 缺少对应的 @SPORE:CONTENT_START"), ""
                continue

            if marker.endswith("_START"):
                block_name = marker[len("@SPORE:"):-len("_START")]
                if block_name not in self.BLOCK_MARKERS:
                    return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 协议块: {marker}"), ""
                if stack:
                    return blocks, ProtocolError("mismatched_end_marker", f"协议块不允许嵌套: {marker}"), ""
                stack.append({"name": block_name, "start_marker": marker, "start": match.start(), "content_start": match.end()})
                continue

            if marker.endswith("_END"):
                block_name = marker[len("@SPORE:"):-len("_END")]
                if block_name not in self.BLOCK_MARKERS:
                    return blocks, ProtocolError("unknown_protocol_block", f"未知 Spore 协议块: {marker}"), ""
                if not stack:
                    return blocks, ProtocolError("mismatched_end_marker", f"缺少开始标识符: {marker}"), ""
                open_block = stack.pop()
                if open_block["name"] != block_name:
                    expected_end = f"@SPORE:{open_block['name']}_END"
                    if expected_end in response[open_block["content_start"]:match.start()]:
                        return blocks, ProtocolError(
                            "mismatched_end_marker",
                            f"{expected_end} 未独占一行（不能与其他内容或标识符粘连在同一行），协议块标识符必须独占一行",
                        ), ""
                    return blocks, ProtocolError(
                        "mismatched_end_marker",
                        f"开始标识符 {open_block['start_marker']} 与结束标识符 {marker} 不匹配",
                    ), ""
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
            return blocks, ProtocolError("missing_end_marker", "缺少结束标识符: @SPORE:CONTENT_END"), ""

        if stack:
            open_block = stack[-1]
            end_marker = f"@SPORE:{open_block['name']}_END"
            if end_marker in response[open_block["content_start"]:]:
                return blocks, ProtocolError(
                    "missing_end_marker",
                    f"{end_marker} 未独占一行（不能与其他内容或标识符粘连在同一行），协议块标识符必须独占一行",
                ), ""
            return blocks, ProtocolError("missing_end_marker", f"缺少结束标识符: {end_marker}"), ""

        # 多个 STOP 时，将所有 span 都纳入已覆盖范围，避免后续出现在 outside_content
        for span in final_spans:
            content_spans.append(span)

        uncovered = self._content_outside_spans(response, content_spans)
        # Soft policy: outside text is treated as REPLY later; ACTION still executes.
        # Hard error removed — warning is attached in parse_response / tool RESULT.
        return blocks, None, uncovered

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

    TRUNCATED_OUTPUT_MESSAGE = (
        "上一轮回复在输出上限处被截断，标识符本身没写错，不要原样重发同一份内容。"
        "请改为分批产出：先输出/写入前一部分，再用追加方式补齐剩余部分，"
        "单次输出规模明显减小。"
    )

    def parse_response(
        self,
        response: str,
        truncated: Optional[bool] = None,
    ) -> ParsedResponse:
        """解析回复。

        Args:
            response: LLM 回复原文
            truncated: 调用方从 API 字段得到的截断结论。None 表示未知。
                协议层只解析结构，不根据回复文本推断传输状态。
        """
        if not response:
            return ParsedResponse(response_type="continue", raw_response="")

        response = self._deduplicate_boundary_markers(response)
        blocks, error, outside_content = self._scan_protocol(response)
        if error:
            is_truncated = bool(truncated) if truncated is not None else False
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=error,
                truncated=is_truncated,
            )

        outside_text = (outside_content or "").strip()
        # 协议解析结果与传输状态彼此独立；这里只透传调用方给出的明确结论。
        is_truncated = bool(truncated)
        
        protocol_warning = self.CONTENT_OUTSIDE_WARNING if outside_text else None

        final_blocks = [block for block in blocks if block["name"] == "STOP"]
        final_pos = final_blocks[0]["start"] if final_blocks else -1
        has_final = bool(final_blocks)
        action_blocks = [block for block in blocks if block["name"] in self.ACTION_BLOCK_NAMES]
        reply_blocks = [block for block in blocks if block["name"] == "REPLY"]
        todo_blocks = [block for block in blocks if block["name"] == "TODO"]

        # TODO 重复：取最后一个，静默丢弃其余（通常是模型截断后重新输出）
        if len(todo_blocks) > 1:
            todo_blocks = [todo_blocks[-1]]

        if len(action_blocks) > 1:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("multiple_action_blocks", "同一轮回复中只能包含一个 ACTION 块"),
                truncated=is_truncated,
            )

        if action_blocks and has_final:
            return ParsedResponse(
                response_type="protocol_error",
                raw_response=response,
                protocol_error=ProtocolError("action_with_final", "ACTION 回复中禁止出现 @SPORE:STOP"),
                truncated=is_truncated,
            )

        reply_contents = [block["content"] for block in reply_blocks if block["content"]]
        # 协议块外非空文本按 REPLY 展示（不阻断 ACTION）
        if outside_text:
            reply_contents = [outside_text] + reply_contents
        reply_content = "\n\n".join(reply_contents) if reply_contents else None

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
                    truncated=is_truncated,
                )

            return ParsedResponse(
                response_type="action",
                prefix_text=reply_content,
                reply_content=reply_content,
                action=parsed_block.first_action,
                action_block=parsed_block,
                raw_response=response,
                protocol_warning=protocol_warning,
                truncated=is_truncated,
            )

        if has_final:
            # STOP 无内容，只看 REPLY
            display_content = reply_content
            return ParsedResponse(
                response_type="final",
                prefix_text=display_content,
                reply_content=display_content,
                raw_response=response,
                protocol_warning=protocol_warning,
                truncated=is_truncated,
            )

        return ParsedResponse(
            response_type="continue",
            prefix_text=reply_content,
            reply_content=reply_content,
            raw_response=response,
            protocol_warning=protocol_warning,
            truncated=is_truncated,
        )

    def _action_name_to_mode(self, name: str) -> ActionMode:
        if name == "ACTION_SEQUENCE":
            return "sequence"
        if name == "ACTION_PARALLEL":
            return "parallel"
        return "single"

    def _invalid_action_message(self, mode: ActionMode) -> str:
        if mode == "sequence":
            return (
                "ACTION_SEQUENCE 工具调用格式错误：编号后必须先写工具名，参数之间用空格分隔；"
                "不能把 `type=read` 这类参数当作工具名。"
                "例如 `1. file type=read ...`"
            )
        if mode == "parallel":
            return (
                "ACTION_PARALLEL 工具调用格式错误：每个子操作必须写成 "
                "`task_id=<唯一ID> tool=<工具名> <参数>`，`task_id`、`tool` 和参数之间必须有空格；"
                "不能把 `type=read` 这类参数当作工具名。"
                "例如 `task_id=readme tool=file type=read ...`"
            )
        return (
            "ACTION_SINGLE 工具调用格式错误：必须先写工具名，再用空格分隔参数；"
            "不能直接以 `type=read` 这类参数开头。"
            "例如 `file type=read file_path=\"C:/test.txt\"`"
        )

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

    def format_truncated(
        self,
        attempt: int = 1,
        api_stop_reason: Optional[str] = None,
        max_output_tokens: Optional[int] = None,
        message: Optional[str] = None,
    ) -> str:
        """回复被输出上限截断时给 LLM 的反馈（不是协议错误）。"""
        return self.result_formatter.format_truncated(
            message or self.TRUNCATED_OUTPUT_MESSAGE,
            attempt=attempt,
            api_stop_reason=api_stop_reason,
            max_output_tokens=max_output_tokens,
        )

    def format_empty_response(self, attempt: int = 1) -> str:
        """模型没有返回任何正文时给 LLM 的反馈。"""
        return self.result_formatter.format_empty_response(attempt=attempt)


    def append_protocol_warning(self, result_text: str, warning: Optional[str] = None) -> str:
        """Append a soft protocol warning to a RESULT payload returned to the LLM."""
        if not warning:
            return result_text
        return f"{result_text}\n\n[协议警告] {warning}"

    def format_protocol_error(self, error: ProtocolError) -> str:
        return self.result_formatter.format_protocol_error(error.code, error.message)

    def parse_todo_from_response(self, response: str) -> Optional[List[Dict[str, str]]]:
        # 多个 TODO 块：取最后一个（与 parse_response 中的兜底策略一致）
        start_marker, end_marker = self.BLOCK_MARKERS["TODO"]
        last_start = response.rfind(start_marker)
        if last_start < 0:
            return None
        content_after = response[last_start + len(start_marker):]
        end_in_tail = self._find_standalone_marker(content_after, end_marker)
        if end_in_tail < 0:
            return None
        todo_content = content_after[:end_in_tail].strip() or None
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
        if status_str in {"completed", "done", "完成", "已完成", "v", "x",
                          "terminé", "termine", "fini", "fertig", "完了"}:
            return "completed"
        if status_str in {"failed", "fail", "失败", "已失败", "échec", "echeс"}:
            return "failed"
        return "pending"
