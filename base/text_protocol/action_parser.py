"""
ACTION block parser for the Spore text protocol.

The protocol keeps a human-readable DSL for tool calls while wrapping action
blocks with explicit START/END markers:

    @SPORE:ACTION_SINGLE_START
    file type=read file_path="C:/test.txt"
    @SPORE:ACTION_SINGLE_END
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


ActionMode = Literal["single", "sequence", "parallel"]


@dataclass
class ParsedAction:
    """One parsed tool call."""

    tool_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    mode: ActionMode = "single"
    step_index: Optional[int] = None
    task_id: Optional[str] = None


@dataclass
class ParsedActionBlock:
    """A parsed ACTION_* block."""

    mode: ActionMode
    actions: List[ParsedAction] = field(default_factory=list)
    raw_text: str = ""

    @property
    def first_action(self) -> Optional[ParsedAction]:
        return self.actions[0] if self.actions else None


class ActionParser:
    """Parser for Spore ACTION blocks and tool-call parameter DSL."""

    ACTION_SINGLE_START = "@SPORE:ACTION_SINGLE_START"
    ACTION_SINGLE_END = "@SPORE:ACTION_SINGLE_END"
    ACTION_SEQUENCE_START = "@SPORE:ACTION_SEQUENCE_START"
    ACTION_SEQUENCE_END = "@SPORE:ACTION_SEQUENCE_END"
    ACTION_PARALLEL_START = "@SPORE:ACTION_PARALLEL_START"
    ACTION_PARALLEL_END = "@SPORE:ACTION_PARALLEL_END"
    REPLY_START = "@SPORE:REPLY_START"
    REPLY_END = "@SPORE:REPLY_END"
    TODO_START = "@SPORE:TODO_START"
    TODO_END = "@SPORE:TODO_END"
    FINAL_MARKER = "@SPORE:FINAL@"

    ACTION_BLOCKS: Dict[str, tuple[str, ActionMode]] = {
        ACTION_SINGLE_START: (ACTION_SINGLE_END, "single"),
        ACTION_SEQUENCE_START: (ACTION_SEQUENCE_END, "sequence"),
        ACTION_PARALLEL_START: (ACTION_PARALLEL_END, "parallel"),
    }

    def parse(self, text: str) -> Optional[ParsedAction]:
        """Compatibility helper returning the first action in a block."""
        block = self.parse_block(text)
        return block.first_action if block else None

    def parse_block(
        self,
        text: str,
        mode: Optional[ActionMode] = None,
        content: Optional[str] = None,
        raw_text: Optional[str] = None,
    ) -> Optional[ParsedActionBlock]:
        """Parse an ACTION_SINGLE/SEQUENCE/PARALLEL block."""
        if content is None:
            found = self._extract_action_block(text)
            if not found:
                return None
            mode, content, raw_text = found

        if mode == "single":
            action = self._parse_action_content(content.strip(), raw_text or content, mode="single")
            if not action:
                return None
            return ParsedActionBlock(mode="single", actions=[action], raw_text=raw_text or content)

        if mode == "sequence":
            actions = self._parse_sequence_actions(content)
            return ParsedActionBlock(mode="sequence", actions=actions, raw_text=raw_text or content) if actions else None

        if mode == "parallel":
            actions = self._parse_parallel_actions(content)
            return ParsedActionBlock(mode="parallel", actions=actions, raw_text=raw_text or content) if actions else None

        return None

    def _extract_action_block(self, text: str) -> Optional[tuple[ActionMode, str, str]]:
        if not text:
            return None

        for start_marker, (end_marker, mode) in self.ACTION_BLOCKS.items():
            start = text.find(start_marker)
            if start < 0:
                continue
            content_start = start + len(start_marker)
            end = text.find(end_marker, content_start)
            if end < 0:
                return None
            raw_end = end + len(end_marker)
            return mode, text[content_start:end].strip(), text[start:raw_end]

        return None

    def _parse_sequence_actions(self, content: str) -> List[ParsedAction]:
        items = self._split_sequence_items(content)
        if not items:
            return []

        indexes = [step_index for step_index, _ in items]
        if any(step_index is None for step_index in indexes):
            return []
        if len(set(indexes)) != len(indexes):
            return []
        if indexes != sorted(indexes):
            return []

        actions: List[ParsedAction] = []
        for step_index, action_text in items:
            action = self._parse_action_content(action_text.strip(), action_text.strip(), mode="sequence")
            if not action:
                return []
            action.step_index = step_index
            actions.append(action)
        return actions

    def _split_sequence_items(self, content: str) -> List[tuple[Optional[int], str]]:
        lines = content.splitlines()
        items: List[tuple[Optional[int], List[str]]] = []
        current_index: Optional[int] = None
        current_lines: List[str] = []
        in_content = False

        for line in lines:
            stripped = line.strip()
            match = None if in_content else re.match(r"^\s*(\d+)\.\s+(.*)$", line)
            if match:
                if current_lines:
                    items.append((current_index, current_lines))
                current_index = int(match.group(1))
                current_lines = [match.group(2)]
            elif current_lines:
                current_lines.append(line)
            elif stripped:
                return []

            if "@SPORE:CONTENT_START" in line and "@SPORE:CONTENT_END" not in line:
                in_content = True
            if "@SPORE:CONTENT_END" in line:
                in_content = False

        if current_lines:
            items.append((current_index, current_lines))

        return [(idx, "\n".join(item_lines).strip()) for idx, item_lines in items if "\n".join(item_lines).strip()]

    def _parse_parallel_actions(self, content: str) -> List[ParsedAction]:
        items = self._split_parallel_items(content)
        if not items:
            return []
        task_ids = [task_id for task_id, _ in items]
        if any(not task_id for task_id in task_ids):
            return []
        if len(set(task_ids)) != len(task_ids):
            return []

        actions: List[ParsedAction] = []

        for task_id, action_text in items:
            parser_text = action_text.strip()
            first_line = parser_text.splitlines()[0].strip() if parser_text else ""
            if first_line.startswith("tool="):
                parser_text = first_line[len("tool="):] + parser_text[len(first_line):]

            action = self._parse_action_content(parser_text, parser_text, mode="parallel")
            if not action:
                return []
            action.task_id = task_id
            actions.append(action)

        return actions

    def _split_parallel_items(self, content: str) -> List[tuple[str, str]]:
        lines = content.splitlines()
        items: List[tuple[str, str]] = []
        current_task_id: Optional[str] = None
        current_lines: List[str] = []
        in_content = False

        for line in lines:
            stripped = line.strip()
            if not in_content and stripped.startswith("task_id="):
                if current_task_id and current_lines:
                    items.append((current_task_id, "\n".join(current_lines).strip()))
                task_id, remainder = self._extract_task_id_and_remainder(stripped)
                current_task_id = task_id
                current_lines = [remainder] if remainder else []
            elif current_task_id:
                current_lines.append(line)
            elif stripped:
                return []

            if "@SPORE:CONTENT_START" in line and "@SPORE:CONTENT_END" not in line:
                in_content = True
            if "@SPORE:CONTENT_END" in line:
                in_content = False

        if current_task_id and current_lines:
            items.append((current_task_id, "\n".join(current_lines).strip()))

        return items

    def _extract_task_id_and_remainder(self, line: str) -> tuple[str, str]:
        match = re.match(r"""task_id=(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+(.*))?$""", line)
        if not match:
            return "", line
        task_id = match.group(1) or match.group(2) or match.group(3) or ""
        remainder = match.group(4) or ""
        if remainder.startswith("tool="):
            remainder = remainder[len("tool="):]
        return task_id, remainder

    def _parse_action_content(
        self,
        content: str,
        raw_text: str,
        mode: ActionMode = "single",
    ) -> Optional[ParsedAction]:
        if not content:
            return None

        lines = content.strip().split("\n")
        first_line = lines[0].strip() if lines else ""
        if not first_line:
            return None

        parts = first_line.split(None, 1)
        tool_name = parts[0]
        param_text = parts[1] if len(parts) > 1 else ""

        if len(lines) > 1:
            remaining_lines = "\n".join(lines[1:])
            param_text = f"{param_text}\n{remaining_lines}" if param_text else remaining_lines

        parameters = self.parse_parameters(param_text, tool_name)
        return ParsedAction(
            tool_name=tool_name,
            parameters=parameters,
            raw_text=raw_text,
            mode=mode,
        )

    def parse_parameters(self, param_text: str, tool_name: str = "") -> Dict[str, Any]:
        """Parse key=value parameters, quoted values, JSON values, and CONTENT blocks."""
        if not param_text or not param_text.strip():
            return {}

        parameters: Dict[str, Any] = {}
        text = param_text.strip()

        i = 0
        while i < len(text):
            while i < len(text) and text[i] in " \t\n":
                i += 1

            if i >= len(text):
                break

            key_start = i
            while i < len(text) and text[i] not in "= \t\n":
                i += 1

            if i >= len(text) or text[i] != "=":
                while i < len(text) and text[i] not in " \t\n":
                    i += 1
                continue

            key = text[key_start:i]
            i += 1

            if i >= len(text):
                parameters[key] = ""
                break

            value, new_i = self._parse_value(text, i, tool_name)
            parameters[key] = value
            i = new_i

        return parameters

    def _parse_value(self, text: str, start: int, tool_name: str = "") -> tuple[Any, int]:
        if start >= len(text):
            return "", start

        while start < len(text) and text[start] in " \t":
            start += 1

        if start >= len(text):
            return "", start

        char = text[start]

        content_start_marker = "@SPORE:CONTENT_START"
        content_end_marker = "@SPORE:CONTENT_END"
        content_start_len = len(content_start_marker)
        content_end_len = len(content_end_marker)

        if text.startswith(content_start_marker, start):
            content_start_end = start + content_start_len
            if text.startswith(content_end_marker, content_start_end):
                return "", content_start_end + content_end_len
            return self._parse_multiline_value(text, start)

        if char == '"':
            return self._parse_quoted_value(text, start, '"', tool_name)

        if char == "'":
            return self._parse_quoted_value(text, start, "'", tool_name)

        if char in "{[":
            return self._parse_json_value(text, start)

        json_literal_result = self._try_parse_json_literal(text, start)
        if json_literal_result is not None:
            return json_literal_result

        return self._parse_simple_value(text, start)

    def _parse_multiline_value(self, text: str, start: int) -> tuple[str, int]:
        start_marker = "@SPORE:CONTENT_START"
        end_marker_text = "@SPORE:CONTENT_END"

        i = start + len(start_marker)
        while i < len(text) and text[i] in " \t\n":
            i += 1

        content_start = i
        end_marker = text.find(end_marker_text, i)

        if end_marker == -1:
            return text[content_start:].rstrip(), len(text)

        content = text[content_start:end_marker].rstrip("\n \t")
        return content, end_marker + len(end_marker_text)

    def _parse_quoted_value(self, text: str, start: int, quote: str, tool_name: str = "") -> tuple[str, int]:
        i = start + 1
        value_chars: List[str] = []

        while i < len(text):
            char = text[i]
            if char == "\\" and i + 1 < len(text):
                next_char = text[i + 1]
                if next_char == quote:
                    value_chars.append(quote)
                    i += 2
                else:
                    value_chars.append(char)
                    i += 1
            elif char == quote:
                return "".join(value_chars), i + 1
            else:
                value_chars.append(char)
                i += 1

        return "".join(value_chars), i

    def _parse_json_value(self, text: str, start: int) -> tuple[Any, int]:
        open_char = text[start]
        close_char = "}" if open_char == "{" else "]"

        depth = 0
        i = start
        in_string = False
        escape_next = False

        while i < len(text):
            char = text[i]

            if escape_next:
                escape_next = False
                i += 1
                continue

            if char == "\\":
                escape_next = True
                i += 1
                continue

            if char == '"':
                in_string = not in_string
            elif not in_string:
                if char == open_char:
                    depth += 1
                elif char == close_char:
                    depth -= 1
                    if depth == 0:
                        json_str = text[start:i + 1]
                        try:
                            return json.loads(json_str), i + 1
                        except json.JSONDecodeError:
                            return json_str, i + 1

            i += 1

        return text[start:], len(text)

    def _try_parse_json_literal(self, text: str, start: int) -> Optional[tuple[Any, int]]:
        i = start
        while i < len(text) and text[i] not in " \t\n":
            i += 1

        token = text[start:i]

        if token in ("true", "false", "null"):
            try:
                return json.loads(token), i
            except json.JSONDecodeError:
                return None

        if token and (token[0].isdigit() or (token[0] == "-" and len(token) > 1 and token[1].isdigit())):
            try:
                if "." in token or "e" in token.lower():
                    return float(token), i
                return int(token), i
            except ValueError:
                return None

        return None

    def _parse_simple_value(self, text: str, start: int) -> tuple[str, int]:
        i = start

        while i < len(text):
            char = text[i]
            if char == "\n":
                break

            if char in " \t":
                j = i + 1
                while j < len(text) and text[j] in " \t":
                    j += 1

                if j < len(text) and text[j] != "\n":
                    k = j
                    while k < len(text) and text[k] not in "= \t\n":
                        k += 1
                    if k < len(text) and text[k] == "=":
                        break

            i += 1

        return text[start:i].strip(), i

    def to_string(self, action: ParsedAction) -> str:
        parts = [action.tool_name]

        for key, value in action.parameters.items():
            formatted_value = self._format_value(value)
            parts.append(f"{key}={formatted_value}")

        content = " ".join(parts)
        if action.mode == "sequence" and action.step_index is not None:
            return f"{action.step_index}. {content}"
        if action.mode == "parallel" and action.task_id:
            return f"task_id={action.task_id} tool={content}"
        return f"{self.ACTION_SINGLE_START}\n{content}\n{self.ACTION_SINGLE_END}"

    def _format_value(self, value: Any) -> str:
        if value is None:
            return '""'

        if isinstance(value, bool):
            return json.dumps(value)

        if isinstance(value, (int, float)):
            return json.dumps(value)

        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)

        value_str = str(value)

        if "\n" in value_str:
            return f"@SPORE:CONTENT_START\n{value_str}\n@SPORE:CONTENT_END"

        if value_str and (value_str[0].isdigit() or value_str[0] == "-"):
            escaped = value_str.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'

        if value_str.lower() in ("true", "false", "null"):
            escaped = value_str.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'

        if " " in value_str or "\t" in value_str or '"' in value_str or "=" in value_str:
            escaped = value_str.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'

        return value_str
