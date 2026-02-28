"""
ACTION 块解析器

解析 LLM 输出中的 ACTION 块，提取工具名称和参数。
支持多种参数格式：简单值、引号字符串、多行内容(@SPORE:CONTENT...@SPORE:CONTENT_END)、JSON。
"""
import re
import json
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class ParsedAction:
    """解析后的 ACTION 数据"""
    tool_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""  # 原始 ACTION 块文本


class ActionParser:
    """ACTION 块解析器"""
    
    ACTION_MARKER = "@SPORE:ACTION"
    RESULT_MARKER = "@SPORE:RESULT"
    REPLY_MARKER = "@SPORE:REPLY"
    FINAL_MARKER = "@SPORE:FINAL@"
    
    def parse(self, text: str) -> Optional[ParsedAction]:
        """
        解析文本中的第一个 ACTION 块
        
        Args:
            text: 包含 ACTION 块的文本
            
        Returns:
            ParsedAction 对象，如果没有找到 ACTION 块则返回 None
        """
        if not text or self.ACTION_MARKER not in text:
            return None
        
        # 找到第一个 ACTION 标记的位置
        action_start = text.find(self.ACTION_MARKER)
        if action_start == -1:
            return None
        
        # 提取 ACTION 块内容（从标记后到下一个标记或文本结束）
        content_start = action_start + len(self.ACTION_MARKER)
        
        # 找到 ACTION 块的结束位置（下一个 ### 标记、FINAL_RESPONSE 或文本结束）
        remaining = text[content_start:]
        
        # 查找可能的结束标记（只在行首检测，避免参数值中的内容被误判）
        # 协议标记应该独占一行或在行首
        def find_line_start_marker(text: str, marker: str) -> int:
            """查找在行首的标记位置"""
            # 检查是否在开头
            if text.startswith(marker):
                return 0
            # 检查换行后的位置
            search_str = "\n" + marker
            pos = text.find(search_str)
            if pos >= 0:
                return pos + 1  # 返回标记的实际位置（跳过换行符）
            return -1
        
        end_markers = [
            find_line_start_marker(remaining, self.ACTION_MARKER),
            find_line_start_marker(remaining, self.RESULT_MARKER),
            find_line_start_marker(remaining, self.REPLY_MARKER),
            find_line_start_marker(remaining, self.FINAL_MARKER),
        ]
        
        # 过滤掉 -1（未找到）并找最小值
        valid_ends = [pos for pos in end_markers if pos > 0]
        if valid_ends:
            content_end = min(valid_ends)
            action_content = remaining[:content_end].strip()
        else:
            action_content = remaining.strip()
        
        # 保存原始文本
        raw_text = self.ACTION_MARKER + "\n" + action_content
        
        # 解析工具名称和参数
        return self._parse_action_content(action_content, raw_text)
    
    def _parse_action_content(self, content: str, raw_text: str) -> Optional[ParsedAction]:
        """
        解析 ACTION 块的内容
        
        Args:
            content: ACTION 块内容（不含 @SPORE:ACTION 标记）
            raw_text: 原始 ACTION 块文本
            
        Returns:
            ParsedAction 对象
        """
        if not content:
            return None
        
        lines = content.strip().split('\n')
        if not lines:
            return None
        
        # 第一行应该包含工具名称（可能还有参数）
        first_line = lines[0].strip()
        if not first_line:
            return None
        
        # 解析第一行：TOOL_NAME param1=value1 param2=value2
        parts = first_line.split(None, 1)  # 最多分割一次
        tool_name = parts[0]
        
        # 收集所有参数文本
        if len(parts) > 1:
            param_text = parts[1]
        else:
            param_text = ""
        
        # 如果有多行，将剩余行也加入参数文本
        if len(lines) > 1:
            remaining_lines = '\n'.join(lines[1:])
            if param_text:
                param_text = param_text + '\n' + remaining_lines
            else:
                param_text = remaining_lines
        
        # 解析参数（传入工具名称用于特殊处理）
        parameters = self.parse_parameters(param_text, tool_name)
        
        return ParsedAction(
            tool_name=tool_name,
            parameters=parameters,
            raw_text=raw_text
        )
    
    def parse_parameters(self, param_text: str, tool_name: str = "") -> Dict[str, Any]:
        """
        解析参数文本，支持多种格式
        
        支持的格式：
        1. 简单值：key=value
        2. 引号字符串：key="value with spaces"
        3. 多行内容：key=```\nmulti\nline\n```
        4. JSON 对象：key={"nested": "value"}
        
        Args:
            param_text: 参数文本
            tool_name: 工具名称（用于特殊处理）
            
        Returns:
            参数字典
        """
        if not param_text or not param_text.strip():
            return {}
        
        parameters = {}
        text = param_text.strip()
        
        # 使用状态机解析参数
        i = 0
        while i < len(text):
            # 跳过空白
            while i < len(text) and text[i] in ' \t\n':
                i += 1
            
            if i >= len(text):
                break
            
            # 解析参数名
            key_start = i
            while i < len(text) and text[i] not in '= \t\n':
                i += 1
            
            if i >= len(text) or text[i] != '=':
                # 没有找到 =，跳过这个 token
                while i < len(text) and text[i] not in ' \t\n':
                    i += 1
                continue
            
            key = text[key_start:i]
            i += 1  # 跳过 =
            
            if i >= len(text):
                parameters[key] = ""
                break
            
            # 解析参数值（传入工具名称用于特殊处理）
            value, new_i = self._parse_value(text, i, tool_name)
            parameters[key] = value
            i = new_i
        
        return parameters
    
    def _parse_value(self, text: str, start: int, tool_name: str = "") -> tuple:
        """
        从指定位置解析参数值
        
        Args:
            text: 完整文本
            start: 开始位置
            tool_name: 工具名称（用于特殊处理）
            
        Returns:
            (value, end_position) 元组
        """
        if start >= len(text):
            return "", start
        
        # 跳过开头的空白（但不跳过换行，因为换行可能是值的一部分）
        while start < len(text) and text[start] in ' \t':
            start += 1
        
        if start >= len(text):
            return "", start
        
        char = text[start]
        
        # 1. 多行内容 @SPORE:CONTENT...@SPORE:CONTENT_END
        # 检查是否以 @SPORE:CONTENT 开头
        if text[start:start+14] == '@SPORE:CONTENT':
            # 检查后面是否是 @SPORE:CONTENT_END（紧跟的情况）
            if start + 14 < len(text) and text[start+14:start+32] == '@SPORE:CONTENT_END':
                # 空内容的情况：@SPORE:CONTENT@SPORE:CONTENT_END
                return "", start + 32
            # 正常情况：后面应该是换行符、空格或其他内容
            return self._parse_multiline_value(text, start)
        
        # 2. 双引号字符串
        if char == '"':
            return self._parse_quoted_value(text, start, '"', tool_name)
        
        # 3. 单引号字符串
        if char == "'":
            return self._parse_quoted_value(text, start, "'", tool_name)
        
        # 4. JSON 对象或数组
        if char == '{' or char == '[':
            return self._parse_json_value(text, start)
        
        # 5. 检查是否是 JSON 字面量（true, false, null, 数字）
        json_literal_result = self._try_parse_json_literal(text, start)
        if json_literal_result is not None:
            return json_literal_result
        
        # 6. 简单值（到下一个空白或参数）
        return self._parse_simple_value(text, start)
    
    def _parse_multiline_value(self, text: str, start: int) -> tuple:
        """解析 @SPORE:CONTENT...@SPORE:CONTENT_END 格式的多行内容"""
        # 跳过开头的 @SPORE:CONTENT (14个字符)
        i = start + 14
        
        # 跳过可能的空格和换行
        while i < len(text) and text[i] in ' \t\n':
            i += 1
        
        content_start = i
        
        # 查找第一个（而不是最后一个）@SPORE:CONTENT_END
        end_marker = text.find('@SPORE:CONTENT_END', i)
        
        if end_marker == -1:
            # 没有找到结束标记，取到文本结束
            return text[content_start:].rstrip(), len(text)
        
        # 提取内容（去除末尾的换行符和空格）
        content = text[content_start:end_marker].rstrip('\n \t')
        return content, end_marker + 18
    
    def _parse_quoted_value(self, text: str, start: int, quote: str, tool_name: str = "") -> tuple:
        """
        解析引号字符串
        
        Args:
            text: 完整文本
            start: 开始位置
            quote: 引号类型（单引号或双引号）
            tool_name: 工具名称（保留参数以保持接口兼容，但不再使用）
        
        Returns:
            (value, end_position) 元组
        """
        i = start + 1  # 跳过开头引号
        value_chars = []
        
        while i < len(text):
            char = text[i]
            
            if char == '\\' and i + 1 < len(text):
                # 转义字符处理
                # 只处理引号转义，避免路径中的 \t、\n、\\ 等被误解析
                # - \" -> "
                # - \' -> '
                # 其他所有情况（包括 \\、\t、\n 等）都保留原样
                next_char = text[i + 1]
                if next_char == quote:
                    # 转义的引号：\" 或 \'
                    value_chars.append(quote)
                    i += 2
                else:
                    # 其他情况：保留反斜杠，继续处理下一个字符
                    # 这样 \\、\t、\n、\r、\S、\P、\A 等都会被保留为原始字符串
                    value_chars.append(char)
                    i += 1
            elif char == quote:
                # 结束引号
                return ''.join(value_chars), i + 1
            else:
                value_chars.append(char)
                i += 1
        
        # 没有找到结束引号
        return ''.join(value_chars), i
    
    def _parse_json_value(self, text: str, start: int) -> tuple:
        """解析 JSON 对象或数组"""
        # 找到匹配的括号
        open_char = text[start]
        close_char = '}' if open_char == '{' else ']'
        
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
            
            if char == '\\':
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
                        json_str = text[start:i+1]
                        try:
                            value = json.loads(json_str)
                            return value, i + 1
                        except json.JSONDecodeError:
                            # JSON 解析失败，作为普通字符串返回
                            return json_str, i + 1
            
            i += 1
        
        # 没有找到匹配的括号
        return text[start:], len(text)
    
    def _try_parse_json_literal(self, text: str, start: int) -> Optional[tuple]:
        """
        尝试解析 JSON 字面量（true, false, null, 数字）
        
        Returns:
            (value, end_position) 元组，如果不是 JSON 字面量则返回 None
        """
        # 找到值的结束位置（只考虑 ASCII 空白）
        i = start
        while i < len(text) and text[i] not in ' \t\n':
            i += 1
        
        token = text[start:i]
        
        # 只处理明确的 JSON 字面量
        # true, false, null
        if token in ('true', 'false', 'null'):
            try:
                value = json.loads(token)
                return value, i
            except json.JSONDecodeError:
                return None
        
        # 数字：必须是纯数字格式（可选负号，可选小数点）
        # 不处理 Infinity, NaN 等特殊值
        if token and (token[0].isdigit() or (token[0] == '-' and len(token) > 1 and token[1].isdigit())):
            # 检查是否是有效的数字格式
            try:
                # 尝试解析为 int 或 float
                if '.' in token or 'e' in token.lower():
                    value = float(token)
                else:
                    value = int(token)
                return value, i
            except ValueError:
                return None
        
        return None
    
    def _parse_simple_value(self, text: str, start: int) -> tuple:
        """解析简单值（到下一个空白或参数）"""
        i = start
        
        while i < len(text):
            char = text[i]
            
            # 遇到换行符，结束当前值
            if char == '\n':
                break
            
            # 遇到空格或制表符，检查是否是新参数
            if char in ' \t':
                # 检查后面是否是新参数
                j = i + 1
                while j < len(text) and text[j] in ' \t':
                    j += 1
                
                if j < len(text) and text[j] != '\n':
                    # 查找 = 号
                    k = j
                    while k < len(text) and text[k] not in '= \t\n':
                        k += 1
                    if k < len(text) and text[k] == '=':
                        # 是新参数，结束当前值
                        break
            
            i += 1
        
        value = text[start:i].strip()
        
        # 简单值保持为字符串，不自动转换类型
        # 这样可以保持 round-trip 一致性
        # 类型转换只在 JSON 上下文中进行
        return value, i
    
    def to_string(self, action: ParsedAction) -> str:
        """
        将 ParsedAction 转换回 ACTION 块字符串
        
        Args:
            action: ParsedAction 对象
            
        Returns:
            ACTION 块字符串
        """
        parts = [self.ACTION_MARKER, action.tool_name]
        
        for key, value in action.parameters.items():
            formatted_value = self._format_value(value)
            parts.append(f"{key}={formatted_value}")
        
        # 工具名和参数在同一行
        if len(parts) > 2:
            return parts[0] + "\n" + parts[1] + " " + " ".join(parts[2:])
        else:
            return parts[0] + "\n" + parts[1]
    
    def _format_value(self, value: Any) -> str:
        """格式化参数值为字符串"""
        if value is None:
            return '""'
        
        if isinstance(value, bool):
            # 布尔值使用 JSON 格式，这样解析时会正确识别
            return json.dumps(value)
        
        if isinstance(value, (int, float)):
            # 数字使用 JSON 格式
            return json.dumps(value)
        
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        
        # 字符串处理
        value_str = str(value)
        
        # 多行内容使用 @SPORE:CONTENT...@SPORE:CONTENT_END 格式
        if '\n' in value_str:
            return f"@SPORE:CONTENT\n{value_str}\n@SPORE:CONTENT_END"
        
        # 检查字符串是否会被误解析为 JSON 字面量或数字
        # 如果字符串以数字或负号开头，需要用引号包裹
        if value_str and (value_str[0].isdigit() or value_str[0] == '-'):
            escaped = value_str.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        
        # 检查是否是 JSON 字面量关键字
        if value_str.lower() in ('true', 'false', 'null'):
            escaped = value_str.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        
        # 包含空格或特殊字符使用双引号
        if ' ' in value_str or '\t' in value_str or '"' in value_str or '=' in value_str:
            escaped = value_str.replace('\\', '\\\\').replace('"', '\\"')
            return f'"{escaped}"'
        
        # 简单值直接返回
        return value_str
