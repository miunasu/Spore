"""
文本协议管理器

管理 Agent 与 LLM 之间的文本协议交互，包括：
- 协议说明注入
- 响应解析
- 结果格式化
"""
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Literal

from .action_parser import ActionParser, ParsedAction
from .result_formatter import ResultFormatter
from .tool_doc_generator import ToolDocGenerator


def find_standalone_marker(text: str, marker: str) -> int:
    """
    查找独占一行的协议标记位置
    
    标记必须满足：在行首，且后面是换行符或文本结束
    
    Args:
        text: 文本内容
        marker: 要查找的标记
        
    Returns:
        标记位置，如果没找到返回 -1
    """
    pos = 0
    while pos < len(text):
        found = text.find(marker, pos)
        if found == -1:
            return -1
        # 检查是否在行首
        if found > 0 and text[found - 1] != '\n':
            pos = found + len(marker)
            continue
        # 检查后面是否是换行符或文本结束
        end_pos = found + len(marker)
        if end_pos >= len(text) or text[end_pos] == '\n':
            return found
        pos = end_pos
    return -1


def is_standalone_marker(text: str, marker: str) -> bool:
    """
    检查文本中是否包含独占一行的标记
    
    Args:
        text: 文本内容
        marker: 要查找的标记
        
    Returns:
        True 如果找到独占一行的标记，否则 False
    """
    return find_standalone_marker(text, marker) >= 0


@dataclass
class ParsedResponse:
    """解析后的 LLM 响应"""
    
    # 响应类型: action=有工具调用, final=任务完成, continue=需要继续
    response_type: Literal["action", "final", "continue"]
    
    # ACTION 块之前的文本内容（用于显示给用户）
    prefix_text: Optional[str] = None
    
    # REPLY 块内容（用于显示给用户）
    reply_content: Optional[str] = None
    
    # 解析后的 ACTION（如果有）
    action: Optional[ParsedAction] = None
    
    # FINAL_RESPONSE 之后的内容（如果有）
    final_content: Optional[str] = None
    
    # 原始响应文本
    raw_response: str = ""


# 协议说明模板
PROTOCOL_TEMPLATE = """
---

## [IMPORTANT] 回复协议（最高优先级）

任务完成后，必须在回复末尾单独一行输出: @SPORE:FINAL@

示例1 - 简单任务:

    @SPORE:REPLY
    你好，有什么可以帮你的？

    @SPORE:FINAL@

示例2 - 调用工具:

    @SPORE:REPLY
    我来读取文件内容。

    @SPORE:ACTION
    Read file_path="C:/test.txt"

示例3 - 工具任务完成后:

    @SPORE:REPLY
    文件已修改完成，验证通过。

    @SPORE:FINAL@

示例4 - 带 TODO 的回复:

    @SPORE:TODO
    1. [completed] 读取文件
    2. [pending] 修改内容

    @SPORE:REPLY
    我已经读取了文件，接下来会修改内容。


规则:
- 给用户的回复内容必须放在 @SPORE:REPLY 块中
- 完成任务 → 必须输出 @SPORE:FINAL@
- **调用工具 → 必须输出 @SPORE:ACTION，不输出 @SPORE:FINAL@**
- 不输出 @SPORE:FINAL@ = 系统认为任务未完成，会继续循环
- **所有回复内容必须放在 @SPORE:REPLY 块中**，这样用户才能看到你的回复
- 如果不输出回复内容，就不用写@SPORE:REPLY 块
- **每次回复要么输出 @SPORE:ACTION（调用工具），要么输出 @SPORE:FINAL@（任务完成），不能两者都不输出**

## 工具调用格式

当需要使用工具时，按以下格式输出:

@SPORE:ACTION
TOOL_NAME param=value

**重要规则：**
1. **每次回复只能包含一个 ACTION 块，即每次回复只能包含一个工具调用**
2. 输出 ACTION 后等待系统返回工具执行结果
3. 不要自己输出 RESULT
系统会自动执行工具并返回结果，然后你可以根据结果继续回复。


## 参数格式

- 简单值: param=value
- 带空格: param="value with spaces"
- 长文本/多行:

    param=@SPORE:CONTENT
    内容可包含任何字符
    包括换行
    @SPORE:CONTENT_END

- JSON: param={{"key": "value"}}

**如果你的工具集中包含如下特定工具，则必须使用 @SPORE:CONTENT...@SPORE:CONTENT_END 格式的参数：**
- write_text_file 的 content 参数
- report_output 的 content 参数
- Edit 的 old_string 和 new_string 参数
- MultiEdit 的 edits 中的 old_string 和 new_string
- python_exec 的 code 参数（多行代码时）

## 可用工具

{tool_docs}
"""


class ProtocolManager:
    """文本协议管理器"""
    
    TODO_MARKER = "@SPORE:TODO"
    REPLY_MARKER = "@SPORE:REPLY"
    
    def __init__(self):
        """初始化协议管理器"""
        self.action_parser = ActionParser()
        self.result_formatter = ResultFormatter()
        self.tool_doc_generator = ToolDocGenerator()
    
    def generate_protocol_instructions(self, tool_definitions: Dict[str, Dict[str, Any]]) -> str:
        """
        生成协议说明文本，包含工具文档
        
        Args:
            tool_definitions: 工具定义字典
            
        Returns:
            协议说明文本
        """
        # 生成工具文档
        tool_docs = self.tool_doc_generator.generate(tool_definitions)
        
        # 填充模板
        return PROTOCOL_TEMPLATE.format(tool_docs=tool_docs)
    
    def inject_protocol(self, original_prompt: str, tool_definitions: Dict[str, Dict[str, Any]]) -> str:
        """
        将协议说明注入到原始 prompt 中
        
        Args:
            original_prompt: 原始 system prompt
            tool_definitions: 工具定义字典
            
        Returns:
            注入协议后的完整 prompt
        """
        protocol_instructions = self.generate_protocol_instructions(tool_definitions)
        
        # 在原始 prompt 后直接追加协议说明（模板已包含分隔符）
        return original_prompt + protocol_instructions
    
    def _find_standalone_marker(self, response: str, marker: str) -> int:
        """调用模块级函数"""
        return find_standalone_marker(response, marker)
    
    def _extract_reply_content(self, response: str) -> Optional[str]:
        """
        从响应中提取 REPLY 块内容
        
        Args:
            response: LLM 响应文本
            
        Returns:
            REPLY 块内容，如果没有则返回 None
        """
        reply_pos = self._find_standalone_marker(response, self.REPLY_MARKER)
        if reply_pos < 0:
            return None
        
        # 提取 REPLY 块内容
        content_start = reply_pos + len(self.REPLY_MARKER)
        remaining = response[content_start:]
        
        # REPLY 块在下一个独占一行的标记处结束
        end_markers = ["@SPORE:ACTION", "@SPORE:TODO", "@SPORE:RESULT", "@SPORE:FINAL@"]
        min_end_pos = len(remaining)
        for marker in end_markers:
            # 使用 find_standalone_marker 查找独占一行的标记
            pos = find_standalone_marker(remaining, marker)
            if pos >= 0 and pos < min_end_pos:
                min_end_pos = pos
        
        return remaining[:min_end_pos].strip() or None
    
    def parse_response(self, response: str) -> ParsedResponse:
        """
        解析 LLM 响应，提取 ACTION 或 FINAL_RESPONSE
        
        Args:
            response: LLM 响应文本
            
        Returns:
            ParsedResponse 对象
        """
        if not response:
            return ParsedResponse(
                response_type="continue",
                raw_response=""
            )
        
        # 检查是否包含 FINAL_RESPONSE（必须独占一行）
        final_marker = self.action_parser.FINAL_MARKER
        final_pos = self._find_standalone_marker(response, final_marker)
        if final_pos >= 0:
            prefix_text = response[:final_pos].strip() if final_pos > 0 else None
            final_content = response[final_pos + len(final_marker):].strip() or None
            reply_content = self._extract_reply_content(response)
            
            return ParsedResponse(
                response_type="final",
                prefix_text=prefix_text,
                reply_content=reply_content,
                final_content=final_content,
                raw_response=response
            )
        
        # 检查是否包含 ACTION（必须独占一行）
        action_marker = self.action_parser.ACTION_MARKER
        action_pos = self._find_standalone_marker(response, action_marker)
        if action_pos >= 0:
            prefix_text = response[:action_pos].strip() if action_pos > 0 else None
            reply_content = self._extract_reply_content(response)
            
            # 解析 ACTION 块（只传递从 ACTION 标记开始的部分）
            action = self.action_parser.parse(response[action_pos:])
            
            # 只有成功解析出 action 才返回 action 类型
            # 如果 action 为 None（只有标记没有内容），则当作 continue 类型处理
            if action:
                return ParsedResponse(
                    response_type="action",
                    prefix_text=prefix_text,
                    reply_content=reply_content,
                    action=action,
                    raw_response=response
                )
            else:
                # ACTION 标记存在但解析失败，当作 continue 处理
                return ParsedResponse(
                    response_type="continue",
                    prefix_text=prefix_text,
                    reply_content=reply_content,
                    raw_response=response
                )
        
        # 既没有 ACTION 也没有 FINAL_RESPONSE
        reply_content = self._extract_reply_content(response)
        return ParsedResponse(
            response_type="continue",
            prefix_text=response.strip() if response.strip() else None,
            reply_content=reply_content,
            raw_response=response
        )
    
    def format_result(self, result: Any, tool_name: Optional[str] = None) -> str:
        """
        格式化工具执行结果为 RESULT 块
        
        Args:
            result: 工具执行结果
            tool_name: 工具名称（可选）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return self.result_formatter.format(result, tool_name)
    
    def format_error(self, error_message: str, tool_name: Optional[str] = None) -> str:
        """
        格式化错误信息为 RESULT 块
        
        Args:
            error_message: 错误信息
            tool_name: 工具名称（可选）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return self.result_formatter.format_error(error_message, tool_name)
    
    def format_interrupt(self, tool_name: Optional[str] = None) -> str:
        """
        格式化中断信息为 RESULT 块
        
        Args:
            tool_name: 被中断的工具名称（可选）
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return self.result_formatter.format_interrupt(tool_name)
    
    def format_not_found(self, tool_name: str) -> str:
        """
        格式化工具未找到错误为 RESULT 块
        
        Args:
            tool_name: 未找到的工具名称
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return self.result_formatter.format_not_found(tool_name)
    
    def format_parse_error(self, error_message: str) -> str:
        """
        格式化解析错误为 RESULT 块
        
        Args:
            error_message: 解析错误信息
            
        Returns:
            格式化后的 RESULT 块字符串
        """
        return self.result_formatter.format_parse_error(error_message)
    
    def parse_todo_from_response(self, response: str) -> Optional[List[Dict[str, str]]]:
        """
        从 LLM 响应中解析 TODO 块并转换为任务列表
        
        支持 TODO 在 ACTION 之前或之后的位置
        支持两种格式：
        - 状态在前: [status] content
        - 状态在后: content [status] 或 content  [status]
        
        Args:
            response: LLM 响应文本
            
        Returns:
            任务列表，每项包含 content 和 status；如果没有 TODO 块返回 None
        """
        if not response:
            return None
        
        # 找到独占一行的 TODO 标记
        todo_pos = self._find_standalone_marker(response, self.TODO_MARKER)
        if todo_pos < 0:
            return None
        
        todo_content = response[todo_pos + len(self.TODO_MARKER):].strip()
        
        # TODO 块在下一个独占一行的标记处结束
        end_markers = ["@SPORE:ACTION", "@SPORE:FINAL@", "@SPORE:TODO", "@SPORE:RESULT", "@SPORE:REPLY"]
        min_end_pos = len(todo_content)
        for marker in end_markers:
            # 使用 find_standalone_marker 查找独占一行的标记
            pos = find_standalone_marker(todo_content, marker)
            if pos >= 0 and pos < min_end_pos:
                min_end_pos = pos
        
        todo_content = todo_content[:min_end_pos].strip()
        
        if not todo_content:
            return None
        
        # 解析 TODO 内容
        # 支持格式: 
        # - 1. [status] content（状态在前）
        # - 1. content [status]（状态在后）
        # - 1.content  [status]（无空格，状态在后）
        tasks = []
        lines = todo_content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 移除序号前缀 (1. 2. 3. 或 - )
            if line[0].isdigit():
                # 找到第一个非数字非点的位置
                i = 0
                while i < len(line) and (line[i].isdigit() or line[i] == '.'):
                    i += 1
                line = line[i:].strip()
            elif line.startswith('-'):
                line = line[1:].strip()
            
            # 解析状态
            status = "pending"
            content = line
            
            # 先尝试状态在前的格式: [status] content
            if line.startswith('['):
                bracket_end = line.find(']')
                if bracket_end > 0:
                    status_str = line[1:bracket_end].strip().lower()
                    content = line[bracket_end + 1:].strip()
                    status = self._parse_status(status_str)
            else:
                # 尝试状态在后的格式: content [status] 或 content  [status]
                # 查找最后一个 [...] 模式
                import re
                match = re.search(r'\[([^\]]*)\]\s*$', line)
                if match:
                    status_str = match.group(1).strip().lower()
                    content = line[:match.start()].strip()
                    status = self._parse_status(status_str)
            
            if content:
                tasks.append({"content": content, "status": status})
        
        return tasks if tasks else None
    
    def _parse_status(self, status_str: str) -> str:
        """解析状态字符串为标准状态值"""
        # 映射各种状态表示
        if status_str in ['completed', 'done', '完成', '已完成', '√', 'v', 'x√']:
            return "completed"
        elif status_str in ['failed', 'fail', '失败', '已失败', 'x', '×']:
            return "failed"
        else:
            # pending, 空格, 空字符串等都视为 pending
            return "pending"
