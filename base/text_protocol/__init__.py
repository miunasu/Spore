"""
文本协议模块

提供 Agent 与 LLM 之间基于文本的交互协议支持。

主要组件：
- ProtocolManager: 协议管理器，负责协议注入、响应解析、结果格式化
- ActionParser: ACTION 块解析器
- ResultFormatter: RESULT 块格式化器
- ToolDocGenerator: 工具文档生成器
"""

from .protocol_manager import (
    ProtocolManager, 
    ParsedResponse,
    find_standalone_marker,
    is_standalone_marker,
    find_stop_reason_marker,
    has_stop_reason_marker,
    is_stop_reason_line,
    extract_stop_reason_blocks,
)
from .action_parser import ActionParser, ParsedAction, ParsedActionBlock
from .result_formatter import ResultFormatter
from .tool_doc_generator import ToolDocGenerator

__all__ = [
    'ProtocolManager',
    'ParsedResponse',
    'ActionParser',
    'ParsedAction',
    'ParsedActionBlock',
    'ResultFormatter',
    'ToolDocGenerator',
    'find_standalone_marker',
    'is_standalone_marker',
    'find_stop_reason_marker',
    'has_stop_reason_marker',
    'is_stop_reason_line',
    'extract_stop_reason_blocks',
]
