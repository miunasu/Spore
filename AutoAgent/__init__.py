"""
AutoAgent 模块 - 包含自动化Agent

自动化Agent通过 IPC 调用 Chat 进程，专注于特定任务

IPC 由 base.ipc_manager.initialize_ipc_system() 统一初始化。

注意：多Agent并发系统已迁移到 base/agent_process.py
"""

from .supervisor import supervisor, end_check
from .mode_selector import select_context_mode, get_mode_description
from .security_agent import security_check, analyze_command_async, analyze_commands_async
from .frontend_agent import expand_html, generate_html

__all__ = [
    "supervisor",
    "end_check",
    "select_context_mode",
    "get_mode_description",
    "security_check",
    "analyze_command_async",
    "analyze_commands_async",
    "generate_html",
    "expand_html",
]
