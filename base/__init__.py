"""Base package for OpenAI chat utilities."""

from .tools import TOOL_DEFINITIONS
from .ipc_manager import initialize_ipc_system, IPCManager

__all__ = [
    "TOOL_DEFINITIONS", 
    "initialize_ipc_system",
    "IPCManager",
]
