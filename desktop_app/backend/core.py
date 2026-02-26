"""
桌面模式核心初始化
复用 main.py 的初始化逻辑，但不启动 CLI 循环
"""
from typing import Optional, Dict, Any, Tuple

# 全局实例（桌面模式共享）
_ipc_manager = None
_state = None
_cli_handler = None
_conv_loop = None
_config = None
_initialized = False

# 主 Agent 工具列表（从 agent_types 导入）
from base.agent_types import MAIN_AGENT_TOOLS


def initialize_desktop_backend() -> Dict[str, Any]:
    """
    初始化桌面后端 - 复用 main.py 的初始化逻辑
    
    Returns:
        Dict: 包含所有初始化实例的字典
    """
    global _ipc_manager, _state, _cli_handler, _conv_loop, _config, _initialized
    
    if _initialized:
        return get_instances_dict()
    
    import time
    from base.config import get_config
    from base.ipc_manager import initialize_ipc_system
    from base.state_manager import MultiSessionManager
    from base.cli_commands import CLICommandHandler
    from base.conversation_loop import ConversationLoop
    from base.prompt_loader import load_system_prompt
    from base.text_protocol import ProtocolManager
    from base.tools import TOOL_DEFINITIONS
    from base.logger import SporeLogger
    
    # 1. 初始化日志（桌面模式不启动监控终端，因为前端有日志显示区域）
    # 设置环境变量，禁止启动监控终端
    import os
    os.environ['SPORE_DESKTOP_MODE'] = '1'
    logger = SporeLogger(start_monitor=False)
    
    # 2. 加载配置（复用 base/config.py）
    _config = get_config()
    # Desktop 模式下不强制验证 API Key，允许用户后续配置
    # _config.validate()  # 注释掉强制验证
    
    # 3. 初始化 IPC 系统（复用 base/ipc_manager.py）
    _ipc_manager = initialize_ipc_system()
    time.sleep(0.5)
    
    # 4. 初始化多会话管理器
    _state = MultiSessionManager()
    
    # 5. 初始化 CLI 命令处理器（传入当前会话）
    _cli_handler = CLICommandHandler(_state.current)
    
    # 6. 加载系统提示并注入协议
    base_prompt = load_system_prompt() or ""
    tool_definitions = {
        name: TOOL_DEFINITIONS[name]
        for name in MAIN_AGENT_TOOLS
        if name in TOOL_DEFINITIONS
    }
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)
    
    # 设置主 Agent 的 agent_id（用于文件修改标志）
    from base.utils.system_io import set_current_agent_id
    set_current_agent_id("main_agent")
    
    # 7. 初始化对话循环（使用当前会话状态）
    _conv_loop = ConversationLoop(
        _state.current, _ipc_manager, _config, system_prompt, tool_names=MAIN_AGENT_TOOLS
    )
    
    _initialized = True
    
    return get_instances_dict()


def get_instances() -> Tuple:
    """
    获取全局实例元组
    
    Returns:
        Tuple: (ipc_manager, state, cli_handler, conv_loop, config)
    """
    return _ipc_manager, _state, _cli_handler, _conv_loop, _config


def get_instances_dict() -> Dict[str, Any]:
    """
    获取全局实例字典
    
    Returns:
        Dict: 包含所有实例的字典
    """
    return {
        'ipc_manager': _ipc_manager,
        'state': _state,
        'cli_handler': _cli_handler,
        'conv_loop': _conv_loop,
        'config': _config
    }


def shutdown_desktop_backend() -> None:
    """关闭桌面后端，清理资源"""
    global _ipc_manager, _initialized
    
    if _ipc_manager:
        _ipc_manager.stop_chat_process()
        _ipc_manager = None
    
    _initialized = False


def is_initialized() -> bool:
    """检查后端是否已初始化"""
    return _initialized


def switch_session(session_id: str) -> Dict[str, Any]:
    """
    切换到指定会话
    
    Args:
        session_id: 会话 ID
        
    Returns:
        Dict: 包含会话信息
    """
    global _cli_handler, _conv_loop
    
    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}
    
    # 切换会话
    new_state = _state.switch_session(session_id)
    
    # 更新 CLI handler 和 ConversationLoop 的状态引用
    if _cli_handler:
        _cli_handler.state = new_state
    if _conv_loop:
        _conv_loop.state = new_state
        
        # 根据新会话的模式更新工具集
        from base.agent_types import get_tools_for_mode
        from base.tools import TOOL_DEFINITIONS
        from base.text_protocol import ProtocolManager
        from base.prompt_loader import load_system_prompt
        
        current_tools = get_tools_for_mode(new_state.context_mode)
        tool_definitions = {
            name: TOOL_DEFINITIONS[name]
            for name in current_tools
            if name in TOOL_DEFINITIONS
        }
        base_prompt = load_system_prompt() or ""
        protocol_manager = ProtocolManager()
        system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)
        _conv_loop.system_prompt = system_prompt
        _conv_loop.tool_names = current_tools
    
    return {
        "success": True,
        "session_id": session_id,
        "message_count": len(new_state.messages)
    }


def create_session(session_id: str) -> Dict[str, Any]:
    """
    创建新会话并切换到该会话
    
    Args:
        session_id: 会话 ID
        
    Returns:
        Dict: 包含会话信息
    """
    global _cli_handler, _conv_loop
    
    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}
    
    # 创建新会话
    new_state = _state.create_session(session_id)
    _state.switch_session(session_id)
    
    # 更新引用
    if _cli_handler:
        _cli_handler.state = new_state
    if _conv_loop:
        _conv_loop.state = new_state
    
    return {
        "success": True,
        "session_id": session_id
    }


def delete_session(session_id: str) -> Dict[str, Any]:
    """
    删除会话
    
    Args:
        session_id: 会话 ID
        
    Returns:
        Dict: 操作结果
    """
    global _cli_handler, _conv_loop
    
    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}
    
    success = _state.delete_session(session_id)
    
    # 如果删除的是当前会话，更新引用到新的当前会话
    if success:
        current = _state.current
        if _cli_handler:
            _cli_handler.state = current
        if _conv_loop:
            _conv_loop.state = current
    
    return {"success": success}


def get_session_manager():
    """获取会话管理器"""
    return _state
