"""
桌面模式核心初始化
复用 main.py 的初始化逻辑，但不启动 CLI 循环
"""
from typing import Optional, Dict, Any, Tuple
from base.session_context import conversation_context

# 全局实例（桌面模式共享）
_ipc_manager = None
_state = None
_cli_handler = None
_conv_loop = None  # 保留用于兼容性，但不再使用
_conv_loop_manager = None  # 新增：ConversationLoop 管理器
_config = None
_initialized = False

# 主 Agent 工具列表（从 agent_types 导入）
from base.agent_types import get_tools_for_mode


def initialize_desktop_backend() -> Dict[str, Any]:
    """
    初始化桌面后端 - 复用 main.py 的初始化逻辑
    
    Returns:
        Dict: 包含所有初始化实例的字典
    """
    global _ipc_manager, _state, _cli_handler, _conv_loop, _conv_loop_manager, _config, _initialized
    
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
    from .conversation_loop_manager import ConversationLoopManager
    
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

    # 4b. 注册会话状态查找，供子 Agent / 工具策略按 conversation_id 解析策略
    from base.tool_policy import set_session_state_lookup
    set_session_state_lookup(
        lambda conversation_id: (
            _state.get_session(conversation_id)
            if (_state is not None and conversation_id)
            else (_state.current if _state is not None else None)
        )
    )
    
    # 5. 初始化 TODO 管理器（依赖会话管理器）
    from base.todo_manager import initialize_todo_manager
    initialize_todo_manager(_state)
    
    # 6. 初始化 CLI 命令处理器（传入当前会话）
    _cli_handler = CLICommandHandler(_state.current)
    
    # 7. 加载系统提示并注入协议
    with conversation_context("default"):
        base_prompt = load_system_prompt() or ""
    initial_context_mode = _state.current.context_mode
    initial_effective_mode = "strong_context" if initial_context_mode == "auto" else initial_context_mode
    initial_tools = get_tools_for_mode(initial_effective_mode)
    tool_definitions = {
        name: TOOL_DEFINITIONS[name]
        for name in initial_tools
        if name in TOOL_DEFINITIONS
    }
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(
        base_prompt,
        tool_definitions,
    )
    
    # 设置主 Agent 的 agent_id（用于文件修改标志）
    from base.utils.system_io import set_current_agent_id
    set_current_agent_id("main_agent")
    
    # 8. 初始化 ConversationLoop 管理器（新架构）
    _conv_loop_manager = ConversationLoopManager(
        session_manager=_state,
        ipc_manager=_ipc_manager,
        config=_config
    )
    
    # 9. 为默认会话创建 ConversationLoop（保持兼容性）
    _conv_loop = _conv_loop_manager.get_loop(
        session_id="default",
        system_prompt=system_prompt,
        tool_names=initial_tools,
    )
    
    _initialized = True
    
    return get_instances_dict()


def get_instances() -> Tuple:
    """
    获取全局实例元组
    
    Returns:
        Tuple: (ipc_manager, state, cli_handler, conv_loop, config, conv_loop_manager)
    
    注意：建议使用 get_session_manager() 等专用函数，而不是直接解包此元组
    """
    return _ipc_manager, _state, _cli_handler, _conv_loop, _config, _conv_loop_manager


def get_session_manager():
    """获取会话管理器（推荐使用）"""
    return _state


def get_conv_loop_manager():
    """获取对话循环管理器（推荐使用）"""
    return _conv_loop_manager


def get_config():
    """获取配置对象（推荐使用）"""
    return _config


def apply_runtime_config() -> Dict[str, Any]:
    """Reload .env and apply runtime-safe settings to the desktop backend."""
    global _config

    if not _initialized:
        return {"success": False, "error": "后端未初始化"}

    from base.config import reload_config
    from base.agent_types import get_tools_for_mode
    from base.prompt_loader import load_system_prompt
    from base.text_protocol import ProtocolManager
    from base.tools import TOOL_DEFINITIONS

    new_config = reload_config()
    _config = new_config

    if _ipc_manager:
        _ipc_manager._config = new_config
        _ipc_manager.stop_chat_process()
        _ipc_manager.start_chat_process()
        _ipc_manager.setup_all_modules()

    if _conv_loop_manager:
        _conv_loop_manager.config = new_config

    applied_mode = new_config.context_mode
    effective_mode = "strong_context" if applied_mode == "auto" else applied_mode
    from base.tool_policy import (
        filter_tool_definitions,
        resolve_mode_policy,
        resolve_enabled_tool_names,
    )
    # Runtime config applies mode default; per-session policies stay on each state
    current_tools = get_tools_for_mode(effective_mode)
    tool_definitions = {
        name: TOOL_DEFINITIONS[name]
        for name in current_tools
        if name in TOOL_DEFINITIONS
    }
    protocol_manager = ProtocolManager()

    if _state:
        for session_id in _state.list_sessions():
            session_state = _state.get_session(session_id)
            if session_state:
                session_state.context_mode = applied_mode

            if _conv_loop_manager and session_id in _conv_loop_manager._loops:
                with conversation_context(session_id):
                    base_prompt = load_system_prompt() or ""
                session_policy = resolve_mode_policy(
                    effective_mode,
                    getattr(session_state, "tool_policies", None) if session_state else None,
                )
                session_tools = resolve_enabled_tool_names(effective_mode, session_policy)
                session_defs = filter_tool_definitions(effective_mode, session_policy)
                system_prompt = protocol_manager.inject_protocol(base_prompt, session_defs)
                loop = _conv_loop_manager._loops[session_id]
                loop.config = new_config
                loop.system_prompt = system_prompt
                loop.tool_names = session_tools

    if _conv_loop:
        _conv_loop.config = new_config
        with conversation_context("default"):
            base_prompt = load_system_prompt() or ""
        default_state = _state.current if _state else None
        default_policy = resolve_mode_policy(
            effective_mode,
            getattr(default_state, "tool_policies", None) if default_state else None,
        )
        default_tools = resolve_enabled_tool_names(effective_mode, default_policy)
        default_defs = filter_tool_definitions(effective_mode, default_policy)
        _conv_loop.system_prompt = protocol_manager.inject_protocol(base_prompt, default_defs)
        _conv_loop.tool_names = default_tools

    if _cli_handler and _state:
        _cli_handler.state = _state.current

    return {
        "success": True,
        "context_mode": applied_mode,
        "tool_names": current_tools,
        "restarted_chat_process": bool(_ipc_manager),
        "message": "配置已应用到当前进程；服务监听地址/端口变更需要重启应用"
    }


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
        'config': _config,
        'conv_loop_manager': _conv_loop_manager,
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
    global _cli_handler
    
    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}
    
    # 切换会话
    new_state = _state.switch_session(session_id)
    
    # 只需要更新 CLI handler 的状态引用
    if _cli_handler:
        _cli_handler.state = new_state
    
    # 注意：不需要更新 conv_loop，因为现在每个会话有独立的 loop
    
    return {
        "success": True,
        "session_id": session_id,
        "message_count": len(new_state.messages)
    }


def create_session(session_id: str, switch_current: bool = False) -> Dict[str, Any]:
    """
    创建新会话。

    Args:
        session_id: 会话 ID
        switch_current: 是否切换全局当前会话。
            - True: 桌面 UI 手动新建会话时使用
            - False(默认): API/流水线只创建隔离会话，不抢占 current

    Returns:
        Dict: 包含会话信息
    """
    global _cli_handler

    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}

    new_state = _state.create_session(session_id)
    if switch_current:
        _state.switch_session(session_id)
        if _cli_handler:
            _cli_handler.state = new_state

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
    global _cli_handler, _conv_loop_manager

    if not _initialized or _state is None:
        return {"success": False, "error": "后端未初始化"}

    # 先终止该会话名下仍在运行的子Agent（会话级，不影响其他会话）
    from base.agent_process import terminate_conversation_agents
    from base.logger import log_error
    try:
        terminate_conversation_agents(session_id)
    except Exception as e:
        log_error("SESSION_AGENT_CLEANUP_ERROR", f"终止会话 {session_id} 的子Agent失败: {e}", e)

    success = _state.delete_session(session_id)

    # 删除对应的 ConversationLoop 实例
    if success and _conv_loop_manager:
        _conv_loop_manager.remove_loop(session_id)
    
    # 如果删除的是当前会话，更新 CLI handler 引用
    if success:
        current = _state.current
        if _cli_handler:
            _cli_handler.state = current
    
    return {"success": success}


def get_session_manager():
    """获取会话管理器"""
    return _state


def get_conv_loop_manager():
    """获取 ConversationLoop 管理器"""
    return _conv_loop_manager
