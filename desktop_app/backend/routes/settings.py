"""
设置 API - 管理系统配置和 characters
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import subprocess
import sys
from pathlib import Path

from ..core import get_instances, apply_runtime_config

router = APIRouter()


def _get_env_path() -> Path:
    """Return the .env file used by the desktop backend."""
    from base.config import _PROJECT_ROOT

    return _PROJECT_ROOT / '.env'


def _upsert_env_key(env_path: Path, key: str, value: str) -> None:
    """Create or update a KEY=value line in .env (does not touch comments)."""
    if not env_path.exists():
        env_path.write_text(f"{key}={value}\n", encoding="utf-8")
        return

    with open(env_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            new_lines.append(line)
            continue
        if stripped.startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] = new_lines[-1] + "\n"
        new_lines.append("\n# Command intercept master switch\n")
        new_lines.append(f"{key}={value}\n")

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)


def _sync_command_intercept(enabled: bool) -> None:
    """Persist and apply command_intercept master switch without restarting chat process."""
    env_path = _get_env_path()
    _upsert_env_key(env_path, "COMMAND_INTERCEPT", "true" if enabled else "false")
    # Keep legacy key in sync for old docs/tools
    _upsert_env_key(env_path, "BLOCK_SHELL_DELETE", "true" if enabled else "false")

    from base.config import get_config as get_base_config

    base_cfg = get_base_config()
    base_cfg.command_intercept = enabled

    try:
        from .. import core as desktop_core
        if getattr(desktop_core, "_config", None) is not None:
            desktop_core._config.command_intercept = enabled
    except Exception:
        pass




class CharacterSelectRequest(BaseModel):
    """选择角色请求"""
    character_name: str


class SettingsUpdateRequest(BaseModel):
    """更新设置请求"""
    default_character: Optional[str] = None
    command_intercept: Optional[bool] = None


class ConfigProfileSaveRequest(BaseModel):
    """Save or update an API config profile."""
    name: str
    values: Dict[str, str]
    profile_id: Optional[str] = None
    description: str = ""


class ConfigProfileApplyRequest(BaseModel):
    """Apply an API config profile to .env."""
    profile_id: str


@router.get("/characters/list")
def list_characters() -> Dict[str, Any]:
    """
    获取所有可用角色列表
    
    Returns:
        {
            "success": true,
            "characters": [
                {"name": "Python专家", "path": "..."},
                ...
            ],
            "current": "Python专家" or null
        }
    """
    try:
        from base.utils.characters import list_character_documents, _characters_root
        from base.character_manager import get_selected_characters
        import os
        
        # 获取 characters 目录路径（用于调试）
        characters_root = _characters_root()
        
        # 获取所有角色（不再检查 enable_characters 配置）
        all_characters = list_character_documents()
        
        # 获取当前激活的角色
        current_characters = get_selected_characters()
        current_name = current_characters[0]["name"] if current_characters else None
        
        return {
            "success": True,
            "enabled": True,
            "characters": all_characters,
            "current": current_name,
            "debug": {
                "characters_root": characters_root,
                "characters_count": len(all_characters),
                "exists": os.path.exists(characters_root) if characters_root else False
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "enabled": False,
            "characters": [],
            "current": None
        }


@router.post("/characters/select")
def select_character(request: CharacterSelectRequest) -> Dict[str, Any]:
    """
    选择/切换角色
    
    Args:
        request: 包含 character_name 的请求
    
    Returns:
        {
            "success": true,
            "message": "已选择角色: Python专家"
        }
    """
    try:
        from base.character_manager import select_character
        
        result = select_character(request.character_name)
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/characters/remove")
def remove_character() -> Dict[str, Any]:
    """
    移除当前角色
    
    Returns:
        {
            "success": true,
            "message": "已移除角色: Python专家"
        }
    """
    try:
        from base.character_manager import remove_character, get_selected_characters
        
        # 获取当前角色
        current_characters = get_selected_characters()
        if not current_characters:
            return {
                "success": False,
                "error": "当前没有激活的角色"
            }
        
        character_name = current_characters[0]["name"]
        result = remove_character(character_name)
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.get("/settings")
def get_settings() -> Dict[str, Any]:
    """
    获取当前设置
    
    Returns:
        {
            "default_character": "Python专家",
            "context_mode": "auto",
            ...
        }
    """
    try:
        from base.config import get_config
        
        config = get_config()
        
        return {
            "success": True,
            "settings": {
                "default_character": config.default_character,
                "context_mode": config.context_mode,
                "max_output_tokens": config.max_output_tokens,
                "command_intercept": getattr(config, "command_intercept", True),
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/env/open")
def open_env_file() -> Dict[str, Any]:
    """Open the .env file currently used by Spore."""
    try:
        env_path = _get_env_path()

        if not env_path.exists():
            return {
                "success": False,
                "error": ".env 文件不存在"
            }

        if sys.platform == "win32":
            os.startfile(str(env_path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(env_path)])
        else:
            subprocess.Popen(["xdg-open", str(env_path)])

        return {
            "success": True,
            "path": str(env_path)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.post("/env/apply")
def apply_env_file() -> Dict[str, Any]:
    """Reload .env and apply runtime-safe settings to the current desktop backend."""
    try:
        return apply_runtime_config()
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.get("/profiles/list")
def list_profiles() -> Dict[str, Any]:
    """List saved API config profiles."""
    try:
        from base.config_profiles import list_config_profiles

        return list_config_profiles(_get_env_path())
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "profiles": [],
            "active_profile_id": None,
        }


@router.post("/profiles/save")
def save_profile(request: ConfigProfileSaveRequest) -> Dict[str, Any]:
    """Save the current API settings as a reusable profile."""
    try:
        from base.config_profiles import save_config_profile

        return save_config_profile(
            name=request.name,
            values=request.values,
            profile_id=request.profile_id,
            description=request.description,
        )
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@router.post("/profiles/apply")
def apply_profile(request: ConfigProfileApplyRequest) -> Dict[str, Any]:
    """Apply a saved API config profile, then reload runtime config."""
    try:
        from base.config_profiles import apply_config_profile

        profile_result = apply_config_profile(request.profile_id, _get_env_path())
        runtime_result = apply_runtime_config()

        return {
            **runtime_result,
            "profile": profile_result.get("profile"),
            "env_values": profile_result.get("env_values"),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@router.delete("/profiles/{profile_id}")
def delete_profile(profile_id: str) -> Dict[str, Any]:
    """Delete a saved API config profile."""
    try:
        from base.config_profiles import delete_config_profile

        return delete_config_profile(profile_id)
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


@router.post("/settings/update")
def update_settings(request: SettingsUpdateRequest) -> Dict[str, Any]:
    """
    更新设置（写入 .env 文件）
    
    Args:
        request: 包含要更新的设置项
    
    Returns:
        {
            "success": true,
            "message": "设置已更新"
        }
    """
    try:
        from base.config import get_config
        
        config = get_config()
        env_path = _get_env_path()
        
        if not env_path.exists():
            return {
                "success": False,
                "error": ".env 文件不存在"
            }
        
        # 读取现有 .env 文件
        with open(env_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 更新配置项
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            stripped = line.strip()
            
            # 更新 DEFAULT_CHARACTER
            if request.default_character is not None and stripped.startswith('DEFAULT_CHARACTER='):
                updated_lines.append(f'DEFAULT_CHARACTER={request.default_character}\n')
                updated_keys.add('DEFAULT_CHARACTER')
            else:
                updated_lines.append(line)
        
        # 如果配置项不存在，添加到文件末尾
        if request.default_character is not None and 'DEFAULT_CHARACTER' not in updated_keys:
            updated_lines.append(f'DEFAULT_CHARACTER={request.default_character}\n')
        
        # 写回文件
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(updated_lines)
        
        # 更新内存中的配置（需要重新加载）
        if request.default_character is not None:
            config.default_character = request.default_character
            apply_runtime_config()

        if request.command_intercept is not None:
            _sync_command_intercept(bool(request.command_intercept))

        return {
            "success": True,
            "message": "settings updated",
            "command_intercept": (
                bool(request.command_intercept)
                if request.command_intercept is not None
                else None
            ),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.get("/settings/command_intercept")
def get_command_intercept() -> Dict[str, Any]:
    """Get command intercept master switch."""
    try:
        from base.config import get_config
        config = get_config()
        enabled = bool(getattr(config, "command_intercept", True))
        return {"success": True, "command_intercept": enabled}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/settings/command_intercept/toggle")
def toggle_command_intercept() -> Dict[str, Any]:
    """Toggle command intercept master switch and persist to .env."""
    try:
        from base.config import get_config
        config = get_config()
        current = bool(getattr(config, "command_intercept", True))
        new_value = not current
        _sync_command_intercept(new_value)
        return {
            "success": True,
            "command_intercept": new_value,
            "message": "command intercept enabled" if new_value else "command intercept disabled",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/settings/command_intercept")
def set_command_intercept(request: SettingsUpdateRequest) -> Dict[str, Any]:
    """Set command intercept master switch."""
    try:
        if request.command_intercept is None:
            return {"success": False, "error": "command_intercept is required"}
        _sync_command_intercept(bool(request.command_intercept))
        return {
            "success": True,
            "command_intercept": bool(request.command_intercept),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Session tool policy (granular tool / sub-tool enablement)
# ---------------------------------------------------------------------------

class ToolPolicyGetRequest(BaseModel):
    conversation_id: Optional[str] = None
    policy_mode: Optional[str] = None  # strong_context | long_context (for auto sessions)


class ToolPolicyUpdateRequest(BaseModel):
    conversation_id: Optional[str] = None
    policy_mode: str  # strong_context | long_context
    policy: Dict[str, Any]


class ToolPolicyScopeRequest(BaseModel):
    scope: str  # session | global
    conversation_id: Optional[str] = None



def _sync_session_loop_tools(state, sid: Optional[str]) -> None:
    """Refresh ConversationLoop tool_names/system_prompt from mode + effective policy scope."""
    if not sid:
        return
    from base.tool_policy import (
        effective_mode_name,
        filter_tool_definitions,
        resolve_enabled_tool_names,
        resolve_mode_policy,
    )
    from base.prompt_loader import load_system_prompt
    from base.text_protocol import ProtocolManager
    from base.session_context import conversation_context
    from ..core import get_conv_loop_manager

    conv_loop_manager = get_conv_loop_manager()
    if not conv_loop_manager:
        return

    eff = effective_mode_name(
        getattr(state, "context_mode", "strong_context"),
        getattr(state, "selected_auto_mode", None),
    )
    mode_policy = resolve_mode_policy(eff, getattr(state, "tool_policies", None))
    current_tools = resolve_enabled_tool_names(eff, mode_policy)
    tool_definitions = filter_tool_definitions(eff, mode_policy)

    with conversation_context(sid):
        base_prompt = load_system_prompt() or ""
    system_prompt = ProtocolManager().inject_protocol(base_prompt, tool_definitions)

    if sid in getattr(conv_loop_manager, "_loops", {}):
        loop = conv_loop_manager._loops[sid]
        loop.tool_names = current_tools
        loop.system_prompt = system_prompt


def _sync_all_session_loop_tools() -> int:
    """Refresh tools/prompt for every live conversation loop (used after global policy changes)."""
    from ..core import get_session_manager, get_conv_loop_manager

    session_manager = get_session_manager()
    conv_loop_manager = get_conv_loop_manager()
    if not session_manager or not conv_loop_manager:
        return 0
    count = 0
    for sid in list(getattr(conv_loop_manager, "_loops", {}).keys()):
        state = session_manager.get_session(sid)
        if state is None:
            continue
        _sync_session_loop_tools(state, sid)
        count += 1
    return count


def _resolve_session_state(conversation_id: Optional[str]):
    from ..core import get_session_manager
    session_manager = get_session_manager()
    if not session_manager:
        return None, None, "后端未初始化"
    if conversation_id:
        state = session_manager.get_session(conversation_id)
        if not state:
            return None, None, f"会话不存在: {conversation_id}"
        return state, conversation_id, None
    return session_manager.current, session_manager.current_session_id, None


@router.get("/tools/catalog")
def get_tools_catalog(mode: Optional[str] = None) -> Dict[str, Any]:
    """Return tool catalog for a mode baseline (no session overrides)."""
    try:
        from base.tool_policy import catalog_for_mode, default_mode_policy, effective_mode_name
        m = effective_mode_name(mode or "strong_context")
        return {
            "success": True,
            "mode": m,
            "catalog": catalog_for_mode(m),
            "default_policy": default_mode_policy(m),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/tools/policy")
def get_tool_policy(
    conversation_id: Optional[str] = None,
    policy_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Get effective tool policy view for the current scope (session or global)."""
    try:
        from base.tool_policy import build_tool_policy_view, get_policy_scope

        state, sid, err = _resolve_session_state(conversation_id)
        if err:
            return {"success": False, "error": err}

        view = build_tool_policy_view(
            context_mode=getattr(state, "context_mode", "strong_context"),
            tool_policies=getattr(state, "tool_policies", None),
            selected_auto_mode=policy_mode or getattr(state, "selected_auto_mode", None),
            scope=get_policy_scope(),
        )
        return {
            "success": True,
            "conversation_id": sid,
            **view,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/tools/policy")
def update_tool_policy(request: ToolPolicyUpdateRequest) -> Dict[str, Any]:
    """Update tool policy for one mode baseline under the current scope."""
    try:
        from base.tool_policy import (
            build_tool_policy_view,
            get_policy_scope,
            set_global_mode_policy,
            set_session_mode_policy,
        )

        if request.policy_mode not in ("strong_context", "long_context"):
            return {"success": False, "error": f"无效 policy_mode: {request.policy_mode}"}

        state, sid, err = _resolve_session_state(request.conversation_id)
        if err:
            return {"success": False, "error": err}

        scope = get_policy_scope()
        synced = 0
        if scope == "global":
            set_global_mode_policy(request.policy_mode, request.policy or {})
            synced = _sync_all_session_loop_tools()
            message = f"全局工具策略已更新 ({request.policy_mode})，已同步 {synced} 个会话"
        else:
            state.tool_policies = set_session_mode_policy(
                getattr(state, "tool_policies", None),
                request.policy_mode,
                request.policy or {},
            )
            _sync_session_loop_tools(state, sid)
            message = f"会话工具策略已更新 ({request.policy_mode})"

        view = build_tool_policy_view(
            context_mode=getattr(state, "context_mode", "strong_context"),
            tool_policies=getattr(state, "tool_policies", None),
            selected_auto_mode=request.policy_mode,
            scope=scope,
        )
        return {
            "success": True,
            "conversation_id": sid,
            "synced_sessions": synced,
            "message": message,
            **view,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/tools/policy/scope")
def update_tool_policy_scope(request: ToolPolicyScopeRequest) -> Dict[str, Any]:
    """Switch tool policy scope between session and global, then refresh loops."""
    try:
        from base.tool_policy import (
            VALID_SCOPES,
            build_tool_policy_view,
            set_policy_scope,
        )

        scope = (request.scope or "").strip().lower()
        if scope not in VALID_SCOPES:
            return {"success": False, "error": f"无效 scope: {request.scope}，可选: session / global"}

        set_policy_scope(scope)
        synced = _sync_all_session_loop_tools()

        state, sid, err = _resolve_session_state(request.conversation_id)
        if err:
            # scope already saved; still report success with limited payload
            return {
                "success": True,
                "scope": scope,
                "synced_sessions": synced,
                "message": f"工具策略作用域已切换为: {scope}",
            }

        view = build_tool_policy_view(
            context_mode=getattr(state, "context_mode", "strong_context"),
            tool_policies=getattr(state, "tool_policies", None),
            selected_auto_mode=getattr(state, "selected_auto_mode", None),
            scope=scope,
        )
        return {
            "success": True,
            "conversation_id": sid,
            "synced_sessions": synced,
            "message": (
                f"工具策略作用域已切换为「{'全局' if scope == 'global' else '仅当前会话'}」"
            ),
            **view,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/tools/policy/reset")
def reset_tool_policy(
    conversation_id: Optional[str] = None,
    policy_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Reset tool policy (one mode or all) to defaults under the current scope."""
    try:
        from base.tool_policy import (
            build_tool_policy_view,
            default_mode_policy,
            get_policy_scope,
            reset_global_mode_policy,
        )

        state, sid, err = _resolve_session_state(conversation_id)
        if err:
            return {"success": False, "error": err}

        scope = get_policy_scope()
        if scope == "global":
            reset_global_mode_policy(policy_mode if policy_mode in ("strong_context", "long_context") else None)
            synced = _sync_all_session_loop_tools()
            message = f"全局工具策略已重置为默认（全部启用），已同步 {synced} 个会话"
        else:
            policies = dict(getattr(state, "tool_policies", None) or {})
            if policy_mode in ("strong_context", "long_context"):
                policies[policy_mode] = default_mode_policy(policy_mode)
            else:
                policies = {
                    "strong_context": default_mode_policy("strong_context"),
                    "long_context": default_mode_policy("long_context"),
                }
            state.tool_policies = policies
            _sync_session_loop_tools(state, sid)
            message = "会话工具策略已重置为默认（全部启用）"

        view = build_tool_policy_view(
            context_mode=getattr(state, "context_mode", "strong_context"),
            tool_policies=getattr(state, "tool_policies", None),
            selected_auto_mode=policy_mode or getattr(state, "selected_auto_mode", None),
            scope=scope,
        )
        return {
            "success": True,
            "conversation_id": sid,
            "message": message,
            **view,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
