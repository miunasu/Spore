"""
命令 API - 复用 base/cli_commands.py 的 CLICommandHandler
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import re
from pathlib import Path

from ..core import get_session_manager, reset_session_runtime
from base.session_context import conversation_context

router = APIRouter()


def _get_target_state(session_manager, conversation_id: Optional[str] = None):
    if conversation_id:
        state = session_manager.get_session(conversation_id)
        if not state:
            raise HTTPException(status_code=404, detail=f"会话不存在: {conversation_id}")
        return state, conversation_id
    return session_manager.current, session_manager.current_session_id


class LoadRequest(BaseModel):
    """加载对话请求"""
    filename: str
    conversation_id: Optional[str] = None


class ConversationCommandRequest(BaseModel):
    conversation_id: Optional[str] = None


class RenameHistoryRequest(BaseModel):
    old_name: str
    new_name: str


class DeleteHistoryRequest(BaseModel):
    filename: str


@router.get("/prompt")
def get_prompt(conversation_id: Optional[str] = None) -> Dict[str, Any]:
    """获取系统提示词"""
    from base.prompt_loader import load_system_prompt
    
    with conversation_context(conversation_id):
        prompt = load_system_prompt()
    return {
        "prompt": prompt
    }


@router.get("/context")
def get_context(full: bool = False, conversation_id: Optional[str] = None) -> Dict[str, Any]:
    """获取上下文 - 复用 state.messages"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    state, _ = _get_target_state(session_manager, conversation_id)
    
    if full:
        return {"messages": state.messages}
    
    # 简化版本（与 CLI 的 context 命令一致）
    return {
        "message_count": len(state.messages),
        "messages": [
            {
                "index": i + 1,
                "role": msg.get("role"),
                "content_preview": msg.get("content", "")[:200]
            }
            for i, msg in enumerate(state.messages)
        ]
    }


@router.post("/memory/clear")
def clear_memory(req: Optional[ConversationCommandRequest] = None):
    """清除记忆 - 复用 CLICommandHandler._handle_memclean_command 逻辑"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.utils import clear_last_todo_content
        from base.todo_manager import todo_write
        
        conversation_id = req.conversation_id if req else None
        state, resolved_conversation_id = _get_target_state(session_manager, conversation_id)
        reset_session_runtime(resolved_conversation_id)
        clear_last_todo_content()
        todo_write([], session_id=resolved_conversation_id)

        # 对话历史已清零，同步清空该会话的对话点快照
        from base.backup_manager import get_backup_manager
        get_backup_manager().clear_checkpoints(resolved_conversation_id)

        return {"success": True, "message": "记忆已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/skills")
def get_skills() -> Dict[str, Any]:
    """获取技能列表 - 复用 utils.collect_skills_md_features"""
    from base.utils.skills import collect_skills_md_features
    
    skills = collect_skills_md_features()
    return {"skills": skills}


@router.post("/savemode")
def toggle_savemode(req: Optional[ConversationCommandRequest] = None) -> Dict[str, Any]:
    """切换节省模式 - 复用 state.toggle_save_mode"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    conversation_id = req.conversation_id if req else None
    state, _ = _get_target_state(session_manager, conversation_id)
    is_enabled = state.toggle_save_mode()
    return {"save_mode": is_enabled}


@router.post("/save")
def save_conversation(req: Optional[ConversationCommandRequest] = None):
    """保存对话 - 复用 memory_manager.save_messages"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import save_messages
        conversation_id = req.conversation_id if req else None
        state, _ = _get_target_state(session_manager, conversation_id)
        save_messages(state.messages)
        return {"success": True, "message": "对话已保存"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/load")
def load_conversation(req: LoadRequest):
    """加载对话 - 复用 memory_manager.load_messages"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import load_messages, auto_save_messages
        state, resolved_conversation_id = _get_target_state(session_manager, req.conversation_id)
        state.messages = load_messages(req.filename)
        state.user_message_count = 0
        # 加载后立即写入/刷新该会话短记忆，使其进入最近 10 会话队列
        auto_save_messages(state.messages, session_id=resolved_conversation_id)
        return {"success": True, "message_count": len(state.messages)}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"文件不存在: {req.filename}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/continue")
def continue_recent(req: Optional[ConversationCommandRequest] = None):
    """继续最近对话 - 复用 memory_manager.get_latest_history_file"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import load_messages, get_latest_history_file, auto_save_messages
        from base import config as _config
        
        conversation_id = req.conversation_id if req else None
        state, resolved_conversation_id = _get_target_state(session_manager, conversation_id)
        latest_file = get_latest_history_file()
        state.messages = load_messages(latest_file)
        state.user_message_count = 0
        _config.memory_continued = True
        # 继续最近对话后，刷新该会话短记忆
        auto_save_messages(state.messages, session_id=resolved_conversation_id)
        
        return {
            "success": True,
            "filename": latest_file,
            "message_count": len(state.messages)
        }
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tokens")
def calculate_tokens(conversation_id: Optional[str] = None) -> Dict[str, Any]:
    """获取指定会话的 token 统计 - Desktop 模式从 state 读取"""
    session_manager = get_session_manager()
    
    if not session_manager:
        return {
            "input": 0,
            "output": 0,
            "cumulative_input": 0,
            "cumulative_output": 0,
            "context": 0
        }
    
    try:
        # 获取指定会话的 state（如果没有指定则使用当前会话）
        if conversation_id:
            state = session_manager.get_session(conversation_id)
            if not state:
                # 会话不存在，返回 0
                return {
                    "input": 0,
                    "output": 0,
                    "cumulative_input": 0,
                    "cumulative_output": 0,
                    "context": 0
                }
        else:
            state = session_manager.current
        
        return {
            "input": state.last_input_tokens,
            "output": state.last_output_tokens,
            "cumulative_input": state.cumulative_input_tokens,  # 累加所有 input（用于算钱）
            "cumulative_output": state.cumulative_output_tokens,  # 累加所有 output（用于算钱）
            "context": state.last_input_tokens  # context = 当前的 input
        }
    except Exception as e:
        return {
            "input": 0,
            "output": 0,
            "cumulative_input": 0,
            "cumulative_output": 0,
            "context": 0
        }


class SetConversationRequest(BaseModel):
    """设置活跃对话请求"""
    conversation_id: str


@router.post("/tokens/set-conversation")
def set_active_conversation(request: SetConversationRequest) -> Dict[str, Any]:
    """设置当前活跃的对话 ID"""
    from base.chat_process import set_current_conversation
    set_current_conversation(request.conversation_id)
    return {"success": True}


@router.post("/character")
def trigger_character(req: Optional[ConversationCommandRequest] = None):
    """触发角色选择 - 复用 AutoAgent.character_choose_agent"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    conversation_id = req.conversation_id if req else None
    state, _ = _get_target_state(session_manager, conversation_id)
    if not state.messages:
        raise HTTPException(status_code=400, detail="没有对话历史")
    
    try:
        from AutoAgent import character_choose_agent
        character_choose_agent(state.messages)
        return {"success": True, "message": "角色选择已触发"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



def _resolve_history_file(filename: str) -> Path:
    history_dir = Path("history").resolve()
    normalized = filename.replace("\\", "/").strip("/")

    if not normalized or normalized.startswith("../") or "/../" in normalized:
        raise HTTPException(status_code=400, detail="Invalid history file path")

    target = (history_dir / normalized).resolve()
    try:
        target.relative_to(history_dir)
    except ValueError:
        raise HTTPException(status_code=403, detail="History file path is outside allowed scope")

    if target.suffix != ".mem":
        raise HTTPException(status_code=400, detail="Only .mem history files are allowed")

    return target


def _build_history_target_path(old_name: str, new_name: str) -> Path:
    source = _resolve_history_file(old_name)
    history_dir = Path("history").resolve()
    raw_new_name = new_name.replace("\\", "/").strip()

    if not raw_new_name:
        raise HTTPException(status_code=400, detail="New filename is empty")

    if "/" in raw_new_name:
        target_rel = raw_new_name.strip("/")
    else:
        parent_rel = source.parent.relative_to(history_dir)
        target_rel = str(parent_rel / raw_new_name) if str(parent_rel) != "." else raw_new_name

    if not target_rel.endswith(".mem"):
        target_rel += ".mem"

    invalid_chars = set('<>:"|?*')
    if any(char in invalid_chars or ord(char) < 32 for char in Path(target_rel).name):
        raise HTTPException(status_code=400, detail="New filename contains invalid characters")

    return _resolve_history_file(target_rel)



@router.post("/history/rename")
def rename_history_file(req: RenameHistoryRequest) -> Dict[str, Any]:
    source = _resolve_history_file(req.old_name)
    target = _build_history_target_path(req.old_name, req.new_name)

    if not source.exists() or not source.is_file():
        raise HTTPException(status_code=404, detail=f"History file does not exist: {req.old_name}")

    if target.exists():
        raise HTTPException(status_code=400, detail="Target history file already exists")

    target.parent.mkdir(parents=True, exist_ok=True)
    source.rename(target)

    history_dir = Path("history").resolve()
    return {
        "success": True,
        "old_name": str(source.relative_to(history_dir)).replace("\\", "/"),
        "new_name": str(target.relative_to(history_dir)).replace("\\", "/")
    }


@router.post("/history/delete")
def delete_history_file(req: DeleteHistoryRequest) -> Dict[str, Any]:
    target = _resolve_history_file(req.filename)

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail=f"History file does not exist: {req.filename}")

    target.unlink()

    # 会话短记忆被删除时，联动清除该会话的对话点快照（checkpoint 与会话数据绑定）
    from base.memory_manager import _session_id_from_autosave_name
    session_key = _session_id_from_autosave_name(target.name)
    if session_key:
        try:
            from base.backup_manager import get_backup_manager
            get_backup_manager().clear_checkpoints(session_key)
        except Exception:
            pass

    return {"success": True, "filename": req.filename}


@router.get("/history/list")
def list_history_files() -> Dict[str, Any]:
    """列出历史文件 - 包括 history 目录下所有 .mem 文件"""
    import os
    from pathlib import Path

    # 触发短记忆旧快照 -> 会话文件迁移，避免 UI 仍显示多份时间戳副本
    try:
        from base.memory_manager import list_autosave_files
        list_autosave_files()
    except Exception:
        pass
    
    history_dir = Path("history")
    if not history_dir.exists():
        return {"files": []}
    
    files = []
    
    # 遍历 history 目录下的所有 .mem 文件（包括子目录）
    for f in history_dir.rglob("*.mem"):
        if f.is_file():
            # 获取相对于 history 目录的路径
            rel_path = f.relative_to(history_dir)
            files.append({
                "name": str(rel_path).replace("\\", "/"),
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime
            })
    
    # 按修改时间排序，最新的在前
    files.sort(key=lambda x: x["modified"], reverse=True)
    return {"files": files}


def _count_log_lines(log_dir: "Path") -> int:
    """统计日志目录中 general.log 的行数"""
    general_log = log_dir / "general.log"
    if not general_log.exists():
        return 0
    try:
        with open(general_log, 'r', encoding='utf-8') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


@router.post("/logs/clear")
def clear_logs(min_lines: int = 10) -> Dict[str, Any]:
    """清理日志文件
    
    Args:
        min_lines: 最小行数阈值，低于此值的日志目录会被自动清理（默认10行）
    """
    import os
    import shutil
    from pathlib import Path
    
    cleared_count = 0
    auto_cleared_count = 0
    errors = []
    
    # 获取当前会话的日志目录（不清理）
    current_session_dir = os.environ.get('SPORE_SESSION_LOG_DIR')
    current_session_name = Path(current_session_dir).name if current_session_dir else None
    
    # 清理 logs/ 目录下的日志文件夹（保留 .gitignore、md 文件夹和当前会话目录）
    logs_dir = Path("logs")
    if logs_dir.exists():
        for item in logs_dir.iterdir():
            if item.is_dir() and item.name != "md" and item.name != current_session_name:
                try:
                    shutil.rmtree(item)
                    cleared_count += 1
                except Exception as e:
                    errors.append(f"logs/{item.name}: {str(e)}")
    
    # 清理 desktop_app/log/ 目录下的日志文件
    desktop_log_dir = Path("desktop_app/log")
    if desktop_log_dir.exists():
        for item in desktop_log_dir.iterdir():
            if item.is_file() and item.suffix == ".log":
                try:
                    item.unlink()
                    cleared_count += 1
                except Exception as e:
                    errors.append(f"desktop_app/log/{item.name}: {str(e)}")
    
    return {
        "success": len(errors) == 0,
        "cleared_count": cleared_count,
        "auto_cleared_count": auto_cleared_count,
        "skipped_current": current_session_name,
        "errors": errors if errors else None
    }


@router.post("/logs/auto-clean")
def auto_clean_short_logs(min_lines: int = 10) -> Dict[str, Any]:
    """自动清理过短的日志目录
    
    Args:
        min_lines: 最小行数阈值，低于此值的日志目录会被清理（默认10行）
    """
    import os
    import shutil
    from pathlib import Path
    
    cleaned_count = 0
    cleaned_dirs = []
    errors = []
    
    # 获取当前会话的日志目录（不清理）
    current_session_dir = os.environ.get('SPORE_SESSION_LOG_DIR')
    current_session_name = Path(current_session_dir).name if current_session_dir else None
    
    logs_dir = Path("logs")
    if logs_dir.exists():
        for item in logs_dir.iterdir():
            if item.is_dir() and item.name != "md" and item.name != current_session_name:
                line_count = _count_log_lines(item)
                if line_count < min_lines:
                    try:
                        shutil.rmtree(item)
                        cleaned_count += 1
                        cleaned_dirs.append(f"{item.name} ({line_count}行)")
                    except Exception as e:
                        errors.append(f"logs/{item.name}: {str(e)}")
    
    return {
        "success": len(errors) == 0,
        "cleaned_count": cleaned_count,
        "cleaned_dirs": cleaned_dirs,
        "min_lines": min_lines,
        "skipped_current": current_session_name,
        "errors": errors if errors else None
    }


class SetModeRequest(BaseModel):
    """设置上下文模式请求"""
    mode: str
    conversation_id: Optional[str] = None


@router.get("/mode")
def get_context_mode(conversation_id: Optional[str] = None) -> Dict[str, Any]:
    """获取当前会话的上下文处理模式"""
    from AutoAgent import get_mode_description
    
    session_manager = get_session_manager()
    
    if not session_manager:
        # 如果后端未初始化，返回默认模式
        from base.config import get_config
        config = get_config()
        mode = config.context_mode
    else:
        # 从目标会话获取模式
        state, _ = _get_target_state(session_manager, conversation_id)
        mode = state.context_mode
    
    return {
        "mode": mode,
        "description": get_mode_description(mode),
        "available_modes": [
            {
                "value": "strong_context",
                "label": "强上下文",
                "description": "适合需要上下文强关联的任务和精确推理"
            },
            {
                "value": "long_context",
                "label": "长上下文",
                "description": "适合大文本处理、大项目编程和信息检索汇总报告。偏向多agent"
            },
            {
                "value": "auto",
                "label": "自动选择",
                "description": "根据任务自动判断使用哪种模式"
            }
        ]
    }


@router.post("/mode")
def set_context_mode(req: SetModeRequest) -> Dict[str, Any]:
    """设置当前会话的上下文处理模式"""
    from AutoAgent import get_mode_description
    
    if req.mode not in ["strong_context", "long_context", "auto"]:
        raise HTTPException(status_code=400, detail=f"无效的模式: {req.mode}")
    
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    # 设置目标会话的模式，并同步工具集（含会话级 tool policy）
    state, resolved_id = _get_target_state(session_manager, req.conversation_id)
    state.context_mode = req.mode
    if req.mode != "auto":
        state.selected_auto_mode = None

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
    eff_mode = effective_mode_name(req.mode, getattr(state, "selected_auto_mode", None))
    mode_policy = resolve_mode_policy(eff_mode, getattr(state, "tool_policies", None))
    current_tools = resolve_enabled_tool_names(eff_mode, mode_policy)
    tool_definitions = filter_tool_definitions(eff_mode, mode_policy)

    if conv_loop_manager:
        with conversation_context(resolved_id):
            base_prompt = load_system_prompt() or ""
        system_prompt = ProtocolManager().inject_protocol(base_prompt, tool_definitions)
        if resolved_id in getattr(conv_loop_manager, "_loops", {}):
            loop = conv_loop_manager._loops[resolved_id]
            loop.tool_names = current_tools
            loop.system_prompt = system_prompt
        else:
            conv_loop_manager.get_loop(
                session_id=resolved_id,
                system_prompt=system_prompt,
                tool_names=current_tools,
            )

    return {
        "success": True,
        "mode": req.mode,
        "description": get_mode_description(req.mode),
        "tool_names": current_tools,
        "message": f"当前会话模式已切换到: {req.mode}",
    }
