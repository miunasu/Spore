"""
命令 API - 复用 base/cli_commands.py 的 CLICommandHandler
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from ..core import get_instances

router = APIRouter()


class LoadRequest(BaseModel):
    """加载对话请求"""
    filename: str


@router.get("/prompt")
def get_prompt() -> Dict[str, Any]:
    """获取系统提示词 - 复用 prompt_loader"""
    from base.prompt_loader import load_system_prompt
    from base.utils.token_counter import count_tokens
    
    prompt = load_system_prompt()
    return {
        "prompt": prompt,
        "token_count": count_tokens(prompt) if prompt else 0
    }


@router.get("/context")
def get_context(full: bool = False) -> Dict[str, Any]:
    """获取上下文 - 复用 state.messages"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    state = session_manager.current
    
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
def clear_memory():
    """清除记忆 - 复用 CLICommandHandler._handle_memclean_command 逻辑"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.utils import clear_last_todo_content
        from base.todo_manager import todo_write
        
        session_manager.current.clear_all()
        clear_last_todo_content()
        todo_write([])
        
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
def toggle_savemode() -> Dict[str, Any]:
    """切换节省模式 - 复用 state.toggle_save_mode"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    is_enabled = session_manager.current.toggle_save_mode()
    return {"save_mode": is_enabled}


@router.post("/save")
def save_conversation():
    """保存对话 - 复用 memory_manager.save_messages"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import save_messages
        save_messages(session_manager.current.messages)
        return {"success": True, "message": "对话已保存"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/load")
def load_conversation(req: LoadRequest):
    """加载对话 - 复用 memory_manager.load_messages"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import load_messages
        state = session_manager.current
        state.messages = load_messages(req.filename)
        state.user_message_count = 0
        return {"success": True, "message_count": len(state.messages)}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"文件不存在: {req.filename}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/continue")
def continue_recent():
    """继续最近对话 - 复用 memory_manager.get_latest_history_file"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        from base.memory_manager import load_messages, get_latest_history_file
        from base import config as _config
        
        state = session_manager.current
        latest_file = get_latest_history_file()
        state.messages = load_messages(latest_file)
        state.user_message_count = 0
        _config.memory_continued = True
        
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
    """获取当前会话的 token 数 - 直接计算 messages 的 token"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        return {"token_count": 0}
    
    try:
        from base.utils.token_counter import count_tokens
        messages = session_manager.current.messages
        token_count = count_tokens(messages) if messages else 0
        return {"token_count": token_count}
    except Exception:
        return {"token_count": 0}


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
def trigger_character():
    """触发角色选择 - 复用 AutoAgent.character_choose_agent"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    state = session_manager.current
    if not state.messages:
        raise HTTPException(status_code=400, detail="没有对话历史")
    
    try:
        from AutoAgent import character_choose_agent
        character_choose_agent(state.messages)
        return {"success": True, "message": "角色选择已触发"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/list")
def list_history_files() -> Dict[str, Any]:
    """列出历史文件 - 包括 history 目录下所有 .mem 文件"""
    import os
    from pathlib import Path
    
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


@router.get("/mode")
def get_context_mode() -> Dict[str, Any]:
    """获取当前会话的上下文处理模式"""
    from AutoAgent import get_mode_description
    
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        # 如果后端未初始化，返回默认模式
        from base.config import get_config
        config = get_config()
        mode = config.context_mode
    else:
        # 从当前会话获取模式
        mode = session_manager.current.context_mode
    
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
    
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    # 设置当前会话的模式
    session_manager.current.context_mode = req.mode
    
    return {
        "success": True,
        "mode": req.mode,
        "description": get_mode_description(req.mode),
        "message": f"当前会话模式已切换到: {req.mode}"
    }
