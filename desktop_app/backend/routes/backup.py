"""
备份回滚 API - 复用 base/backup_manager.py 的 BackupManager

桌面端的 checkpoint/rewind 入口，与 CLI 的 checkpoints/rewind/filehistory/rollback
命令（base/cli_commands.py）语义一致：
- 对话点快照：列出 / 回滚（同时恢复文件 + 截断对话历史 + 清 TODO）
- 文件级备份：列出被跟踪文件 / 查看版本历史 / 恢复到指定版本
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any

from ..core import get_session_manager
from base.backup_manager import get_backup_manager
from base.logger import log_error
from base.utils import clear_last_todo_content
from base.todo_manager import todo_write

router = APIRouter()


def _resolve_conversation_id(session_manager, conversation_id: Optional[str]) -> str:
    if conversation_id:
        if not session_manager.get_session(conversation_id):
            raise HTTPException(status_code=404, detail=f"会话不存在: {conversation_id}")
        return conversation_id
    return session_manager.current_session_id


class RewindRequest(BaseModel):
    """对话点回滚请求：checkpoint_id 与 steps 二选一，都不传默认回退 1 个对话点"""
    conversation_id: Optional[str] = None
    checkpoint_id: Optional[str] = None
    steps: Optional[int] = None


class RestoreFileRequest(BaseModel):
    """文件恢复请求：version_id（0 表示 baseline）与 steps 二选一"""
    path: str
    version_id: Optional[int] = None
    steps: Optional[int] = None


@router.get("/checkpoints")
def list_checkpoints(conversation_id: Optional[str] = None) -> Dict[str, Any]:
    """列出指定会话的对话点快照"""
    session_manager = get_session_manager()
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")

    resolved_id = _resolve_conversation_id(session_manager, conversation_id)
    checkpoints = get_backup_manager().list_checkpoints(resolved_id)
    return {
        "success": True,
        "conversation_id": resolved_id,
        "checkpoints": checkpoints,
    }


@router.post("/rewind")
def rewind(req: RewindRequest) -> Dict[str, Any]:
    """
    回滚到指定对话点：恢复文件 + 截断对话历史 + 清 TODO（与 CLI rewind 收尾一致）

    并发保护：若该会话正在生成（execution_lock 被占用）则拒绝，避免回滚
    与进行中的轮次互相覆盖；回滚后 bump interrupt_epoch，使排队中的旧轮次失效。
    """
    from ..core import get_conv_loop_manager

    session_manager = get_session_manager()
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")

    resolved_id = _resolve_conversation_id(session_manager, req.conversation_id)
    state = session_manager.get_session(resolved_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"会话不存在: {resolved_id}")

    conv_loop_manager = get_conv_loop_manager()
    loop = (
        conv_loop_manager._loops.get(resolved_id)
        if conv_loop_manager else None
    )
    lock = loop.execution_lock if loop else None
    acquired = lock.acquire(blocking=False) if lock else True
    if not acquired:
        raise HTTPException(status_code=409, detail="会话正在生成中，请先停止再回滚")

    try:
        result = get_backup_manager().rewind(
            resolved_id,
            checkpoint_id=req.checkpoint_id,
            steps=req.steps,
        )
        partial = bool(result.get("restored") or result.get("deleted"))
        if not result.get("ok") and not partial:
            raise HTTPException(status_code=400, detail=result.get("error", "回滚失败"))

        # 使排队中但尚未开始的旧轮次失效，避免回滚后被旧回复覆盖
        state.interrupt_epoch += 1

        message_count = result["message_count"]
        if len(state.messages) > message_count:
            state.messages = state.messages[:message_count]
        clear_last_todo_content()
        todo_write([], session_id=resolved_id)

        return {
            "success": bool(result.get("ok")),
            "conversation_id": resolved_id,
            "checkpoint": result.get("checkpoint"),
            "ts": result.get("ts"),
            "message_count": message_count,
            "restored": result.get("restored", []),
            "deleted": result.get("deleted", []),
            "skipped": result.get("skipped", []),
            "failed": result.get("failed", []),
        }
    except HTTPException:
        raise
    except Exception as e:
        log_error("BACKUP_REWIND_ERROR", f"对话点回滚失败: {resolved_id}", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if lock is not None and acquired:
            lock.release()


@router.get("/files")
def list_tracked_files() -> Dict[str, Any]:
    """列出所有有备份记录的文件"""
    return {"success": True, "files": get_backup_manager().list_tracked_files()}


@router.get("/files/history")
def get_file_history(path: str) -> Dict[str, Any]:
    """查看某文件的备份版本历史"""
    result = get_backup_manager().get_history(path)
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "没有该文件的备份记录"))
    return {
        "success": True,
        "path": result["path"],
        "has_baseline": result["has_baseline"],
        "versions": result["versions"],
    }


@router.post("/files/restore")
def restore_file(req: RestoreFileRequest) -> Dict[str, Any]:
    """恢复文件到指定版本（version_id=0 表示 baseline；恢复本身会记录为新版本，可撤销）"""
    result = get_backup_manager().restore_file(
        req.path,
        version_id=req.version_id,
        steps=req.steps,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "恢复失败"))
    return {
        "success": True,
        "path": result["path"],
        "restored_to_version": result["restored_to_version"],
        "deleted": result["deleted"],
    }
