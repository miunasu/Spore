"""
任务级自驱 API —— 循环所有权收归后端

POST /api/task/submit   提交任务，后端在后台线程自驱循环直至终态（内置 total_timeout watchdog）
GET  /api/task/status   查询任务状态（按 task_id，或按 session_id 查询该会话的任务）

中断复用 POST /api/chat/interrupt（带 conversation_id）：
接口立即退役当前 task 并精确唤醒 IPC waiter；同步 provider 若迟到，其回复会被丢弃。

事件流：在循环关键节点通过既有 WS 通道（websocket/ipc_bridge.send_ws_message）
发结构化事件，统一信封：
    {"type": "task_event", "event": <名>, "session_id", "task_id",
     "submission_id", "round": int, "ts": iso8601, "data": {...}}
事件名：task_started / round_chunk / round_reply / tool_call / tool_result /
todo_update / task_finished。
tool_call/tool_result/todo_update 由 conv_loop.event_emitter 回调注入产生
（base/ 不直接依赖 websocket 模块）。工具类字符串字段截断为 8KB，回复正文
允许到 256KB。

任务注册表为进程内内存（Spore 重启任务作废是可接受语义）。
"""
import threading
import time
import uuid
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from base.logger import log_error

router = APIRouter()

# 任务注册表（进程内）。worker 是否退出与 task 是否仍有权产生结果分开管理：
# active 索引一旦移除，旧 worker 即使仍在等待同步 provider，也不能再发可见事件。
_tasks: Dict[str, Dict[str, Any]] = {}
_active_tasks_by_session: Dict[str, str] = {}
_tasks_lock = threading.Lock()

# 专用线程池跑任务循环（不与 /send 的 _executor 抢线程）
_task_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="spore-task")

# 事件 content 截断上限（8KB）
_MAX_EVENT_CONTENT = 8 * 1024
_MAX_REPLY_CONTENT = 256 * 1024


def _now_iso() -> str:
    """本地时区的 ISO8601 时间戳"""
    return datetime.now(timezone.utc).astimezone().isoformat()


def _truncate(value: Any, limit: int = _MAX_EVENT_CONTENT) -> Any:
    """事件体积控制：字符串截断到 limit（其他类型原样返回）"""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"...[已截断 {len(value) - limit} 字符]"
    return value


def _send_envelope(envelope: Dict[str, Any]) -> None:
    """
    发送事件信封到 WS 推送进程。

    单独抽出来便于测试替换（monkeypatch 此函数即可捕获全部事件）。
    """
    try:
        from ..websocket.ipc_bridge import send_ws_message
        send_ws_message(envelope)
    except Exception as e:
        log_error("TASK_EVENT_SEND_ERROR", f"发送任务事件失败: {e}", e)


def _emit_task_event(event: str, session_id: str, task_id: str,
                     submission_id: str, round_num: int,
                     data: Optional[Dict[str, Any]] = None) -> None:
    """按统一信封发出 task_event，并按字段类型控制字符串体积。"""
    safe_data = {}
    for key, value in (data or {}).items():
        limit = (
            _MAX_REPLY_CONTENT
            if event in ("round_chunk", "round_reply") and key in ("content", "raw_response")
            else _MAX_EVENT_CONTENT
        )
        safe_data[key] = _truncate(value, limit)
    _send_envelope({
        "type": "task_event",
        "event": event,
        "session_id": session_id,
        "task_id": task_id,
        "submission_id": submission_id,
        "round": round_num,
        "ts": _now_iso(),
        "data": safe_data,
    })


def _is_active_task(session_id: str, task_id: str) -> bool:
    """检查 task 是否仍是该会话唯一有权产生结果的任务。"""
    with _tasks_lock:
        entry = _tasks.get(task_id)
        return bool(
            entry
            and entry["status"] == "running"
            and _active_tasks_by_session.get(session_id) == task_id
        )


def _emit_active_task_event(event: str, session_id: str, task_id: str,
                            submission_id: str, round_num: int,
                            data: Optional[Dict[str, Any]] = None) -> bool:
    """仅为仍 active 的 task 发送事件；检查与入队在同一临界区。"""
    with _tasks_lock:
        entry = _tasks.get(task_id)
        if not (
            entry
            and entry["status"] == "running"
            and _active_tasks_by_session.get(session_id) == task_id
        ):
            return False
        _emit_task_event(
            event, session_id, task_id, submission_id, round_num, data
        )
        return True


def interrupt_session_task(session_id: str) -> Optional[Dict[str, Any]]:
    """立即退役会话当前任务并发出唯一的 interrupted 终态事件。"""
    with _tasks_lock:
        task_id = _active_tasks_by_session.pop(session_id, None)
        if task_id is None:
            return None

        entry = _tasks.get(task_id)
        if entry is None or entry["status"] != "running":
            return None

        entry["status"] = "interrupted"
        entry["cancel_requested"] = True
        entry["finished_at"] = _now_iso()
        entry["finished_event_sent"] = True
        snapshot = dict(entry)

    _emit_task_event(
        "task_finished",
        session_id,
        task_id,
        snapshot["submission_id"],
        snapshot["rounds"],
        {"status": "interrupted", "rounds": snapshot["rounds"]},
    )
    return snapshot


class TaskSubmitRequest(BaseModel):
    """任务提交请求"""
    session_id: str
    submission_id: str
    message: str
    total_timeout: float = 1800.0


def has_active_task(session_id: str) -> bool:
    """返回指定会话当前是否有 active running task。"""
    with _tasks_lock:
        task_id = _active_tasks_by_session.get(session_id)
        entry = _tasks.get(task_id) if task_id else None
        return bool(entry and entry.get("status") == "running")


def _submit_task_impl(
    session_id: str,
    submission_id: str,
    message: str,
    total_timeout: float,
    source: str = "user",
    notice: Optional[Dict[str, Any]] = None,
    delivery_generation: Optional[int] = None,
) -> Dict[str, Any]:
    """提交用户任务或后端自发的子Agent完成通知任务。"""
    from ..core import get_session_manager, get_conv_loop_manager

    session_manager = get_session_manager()
    conv_loop_manager = get_conv_loop_manager()
    if not session_manager or not conv_loop_manager:
        return {"success": False, "error": "后端未初始化"}
    if not message or not message.strip():
        return {"success": False, "error": "message 不能为空"}

    session_exists = session_id in session_manager.list_sessions()
    if not session_exists:
        # 用户显式提交可创建会话；后台通知绝不能复活已删除的会话。
        if source == "agent_notification":
            return {"success": False, "error": f"通知目标会话已不存在: {session_id}"}
        session_manager.create_session(session_id)

    target_state = session_manager.get_session(session_id)
    if target_state is None:
        return {"success": False, "error": f"会话不存在: {session_id}"}

    task_id = uuid.uuid4().hex
    conv_loop = conv_loop_manager.get_loop(session_id=session_id)
    delivery_guard = nullcontext(True)
    if source == "agent_notification":
        if delivery_generation is None:
            return {"success": False, "error": "通知任务缺少 delivery generation"}
        from ..agent_notification import notification_delivery_guard
        delivery_guard = notification_delivery_guard(session_id, delivery_generation)

    # 先等待主轮次退出，再拿通知 generation guard；clear_session 不会被锁等待拖住，
    # 且 guard 内的 generation 校验与 task 注册仍保持原子。
    with conv_loop.execution_lock:
        with delivery_guard as delivery_valid:
            if not delivery_valid:
                return {"success": False, "error": "子Agent通知已因会话换代作废"}
            with _tasks_lock:
                active_task_id = _active_tasks_by_session.get(session_id)
                if active_task_id is not None:
                    return {
                        "success": False,
                        "error": f"会话 {session_id} 已有运行中的任务: {active_task_id}",
                    }

                entry = {
                    "task_id": task_id,
                    "submission_id": submission_id,
                    "session_id": session_id,
                    "source": source,
                    "notice": notice,
                    "status": "running",
                    "rounds": 0,
                    "started_at": _now_iso(),
                    "finished_at": None,
                    "last_content": "",
                    "error": None,
                    "interrupt_epoch": target_state.interrupt_epoch,
                    "cancel_requested": False,
                    "worker_done": False,
                    "finished_event_sent": False,
                }

                # 只清理 worker 已退出的旧终态，不能删除仍被旧 worker 引用的 entry。
                stale_ids = [
                    tid for tid, task in _tasks.items()
                    if task["session_id"] == session_id and task.get("worker_done")
                ]
                for stale_id in stale_ids:
                    del _tasks[stale_id]

                # task 被接受即记录输入；系统通知使用固定前缀，历史接口会映射为 system。
                target_state.add_user_message(message)
                entry["user_message_added"] = True
                _tasks[task_id] = entry
                _active_tasks_by_session[session_id] = task_id

    _task_executor.submit(
        _run_task_loop, task_id, session_id, message, float(total_timeout)
    )
    return {
        "success": True,
        "task_id": task_id,
        "submission_id": submission_id,
        "source": source,
    }


@router.post("/submit")
def submit_task(req: TaskSubmitRequest) -> Dict[str, Any]:
    """
    提交用户任务：会话不存在则创建；同 session 已有 running 任务则拒绝；
    提交时清掉该 session 的旧终态条目。任务在专用线程池中自驱直至终态。
    """
    return _submit_task_impl(
        req.session_id,
        req.submission_id,
        req.message,
        float(req.total_timeout),
        source="user",
    )


def submit_agent_notification_task(
    session_id: str,
    message: str,
    notice: Dict[str, Any],
    delivery_generation: int,
) -> Dict[str, Any]:
    """提交由后端自发启动的子Agent完成通知任务。"""
    return _submit_task_impl(
        session_id,
        f"agent-notify-{uuid.uuid4().hex[:12]}",
        message,
        1800.0,
        source="agent_notification",
        notice=notice,
        delivery_generation=delivery_generation,
    )


@router.get("/status")
def task_status(task_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
    """
    查询任务状态。

    - ?task_id=  → 返回该任务的注册表条目；未知 task_id 返回明确错误
    - ?session_id= → 返回该会话名下的任务列表（供前端恢复状态用）
    """
    with _tasks_lock:
        if task_id:
            entry = _tasks.get(task_id)
            if entry is None:
                return {"success": False, "error": f"未知任务: {task_id}"}
            return {"success": True, "task": dict(entry)}
        if session_id:
            tasks = [dict(t) for t in _tasks.values() if t["session_id"] == session_id]
            active_task_id = _active_tasks_by_session.get(session_id)
            active_task = _tasks.get(active_task_id) if active_task_id else None
            return {
                "success": True,
                "tasks": tasks,
                "active_task": dict(active_task) if active_task else None,
            }
    return {"success": False, "error": "需要提供 task_id 或 session_id 查询参数"}


def _run_task_loop(task_id: str, session_id: str, message: str, total_timeout: float) -> None:
    """运行后端自驱任务；失去 active 身份后旧 worker 仅负责退出。"""
    from base.session_context import conversation_context, task_source_context

    # 整段任务循环绑定会话与来源：日志/TODO/侧信道及工具策略全程隔离。
    task_entry = _tasks.get(task_id, {})
    source = task_entry.get("source", "user")
    epoch = task_entry.get("interrupt_epoch")
    with conversation_context(session_id), task_source_context(source, epoch):
        _run_task_loop_body(task_id, session_id, message, total_timeout)


def _run_task_loop_body(task_id: str, session_id: str, message: str, total_timeout: float) -> None:
    """任务循环实现体（调用方已绑定 conversation_context）。"""
    from ..core import get_session_manager
    from .chat import extract_stream_user_visible_content, run_single_round

    entry = _tasks[task_id]
    submission_id = entry["submission_id"]
    request_epoch = entry["interrupt_epoch"]
    status = "failed"
    error: Optional[str] = None
    rounds = 0
    started = time.monotonic()
    stream_snapshot = ""

    def _emitter(event: str, data: Dict[str, Any]) -> None:
        nonlocal stream_snapshot
        if event == "llm_chunk":
            reset = data.get("event") == "start"
            if reset:
                stream_snapshot = ""
            visible = extract_stream_user_visible_content(data.get("content") or "")
            if not reset and visible == stream_snapshot:
                return
            previous = stream_snapshot
            replace = not visible.startswith(previous)
            content = visible if replace else visible[len(previous):]
            stream_snapshot = visible
            _emit_active_task_event(
                "round_chunk",
                session_id,
                task_id,
                submission_id,
                entry["rounds"] + 1,
                {"content": content, "reset": reset, "replace": replace},
            )
            return

        # 命令意图 / 恶意通知 / 处置建议是异步旁路产物：研判可能晚于任务终态完成
        # （恶意研判甚至会主动中断该任务），迟到的事件仍要送达前端，不受 active 门限制
        if event in ("command_intent", "security_malicious", "security_remediation"):
            _emit_task_event(
                event, session_id, task_id, submission_id,
                entry["rounds"] + 1, data,
            )
            return
        _emit_active_task_event(
            event,
            session_id,
            task_id,
            submission_id,
            entry["rounds"] + 1,
            data,
        )

    try:
        session_manager = get_session_manager()
        target_state = session_manager.get_session(session_id)
        if target_state is None:
            raise RuntimeError(f"会话不存在: {session_id}")

        start_data: Dict[str, Any] = {
            "message": message,
            "source": entry.get("source", "user"),
        }
        if entry.get("notice") is not None:
            start_data["notice"] = entry["notice"]
        _emit_active_task_event(
            "task_started",
            session_id,
            task_id,
            submission_id,
            0,
            start_data,
        )

        pending_message: Optional[str] = message
        while _is_active_task(session_id, task_id):
            if target_state.interrupt_epoch != request_epoch:
                status = "interrupted"
                break

            if time.monotonic() - started >= total_timeout:
                status = "timeout"
                error = f"任务超时（total_timeout={total_timeout}s）"
                # 主任务与已异步派发的子Agent生命周期解耦；普通任务超时不终止后台子Agent。
                break

            result = run_single_round(
                session_id,
                pending_message,
                expected_epoch=request_epoch,
                event_emitter=_emitter,
                message_already_added=bool(entry.get("user_message_added")),
            )
            pending_message = None

            if (
                not _is_active_task(session_id, task_id)
                or result["status"] == "interrupted"
                or target_state.interrupt_epoch != request_epoch
            ):
                status = "interrupted"
                break

            if result["status"] == "error":
                status = "failed"
                error = result.get("error") or "未知错误"
                break

            rounds += 1
            clean_reply = result.get("clean_reply") or ""
            with _tasks_lock:
                if _active_tasks_by_session.get(session_id) != task_id:
                    status = "interrupted"
                    break
                entry["rounds"] = rounds
                if clean_reply:
                    entry["last_content"] = clean_reply

            _emit_active_task_event(
                "round_reply",
                session_id,
                task_id,
                submission_id,
                rounds,
                {
                    "content": clean_reply,
                    "raw_response": result.get("raw_reply") or "",
                    "sent_messages": result.get("sent_messages") or [],
                },
            )

            if not result["should_continue"]:
                status = "succeeded"
                break

    except Exception as e:
        status = "failed"
        error = str(e)
        log_error("TASK_LOOP_ERROR", f"任务 {task_id} 执行异常: {e}", e)
    finally:
        emit_finished = False
        with _tasks_lock:
            entry["worker_done"] = True
            is_authoritative = (
                entry["status"] == "running"
                and _active_tasks_by_session.get(session_id) == task_id
            )
            if is_authoritative:
                _active_tasks_by_session.pop(session_id, None)
                entry["status"] = status
                entry["rounds"] = rounds
                entry["finished_at"] = _now_iso()
                entry["error"] = error
                if not entry["finished_event_sent"]:
                    entry["finished_event_sent"] = True
                    emit_finished = True

        if emit_finished:
            finish_data: Dict[str, Any] = {"status": status, "rounds": rounds}
            if error:
                finish_data["error"] = error
            _emit_task_event(
                "task_finished",
                session_id,
                task_id,
                submission_id,
                rounds,
                finish_data,
            )

        # 此处已释放 _tasks_lock；通知管理器可安全检查忙闲并冲刷挂起通知。
        try:
            from ..agent_notification import on_task_finished
            on_task_finished(session_id, status)
        except Exception as e:
            log_error(
                "AGENT_NOTIFICATION_FLUSH_ERROR",
                f"任务 {task_id} 结束后冲刷子Agent通知失败: {e}",
                e,
            )
