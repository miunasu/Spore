"""桌面端异步子Agent派发的完成通知与自动投递管理。"""
from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from base.agent_database import AgentStatus, SubAgentDatabase
from base.logger import log_error, log_info


_RESULT_SUMMARY_LIMIT = 500
_INTERRUPT_FLUSH_DELAY = 0.35
_WATCHDOG_GRACE_PERIOD = 12.0
_state_lock = threading.Lock()


@dataclass
class _DispatchRecord:
    dispatch_id: str
    manager: Any
    task_ids: List[str]
    generation: int
    expected_epoch: Optional[int]
    done: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    timer: Optional[threading.Timer] = None


_dispatches: Dict[str, Dict[str, _DispatchRecord]] = {}
_pending: Dict[str, List[Dict[str, Any]]] = {}
_delivering: Set[str] = set()
_session_generations: Dict[str, int] = {}
_progress_by_session: Dict[str, Dict[str, Dict[str, Any]]] = {}
_interrupt_flush_timers: Dict[str, threading.Timer] = {}
_shutting_down = False


def _result_summary(database: SubAgentDatabase) -> str:
    text = str(database.final_result or database.error_message or "（无结果内容）").strip()
    if len(text) > _RESULT_SUMMARY_LIMIT:
        return text[:_RESULT_SUMMARY_LIMIT] + f"...[已截断 {len(text) - _RESULT_SUMMARY_LIMIT} 字符]"
    return text


def _progress_snapshot(record: _DispatchRecord) -> Dict[str, Any]:
    running = [task_id for task_id in record.task_ids if task_id not in record.done]
    return {
        "dispatch_id": record.dispatch_id,
        "done": len(record.done),
        "total": len(record.task_ids),
        "running": running,
    }


def _session_epoch_matches(session_id: str, expected_epoch: Optional[int]) -> bool:
    if expected_epoch is None:
        return True
    try:
        from .core import get_session_manager
        session_manager = get_session_manager()
        state = session_manager.get_session(session_id) if session_manager else None
        return bool(state and state.interrupt_epoch == expected_epoch)
    except Exception:
        return False


def initialize() -> None:
    """初始化本进程的通知代次；同进程重启前先清掉旧实例状态。"""
    shutdown()
    global _shutting_down
    with _state_lock:
        _shutting_down = False


def register_dispatch(
    session_id: str,
    manager: Any,
    tasks: List[Any],
    expected_epoch: Optional[int] = None,
) -> Tuple[
    str,
    Callable[[str, SubAgentDatabase], None],
    Callable[[], str],
    Callable[[], None],
]:
    """预登记异步派发，返回 dispatch_id、终态回调、原子启动与撤销函数。"""
    dispatch_id = uuid.uuid4().hex
    task_ids = [str(task.task_id) for task in tasks]

    with _state_lock:
        if _shutting_down or not _session_epoch_matches(session_id, expected_epoch):
            raise RuntimeError("当前会话已换代，取消过期的子Agent派发")
        generation = _session_generations.get(session_id, 0)
        record = _DispatchRecord(
            dispatch_id=dispatch_id,
            manager=manager,
            task_ids=task_ids,
            generation=generation,
            expected_epoch=expected_epoch,
        )
        _dispatches.setdefault(session_id, {})[dispatch_id] = record
        _progress_by_session.setdefault(session_id, {})[dispatch_id] = _progress_snapshot(record)

    def _callback(agent_id: str, database: SubAgentDatabase) -> None:
        _on_agent_complete(session_id, dispatch_id, agent_id, database)

    def _start() -> str:
        """在通知锁内复核代次并启动线程；clear_session 与此操作互斥。"""
        with _state_lock:
            current = _dispatches.get(session_id, {}).get(dispatch_id)
            if (
                _shutting_down
                or current is not record
                or _session_generations.get(session_id, 0) != generation
                or not _session_epoch_matches(session_id, expected_epoch)
            ):
                raise RuntimeError("当前会话已换代，取消过期的子Agent派发")

            manager.completion_callback = _callback
            manager_dispatch_id = manager.dispatch_tasks(tasks)

            from base.config import get_config
            timeout = max(0.0, float(get_config().multi_agent_total_timeout))
            if timeout > 0:
                timer = threading.Timer(timeout, _watchdog_timeout, args=(session_id, dispatch_id))
                timer.daemon = True
                timer.name = f"subagent-watchdog-{dispatch_id[:8]}"
                record.timer = timer
                timer.start()
            return manager_dispatch_id

    def _cancel() -> None:
        cancel_dispatch_registration(session_id, dispatch_id)

    return dispatch_id, _callback, _start, _cancel


def cancel_dispatch_registration(session_id: str, dispatch_id: str) -> None:
    """派发启动失败时撤销预登记并清理可能已登记的 manager。"""
    record = None
    with _state_lock:
        session_dispatches = _dispatches.get(session_id)
        if session_dispatches:
            record = session_dispatches.pop(dispatch_id, None)
            if not session_dispatches:
                _dispatches.pop(session_id, None)
        progress = _progress_by_session.get(session_id)
        if progress:
            progress.pop(dispatch_id, None)
            if not progress:
                _progress_by_session.pop(session_id, None)
    if record and record.timer:
        record.timer.cancel()
    if record:
        try:
            record.manager.terminate_own_agents()
            from base.agent_process import unregister_conversation_agent_manager
            unregister_conversation_agent_manager(session_id, record.manager)
        except Exception as e:
            log_error("SUBAGENT_DISPATCH_CANCEL_ERROR", f"撤销异步派发 {dispatch_id} 失败", e)


def _watchdog_timeout(session_id: str, dispatch_id: str) -> None:
    with _state_lock:
        record = _dispatches.get(session_id, {}).get(dispatch_id)
        manager = record.manager if record else None
    if manager is None:
        return

    log_info(
        f"异步子Agent派发 {dispatch_id} 超时，终止仍在运行的子Agent",
        context={"session_id": session_id, "dispatch_id": dispatch_id},
    )
    try:
        manager.terminate_own_agents()
    except Exception as e:
        log_error("SUBAGENT_WATCHDOG_ERROR", f"异步派发 {dispatch_id} watchdog 终止失败", e)

    timer = threading.Timer(
        _WATCHDOG_GRACE_PERIOD,
        _force_finalize_watchdog,
        args=(session_id, dispatch_id),
    )
    timer.daemon = True
    timer.name = f"subagent-watchdog-finalize-{dispatch_id[:8]}"
    timer.start()


def _force_finalize_watchdog(session_id: str, dispatch_id: str) -> None:
    """终止宽限期后为仍卡死的线程合成 INTERRUPTED 终态；迟到回调会被去重。"""
    with _state_lock:
        record = _dispatches.get(session_id, {}).get(dispatch_id)
        if record is None:
            return
        unfinished = [task_id for task_id in record.task_ids if task_id not in record.done]
        databases = dict(record.manager.agent_databases)

    for task_id in unfinished:
        database = databases.get(task_id)
        if database is None:
            continue
        if database.status not in (AgentStatus.COMPLETED, AgentStatus.ERROR, AgentStatus.INTERRUPTED):
            database.set_status(AgentStatus.INTERRUPTED)
            if not database.error_message:
                database.error_message = "异步子Agent执行超时，已由 watchdog 终止"
        _on_agent_complete(session_id, dispatch_id, task_id, database)


def _on_agent_complete(
    session_id: str,
    dispatch_id: str,
    agent_id: str,
    database: SubAgentDatabase,
) -> None:
    manager_to_unregister = None
    with _state_lock:
        session_dispatches = _dispatches.get(session_id)
        record = session_dispatches.get(dispatch_id) if session_dispatches else None
        if record is None or agent_id in record.done:
            return

        agent_result = {
            "task_id": agent_id,
            "status": database.status.value,
            "summary": _result_summary(database),
            "tokens": database.total_tokens,
        }
        record.done[agent_id] = agent_result
        progress = _progress_snapshot(record)
        _progress_by_session.setdefault(session_id, {})[dispatch_id] = progress
        _pending.setdefault(session_id, []).append({
            "dispatch_id": dispatch_id,
            "agent": agent_result,
            "progress": progress,
        })

        if len(record.done) >= len(record.task_ids):
            if record.timer:
                record.timer.cancel()
            manager_to_unregister = record.manager
            session_dispatches.pop(dispatch_id, None)
            if not session_dispatches:
                _dispatches.pop(session_id, None)

    if manager_to_unregister is not None:
        try:
            from base.agent_process import unregister_conversation_agent_manager
            unregister_conversation_agent_manager(session_id, manager_to_unregister)
        except Exception as e:
            log_error(
                "SUBAGENT_MANAGER_UNREGISTER_ERROR",
                f"注销异步派发 {dispatch_id} 的Agent管理器失败",
                e,
            )

    _try_flush(session_id)


def _aggregate_notice(
    entries: List[Dict[str, Any]],
    progress_by_dispatch: Dict[str, Dict[str, Any]],
) -> Tuple[str, Dict[str, Any]]:
    done = sum(item["done"] for item in progress_by_dispatch.values())
    total = sum(item["total"] for item in progress_by_dispatch.values())
    running: List[str] = []
    for item in progress_by_dispatch.values():
        running.extend(item["running"])

    agents = [entry["agent"] for entry in entries]
    lines = [
        "[系统通知] 子Agent完成通知（本消息由系统自动注入，非用户输入）",
        "",
        "本次新完成:",
    ]
    for agent in agents:
        lines.append(f"- {agent['task_id']} ({agent['status']}): {agent['summary']}")
    running_text = ", ".join(running) if running else "无"
    lines.extend([
        "",
        f"总体进度: 已完成 {done}/{total}；仍在运行: {running_text}",
        "",
        "处理要求: 若决定继续等待其余子Agent，直接输出 "
        "@SPORE:STOP_REASON=等待子Agent完成，不要重复派发、不要空转轮询；"
        "若已可基于现有结果推进，正常执行。",
    ])

    notice = {
        "kind": "subagent_completed",
        "agents": [
            {"task_id": agent["task_id"], "status": agent["status"]}
            for agent in agents
        ],
        "done": done,
        "total": total,
        "running": running,
    }
    return "\n".join(lines), notice


@contextmanager
def notification_delivery_guard(session_id: str, generation: int) -> Iterator[bool]:
    """让通知 generation 校验与 task 注册处于同一临界区。"""
    _state_lock.acquire()
    try:
        valid = (
            not _shutting_down
            and _session_generations.get(session_id, 0) == generation
            and session_id in _delivering
        )
        yield valid
    finally:
        _state_lock.release()


def _try_flush(session_id: str) -> None:
    """会话空闲时把当前 pending 合并成一个后端自发任务。"""
    from .routes.task import has_active_task

    with _state_lock:
        if _shutting_down or session_id in _delivering or not _pending.get(session_id):
            return
        if has_active_task(session_id):
            return
        entries = _pending.pop(session_id)
        _delivering.add(session_id)
        generation = _session_generations.get(session_id, 0)
        progress_snapshot = {
            dispatch_id: dict(progress)
            for dispatch_id, progress in _progress_by_session.get(session_id, {}).items()
        }

    def _deliver() -> None:
        result: Dict[str, Any] = {"success": False, "error": "通知已作废"}
        try:
            message, notice = _aggregate_notice(entries, progress_snapshot)
            from .routes.task import submit_agent_notification_task
            result = submit_agent_notification_task(
                session_id,
                message,
                notice,
                delivery_generation=generation,
            )
        except Exception as e:
            result = {"success": False, "error": str(e)}
            log_error(
                "SUBAGENT_NOTIFICATION_SUBMIT_ERROR",
                f"提交会话 {session_id} 的子Agent完成通知失败",
                e,
            )
        finally:
            retry = False
            with _state_lock:
                _delivering.discard(session_id)
                still_current = (
                    not _shutting_down
                    and _session_generations.get(session_id, 0) == generation
                )
                if not result.get("success") and still_current:
                    _pending.setdefault(session_id, [])[0:0] = entries
                    retry = True
                elif result.get("success") and still_current:
                    no_running = all(
                        not progress.get("running")
                        for progress in _progress_by_session.get(session_id, {}).values()
                    )
                    if no_running and not _pending.get(session_id) and not _dispatches.get(session_id):
                        _progress_by_session.pop(session_id, None)
            if retry:
                _schedule_idle_flush(session_id, generation)

    threading.Thread(
        target=_deliver,
        daemon=True,
        name=f"subagent-notify-{session_id[:8]}",
    ).start()


def _schedule_idle_flush(session_id: str, generation: Optional[int] = None) -> None:
    with _state_lock:
        if _shutting_down:
            return
        current_generation = _session_generations.get(session_id, 0)
        if generation is not None and generation != current_generation:
            return
        previous = _interrupt_flush_timers.pop(session_id, None)
        if previous:
            previous.cancel()

        def _flush() -> None:
            with _state_lock:
                _interrupt_flush_timers.pop(session_id, None)
                if (
                    _shutting_down
                    or _session_generations.get(session_id, 0) != current_generation
                ):
                    return
            _try_flush(session_id)

        timer = threading.Timer(_INTERRUPT_FLUSH_DELAY, _flush)
        timer.daemon = True
        timer.name = f"subagent-idle-flush-{session_id[:8]}"
        _interrupt_flush_timers[session_id] = timer
        timer.start()


def on_task_finished(session_id: str, status: str) -> None:
    """任务终态 hook；Stop 后短暂让路给用户，再检查是否可投递。"""
    if status == "interrupted":
        _schedule_idle_flush(session_id)
    else:
        _try_flush(session_id)


def clear_session(session_id: str) -> None:
    """作废会话全部派发、pending、在途投递与重试 timer。"""
    with _state_lock:
        records = list(_dispatches.pop(session_id, {}).values())
        _pending.pop(session_id, None)
        _progress_by_session.pop(session_id, None)
        _delivering.discard(session_id)
        _session_generations[session_id] = _session_generations.get(session_id, 0) + 1
        retry_timer = _interrupt_flush_timers.pop(session_id, None)
    if retry_timer:
        retry_timer.cancel()
    for record in records:
        if record.timer:
            record.timer.cancel()


def shutdown() -> None:
    """关闭通知管理器，作废所有旧回调并终止全部登记 manager。"""
    global _shutting_down
    with _state_lock:
        _shutting_down = True
        records = [record for group in _dispatches.values() for record in group.values()]
        retry_timers = list(_interrupt_flush_timers.values())
        known_sessions = set(_session_generations) | set(_dispatches) | set(_pending) | set(_delivering)
        for session_id in known_sessions:
            _session_generations[session_id] = _session_generations.get(session_id, 0) + 1
        _dispatches.clear()
        _pending.clear()
        _progress_by_session.clear()
        _delivering.clear()
        _interrupt_flush_timers.clear()

    for timer in retry_timers:
        timer.cancel()
    seen_managers = set()
    for record in records:
        if record.timer:
            record.timer.cancel()
        manager = record.manager
        if id(manager) in seen_managers:
            continue
        seen_managers.add(id(manager))
        try:
            manager.terminate_own_agents()
        except Exception as e:
            log_error("SUBAGENT_NOTIFICATION_SHUTDOWN_ERROR", "关闭异步子Agent失败", e)


def get_progress(session_id: str) -> Dict[str, Any]:
    """返回会话当前所有异步派发的只读进度快照。"""
    with _state_lock:
        progress_items = [
            dict(progress)
            for progress in _progress_by_session.get(session_id, {}).values()
        ]
        pending_count = len(_pending.get(session_id, []))

    return {
        "success": True,
        "session_id": session_id,
        "active_dispatches": progress_items,
        "pending_notifications": pending_count,
        "running_agents": sum(len(item["running"]) for item in progress_items),
    }
