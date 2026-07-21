"""
恶意命令研判触发的会话自中断

供 AutoAgent 后台研判线程调用：当意图/恶意研判判定某条已异步执行的命令
为恶意时，命令本身已拦不住，只能立即中断当前会话，阻止 Agent 继续按恶意
方向推进。逻辑与 routes/chat.py 的 /interrupt 端点一致（bump epoch + 退役
task + 取消在途请求 + 终止子 Agent），全部同步且各自持锁，可从 daemon 线程调用。
"""
from typing import Any, Dict, Optional

from base.logger import log_error, log_info


def emit_security_task_event(session_id: str, event: str, data: Dict[str, Any]) -> bool:
    """
    直接经 WS 桥发一条 task_event（不经 ConversationLoop.event_emitter）。

    熔断后的处置建议在会话循环终止之后才由二次研判产出，此时轮次的
    event_emitter 已被还原（SessionConversationLoop 无常驻 emitter），
    走常规 emit 会丢事件；前端对 command_intent/security_* 类事件仅按顶层
    session_id 路由、不依赖 task_id/submission_id，故这里用合成信封直投。
    """
    try:
        from .routes.task import _emit_task_event
        _emit_task_event(
            event=event,
            session_id=session_id,
            task_id="",
            submission_id="",
            round_num=0,
            data=data,
        )
        return True
    except Exception as e:
        log_error("SECURITY_EVENT_EMIT_ERROR", f"直投安全事件失败: {event}", e)
        return False


def interrupt_session_for_malicious(
    session_id: str,
    expected_epoch: Optional[int] = None,
) -> bool:
    """
    因恶意命令中断指定会话。返回是否实际执行了中断。

    expected_epoch: 派发研判时捕获的 interrupt_epoch。若当前 epoch 已变
        （用户已手动 Stop 或已进入新一轮），说明该会话状态已翻篇，不再补刀，
        避免误杀无关的新任务。
    """
    try:
        from .core import get_session_manager, get_conv_loop_manager
        from .routes.task import interrupt_session_task
        from base.agent_process import terminate_conversation_agents

        session_manager = get_session_manager()
        state = session_manager.get_session(session_id) if session_manager else None
        if state is None:
            return False

        # 竞态守护：研判返回前用户已手动中断/换代，则不再重复中断
        if expected_epoch is not None and state.interrupt_epoch != expected_epoch:
            log_info("SECURITY_INTERRUPT",
                     f"跳过恶意中断（epoch 已变: {expected_epoch} -> {state.interrupt_epoch}）: {session_id}")
            return False

        state.interrupt_epoch += 1
        # 先作废通知 generation；若旧投递已进入注册临界区，clear_session 会等待它
        # 完成，随后下面的 interrupt_session_task 必定能退役刚注册的通知任务。
        from .agent_notification import clear_session
        clear_session(session_id)
        interrupt_session_task(session_id)

        conv_loop_manager = get_conv_loop_manager()
        loop = conv_loop_manager._loops.get(session_id) if conv_loop_manager else None
        if loop is not None:
            try:
                loop.cancel_current_request()
            except Exception as e:
                log_error("SECURITY_INTERRUPT_CANCEL_ERROR", f"取消在途请求失败: {session_id}", e)

        try:
            terminate_conversation_agents(session_id)
        except Exception as e:
            log_error("SECURITY_INTERRUPT_AGENT_ERROR", f"终止子 Agent 失败: {session_id}", e)

        log_info("SECURITY_INTERRUPT", f"已因恶意命令中断会话: {session_id}")
        return True
    except Exception as e:
        log_error("SECURITY_INTERRUPT_ERROR", f"恶意命令中断会话异常: {session_id}", e)
        return False
