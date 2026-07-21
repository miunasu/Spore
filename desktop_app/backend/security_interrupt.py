"""
恶意命令研判触发的会话自中断

供 AutoAgent 后台研判线程调用：当意图/恶意研判判定某条已异步执行的命令
为恶意时，命令本身已拦不住，只能立即中断当前会话，阻止 Agent 继续按恶意
方向推进。逻辑与 routes/chat.py 的 /interrupt 端点一致（bump epoch + 退役
task + 取消在途请求 + 终止子 Agent），全部同步且各自持锁，可从 daemon 线程调用。
"""
from typing import Optional

from base.logger import log_error, log_info


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
