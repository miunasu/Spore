"""
对话 API - 复用 base/conversation_loop.py 的 ConversationLoop
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
import re

from ..core import (
    create_session,
    delete_session,
    get_instances,
    get_session_manager,
    reset_session_runtime,
    switch_session,
)
from base.logger import log_info, log_error
from base.agent_types import get_tools_for_mode
from base.tools import TOOL_DEFINITIONS
from base.text_protocol import ProtocolManager
from base.prompt_loader import load_system_prompt
from base.utils import clear_last_todo_content
from base.todo_manager import todo_write
from AutoAgent import select_context_mode
from base.session_context import conversation_context

router = APIRouter()

# 线程池用于执行阻塞的对话操作
# 增加线程数以支持多 Agent 并发
_executor = ThreadPoolExecutor(max_workers=16)


def is_stop_reason_line(stripped: str) -> bool:
    return bool(re.match(r"^@SPORE:STOP_REASON\s*=", stripped or ""))


def is_hidden_protocol_line(stripped: str) -> bool:
    if is_stop_reason_line(stripped):
        return True
    return stripped in {
        "@SPORE:REPLY_START",
        "@SPORE:REPLY_END",
        "@SPORE:CONTENT_START",
        "@SPORE:CONTENT_END",
        "@SPORE:RESULT",
    }


def extract_user_visible_content(reply: str) -> str:
    """
    从 AI 回复中提取用户可见的内容，去除协议标记

    协议标记包括：
    - @SPORE:REPLY_START ... @SPORE:REPLY_END (提取其中的内容作为用户可见内容)
    - @SPORE:TODO_START ... @SPORE:TODO_END
    - @SPORE:ACTION_SINGLE/SEQUENCE/PARALLEL_START ... END
    - ### RULE_REMINDER
    - @SPORE:STOP_REASON=<自然语言原因>
    - @SPORE:CONTENT_END

    结束轮展示优先级：
    1. 存在 REPLY 块时，只展示 REPLY 内容（忽略 STOP_REASON）
    2. 没有 REPLY、只有 STOP_REASON 时，展示 STOP_REASON 内容
    3. 都没有时，过滤协议标记后展示剩余文本
    """
    if not reply:
        return ""

    visible_lines = []
    in_protocol_block = False
    lines = reply.split('\n')

    # 收集所有 REPLY 块（可能有多个），按出现顺序拼接展示
    reply_segments = []
    current_segment: Optional[list] = None
    has_reply_block = False
    for line in lines:
        stripped = line.strip()
        if current_segment is None:
            if stripped == "@SPORE:REPLY_START":
                has_reply_block = True
                current_segment = []
            continue
        if stripped == "@SPORE:REPLY_END" or is_stop_reason_line(stripped):
            reply_segments.append("\n".join(current_segment).strip())
            current_segment = None
            continue
        if is_hidden_protocol_line(stripped):
            continue
        current_segment.append(line)
    if current_segment is not None:
        reply_segments.append("\n".join(current_segment).strip())

    # 有 REPLY 块时优先只展示 REPLY（结束轮同时带 STOP_REASON 时不显示原因文本）
    if has_reply_block:
        return "\n\n".join(seg for seg in reply_segments if seg)

    # 无 REPLY 时，STOP_REASON 的自然语言原因作为用户可见内容
    try:
        from base.text_protocol import extract_stop_reason_blocks
        stop_blocks, stop_err = extract_stop_reason_blocks(reply)
        if not stop_err and stop_blocks:
            reason = (stop_blocks[0].get("content") or "").strip()
            if reason:
                return reason
    except Exception:
        pass

    for line in lines:
        stripped = line.strip()

        if re.match(r"^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_START$", stripped):
            in_protocol_block = True
            continue

        if re.match(r"^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_END$", stripped):
            in_protocol_block = False
            continue

        if is_hidden_protocol_line(stripped):
            if is_stop_reason_line(stripped):
                break
            continue

        if stripped.startswith('### RULE_REMINDER') or in_protocol_block:
            continue

        visible_lines.append(line)

    return '\n'.join(visible_lines).strip()


class ChatRequest(BaseModel):
    """聊天请求模型"""
    message: str
    conversation_id: Optional[str] = None  # 新增：指定会话 ID


class InterruptRequest(BaseModel):
    """中断请求模型"""
    conversation_id: Optional[str] = None


class ConversationRequest(BaseModel):
    conversation_id: Optional[str] = None


class ChatResponse(BaseModel):
    """聊天响应模型"""
    status: str
    content: Optional[str] = None
    message: Optional[str] = None
    should_continue: bool = False
    sent_messages: Optional[list] = None  # 实际发送给LLM的消息（用于前端显示）
    raw_response: Optional[str] = None  # LLM返回的原始响应（包含协议标记）


class SessionNotFoundError(Exception):
    """目标会话不存在（且无法创建）"""
    pass


def run_single_round(
    conversation_id: str,
    message: Optional[str] = None,
    expected_epoch: Optional[int] = None,
    event_emitter=None,
    message_already_added: bool = False,
) -> Dict[str, Any]:
    """
    执行一轮对话（阻塞调用，应在线程池中运行）。

    这是 /api/chat/send 与 /api/task/submit 任务循环共用的唯一循环体实现：
    准备会话/系统提示 → （可选）添加用户消息 → LLM 请求 →
    validate_and_check_response（内部同步执行 ACTION 工具）。
    不允许在别处出现第三份循环实现。

    Args:
        conversation_id: 目标会话 ID（不存在则创建）
        message: 用户消息；None 或空串表示不添加用户消息，直接继续对话（心跳轮）

    Returns:
        {
            "status": "success" | "error" | "interrupted",
            "should_continue": bool,        # 仅 status=="success" 时有意义
            "clean_reply": str,             # 剥去协议标记后的用户可见内容
            "raw_reply": str,               # LLM 原始响应（含协议标记）
            "sent_messages": list,          # 实际发送给 LLM 的消息
            "error": Optional[str],         # 仅 status=="error" 时有值
        }
    """
    from ..core import get_conv_loop_manager

    ipc_manager, session_manager, _, _, config = get_instances()[:5]
    conv_loop_manager = get_conv_loop_manager()

    if not conv_loop_manager or not session_manager:
        raise RuntimeError("后端未初始化")

    def _result(status: str, should_continue: bool = False, clean_reply: str = "",
                raw_reply: str = "", sent_messages: Optional[list] = None,
                error: Optional[str] = None) -> Dict[str, Any]:
        return {
            "status": status,
            "should_continue": should_continue,
            "clean_reply": clean_reply,
            "raw_reply": raw_reply,
            "sent_messages": sent_messages or [],
            "error": error,
        }

    # Parameter is `message`; body uses message_text for optional/empty-safe access.
    message_text = message or ""

    # 确保会话存在
    if conversation_id not in session_manager.list_sessions():
        session_manager.create_session(conversation_id)

    # 注意：不再 switch_session(conversation_id)。
    # 任务/流水线并发时切换全局 current 会污染其它会话的 TODO/CLI 侧信道。
    # load_system_prompt / TODO 通过下方 conversation_context(conversation_id) 绑定。

    # 获取该会话的状态
    target_state = session_manager.get_session(conversation_id)
    if not target_state:
        raise SessionNotFoundError(f"会话不存在: {conversation_id}")

    request_epoch = (
        target_state.interrupt_epoch if expected_epoch is None else expected_epoch
    )

    # Resolve tools via mode baseline + tool policy (session or global scope)
    from base.tool_policy import (
        effective_mode_name,
        filter_tool_definitions,
        resolve_enabled_tool_names,
        resolve_mode_policy,
    )

    selected_mode = None
    if target_state.context_mode == "auto" and message_text.strip():
        selected_mode = select_context_mode(message_text)
        target_state.selected_auto_mode = selected_mode
    elif target_state.context_mode == "auto":
        selected_mode = getattr(target_state, "selected_auto_mode", None) or "strong_context"
    else:
        target_state.selected_auto_mode = None

    eff_mode = effective_mode_name(target_state.context_mode, selected_mode)
    mode_policy = resolve_mode_policy(eff_mode, getattr(target_state, "tool_policies", None))
    current_tools = resolve_enabled_tool_names(eff_mode, mode_policy)
    tool_definitions = filter_tool_definitions(eff_mode, mode_policy)

    with conversation_context(conversation_id):
        base_prompt = load_system_prompt() or ""
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(
        base_prompt,
        tool_definitions,
    )

    # Get or create this session's ConversationLoop
    conv_loop = conv_loop_manager.get_loop(
        session_id=conversation_id,
        system_prompt=system_prompt,
        tool_names=current_tools,
    )
    # Keep loop fields in sync; runtime resolution prefers state policy
    conv_loop.tool_names = current_tools
    conv_loop.system_prompt = system_prompt

    with conv_loop.execution_lock:
        if target_state.interrupt_epoch != request_epoch:
            return _result("interrupted")

        # 更新 ConversationLoop 的配置（可能会话模式改变了）
        conv_loop.system_prompt = system_prompt
        conv_loop.tool_names = current_tools

        # 首轮 user 消息只在这里添加；它属于用户已确认的输入，中断不回滚。
        if message_text.strip() and not message_already_added:
            target_state.add_user_message(message_text)

        checkpoint = {
            "messages": copy.deepcopy(target_state.messages),
            "llm_reply_count": target_state.llm_reply_count,
            "last_answer": target_state.last_answer,
            "current_answer": target_state.current_answer,
            "todos": copy.deepcopy(target_state.todos),
            "last_input_tokens": target_state.last_input_tokens,
            "last_output_tokens": target_state.last_output_tokens,
            "cumulative_input_tokens": target_state.cumulative_input_tokens,
            "cumulative_output_tokens": target_state.cumulative_output_tokens,
        }

        previous_emitter = getattr(conv_loop, "event_emitter", None)
        conv_loop.event_emitter = event_emitter

        def _rollback_interrupted_round() -> None:
            target_state.messages = checkpoint["messages"]
            target_state.llm_reply_count = checkpoint["llm_reply_count"]
            target_state.last_answer = checkpoint["last_answer"]
            target_state.current_answer = checkpoint["current_answer"]
            if target_state.todos != checkpoint["todos"]:
                todo_write(checkpoint["todos"], session_id=conversation_id)
            else:
                target_state.todos = checkpoint["todos"]
            target_state.last_input_tokens = checkpoint["last_input_tokens"]
            target_state.last_output_tokens = checkpoint["last_output_tokens"]
            target_state.cumulative_input_tokens = checkpoint["cumulative_input_tokens"]
            target_state.cumulative_output_tokens = checkpoint["cumulative_output_tokens"]

        try:
            with conversation_context(conversation_id):
                conv_loop.manage_context_length()
                conv_loop.fix_incomplete_messages()
                response = conv_loop.send_chat_request(
                    conversation_id=conversation_id,
                    expected_epoch=request_epoch,
                )

            if target_state.interrupt_epoch != request_epoch or response is None:
                _rollback_interrupted_round()
                return _result("interrupted")

            if response.get("status") == "error":
                return _result("error", error=response.get("data", "未知错误"))

            reply_data = response.get("data", {})
            reply = reply_data.get("content", "")
            sent_messages = reply_data.get("sent_messages", [])

            if target_state.interrupt_epoch != request_epoch:
                _rollback_interrupted_round()
                return _result("interrupted")

            with conversation_context(conversation_id):
                result = conv_loop.validate_and_check_response(reply)

            # 覆盖 response 刚通过检查、用户随即点 Stop 的临界窗口。
            if target_state.interrupt_epoch != request_epoch:
                _rollback_interrupted_round()
                return _result("interrupted")

            clean_reply = extract_user_visible_content(reply)
            return _result(
                "success",
                should_continue=(result == "continue"),
                clean_reply=clean_reply,
                raw_reply=reply,
                sent_messages=sent_messages,
            )
        finally:
            if getattr(conv_loop, "event_emitter", None) is event_emitter:
                conv_loop.event_emitter = previous_emitter


@router.post("/send", response_model=ChatResponse)
async def send_message(req: ChatRequest):
    """
    发送消息 - 使用独立的 ConversationLoop 实例
    每个会话有自己的 ConversationLoop，实现真正的并发处理

    如果 message 为空，则不添加用户消息，直接继续对话（用于连续输出）
    单步语义不变：内部与任务循环共用 run_single_round。
    """
    from ..core import get_conv_loop_manager

    _, session_manager, _, _, _ = get_instances()[:5]
    conv_loop_manager = get_conv_loop_manager()

    if not conv_loop_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")

    # 确定目标会话 ID
    conversation_id = req.conversation_id or session_manager.current_session_id

    try:
        # 在线程池中执行阻塞的单轮循环体
        loop = asyncio.get_event_loop()
        round_result = await loop.run_in_executor(
            _executor, run_single_round, conversation_id, req.message
        )
    except SessionNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        log_error("CHAT_SEND_ERROR", f"Error in send_message: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))

    if round_result["status"] == "interrupted":
        return ChatResponse(status="interrupted")

    if round_result["status"] == "error":
        return ChatResponse(
            status="error",
            message=round_result.get("error") or "未知错误"
        )

    return ChatResponse(
        status="success",
        content=round_result["clean_reply"],
        should_continue=round_result["should_continue"],
        sent_messages=round_result["sent_messages"],  # 实际发送给LLM的消息
        raw_response=round_result["raw_reply"]  # LLM返回的原始响应（包含协议标记）
    )


@router.post("/interrupt")
def interrupt(req: InterruptRequest = InterruptRequest()):
    """中断当前主Agent任务；后台异步子Agent继续运行。"""
    from ..core import get_conv_loop_manager
    session_manager = get_session_manager()
    conv_loop_manager = get_conv_loop_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")

    conversation_id = req.conversation_id or session_manager.current_session_id
    target_state = session_manager.get_session(conversation_id)
    if not target_state:
        raise HTTPException(status_code=404, detail=f"会话不存在: {conversation_id}")

    try:
        from .task import interrupt_session_task

        target_state.interrupt_epoch += 1
        retired_task = interrupt_session_task(conversation_id)

        target_loop = (
            conv_loop_manager._loops.get(conversation_id)
            if conv_loop_manager else None
        )
        request_cancelled = target_loop.cancel_current_request() if target_loop else False

        return {
            "success": True,
            "message": "对话已立即中断，旧请求回复将被丢弃",
            "task_id": retired_task.get("task_id") if retired_task else None,
            "submission_id": retired_task.get("submission_id") if retired_task else None,
            "interrupt_epoch": target_state.interrupt_epoch,
            "request_cancelled": request_cancelled,
            "agents_terminated": False,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
def get_history(raw: bool = False, session_id: Optional[str] = None) -> Dict[str, Any]:
    """获取对话历史
    
    Args:
        raw: 是否返回原始内容（包含协议标记），默认 False 返回处理后的干净内容
        session_id: 会话 ID，如果不指定则使用当前会话
    """
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    # 获取指定会话的状态
    if session_id:
        target_state = session_manager.get_session(session_id)
        if not target_state:
            raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")
    else:
        target_state = session_manager.current
    
    if raw:
        # 返回原始消息（包含协议标记）
        return {"messages": target_state.messages}
    
    # 处理消息，提取用户可见内容
    clean_messages = []
    for msg in target_state.messages:
        content = msg.get("content", "")
        if msg.get("role") == "assistant":
            clean_content = extract_user_visible_content(content)
            if clean_content:  # 只添加有内容的消息
                clean_messages.append({
                    "role": msg["role"],
                    "content": clean_content
                })
        elif msg.get("role") == "user" and content.lstrip().startswith("[系统通知]"):
            first_line = content.strip().splitlines()[0]
            clean_messages.append({
                "role": "system",
                "content": first_line.replace("[系统通知]", "", 1).strip(),
            })
        else:
            clean_messages.append(msg)
    
    return {"messages": clean_messages}


@router.post("/new")
def new_conversation(req: Optional[ConversationRequest] = None):
    """新建对话 - 清空目标会话状态"""
    session_manager = get_session_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        conversation_id = (req.conversation_id if req else None) or session_manager.current_session_id
        target_state = session_manager.get_session(conversation_id)
        if not target_state:
            target_state = session_manager.create_session(conversation_id)

        reset_session_runtime(conversation_id)
        clear_last_todo_content()
        todo_write([], session_id=conversation_id)

        # 新对话从零开始：清空该会话的对话点快照，避免跨对话累积导致 rewind 语义错乱
        from base.backup_manager import get_backup_manager
        get_backup_manager().clear_checkpoints(conversation_id)

        return {"success": True, "message": "已创建新对话"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



class SwitchSessionRequest(BaseModel):
    """切换会话请求"""
    session_id: str


class CreateSessionRequest(BaseModel):
    """创建会话请求"""
    session_id: str
    # UI 手动新建会话默认切到新会话；流水线/API 应传 False，避免抢占 current
    switch_current: bool = True


@router.post("/session/switch")
def switch_session_route(req: SwitchSessionRequest) -> Dict[str, Any]:
    """切换到指定会话"""
    return switch_session(req.session_id)


@router.post("/session/create")
def create_session_route(req: CreateSessionRequest) -> Dict[str, Any]:
    """创建新会话"""
    return create_session(req.session_id, switch_current=req.switch_current)


@router.post("/session/delete")
def delete_session_route(req: SwitchSessionRequest) -> Dict[str, Any]:
    """删除会话"""
    return delete_session(req.session_id)


@router.get("/session/list")
def list_sessions() -> Dict[str, Any]:
    """列出所有会话"""
    manager = get_session_manager()
    if not manager:
        return {"sessions": [], "current": None}
    return {
        "sessions": manager.list_sessions(),
        "current": manager.current_session_id
    }
