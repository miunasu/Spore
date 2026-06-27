"""
对话 API - 复用 base/conversation_loop.py 的 ConversationLoop
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor
import re

from ..core import get_instances, switch_session, create_session, delete_session, get_session_manager
from base.logger import log_info, log_error
from base.agent_types import get_tools_for_mode
from base.tools import TOOL_DEFINITIONS
from base.text_protocol import ProtocolManager
from base.prompt_loader import load_system_prompt
from base.utils import clear_last_todo_content
from base.todo_manager import todo_write
from base.agent_process import get_current_agent_manager
from base.interrupt_handler import get_interrupt_handler
from AutoAgent import select_context_mode

router = APIRouter()

# 线程池用于执行阻塞的对话操作
# 增加线程数以支持多 Agent 并发
_executor = ThreadPoolExecutor(max_workers=16)


def extract_user_visible_content(reply: str) -> str:
    """
    从 AI 回复中提取用户可见的内容，去除协议标记
    
    协议标记包括：
    - @SPORE:REPLY_START ... @SPORE:REPLY_END (提取其中的内容作为用户可见内容)
    - @SPORE:TODO_START ... @SPORE:TODO_END
    - @SPORE:ACTION_SINGLE/SEQUENCE/PARALLEL_START ... END
    - ### RULE_REMINDER
    - @SPORE:FINAL@
    - @SPORE:CONTENT_END
    """
    if not reply:
        return ""
    
    visible_lines = []
    in_protocol_block = False
    lines = reply.split('\n')

    for i, line in enumerate(lines):
        if line.strip() == "@SPORE:REPLY_START":
            reply_lines = []
            for candidate in lines[i + 1:]:
                if candidate.strip() == "@SPORE:REPLY_END":
                    return "\n".join(reply_lines).strip()
                reply_lines.append(candidate)
            return "\n".join(reply_lines).strip()
    
    for line in lines:
        stripped = line.strip()

        if re.match(r"^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_START$", stripped):
            in_protocol_block = True
            continue

        if re.match(r"^@SPORE:(TODO|ACTION_SINGLE|ACTION_SEQUENCE|ACTION_PARALLEL)_END$", stripped):
            in_protocol_block = False
            continue

        if stripped in {"@SPORE:FINAL@", "@SPORE:CONTENT_START", "@SPORE:CONTENT_END"}:
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


class ChatResponse(BaseModel):
    """聊天响应模型"""
    status: str
    content: Optional[str] = None
    message: Optional[str] = None
    should_continue: bool = False
    sent_messages: Optional[list] = None  # 实际发送给LLM的消息（用于前端显示）
    raw_response: Optional[str] = None  # LLM返回的原始响应（包含协议标记）


@router.post("/send", response_model=ChatResponse)
async def send_message(req: ChatRequest):
    """
    发送消息 - 使用独立的 ConversationLoop 实例
    每个会话有自己的 ConversationLoop，实现真正的并发处理
    
    如果 message 为空，则不添加用户消息，直接继续对话（用于连续输出）
    """
    from ..core import get_conv_loop_manager
    
    ipc_manager, session_manager, _, _, config = get_instances()[:5]
    conv_loop_manager = get_conv_loop_manager()
    
    if not conv_loop_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    # 确定目标会话 ID
    conversation_id = req.conversation_id or session_manager.current_session_id
    
    # 确保会话存在
    if conversation_id not in session_manager.list_sessions():
        session_manager.create_session(conversation_id)
    
    # 切换到目标会话（确保 session_manager.current 指向正确的会话）
    # 这样 load_system_prompt() 中的 get_current_todos_for_prompt() 才能获取正确的TODO
    session_manager.switch_session(conversation_id)
    
    # 获取该会话的状态
    target_state = session_manager.get_session(conversation_id)
    if not target_state:
        raise HTTPException(status_code=404, detail=f"会话不存在: {conversation_id}")

    request_epoch = target_state.interrupt_epoch
        
    # 根据会话的模式确定工具集
    if target_state.context_mode == "auto" and req.message.strip():
        selected_mode = select_context_mode(req.message)
        current_tools = get_tools_for_mode(selected_mode)
    else:
        current_tools = get_tools_for_mode(target_state.context_mode)
    
    # 准备系统提示和工具定义
    tool_definitions = {
        name: TOOL_DEFINITIONS[name]
        for name in current_tools
        if name in TOOL_DEFINITIONS
    }
    base_prompt = load_system_prompt() or ""
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(
        base_prompt,
        tool_definitions,
    )
    
    # 获取或创建该会话的 ConversationLoop 实例
    conv_loop = conv_loop_manager.get_loop(
        session_id=conversation_id,
        system_prompt=system_prompt,
        tool_names=current_tools
    )
    
    # 更新 ConversationLoop 的配置（可能会话模式改变了）
    conv_loop.system_prompt = system_prompt
    conv_loop.tool_names = current_tools
    
    # 只有非空消息才添加用户消息
    if req.message.strip():
        target_state.add_user_message(req.message)
    
    def _do_chat():
        """在线程池中执行的阻塞操作"""
        # 现在每个会话有独立的 conv_loop，不需要担心并发问题
        # conv_loop.state 绑定到特定的会话状态，不会被其他请求影响
        
        # 管理上下文长度
        conv_loop.manage_context_length()
        
        # 修复不完整的消息
        conv_loop.fix_incomplete_messages()
        
        # 发送请求并获取响应
        return conv_loop.send_chat_request(conversation_id=conversation_id)
    
    try:
        # 在线程池中执行阻塞操作
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(_executor, _do_chat)

        if target_state.interrupt_epoch != request_epoch:
            return ChatResponse(status="interrupted")
        
        if response is None:
            return ChatResponse(status="interrupted")
        
        if response.get("status") == "error":
            return ChatResponse(
                status="error",
                message=response.get("data", "未知错误")
            )
        
        # 处理响应
        reply_data = response.get("data", {})
        reply = reply_data.get("content", "")
        sent_messages = reply_data.get("sent_messages", [])

        if target_state.interrupt_epoch != request_epoch:
            return ChatResponse(status="interrupted")
        
        # 使用文本协议验证和处理响应
        result = conv_loop.validate_and_check_response(reply)
        
        # 提取用户可见内容（去除协议标记）
        clean_reply = extract_user_visible_content(reply)
                
        return ChatResponse(
            status="success",
            content=clean_reply,
            should_continue=(result == "continue"),
            sent_messages=sent_messages,  # 实际发送给LLM的消息
            raw_response=reply  # LLM返回的原始响应（包含协议标记）
        )
    
    except Exception as e:
        log_error("CHAT_SEND_ERROR", f"Error in send_message: {str(e)}", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/interrupt")
def interrupt(req: InterruptRequest = InterruptRequest()):
    """
    中断当前请求 - 包括主 Agent 和所有子 Agent
    """
    _, session_manager, _, conv_loop, _ = get_instances()
    from ..core import get_conv_loop_manager
    conv_loop_manager = get_conv_loop_manager()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")

    conversation_id = req.conversation_id or session_manager.current_session_id
    target_state = session_manager.get_session(conversation_id)
    if not target_state:
        raise HTTPException(status_code=404, detail=f"会话不存在: {conversation_id}")

    target_state.interrupt_epoch += 1

    target_loop = None
    if conv_loop_manager:
        target_loop = conv_loop_manager._loops.get(conversation_id)
    if target_loop is None:
        target_loop = conv_loop
    
    try:
        # 1. 调用 conv_loop 的中断处理方法（处理主 Agent）
        if target_loop:
            target_loop.handle_keyboard_interrupt()
        
        # 2. 直接终止当前活动的Agent管理器（处理子 Agent）
        agent_manager = get_current_agent_manager()
        if agent_manager:
            agent_manager.terminate_all()
        
        # 3. 同时调用 InterruptHandler 广播终止信号（兼容性）
        interrupt_handler = get_interrupt_handler()
        interrupt_handler.broadcast_termination()
        
        return {"success": True, "message": "中断请求已发送（包括所有子 Agent）"}
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
        if msg.get("role") == "assistant":
            clean_content = extract_user_visible_content(msg.get("content", ""))
            if clean_content:  # 只添加有内容的消息
                clean_messages.append({
                    "role": msg["role"],
                    "content": clean_content
                })
        else:
            clean_messages.append(msg)
    
    return {"messages": clean_messages}


@router.post("/new")
def new_conversation():
    """新建对话 - 清空当前会话状态"""
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        clear_last_todo_content()
        todo_write([])
        
        return {"success": True, "message": "已创建新对话"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



class SwitchSessionRequest(BaseModel):
    """切换会话请求"""
    session_id: str


@router.post("/session/switch")
def switch_session_route(req: SwitchSessionRequest) -> Dict[str, Any]:
    """切换到指定会话"""
    return switch_session(req.session_id)


@router.post("/session/create")
def create_session_route(req: SwitchSessionRequest) -> Dict[str, Any]:
    """创建新会话"""
    return create_session(req.session_id)


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
