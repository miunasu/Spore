"""
对话 API - 复用 base/conversation_loop.py 的 ConversationLoop
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..core import get_instances
import re

router = APIRouter()

# 线程池用于执行阻塞的对话操作
# 增加线程数以支持多 Agent 并发
_executor = ThreadPoolExecutor(max_workers=16)


def extract_user_visible_content(reply: str) -> str:
    """
    从 AI 回复中提取用户可见的内容，去除协议标记
    
    协议标记包括：
    - @SPORE:REPLY ... (提取其中的内容作为用户可见内容)
    - @SPORE:TODO ... (到下一个标记或文本结束)
    - @SPORE:ACTION ... (到 @SPORE:CONTENT_END 或下一个标记或文本结束)
    - ### RULE_REMINDER
    - @SPORE:FINAL@
    - @SPORE:CONTENT_END
    """
    if not reply:
        return ""
    
    # 优先提取 @SPORE:REPLY 块内容
    reply_marker = "@SPORE:REPLY"
    reply_pos = -1
    lines = reply.split('\n')
    for i, line in enumerate(lines):
        # 只匹配独占一行的 @SPORE:REPLY（避免误匹配回复内容中提到的标记）
        if line.strip() == reply_marker:
            reply_pos = i
            break
    
    if reply_pos >= 0:
        # 找到 REPLY 块，提取其内容
        reply_lines = []
        end_markers = ['@SPORE:ACTION', '@SPORE:TODO', '@SPORE:RESULT', '@SPORE:FINAL@']
        for i in range(reply_pos + 1, len(lines)):
            line = lines[i]
            stripped = line.strip()
            # 检查是否遇到结束标记（也要求独占一行）
            is_end = False
            for marker in end_markers:
                if stripped == marker:
                    is_end = True
                    break
            if is_end:
                break
            reply_lines.append(line)
        return '\n'.join(reply_lines).strip()
    
    # 没有 REPLY 块，使用原有逻辑
    # 先找到 @SPORE:ACTION 的位置，截取之前的内容
    action_pos = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('@SPORE:ACTION'):
            action_pos = i
            break
    
    # 如果有 ACTION，只处理 ACTION 之前的内容
    if action_pos >= 0:
        lines = lines[:action_pos]
    
    visible_lines = []
    in_todo_block = False
    
    # 协议结束标记
    end_markers = ['@SPORE:FINAL@', '@SPORE:CONTENT_END']
    
    for line in lines:
        stripped = line.strip()
        
        # 检查是否是 TODO 块开始
        if stripped.startswith('@SPORE:TODO'):
            in_todo_block = True
            continue
        
        # 检查是否是 RULE_REMINDER（单行跳过）
        if stripped.startswith('### RULE_REMINDER'):
            continue
        
        # TODO 块内：直到遇到下一个标记或空行结束
        if in_todo_block:
            if stripped.startswith('@SPORE:'):
                in_todo_block = False
                # 如果是其他协议标记，继续跳过
                if stripped.startswith('@SPORE:TODO') or stripped.startswith('### RULE_REMINDER'):
                    continue
            elif stripped == '':
                # 空行可能是 TODO 块结束，也可能是 TODO 内的空行
                # 保守处理：继续跳过
                continue
            else:
                # TODO 块内的内容，跳过
                continue
        
        # 跳过/清理结束标记
        has_marker = False
        for marker in end_markers:
            if marker in line:
                has_marker = True
                line = line.replace(marker, '')
                break
        
        if has_marker:
            if line.strip():
                visible_lines.append(line)
            continue
        
        # 普通内容
        visible_lines.append(line)
    
    return '\n'.join(visible_lines).strip()


class ChatRequest(BaseModel):
    """聊天请求模型"""
    message: str


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
    发送消息 - 复用 ConversationLoop 的对话逻辑
    使用线程池异步执行，避免阻塞其他 API 请求
    
    如果 message 为空，则不添加用户消息，直接继续对话（用于连续输出）
    """
    ipc_manager, session_manager, _, conv_loop, config = get_instances()
    
    if not conv_loop:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    # 获取当前会话状态
    state = session_manager.current
    
    # 根据当前会话的模式更新工具集
    from base.agent_types import get_tools_for_mode
    from base.tools import TOOL_DEFINITIONS
    from base.text_protocol import ProtocolManager
    from base.prompt_loader import load_system_prompt
    from AutoAgent import select_context_mode
    
    # 如果是auto模式，先判断应该使用哪种模式
    if state.context_mode == "auto" and req.message.strip():
        selected_mode = select_context_mode(req.message)
        current_tools = get_tools_for_mode(selected_mode)
    else:
        current_tools = get_tools_for_mode(state.context_mode)
    
    # 更新工具集和系统提示
    tool_definitions = {
        name: TOOL_DEFINITIONS[name]
        for name in current_tools
        if name in TOOL_DEFINITIONS
    }
    base_prompt = load_system_prompt() or ""
    protocol_manager = ProtocolManager()
    system_prompt = protocol_manager.inject_protocol(base_prompt, tool_definitions)
    conv_loop.system_prompt = system_prompt
    conv_loop.tool_names = current_tools
    
    # 只有非空消息才添加用户消息
    if req.message.strip():
        state.add_user_message(req.message)
    
    def _do_chat():
        """在线程池中执行的阻塞操作"""
        # 管理上下文长度
        conv_loop.manage_context_length()
        
        # 修复不完整的消息
        conv_loop.fix_incomplete_messages()
        
        # 发送请求并获取响应（复用 conv_loop.send_chat_request）
        return conv_loop.send_chat_request()
    
    try:
        # 在线程池中执行阻塞操作
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(_executor, _do_chat)
        
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
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/interrupt")
def interrupt():
    """
    中断当前请求 - 包括主 Agent 和所有子 Agent
    """
    _, _, _, conv_loop, _ = get_instances()
    
    if not conv_loop:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    try:
        # 1. 调用 conv_loop 的中断处理方法（处理主 Agent）
        conv_loop.handle_keyboard_interrupt()
        
        # 2. 直接终止当前活动的Agent管理器（处理子 Agent）
        from base.agent_process import get_current_agent_manager
        agent_manager = get_current_agent_manager()
        if agent_manager:
            agent_manager.terminate_all()
        
        # 3. 同时调用 InterruptHandler 广播终止信号（兼容性）
        from base.interrupt_handler import get_interrupt_handler
        interrupt_handler = get_interrupt_handler()
        interrupt_handler.broadcast_termination()
        
        return {"success": True, "message": "中断请求已发送（包括所有子 Agent）"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
def get_history(raw: bool = False) -> Dict[str, Any]:
    """获取对话历史
    
    Args:
        raw: 是否返回原始内容（包含协议标记），默认 False 返回处理后的干净内容
    """
    _, session_manager, _, _, _ = get_instances()
    
    if not session_manager:
        raise HTTPException(status_code=503, detail="后端未初始化")
    
    if raw:
        # 返回原始消息（包含协议标记）
        return {"messages": session_manager.current.messages}
    
    # 处理消息，提取用户可见内容
    clean_messages = []
    for msg in session_manager.current.messages:
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
        from base.utils import clear_last_todo_content
        from base.todo_manager import todo_write
        
        session_manager.current.clear_all()
        clear_last_todo_content()
        todo_write([])
        
        return {"success": True, "message": "已创建新对话"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



class SwitchSessionRequest(BaseModel):
    """切换会话请求"""
    session_id: str


@router.post("/session/switch")
def switch_session(req: SwitchSessionRequest) -> Dict[str, Any]:
    """切换到指定会话"""
    from ..core import switch_session as do_switch
    return do_switch(req.session_id)


@router.post("/session/create")
def create_session(req: SwitchSessionRequest) -> Dict[str, Any]:
    """创建新会话"""
    from ..core import create_session as do_create
    return do_create(req.session_id)


@router.post("/session/delete")
def delete_session(req: SwitchSessionRequest) -> Dict[str, Any]:
    """删除会话"""
    from ..core import delete_session as do_delete
    return do_delete(req.session_id)


@router.get("/session/list")
def list_sessions() -> Dict[str, Any]:
    """列出所有会话"""
    from ..core import get_session_manager
    manager = get_session_manager()
    if not manager:
        return {"sessions": [], "current": None}
    return {
        "sessions": manager.list_sessions(),
        "current": manager.current_session_id
    }
