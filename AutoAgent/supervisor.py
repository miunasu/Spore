
#Supervisor Agent - 循环检测子 Agent

#检测 LLM 回复是否陷入循环

import os
from base.config import get_config, current_agent_name
from base.prompt_loader import load_system_prompt
from base.utils.json_utils import json_query
from base.todo_manager import get_current_todos_for_prompt
from base.utils import todo_print, terminal
from base.logger import log_error

# 全局变量用于存储 IPC 管理器（从 main.py 传入）
_ipc_manager = None


def set_ipc_manager(ipc_manager):
    """设置全局 IPC 管理器"""
    global _ipc_manager
    _ipc_manager = ipc_manager


def supervisor(last_answer: str, current_answer: str) -> bool:
    """
    检测 LLM 回复是否应该结束
    
    Args:
        last_answer: 上次回复内容（可以为空）
        current_answer: 本次回复内容
    
    Returns:
        True 表示应该结束，False 表示继续
    """
    if _ipc_manager is None:
        # 如果没有 IPC 管理器，默认不检测循环
        return False
    
    if not current_answer or not current_answer.strip():
        return False
    
    # 构建消息
    if last_answer:
        content = f"上次回复: {last_answer}\n本次回复: {current_answer}"
    else:
        # 没有上次回复时，只判断当前回复是否表达了结束
        content = f"上次回复: (无)\n本次回复: {current_answer}"
    
    messages = [
        {"role": "user", "content": content},
    ]
    
    system_prompt = load_system_prompt("prompt/supervisor_prompt.md")
    try:
        # 通过 IPC 发送请求
        _config = get_config()
        request_id = _ipc_manager.send_chat_request(
            messages=messages,
            model=_config.get_model(),
            temperature=_config.get_temperature("supervisor"),
            system=system_prompt,
            tool_calls=False
        )
        
        # 等待响应
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=30)
        
        if response is None or response.get("status") != "success":
            return False
        
        reply_data = response.get("data", {})
        reply_content = reply_data.get("content", "")

        reply = reply_content.strip().upper()
        
        # 更严格的判断逻辑
        if "YES" in reply:
            return True
        else:
            return False
            
    except Exception as exc:
        print(f"Spore> [错误] {exc}")
        log_error(
            "SUPERVISOR_ERROR",
            "Supervisor loop detection failed",
            exc,
            context={"last_answer_preview": last_answer[:100] if last_answer else None}
        )
        return False  # 异常时默认不检测为循环



def end_check(last_answer: str, current_answer: str, reply: str) -> str:
    """
    检查是否应该结束对话（文本协议版本）
    
    Args:
        last_answer: 上次回复内容
        current_answer: 本次回复内容
        reply: 原始回复（用于检测 FINAL_RESPONSE）
    
    Returns:
        "End" 表示结束，"continue" 表示继续，"" 表示正常
    """
    # 打印最终回复
    if current_answer != "":
        print(f"{current_agent_name}> {current_answer}")
    
    # 检测 FINAL_RESPONSE 标记（文本协议）
    if "@SPORE:FINAL@" in reply:
        return "End"
    
    # 使用 supervisor 检测循环
    if supervisor(last_answer, current_answer):
        return "End"
    
    # 检查 TODO 状态
    if current_agent_name == "Spore":
        todo_content = get_current_todos_for_prompt()
        if todo_content is None or todo_content == "当前没有任务规划":
            return "continue"
        todo_print()

    return ""