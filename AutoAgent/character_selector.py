
#Character Selector Agent - 角色选择子 Agent

#分析对话历史，自动推荐和选择合适的角色

from typing import List, Dict
from base.config import get_config
from base.prompt_loader import load_system_prompt
from base.character_manager import (
    get_current_characters_for_prompt,
    select_character,
)
from base.logger import log_error


# 全局变量用于存储 IPC 管理器（从 main.py 传入）
_ipc_manager = None


def set_ipc_manager(ipc_manager):
    """设置全局 IPC 管理器"""
    global _ipc_manager
    _ipc_manager = ipc_manager


def character_choose_agent(messages: List[Dict[str, str]]):
    """
    分析对话历史，自动选择合适的角色。
    
    参数:
        messages: 对话历史消息列表
    
    返回:
        str: 角色名称，如果没有匹配则返回 "default"
    """
    if not messages:
        return "default"
    
    if _ipc_manager is None:
        # 如果没有 IPC 管理器，不进行角色选择
        return "default"
    
    # 从后往前找最近5条用户消息，并保留这期间的所有对话
    user_count = 0
    start_index = len(messages)
    
    # 从后往前遍历，找到第5条用户消息的位置
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "user":
            user_count += 1
            if user_count == 5:
                start_index = i
                break
    
    # 提取从第5条用户消息到最后的所有对话
    recent_messages = messages[start_index:]
    
    if not recent_messages:
        return "default"
    
    # 构建分析内容，包含用户和assistant的对话
    conversation_parts = []
    for msg in recent_messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if role == "user":
            conversation_parts.append(f"用户: {content}")
        elif role == "assistant":
            conversation_parts.append(f"助手: {content}")
    
    conversation_text = "\n\n".join(conversation_parts)
    

    # 构建分析消息
    analysis_messages = [
        {
            "role": "user",
            "content": f"当前选择角色：{get_current_characters_for_prompt()}\n请分析以下用户消息，判断是否需要选择或者切换其他专业角色：\n\n{conversation_text}"
        }
    ]
    
    # 加载提示词
    system_prompt = load_system_prompt("prompt/character_selector_prompt.md")
    
    try:
        # 通过 IPC 发送请求
        _config = get_config()
        request_id = _ipc_manager.send_chat_request(
            messages=analysis_messages,
            model=_config.get_model(),
            temperature=_config.get_temperature("character_selector"),
            system=system_prompt,
            tool_calls=False
        )
        
        # 等待响应
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=30)
        
        if response is None or response.get("status") != "success":
            return "default"
        
        reply_data = response.get("data", {})
        result = reply_data.get("content", "").strip()
        
        # 验证返回的角色是否存在并自动选择
        if result and result != "default":
            # 检查角色是否真实存在
            from base.utils.characters import list_character_documents
            all_characters = list_character_documents()
            character_names = [doc["name"] for doc in all_characters]
            
            if result in character_names:
                # Agent推荐了具体角色，自动选择
                select_result = select_character(result)
        #         if select_result.get("success"):
        #             print(f"[角色推荐] {select_result.get('message')}")
        #         else:
        #             print(f"[角色推荐] 选择失败: {select_result.get('error')}")
        #     else:
        #         print(f"[角色推荐] Agent返回了不存在的角色: {result}")
        # else:
        #     print(f"[角色推荐] 当前对话无需特定角色，保持默认状态")

    except Exception as exc:
        print(f"[角色推荐] 分析失败: {exc}")
        log_error(
            "CHARACTER_SELECTOR_ERROR",
            "Character selection analysis failed",
            exc,
            context={"message_count": len(messages)}
        )
