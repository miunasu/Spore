"""
Mode Selector Agent - 上下文模式选择子 Agent

根据用户输入自动判断应该使用哪种上下文处理模式。
"""
from typing import Optional
from base.config import get_config
from base.prompt_loader import load_system_prompt
from base.logger import log_info, log_error


# 全局变量用于存储 IPC 管理器（从 main.py 传入）
_ipc_manager = None


def set_ipc_manager(ipc_manager):
    """设置全局 IPC 管理器"""
    global _ipc_manager
    _ipc_manager = ipc_manager


def select_context_mode(user_input: str) -> str:
    """
    根据用户输入自动选择上下文处理模式
    
    Args:
        user_input: 用户输入的文本
    
    Returns:
        str: 选择的模式，"strong_context" 或 "long_context"
    """
    if _ipc_manager is None:
        # 如果没有 IPC 管理器，默认使用强上下文模式
        log_info("MODE_SELECTOR", "IPC管理器未初始化，使用默认模式: strong_context")
        return "strong_context"
    
    if not user_input or not user_input.strip():
        return "strong_context"
    
    try:
        # 构建分析消息
        messages = [
            {"role": "user", "content": f"用户输入：{user_input}"}
        ]
        
        # 加载提示词
        system_prompt = load_system_prompt("prompt/model_prompt.md")
        
        # 通过 IPC 发送请求
        _config = get_config()
        request_id = _ipc_manager.send_chat_request(
            messages=messages,
            model=_config.get_model(),
            temperature=0.1,  # 使用较低的temperature确保稳定输出
            system=system_prompt,
            tool_calls=False
        )
        
        # 等待响应
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=30)
        
        if response is None or response.get("status") != "success":
            log_info("MODE_SELECTOR", "LLM响应失败，使用默认模式: strong_context")
            return "strong_context"
        
        reply_data = response.get("data", {})
        reply = reply_data.get("content", "").strip()
        
        # 解析响应
        # 期望格式：{"mode": "strong_context"} 或 {"mode": "long_context"}
        import re
        import json
        
        # 尝试提取JSON
        json_match = re.search(r'\{[^}]+\}', reply)
        if json_match:
            try:
                result = json.loads(json_match.group())
                mode = result.get("mode", "strong_context")
                
                if mode in ["strong_context", "long_context"]:
                    log_info("MODE_SELECTOR", f"自动选择模式: {mode}")
                    return mode
            except json.JSONDecodeError:
                pass
        
        # 如果JSON解析失败，尝试直接匹配关键词
        reply_lower = reply.lower()
        if "long_context" in reply_lower:
            log_info("MODE_SELECTOR", "自动选择模式: long_context (关键词匹配)")
            return "long_context"
        
        # 默认返回强上下文模式
        log_info("MODE_SELECTOR", "使用默认模式: strong_context")
        return "strong_context"
        
    except Exception as e:
        log_error("MODE_SELECTOR", f"模式选择失败: {e}", e)
        return "strong_context"


def get_mode_description(mode: str) -> str:
    """
    获取模式的描述信息
    
    Args:
        mode: 模式名称
    
    Returns:
        str: 模式描述
    """
    descriptions = {
        "strong_context": "强上下文关联模式 - 适合需要上下文强关联的任务和精确推理",
        "long_context": "长上下文处理模式 - 适合大文本处理、大项目编程和信息检索汇总报告。偏向多agent",
        "auto": "自动选择模式 - 根据任务自动判断使用哪种模式"
    }
    return descriptions.get(mode, "未知模式")
