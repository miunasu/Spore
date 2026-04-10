"""Token计数工具模块

使用 tiktoken 进行本地 token 估算，仅用于判断工具返回是否超大。
精确的 token 统计从 LLM API 响应的 usage 字段获取。

要求：必须安装 tiktoken
"""

from typing import Union, List, Dict
import json


def count_tokens(text: Union[str, List[Dict]]) -> int:
    """
    使用 tiktoken 估算文本的 token 数量（仅用于判断工具返回是否超大）
    
    参数:
        text: 要估算的文本内容，可以是：
              - 字符串：直接估算 token 数
              - 消息列表：[{"role": "user", "content": "..."}, ...]
    
    返回:
        int: 估算的 token 数量
        
    异常:
        ImportError: 如果 tiktoken 未安装
    """
    try:
        import tiktoken
    except ImportError:
        raise ImportError(
            "tiktoken is required for token counting. "
            "Install it with: pip install tiktoken"
        )
    
    # 使用 cl100k_base 编码（适用于 GPT-4 和 Claude 的近似）
    encoding = tiktoken.get_encoding("cl100k_base")
    
    # 如果是消息列表
    if isinstance(text, list):
        total = 0
        for msg in text:
            total += 4  # 每条消息的开销
            
            role = msg.get("role", "")
            if role:
                total += len(encoding.encode(role))
            
            content = msg.get("content", "")
            if content:
                if not isinstance(content, str):
                    content = json.dumps(content, ensure_ascii=False)
                total += len(encoding.encode(content))
        
        total += 3  # 对话的开销
        return total
    
    # 如果是字符串
    if isinstance(text, str):
        return len(encoding.encode(text))
    
    return 0
