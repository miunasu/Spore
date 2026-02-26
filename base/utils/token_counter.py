"""Token计数工具模块

提供文本token数量的计算功能。
支持 GPT/DeepSeek (tiktoken) 和 Claude (anthropic-tokenizer) 两种计算方式。
"""

from typing import Optional, Union, List, Dict
import os

# 从环境变量获取 tokenizer 类型，默认为 gpt
# 可选值: gpt, claude
_TOKENIZER_TYPE = os.getenv("TOKENIZER_TYPE", "gpt").lower()


def count_tokens(text: Union[str, List[Dict]], model: str = "deepseek-chat") -> int:
    """
    计算文本的token数量。
    
    参数:
        text: 要计算的文本内容，可以是：
              - 字符串：直接计算token数
              - 消息列表：[{"role": "user", "content": "..."}, ...]
        model: 模型名称，默认为"deepseek-chat"
               支持: deepseek-chat, deepseek-coder, gpt-4, gpt-3.5-turbo等
    
    返回:
        int: token数量
    
    示例:
        >>> count_tokens("Hello, world!")
        4
        >>> count_tokens("你好，世界！")
        6
        >>> messages = [{"role": "user", "content": "你好"}]
        >>> count_tokens(messages)
        8
    """
    # 如果是消息列表，转换为文本
    if isinstance(text, list):
        return _count_messages_tokens(text, model)
    
    # 确保 text 是字符串类型
    if not isinstance(text, str):
        if text is None:
            return 0
        # 如果是其他类型，转换为字符串
        import json
        text = json.dumps(text, ensure_ascii=False)
    
    # 根据 tokenizer 类型选择计算方式
    if _TOKENIZER_TYPE == "claude":
        return _count_tokens_claude(text)
    else:
        return _count_tokens_tiktoken(text, model)


def _count_tokens_tiktoken(text: str, model: str = "deepseek-chat") -> int:
    """使用 tiktoken 计算 token 数（GPT/DeepSeek）"""
    try:
        import tiktoken
    except ImportError:
        print("未安装tiktoken，使用简单估算")
        return _estimate_tokens(text)
    
    try:
        # DeepSeek使用cl100k_base编码（与GPT-4相同）
        if "deepseek" in model.lower():
            encoding = tiktoken.get_encoding("cl100k_base")
        else:
            # 获取对应模型的编码器
            encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        # 如果模型不存在，使用cl100k_base作为默认
        encoding = tiktoken.get_encoding("cl100k_base")
    
    # 允许所有特殊token，避免遇到特殊标记时报错
    tokens = encoding.encode(text, allowed_special='all')
    return len(tokens)


def _count_tokens_claude(text: str) -> int:
    """使用 anthropic tokenizer 计算 token 数（Claude）"""
    try:
        from anthropic import Anthropic
        client = Anthropic()
        # 使用 anthropic 的 count_tokens 方法
        return client.count_tokens(text)
    except ImportError:
        # 如果没有安装 anthropic，使用估算
        # Claude 的 tokenizer 与 GPT 类似但略有不同
        # 中文字符约 1.2-1.5 token，英文约 0.25 token/字符
        return _estimate_tokens_claude(text)
    except Exception:
        return _estimate_tokens_claude(text)


def _estimate_tokens_claude(text: str) -> int:
    """Claude token 估算（当 anthropic 库不可用时）"""
    if not text:
        return 0
    
    # Claude 的 tokenizer 特点：
    # - 英文: 约 4 个字符 = 1 个 token
    # - 中文: 约 1.2 个字符 = 1 个 token（比 GPT 略少）
    chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    total_chars = len(text)
    english_chars = total_chars - chinese_chars
    
    estimated = (english_chars / 4.0) + (chinese_chars / 1.2)
    return int(estimated) + 1


def _count_messages_tokens(messages: List[Dict], model: str = "deepseek-chat") -> int:
    """
    计算消息列表的总token数量。
    
    参数:
        messages: 消息列表 [{"role": "user", "content": "..."}, ...]
        model: 模型名称
    
    返回:
        int: 总token数量
    """
    import json
    
    if not messages:
        return 0
    
    # 根据 tokenizer 类型选择计算方式
    if _TOKENIZER_TYPE == "claude":
        return _count_messages_tokens_claude(messages)
    else:
        return _count_messages_tokens_tiktoken(messages, model)


def _count_messages_tokens_tiktoken(messages: List[Dict], model: str = "deepseek-chat") -> int:
    """使用 tiktoken 计算消息列表的 token 数"""
    import json
    
    try:
        import tiktoken
    except ImportError:
        # 如果没有tiktoken，使用简单估算
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if content:
                if not isinstance(content, str):
                    if content is None:
                        continue
                    content = json.dumps(content, ensure_ascii=False)
                total += _estimate_tokens(content)
        return total + len(messages) * 4 + 3
    
    try:
        if "deepseek" in model.lower():
            encoding = tiktoken.get_encoding("cl100k_base")
        else:
            encoding = tiktoken.encoding_for_model(model)
    except KeyError:
        encoding = tiktoken.get_encoding("cl100k_base")
    
    total_tokens = 0
    
    for msg in messages:
        total_tokens += 4
        
        role = msg.get("role", "")
        if role:
            total_tokens += len(encoding.encode(role, allowed_special='all'))
        
        content = msg.get("content", "")
        if content:
            if not isinstance(content, str):
                if content is None:
                    continue
                content = json.dumps(content, ensure_ascii=False)
            total_tokens += len(encoding.encode(content, allowed_special='all'))
        
        name = msg.get("name", "")
        if name and isinstance(name, str):
            total_tokens += len(encoding.encode(name, allowed_special='all'))
        
        tool_calls = msg.get("tool_calls")
        if tool_calls:
            tool_calls_str = json.dumps(tool_calls, ensure_ascii=False)
            total_tokens += len(encoding.encode(tool_calls_str, allowed_special='all'))
        
        tool_call_id = msg.get("tool_call_id", "")
        if tool_call_id and isinstance(tool_call_id, str):
            total_tokens += len(encoding.encode(tool_call_id, allowed_special='all'))
    
    total_tokens += 3
    return total_tokens


def _count_messages_tokens_claude(messages: List[Dict]) -> int:
    """使用 Claude 方式计算消息列表的 token 数"""
    import json
    
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if content:
            if not isinstance(content, str):
                if content is None:
                    continue
                content = json.dumps(content, ensure_ascii=False)
            
            if _TOKENIZER_TYPE == "claude":
                total += _count_tokens_claude(content)
            else:
                total += _estimate_tokens_claude(content)
        
        # Claude 消息格式开销（约 4 tokens/消息）
        total += 4
    
    # 整体对话开销
    total += 3
    return total


def _estimate_tokens(text: str) -> int:
    """
    当tiktoken不可用时的简单token估算。
    
    粗略估算规则：
    - 英文: 约4个字符 = 1个token
    - 中文: 约1.5个字符 = 1个token
    """
    if not text:
        return 0
    
    # 确保 text 是字符串类型
    if not isinstance(text, str):
        import json
        text = json.dumps(text, ensure_ascii=False)
    
    # 统计中英文字符
    chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
    total_chars = len(text)
    english_chars = total_chars - chinese_chars
    
    # 粗略估算
    estimated = (english_chars / 4.0) + (chinese_chars / 1.5)
    return int(estimated) + 1


def get_max_tokens(model: str = "deepseek-chat") -> Optional[int]:
    """
    获取模型的最大上下文token限制。
    
    参数:
        model: 模型名称
    
    返回:
        int: 最大token数，如果未知则返回None
    
    示例:
        >>> get_max_tokens("deepseek-chat")
        128000
    """
    model_limits = {
        # DeepSeek models
        "deepseek-chat": 128000,
        "deepseek-coder": 128000,
        
        # OpenAI models
        "gpt-4": 8192,
        "gpt-4-0613": 8192,
        "gpt-4-32k": 32768,
        "gpt-4-32k-0613": 32768,
        "gpt-4-turbo": 128000,
        "gpt-4-turbo-preview": 128000,
        "gpt-3.5-turbo": 4096,
        "gpt-3.5-turbo-16k": 16384,
        
        # Claude models
        "claude-2": 100000,
        "claude-2.1": 200000,
        "claude-3-opus": 200000,
        "claude-3-sonnet": 200000,
    }
    
    return model_limits.get(model)
