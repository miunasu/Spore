"""
LLM 响应健康检查

系统过去只能看到"回复文本"，无法区分下面这些状态，导致被截断的回复和空回复
都被当成正常成功回复处理：

    正常说完 / 被 max_tokens 截断 / 拒答或被内容过滤 / 需要续调 / 空回复

截断只根据提供方返回的明确终止状态判断。回复文本可以包含任意原始代码和协议
示例，不能可靠证明传输是否截断；协议结构是否完整由 ProtocolManager 独立处理。

API 字段全部容错读取：字段缺失、被第三方中转裁剪、类型不符、对象换成 dict，
一律降级为 UNKNOWN，绝不抛异常。
"""
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 归一化的终止状态
#
# 注意：这里的"终止原因"是传输层概念（生成为什么停下来），与 Spore 文本协议的
# @SPORE:STOP_REASON（模型声明任务已完成）是两回事，不可互相映射。
# 命名上一律用 api_stop_reason / finish_state，避免与协议层的 stop_reason 混淆。
# ---------------------------------------------------------------------------
FINISH_COMPLETE = "complete"      # 模型自然说完这一轮
FINISH_TRUNCATED = "truncated"    # 撞到输出上限，内容被砍断
FINISH_REFUSAL = "refusal"        # 拒答 / 被内容过滤
FINISH_TOOL_USE = "tool_use"      # 原生 function calling 停止（Spore 走文本协议，正常不出现）
FINISH_PAUSED = "paused"          # 长任务暂停，需要续调
FINISH_UNKNOWN = "unknown"        # 字段缺失或无法识别

# Anthropic Messages API: response.stop_reason
_ANTHROPIC_STOP_REASONS = {
    "end_turn": FINISH_COMPLETE,
    "stop_sequence": FINISH_COMPLETE,
    "max_tokens": FINISH_TRUNCATED,
    "model_context_window_exceeded": FINISH_TRUNCATED,
    "refusal": FINISH_REFUSAL,
    "tool_use": FINISH_TOOL_USE,
    "pause_turn": FINISH_PAUSED,
}

# OpenAI Chat Completions: choices[0].finish_reason
# OpenAI Responses:        incomplete_details.reason
_OPENAI_FINISH_REASONS = {
    "stop": FINISH_COMPLETE,
    "length": FINISH_TRUNCATED,
    "max_output_tokens": FINISH_TRUNCATED,
    "max_tokens": FINISH_TRUNCATED,
    "content_filter": FINISH_REFUSAL,
    "refusal": FINISH_REFUSAL,
    "tool_calls": FINISH_TOOL_USE,
    "function_call": FINISH_TOOL_USE,
}

# 思考类内容块：这些块承载的是推理过程而非给用户的正文，提取正文时必须排除。
# 除官方的 thinking / redacted_thinking 外，还覆盖部分第三方中转自造的类型名。
THINKING_BLOCK_TYPES = frozenset({
    "thinking",
    "redacted_thinking",
    "reasoning",
    "reasoning_content",
})

# 明确不承载正文的其他块类型（工具调用等）
_NON_TEXT_BLOCK_TYPES = frozenset({
    "tool_use",
    "server_tool_use",
    "tool_result",
    "web_search_tool_result",
})


# ---------------------------------------------------------------------------
# 容错取值工具：对象 / dict 两种形态都支持，取不到一律返回 default
# ---------------------------------------------------------------------------
def _get(obj: Any, key: str, default: Any = None) -> Any:
    """从对象属性或 dict 键取值。任何异常都返回 default。"""
    if obj is None:
        return default
    try:
        if isinstance(obj, dict):
            value = obj.get(key, default)
        else:
            value = getattr(obj, key, default)
    except Exception:
        return default
    return default if value is None else value


def _first(seq: Any) -> Any:
    """取序列首元素；不可迭代或为空返回 None。"""
    if seq is None or isinstance(seq, (str, bytes, dict)):
        return None
    try:
        for item in seq:
            return item
    except TypeError:
        return None
    return None


def _int(value: Any) -> int:
    """尽力转 int，失败返回 0。"""
    if value is None or isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# 一、API 字段判据
# ---------------------------------------------------------------------------
def extract_finish_reason(response: Any) -> Tuple[Optional[str], str]:
    """容错提取终止原因。

    Returns:
        (原始字段值, 归一化状态)。取不到时返回 (None, FINISH_UNKNOWN)。
    """
    try:
        # Anthropic Messages: stop_reason
        raw = _get(response, "stop_reason")
        if isinstance(raw, str) and raw.strip():
            key = raw.strip().lower()
            return raw, _ANTHROPIC_STOP_REASONS.get(key, FINISH_UNKNOWN)

        # OpenAI Chat Completions: choices[0].finish_reason
        choice = _first(_get(response, "choices"))
        raw = _get(choice, "finish_reason")
        if isinstance(raw, str) and raw.strip():
            key = raw.strip().lower()
            return raw, _OPENAI_FINISH_REASONS.get(key, FINISH_UNKNOWN)

        # OpenAI Responses: status + incomplete_details.reason
        status = _get(response, "status")
        if isinstance(status, str) and status.strip():
            key = status.strip().lower()
            if key == "incomplete":
                reason = _get(_get(response, "incomplete_details"), "reason")
                if isinstance(reason, str) and reason.strip():
                    return reason, _OPENAI_FINISH_REASONS.get(
                        reason.strip().lower(), FINISH_TRUNCATED
                    )
                return status, FINISH_TRUNCATED
            if key == "completed":
                return status, FINISH_COMPLETE
            if key == "failed":
                return status, FINISH_UNKNOWN
    except Exception:
        pass
    return None, FINISH_UNKNOWN


def extract_usage(response: Any) -> Dict[str, int]:
    """兼容 OpenAI 两套 API 与 Anthropic Messages 的 usage 字段。

    官方字段如下：

    - OpenAI Chat Completions: ``prompt_tokens`` / ``completion_tokens``；
      缓存明细在 ``prompt_tokens_details.cached_tokens``。
    - OpenAI Responses: ``input_tokens`` / ``output_tokens``；
      缓存明细在 ``input_tokens_details.cached_tokens``。
    - Anthropic Messages: ``input_tokens`` / ``output_tokens``；缓存量单独在
      ``cache_read_input_tokens`` / ``cache_creation_input_tokens``。

    OpenAI 的 cached_tokens 是 input/prompt_tokens 的子集，不能重复相加；
    Anthropic 的两个缓存字段不含在 input_tokens 中，计算真实上下文时需要补回。

    Returns:
        ``input_tokens`` 是跨 provider 统一后的完整输入上下文，始终与
        ``context_tokens`` 相等；``api_input_tokens`` 保留提供方主字段原值。
        Claude 开启缓存时二者不同，因为缓存 token 由独立 API 字段返回。
    """
    result = {
        "api_input_tokens": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "context_tokens": 0,
    }
    usage = _get(response, "usage")
    if usage is None:
        return result

    try:
        raw_input = _get(usage, "input_tokens")
        if raw_input is not None:
            base_input = _int(raw_input)
        else:
            base_input = _int(_get(usage, "prompt_tokens"))

        raw_output = _get(usage, "output_tokens")
        if raw_output is not None:
            base_output = _int(raw_output)
        else:
            base_output = _int(_get(usage, "completion_tokens"))

        anthropic_cache_read = _get(usage, "cache_read_input_tokens")
        anthropic_cache_write = _get(usage, "cache_creation_input_tokens")
        is_anthropic = (
            anthropic_cache_read is not None or anthropic_cache_write is not None
        )
        cache_write = _int(anthropic_cache_write)

        if is_anthropic:
            cache_read = _int(anthropic_cache_read)
        else:
            # Responses 与 Chat Completions 的 details 字段名称不同。
            responses_details = _get(usage, "input_tokens_details")
            chat_details = _get(usage, "prompt_tokens_details")
            cache_read = _int(_get(responses_details, "cached_tokens"))
            if responses_details is None:
                cache_read = _int(_get(chat_details, "cached_tokens"))

        full_input = base_input + cache_read + cache_write if is_anthropic else base_input
        result["api_input_tokens"] = base_input
        result["input_tokens"] = full_input
        result["output_tokens"] = base_output
        result["cache_read_input_tokens"] = cache_read
        result["cache_creation_input_tokens"] = cache_write
        result["context_tokens"] = full_input
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# 内容块：提取与诊断
# ---------------------------------------------------------------------------
def iter_content_blocks(response: Any) -> List[Any]:
    """取 Anthropic 风格的 content 数组。取不到或是纯字符串时返回空列表。"""
    blocks = _get(response, "content")
    if blocks is None or isinstance(blocks, (str, bytes, dict)):
        return []
    try:
        return list(blocks)
    except TypeError:
        return []


def block_type(block: Any) -> Optional[str]:
    """取块类型，dict / 对象均支持；取不到返回 None。"""
    if isinstance(block, dict):
        value = block.get("type")
    else:
        value = getattr(block, "type", None)
    return value if isinstance(value, str) and value else None


def block_text(block: Any) -> str:
    """取块内文本，dict / 对象 / 纯字符串均支持；取不到返回空串。"""
    if isinstance(block, str):
        return block
    if isinstance(block, dict):
        for key in ("text", "output_text", "content"):
            value = block.get(key)
            if isinstance(value, str):
                return value
        return ""
    for key in ("text", "output_text"):
        value = getattr(block, key, None)
        if isinstance(value, str):
            return value
    return ""


def block_thinking(block: Any) -> str:
    """取思考/推理块中的文本，供诊断记录长度，不作为用户可见正文。"""
    if isinstance(block, dict):
        for key in ("thinking", "reasoning", "reasoning_content"):
            value = block.get(key)
            if isinstance(value, str):
                return value
        return ""
    for key in ("thinking", "reasoning", "reasoning_content"):
        value = getattr(block, key, None)
        if isinstance(value, str):
            return value
    return ""


def is_text_bearing(block: Any) -> bool:
    """判断块是否承载给用户的正文。

    采用**排除式**而非白名单：除思考块和已知的非正文块外，凡是能取到文本的块
    都算正文。白名单（只认 type == "text"）会在两种情况下静默丢掉整条回复：
    模型引入了新块类型，或第三方中转自造了类型名。
    """
    kind = block_type(block)
    if kind is not None:
        normalized = kind.strip().lower()
        if normalized in THINKING_BLOCK_TYPES or normalized in _NON_TEXT_BLOCK_TYPES:
            return False
    return bool(block_text(block))


def extract_text(response: Any) -> str:
    """从 Anthropic 风格响应中提取用户可见正文（排除思考块）。"""
    parts: List[str] = []
    for block in iter_content_blocks(response):
        if is_text_bearing(block):
            parts.append(block_text(block))
    return "".join(parts)


def describe_content_blocks(response: Any) -> List[Dict[str, Any]]:
    """块级诊断信息，写入 raw 日志。

    有了它才能区分"模型压根没生成文本块"（思考吃满额度）和"生成了但被提取逻辑
    丢掉"（未知块类型 / dict 形态）—— 这两种情况过去在日志里长得一模一样。
    """
    described: List[Dict[str, Any]] = []
    for block in iter_content_blocks(response):
        try:
            text_bearing = is_text_bearing(block)
            visible_text_length = len(block_text(block)) if text_bearing else 0
            described.append({
                "type": block_type(block) or type(block).__name__,
                # 保留 text_length 兼容已有日志消费者，但明确它只表示用户可见正文。
                "text_length": visible_text_length,
                "visible_text_length": visible_text_length,
                "thinking_length": len(block_thinking(block)),
                "text_bearing": text_bearing,
            })
        except Exception:
            described.append({
                "type": "<undescribable>",
                "text_length": 0,
                "visible_text_length": 0,
                "thinking_length": 0,
                "text_bearing": False,
            })
    return described


def is_effectively_empty(text: Optional[str]) -> bool:
    """回复是否为空（含纯空白）。"""
    return not text or not text.strip()


# ---------------------------------------------------------------------------
# 二、合并判定
# ---------------------------------------------------------------------------
def _merge_usage_fallback(
    usage: Dict[str, int], usage_fallback: Optional[Tuple[int, int]]
) -> Dict[str, int]:
    """把调用路径自己解析出的 token 数补进 usage（只补 0 值，不覆盖已有数字）。

    容错到底：fallback 结构不对就原样返回，绝不让它影响健康判定。
    """
    if not usage_fallback:
        return usage
    try:
        fb_input = _int(usage_fallback[0])
        fb_output = _int(usage_fallback[1])
        merged = dict(usage)
        if not merged.get("input_tokens"):
            merged["input_tokens"] = fb_input
        if not merged.get("api_input_tokens"):
            merged["api_input_tokens"] = fb_input
        if not merged.get("output_tokens"):
            merged["output_tokens"] = fb_output
        # input_tokens 已统一为完整上下文，context 不再重复叠加缓存明细。
        if not merged.get("context_tokens"):
            merged["context_tokens"] = merged.get("input_tokens") or 0
        return merged
    except Exception:
        return usage


def assess(
    response: Any,
    text: str,
    max_tokens: Optional[int] = None,
    usage_fallback: Optional[Tuple[int, int]] = None,
) -> Dict[str, Any]:
    """根据 API 终止状态给出回复健康信息，并附带 usage 与内容块诊断。

    Args:
        response: provider 返回的原始响应对象（对象或 dict 均可）
        text: 已提取出的用户可见正文
        max_tokens: 保留的调用兼容参数；截断判定不再根据 token 用量推断
        usage_fallback: 调用路径自己解析出的 ``(input_tokens, output_tokens)``。
            通用提取拿不到 usage 时用于补齐诊断与统计字段。

    Returns:
        含 api_stop_reason / finish_state / truncated / truncation_source /
        truncation_hint / empty / usage / content_blocks 的 dict。
    """
    api_stop_reason, finish_state = extract_finish_reason(response)
    usage = extract_usage(response)
    usage = _merge_usage_fallback(usage, usage_fallback)
    truncated = finish_state == FINISH_TRUNCATED
    source = "api" if truncated else None

    return {
        "api_stop_reason": api_stop_reason,
        "finish_state": finish_state,
        "truncated": truncated,
        "truncation_source": source,
        # 保留字段兼容日志与现有消费者；文本启发式不再参与截断判定。
        "truncation_hint": None,
        "truncation_confidence": None,
        "empty": is_effectively_empty(text),
        "refusal": finish_state == FINISH_REFUSAL,
        "paused": finish_state == FINISH_PAUSED,
        "usage": usage,
        "content_blocks": describe_content_blocks(response),
    }
