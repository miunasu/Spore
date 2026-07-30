"""
LLM 响应健康检查

系统过去只能看到"回复文本"，无法区分下面这些状态，导致被截断的回复和空回复
都被当成正常成功回复处理：

    正常说完 / 被 max_tokens 截断 / 拒答或被内容过滤 / 需要续调 / 空回复

本模块提供两条互补的判据来恢复这个区分能力：

1. **API 字段**：只识别 OpenAI（GPT）与 Anthropic（Claude）两家的字段。
   全部容错读取 —— 字段缺失、被第三方中转裁剪、类型不符、对象换成 dict，
   一律降级为 UNKNOWN，绝不抛异常。这样换任何一家兼容 API 都不会因为
   少一个字段而崩掉。

2. **回复文本自身的特征**：完全不依赖 API 字段。中转不返回 stop_reason 时，
   靠未闭合的协议块、残缺的标识符尾巴、未闭合的代码围栏等特征判断截断。

两条判据由调用方合并使用：API 字段说了算，没说才看文本特征。
"""
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
    """容错提取 usage，并补齐两家的缓存 token。

    两家对 input 的口径不同，必须分开处理，否则上下文规模会被严重低估：

    - Anthropic: ``input_tokens`` **不含**缓存命中部分，缓存量单独放在
      ``cache_read_input_tokens`` / ``cache_creation_input_tokens``。
      只读 input_tokens 会得到个位数，上下文压缩因此永远不触发。
    - OpenAI: ``prompt_tokens`` **已含**缓存部分，``cached_tokens`` 只是其中的
      子集，再加一遍就重复计算了。

    Returns:
        含 input_tokens / output_tokens / cache_read_input_tokens /
        cache_creation_input_tokens / context_tokens 的 dict。
        context_tokens 表示"真实上下文规模"，供上下文压缩判断使用。
    """
    result = {
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
        anthropic_style = False

        raw_input = _get(usage, "input_tokens")
        if raw_input is not None:
            anthropic_style = True
            base_input = _int(raw_input)
        else:
            base_input = _int(_get(usage, "prompt_tokens"))

        base_output = _int(_get(usage, "output_tokens"))
        if base_output == 0:
            base_output = _int(_get(usage, "completion_tokens"))

        cache_read = _int(_get(usage, "cache_read_input_tokens"))
        cache_write = _int(_get(usage, "cache_creation_input_tokens"))
        if cache_read or cache_write:
            anthropic_style = True
        else:
            # OpenAI 把缓存命中放在 prompt_tokens_details.cached_tokens（属于 prompt_tokens 的子集）
            cache_read = _int(_get(_get(usage, "prompt_tokens_details"), "cached_tokens"))

        result["input_tokens"] = base_input
        result["output_tokens"] = base_output
        result["cache_read_input_tokens"] = cache_read
        result["cache_creation_input_tokens"] = cache_write
        # Anthropic 口径要把缓存补回来，OpenAI 口径不能重复累加
        context = base_input + cache_read + cache_write if anthropic_style else base_input
        result["context_tokens"] = max(context, base_input)
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
            described.append({
                "type": block_type(block) or type(block).__name__,
                "text_length": len(block_text(block)),
                "text_bearing": is_text_bearing(block),
            })
        except Exception:
            described.append({"type": "<undescribable>", "text_length": 0, "text_bearing": False})
    return described


# ---------------------------------------------------------------------------
# 二、文本判据（完全不依赖 API 字段）
# ---------------------------------------------------------------------------
@dataclass
class TruncationHint:
    """文本截断线索。

    confidence 为 "high" 时可单独作为截断判定依据；"low" 只作日志线索，
    避免把正常回复误判成截断。
    """
    reason: str
    confidence: str


_DEFAULT_CONTENT_START = "@SPORE:CONTENT_START"
_DEFAULT_CONTENT_END = "@SPORE:CONTENT_END"
_EXTRA_MARKERS = ("@SPORE:STOP_REASON", "@SPORE:RESULT")

# 句子/代码块的正常收尾字符
_TERMINAL_CHARS = frozenset("。！？；：、）】》」』…\"'`)]}>.!?;:,\n")


def _spore_markers() -> Tuple[Dict[str, Tuple[str, str]], str, str]:
    """取协议块标识符，以 protocol_manager 为唯一事实来源。

    延迟导入避免模块加载期的循环依赖；导入失败时退回内置常量，
    保证本模块在任何情况下都可用。
    """
    try:
        from .text_protocol.protocol_manager import (
            CONTENT_END_MARKER,
            CONTENT_START_MARKER,
            ProtocolManager,
        )
        return dict(ProtocolManager.BLOCK_MARKERS), CONTENT_START_MARKER, CONTENT_END_MARKER
    except Exception:
        return {}, _DEFAULT_CONTENT_START, _DEFAULT_CONTENT_END


def _all_marker_names(
    markers: Dict[str, Tuple[str, str]], content_start: str, content_end: str
) -> Iterable[str]:
    for pair in markers.values():
        for marker in pair:
            yield marker
    yield content_start
    yield content_end
    for marker in _EXTRA_MARKERS:
        yield marker


def _has_partial_marker_tail(
    text: str, markers: Dict[str, Tuple[str, str]], content_start: str, content_end: str
) -> bool:
    """尾部是不是一个写到一半的协议标识符。"""
    tail = text[-64:]
    at_pos = tail.rfind("@")
    if at_pos < 0:
        return False
    fragment = tail[at_pos:]
    if "\n" in fragment or len(fragment) < 2:
        return False
    for marker in _all_marker_names(markers, content_start, content_end):
        if marker.startswith(fragment) and fragment != marker:
            return True
    return False


def _ends_cleanly(text: str) -> bool:
    stripped = text.rstrip()
    if not stripped:
        return True
    last_line = stripped.rsplit("\n", 1)[-1].strip()
    # 以协议标识符收尾属于正常结束（标识符本身不带标点）
    if last_line.startswith("@SPORE:"):
        return True
    return stripped[-1] in _TERMINAL_CHARS


def looks_truncated(text: Optional[str]) -> Optional[TruncationHint]:
    """仅凭回复文本判断是否被截断，不依赖任何 API 字段。

    用于中转不返回 stop_reason / finish_reason 的场景。
    """
    if not text or not text.strip():
        return None

    markers, content_start, content_end = _spore_markers()

    # CONTENT 块未闭合 —— 最强判据：正文写到一半就断了
    if text.count(content_start) > text.count(content_end):
        return TruncationHint("unclosed_content_block", "high")

    # 协议块未闭合
    for name, pair in markers.items():
        start_marker, end_marker = pair
        if text.count(start_marker) > text.count(end_marker):
            return TruncationHint("unclosed_block:{0}".format(name), "high")

    # 尾部是残缺的协议标识符
    if _has_partial_marker_tail(text, markers, content_start, content_end):
        return TruncationHint("partial_marker_tail", "high")

    # 代码围栏未闭合
    if text.count("```") % 2 == 1:
        return TruncationHint("unclosed_code_fence", "high")

    # 收尾没有任何终止性字符（弱判据，只作线索）
    if not _ends_cleanly(text):
        return TruncationHint("no_terminal_punctuation", "low")

    return None


def hit_output_cap(
    output_tokens: int, max_tokens: int, tolerance: float = 0.98
) -> bool:
    """输出 token 数是否贴住上限。

    与 API 字段无关的第三条判据：即使中转把 stop_reason 抹掉了，
    output_tokens 贴着 max_tokens 也几乎必然意味着被砍断。
    """
    if not output_tokens or not max_tokens or max_tokens <= 0:
        return False
    return output_tokens >= max_tokens * tolerance


def is_effectively_empty(text: Optional[str]) -> bool:
    """回复是否为空（含纯空白）。"""
    return not text or not text.strip()


# ---------------------------------------------------------------------------
# 三、合并判定
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
        if not merged.get("output_tokens"):
            merged["output_tokens"] = fb_output
        # context_tokens 同步兜底，否则上下文压缩仍会低估规模
        if not merged.get("context_tokens"):
            merged["context_tokens"] = max(
                merged.get("input_tokens") or 0,
                (merged.get("input_tokens") or 0)
                + (merged.get("cache_read_input_tokens") or 0)
                + (merged.get("cache_creation_input_tokens") or 0),
            )
        return merged
    except Exception:
        return usage


def assess(
    response: Any,
    text: str,
    max_tokens: Optional[int] = None,
    usage_fallback: Optional[Tuple[int, int]] = None,
) -> Dict[str, Any]:
    """综合 API 字段与文本特征，给出这次回复的健康状况。

    Args:
        response: provider 返回的原始响应对象（对象或 dict 均可）
        text: 已提取出的用户可见正文
        max_tokens: 本次请求设置的输出上限，用于"贴顶"判据
        usage_fallback: 调用路径自己解析出的 ``(input_tokens, output_tokens)``。
            通用提取拿不到 usage 时（第三方中转返回非标准 usage 结构）用它兜底 ——
            少了这个兜底，output_tokens 会是 0，"贴顶 max_tokens"这条截断判据
            等于完全失效。

    Returns:
        含 api_stop_reason / finish_state / truncated / truncation_source /
        truncation_hint / empty / usage / content_blocks 的 dict。
    """
    api_stop_reason, finish_state = extract_finish_reason(response)
    usage = extract_usage(response)
    usage = _merge_usage_fallback(usage, usage_fallback)
    hint = looks_truncated(text)

    truncated = False
    source = None
    if finish_state == FINISH_TRUNCATED:
        # API 明说了，优先采信
        truncated = True
        source = "api"
    elif hit_output_cap(usage.get("output_tokens", 0), max_tokens or 0):
        truncated = True
        source = "output_cap"
    elif finish_state == FINISH_UNKNOWN and hint is not None and hint.confidence == "high":
        # API 字段不可用时才让文本判据说话，避免与 API 结论打架
        truncated = True
        source = "text"

    return {
        "api_stop_reason": api_stop_reason,
        "finish_state": finish_state,
        "truncated": truncated,
        "truncation_source": source,
        "truncation_hint": hint.reason if hint else None,
        "truncation_confidence": hint.confidence if hint else None,
        "empty": is_effectively_empty(text),
        "refusal": finish_state == FINISH_REFUSAL,
        "paused": finish_state == FINISH_PAUSED,
        "usage": usage,
        "content_blocks": describe_content_blocks(response),
    }
