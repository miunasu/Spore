from unittest.mock import Mock

from base.conversation_loop import ConversationLoop
from base.response_health import assess, extract_usage
from base.text_protocol.protocol_manager import ProtocolManager
from base.tool_policy import check_action_allowed, default_mode_policy


def test_parallel_action_with_glued_tool_field_returns_format_error():
    response = """@SPORE:ACTION_PARALLEL_START
task_id=read_protocol_mgr_200_400tool=file type=read file_path="C:/protocol_manager.py"
task_id=search_store tool=Grep pattern="TODO" path="C:/chatStore.ts"
@SPORE:ACTION_PARALLEL_END"""

    parsed = ProtocolManager().parse_response(response)

    assert parsed.response_type == "protocol_error"
    assert parsed.protocol_error is not None
    assert parsed.protocol_error.code == "invalid_action_block"
    assert "之间必须有空格" in parsed.protocol_error.message
    assert "不提供工具" not in parsed.protocol_error.message


def test_single_action_missing_tool_name_returns_format_error():
    response = """@SPORE:ACTION_SINGLE_START
type=read file_path="C:/protocol_manager.py"
@SPORE:ACTION_SINGLE_END"""

    parsed = ProtocolManager().parse_response(response)

    assert parsed.response_type == "protocol_error"
    assert parsed.protocol_error is not None
    assert "必须先写工具名" in parsed.protocol_error.message
    assert "不提供工具" not in parsed.protocol_error.message


def test_policy_guard_does_not_report_parameter_as_unavailable_tool():
    error = check_action_allowed(
        "type=read",
        {"file_path": "C:/protocol_manager.py"},
        "strong_context",
        default_mode_policy("strong_context"),
    )

    assert error is not None
    assert "工具调用格式错误" in error
    assert "不提供工具" not in error


def test_valid_file_read_remains_allowed_in_strong_context():
    error = check_action_allowed(
        "file",
        {"type": "read", "file_path": "C:/protocol_manager.py"},
        "strong_context",
        default_mode_policy("strong_context"),
    )

    assert error is None


def test_stop_with_complete_action_at_output_cap_is_not_marked_truncated():
    text = """@SPORE:ACTION_SINGLE_START
file type=write file_path="C:/report.py" content=@SPORE:CONTENT_START
print("done")
@SPORE:CONTENT_END
@SPORE:ACTION_SINGLE_END"""
    response = {
        "choices": [{"finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 100000},
    }

    health = assess(response, text, max_tokens=100000)

    assert health["finish_state"] == "complete"
    assert health["truncated"] is False
    assert health["truncation_source"] is None


def test_output_cap_does_not_infer_truncation_when_finish_reason_is_unknown():
    response = {"usage": {"prompt_tokens": 100, "completion_tokens": 98000}}

    health = assess(response, "complete response.", max_tokens=100000)

    assert health["finish_state"] == "unknown"
    assert health["truncated"] is False
    assert health["truncation_source"] is None


def test_backticks_inside_action_code_are_not_treated_as_markdown_fence():
    text = """@SPORE:ACTION_SINGLE_START
edit type=line file_path="C:/report.py" mode=replace start_line=1 end_line=2 new_string=@SPORE:CONTENT_START
    for line in lines:
        if line.startswith('```'):
            continue
@SPORE:CONTENT_END
@SPORE:ACTION_SINGLE_END"""
    response = {
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 15, "output_tokens": 1567},
    }

    health = assess(response, text, max_tokens=100000)

    assert health["finish_state"] == "complete"
    assert health["truncation_hint"] is None
    assert health["truncated"] is False


def test_openai_chat_usage_fields_are_normalized_without_double_counting_cache():
    usage = extract_usage({
        "usage": {
            "prompt_tokens": 120,
            "completion_tokens": 30,
            "prompt_tokens_details": {"cached_tokens": 80},
        }
    })

    assert usage["input_tokens"] == 120
    assert usage["api_input_tokens"] == 120
    assert usage["output_tokens"] == 30
    assert usage["cache_read_input_tokens"] == 80
    assert usage["context_tokens"] == 120


def test_openai_responses_usage_fields_are_normalized():
    usage = extract_usage({
        "usage": {
            "input_tokens": 120,
            "output_tokens": 30,
            "input_tokens_details": {"cached_tokens": 80},
            "output_tokens_details": {"reasoning_tokens": 20},
        }
    })

    assert usage["input_tokens"] == 120
    assert usage["api_input_tokens"] == 120
    assert usage["output_tokens"] == 30
    assert usage["cache_read_input_tokens"] == 80
    assert usage["context_tokens"] == 120


def test_anthropic_usage_fields_add_cache_to_context_only():
    usage = extract_usage({
        "usage": {
            "input_tokens": 5,
            "output_tokens": 30,
            "cache_read_input_tokens": 80,
            "cache_creation_input_tokens": 10,
        }
    })

    assert usage["api_input_tokens"] == 5
    assert usage["input_tokens"] == 95
    assert usage["output_tokens"] == 30
    assert usage["cache_read_input_tokens"] == 80
    assert usage["cache_creation_input_tokens"] == 10
    assert usage["context_tokens"] == 95


def test_markdown_fence_does_not_override_complete_transport_state():
    response = {"stop_reason": "end_turn"}

    health = assess(response, "```python\nprint('unfinished')", max_tokens=100000)

    assert health["finish_state"] == "complete"
    assert health["truncated"] is False
    assert health["truncation_source"] is None
    assert health["truncation_hint"] is None


def test_explicit_api_length_state_marks_reply_truncated():
    response = {
        "choices": [{"finish_reason": "length"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 100000},
    }

    health = assess(response, "partial response", max_tokens=100000)

    assert health["finish_state"] == "truncated"
    assert health["truncated"] is True
    assert health["truncation_source"] == "api"


def test_protocol_error_respects_explicit_not_truncated_state():
    response = '@SPORE:ACTION_SINGLE_START\nfile type=read file_path="C:/report.py"'

    parsed = ProtocolManager().parse_response(response, truncated=False)

    assert parsed.response_type == "protocol_error"
    assert parsed.protocol_error is not None
    assert parsed.protocol_error.code == "missing_end_marker"
    assert parsed.truncated is False


def test_protocol_error_preserves_explicit_truncated_state_without_rewriting_error():
    response = '@SPORE:ACTION_SINGLE_START\nfile type=read file_path="C:/report.py"'

    parsed = ProtocolManager().parse_response(response, truncated=True)

    assert parsed.response_type == "protocol_error"
    assert parsed.protocol_error is not None
    assert parsed.protocol_error.code == "missing_end_marker"
    assert parsed.truncated is True


def test_explicitly_truncated_final_uses_recovery_instead_of_being_accepted():
    loop = object.__new__(ConversationLoop)
    loop.protocol_manager = ProtocolManager()
    loop._update_todo_from_response = Mock()
    loop._handle_truncated_reply = Mock(return_value="continue")
    reply = "@SPORE:STOP_REASON=partial final answer"
    meta = {
        "truncated": True,
        "api_stop_reason": "max_tokens",
        "finish_state": "truncated",
    }

    result = loop.validate_and_check_response(reply, reply_meta=meta)

    assert result == "continue"
    loop._handle_truncated_reply.assert_called_once()
