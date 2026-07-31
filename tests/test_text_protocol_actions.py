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
