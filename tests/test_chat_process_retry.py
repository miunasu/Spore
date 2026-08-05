import queue
import threading
from unittest.mock import Mock, patch

from base.chat_process import ChatProcess


def _chat_process():
    process = ChatProcess(queue.Queue(), queue.Queue(), threading.Event())
    process.config.log_raw_enabled = False
    return process


def test_retry_error_detail_prefers_nested_provider_message():
    process = _chat_process()
    result = {
        "status": "error",
        "data": "Error code: 503",
        "raw_payload": {
            "body": {
                "error": {
                    "code": "model_not_found",
                    "message": "No available channel for model claude-opus-5",
                }
            },
            "message": "generic SDK summary",
        },
    }

    assert process._retry_error_detail(result) == (
        "No available channel for model claude-opus-5"
    )


def test_retry_error_detail_parses_response_text_and_normalizes_fallback():
    process = _chat_process()
    result = {
        "status": "error",
        "data": "fallback\nmessage",
        "raw_payload": {
            "response_text": (
                '{"error":{"message":"Distributor channel unavailable"}}'
            ),
        },
    }

    assert process._retry_error_detail(result) == "Distributor channel unavailable"
    assert process._retry_error_detail({"data": "fallback\nmessage"}) == "fallback message"
    assert process._retry_error_detail({"data": "x" * 20}, limit=10) == "xxxxxxx..."


def test_retry_progress_includes_concrete_provider_error():
    process = _chat_process()
    process._RETRY_DELAYS = [0, 5, 15, 25]
    provider_message = (
        "No available channel for model claude-opus-5 under group "
        "ClaudeCode-Kiro逆向 (distributor)"
    )
    failure = {
        "status": "error",
        "data": "Error code: 503",
        "error_meta": {"status_code": 503},
        "raw_payload": {
            "body": {"error": {"message": provider_message}},
        },
    }
    success = {"status": "success", "data": {"content": "ok"}, "health": {}}
    process._do_single_llm_call = Mock(side_effect=[failure, success])

    with patch.object(process, "_wait_retry_delay", return_value=True), patch(
        "base.chat_process.log_error"
    ):
        result = process._do_llm_call(
            "default_e5b60bdc-58f0-4d01-9328-026cdba55db3",
            {"stream": False},
        )

    progress = [
        item
        for item in list(process.response_queue.queue)
        if item.get("status") == "progress"
    ]
    assert result is success
    assert len(progress) == 1
    assert progress[0]["data"]["attempt"] == 2
    assert progress[0]["data"]["total"] == 4
    assert provider_message in progress[0]["data"]["message"]
    assert "5秒后进行第 2 次请求尝试" in progress[0]["data"]["message"]
