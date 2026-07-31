import queue
import threading

from base.chat_process import ChatProcess
from base.ipc_manager import IPCManager
from desktop_app.backend.routes.chat import extract_stream_user_visible_content


class _IterableStream:
    def __init__(self, items):
        self.items = items
        self.closed = False

    def __iter__(self):
        return iter(self.items)

    def close(self):
        self.closed = True


class _Endpoint:
    def __init__(self, result):
        self.result = result
        self.params = None

    def create(self, **params):
        self.params = params
        return self.result


class _NoStreamOptionsEndpoint(_Endpoint):
    def __init__(self, result):
        super().__init__(result)
        self.calls = []

    def create(self, **params):
        self.calls.append(params)
        if "stream_options" in params:
            raise ValueError("unknown field: stream_options")
        return self.result


class _AnthropicStream:
    def __init__(self, parts, final_message):
        self.text_stream = iter(parts)
        self.final_message = final_message

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get_final_message(self):
        return self.final_message


class _AnthropicEndpoint:
    def __init__(self, stream):
        self.message_stream = stream
        self.params = None

    def stream(self, **params):
        self.params = params
        return self.message_stream


def _chat_process():
    process = ChatProcess(queue.Queue(), queue.Queue(), threading.Event())
    process.config.log_raw_enabled = False
    return process


def _stream_deltas(process):
    deltas = []
    while not process.response_queue.empty():
        event = process.response_queue.get_nowait()
        if event.get("status") == "stream" and event.get("data", {}).get("event") == "delta":
            deltas.append(event["data"]["content"])
    return deltas


def test_openai_chat_stream_is_aggregated_and_forwarded():
    process = _chat_process()
    stream = _IterableStream([
        {"id": "c1", "model": "m", "choices": [{"delta": {"role": "assistant", "content": "你"}}]},
        {"id": "c1", "model": "m", "choices": [{"delta": {"content": "好"}, "finish_reason": "stop"}]},
        {"id": "c1", "model": "m", "choices": [], "usage": {"prompt_tokens": 3, "completion_tokens": 2}},
    ])
    endpoint = _Endpoint(stream)

    response = process._stream_openai_chat("req", endpoint, {"model": "m"}, {})
    content, role, input_tokens, output_tokens = process._extract_openai_chat_completion(response)

    assert endpoint.params["stream"] is True
    assert endpoint.params["stream_options"] == {"include_usage": True}
    assert stream.closed is True
    assert content == "你好"
    assert role == "assistant"
    assert (input_tokens, output_tokens) == (3, 2)
    assert _stream_deltas(process) == ["你", "好"]


def test_openai_responses_stream_uses_final_response():
    process = _chat_process()
    final = {
        "status": "completed",
        "output_text": "hello",
        "usage": {"input_tokens": 4, "output_tokens": 1},
    }
    endpoint = _Endpoint(_IterableStream([
        {"type": "response.output_text.delta", "delta": "hel"},
        {"type": "response.output_text.delta", "delta": "lo"},
        {"type": "response.completed", "response": final},
    ]))

    response = process._stream_openai_responses("req", endpoint, {"model": "m"}, {})

    assert endpoint.params["stream"] is True
    assert response is final
    assert process._extract_openai_responses_text(response) == "hello"
    assert _stream_deltas(process) == ["hel", "lo"]


def test_openai_chat_stream_falls_back_for_gateway_without_stream_options():
    process = _chat_process()
    endpoint = _NoStreamOptionsEndpoint(_IterableStream([
        {"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}]},
    ]))

    response = process._stream_openai_chat("req", endpoint, {"model": "m"}, {})

    assert len(endpoint.calls) == 2
    assert endpoint.calls[1] == {"model": "m", "stream": True}
    assert process._extract_openai_chat_completion(response)[0] == "ok"


def test_anthropic_stream_returns_final_message_and_forwards_text_only():
    process = _chat_process()
    final = {
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "done"}],
        "usage": {"input_tokens": 2, "output_tokens": 1},
    }
    endpoint = _AnthropicEndpoint(_AnthropicStream(["do", "ne"], final))

    response = process._create_anthropic_message(
        "req", endpoint, {"model": "claude", "max_tokens": 10}, {}, stream=True
    )

    assert response is final
    assert endpoint.params["model"] == "claude"
    assert _stream_deltas(process) == ["do", "ne"]


def test_stream_visible_snapshot_hides_protocol_sections_and_partial_markers():
    assert extract_stream_user_visible_content("@SPO") == ""
    assert extract_stream_user_visible_content(
        "@SPORE:REPLY_START\n正在处理"
    ) == "正在处理"
    assert extract_stream_user_visible_content(
        "@SPORE:REPLY_START\n正在处理\n@SPORE:REPLY_END\n"
        "@SPORE:ACTION_SINGLE_START\n{\"tool_name\":\"shell\"}"
    ) == "正在处理"


def test_ipc_stream_handler_accumulates_and_resets_per_request():
    # IPCManager.__init__ creates Windows named pipes; this unit only needs the
    # stream-routing state and therefore avoids OS process primitives.
    manager = object.__new__(IPCManager)
    manager.process_started = False
    manager._cache_lock = threading.Lock()
    manager._cancelled_request_ids = set()
    manager._stream_lock = threading.Lock()
    received = []
    manager._stream_callbacks = {"req": received.append}
    manager._stream_buffers = {"req": ""}

    manager._handle_stream_response({
        "request_id": "req", "status": "stream", "data": {"event": "delta", "content": "a"}
    })
    manager._handle_stream_response({
        "request_id": "req", "status": "stream", "data": {"event": "delta", "content": "b"}
    })
    manager._handle_stream_response({
        "request_id": "req", "status": "stream", "data": {"event": "start", "content": ""}
    })

    assert [item["content"] for item in received] == ["a", "ab", ""]
    assert received[-1]["event"] == "start"


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"{len(tests)} streaming tests passed")
