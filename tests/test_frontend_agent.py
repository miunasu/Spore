import json

from base.html_artifacts import HtmlArtifactStore
from base.config import Config
from AutoAgent import frontend_agent


HTML_V1 = "<!doctype html><html><body><button>Run</button></body></html>"
HTML_V2 = "<!doctype html><html><body><main><button aria-label=\"Run\">Run</button></main></body></html>"


def _final_reply(payload, reason="frontend_operation_complete"):
    return json.dumps(payload) + f"\n@SPORE:STOP_REASON={reason}"


def _mutation_payload(payload):
    return "interrupt\n" + json.dumps(payload)


def _mutation_reply(payload, reason="html_update_complete"):
    return _mutation_payload(payload) + f"\n@SPORE:STOP_REASON={reason}"


class _Config:
    frontend_agent_timeout = 60
    frontend_agent_max_iterations = 3

    def resolve_agent_llm(self, profile):
        assert profile == "frontend"
        return {"model": "frontend-model"}


class _IPC:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return f"request-{len(self.requests)}"

    def get_chat_response(self, request_id, timeout):
        content = self.replies.pop(0)
        callback = self.requests[-1].get("stream_callback")
        if callback:
            callback({"event": "start", "delta": "", "content": ""})
            midpoint = max(1, len(content) // 2)
            callback({"event": "delta", "delta": content[:midpoint], "content": content[:midpoint]})
            callback({"event": "delta", "delta": content[midpoint:], "content": content})
        return {"status": "success", "data": {"content": content}}


def test_extract_html_response_supports_fences_and_wrapped_documents():
    assert frontend_agent.extract_html_response(f"```html\n{HTML_V1}\n```") == HTML_V1
    assert frontend_agent.extract_html_response(f"Here it is:\n{HTML_V1}\nDone") == HTML_V1
    assert frontend_agent.extract_html_response("No HTML") is None


def test_generate_html_reviews_and_persists(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    ipc = _IPC([HTML_V1, HTML_V2])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.generate_html(
        "demo-tool",
        "A small interactive tool",
        semantic_label="tool",
        title="Demo tool",
        conversation_id="session-1",
    )

    assert result["generated"] is True
    assert result["reviewed"] is True
    assert result["iterations"] == 2
    assert '<html data-spore-artifact-id="demo-tool">' in store.load("demo-tool")["content"]
    assert [request["agent_profile"] for request in ipc.requests] == ["frontend", "frontend"]
    assert all(request["model"] == "frontend-model" for request in ipc.requests)


def test_frontend_profile_overrides_sub_agent_model(monkeypatch):
    monkeypatch.setenv("LLM_SDK", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "main-model")
    monkeypatch.setenv("SUB_AGENT_OPENAI_MODEL", "sub-model")
    monkeypatch.setenv("AGENT_FRONTEND_OPENAI_MODEL", "frontend-model")

    resolved = Config().resolve_agent_llm("frontend")
    assert resolved["sdk"] == "openai"
    assert resolved["model"] == "frontend-model"


def test_process_html_interactions_evolves_from_click_batch(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    initial = (
        '<!doctype html><html><body><main><p>Transport Layer Security</p>'
        '<button data-spore-target="details">Open details</button></main></body></html>'
    )
    store.save("demo-tool", initial)
    mutation = _mutation_reply({
        "decision": "mutate",
        "intent": "Explain Transport and materialize the requested detail view",
        "mutations": [
            {
                "op": "after",
                "target_ref": "click-1",
                "html": '<aside class="term-explanation">Transport carries protected data.</aside>',
            },
            {
                "op": "after",
                "target_ref": "click-2",
                "html": '<section id="details">Generated details</section>',
            },
        ],
    })
    ipc = _IPC([mutation])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions("demo-tool", [
        {
            "timestamp_ms": 100,
            "elapsed_ms": 0,
            "tag": "p",
            "text": "Transport Layer Security",
            "clicked_word": "Transport",
            "dom_path": "body > main:nth-of-type(1) > p:nth-of-type(1)",
        },
        {
            "timestamp_ms": 900,
            "elapsed_ms": 800,
            "tag": "button",
            "text": "Open details",
            "spore_target": "details",
            "spore_request": "Generate the detailed view",
            "dom_path": "body > main:nth-of-type(1) > button:nth-of-type(1)",
        },
    ])

    assert result["generated"] is True
    assert result["decision"] == "updated"
    assert result["event_count"] == 2
    assert result["mutation_count"] == 2
    assert 'id="details"' in result["content"]
    assert "Transport carries protected data." in result["content"]
    assert len(ipc.requests) == 1
    request_content = ipc.requests[0]["messages"][0]["content"]
    assert '"clicked_word": "Transport"' in request_content
    assert '"ref": "click-1"' in request_content
    assert '"ref": "click-2"' in request_content
    assert "Current HTML:" not in request_content
    assert initial not in request_content


def test_process_html_interactions_accepts_no_change(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    ipc = _IPC([_final_reply({
        "decision": "no_change",
        "intent": "the button already worked locally",
        "mutations": [],
    })])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [{"tag": "button", "text": "Run", "viewport": "invalid"}],
    )

    assert result["generated"] is False
    assert result["decision"] == "no_change"
    assert result["intent"] == "the button already worked locally"
    assert result["content"] == store.load("demo-tool")["content"]


def test_process_html_interactions_retries_unknown_reference(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    invalid = _mutation_reply({
        "decision": "mutate",
        "intent": "Add details",
        "mutations": [{"op": "after", "target_ref": "invented", "html": "<p>Wrong</p>"}],
    })
    valid = _mutation_reply({
        "decision": "mutate",
        "intent": "Add details",
        "mutations": [{"op": "after", "target_ref": "click-1", "html": "<p>Ready</p>"}],
    })
    ipc = _IPC([invalid, valid])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions("demo-tool", [{
        "tag": "button",
        "text": "Run",
        "dom_path": "body > button:nth-of-type(1)",
    }])

    assert result["iterations"] == 2
    assert "Ready" in result["content"]
    assert "Wrong" not in result["content"]
    assert "unknown target_ref" in ipc.requests[1]["messages"][-1]["content"]


def test_process_html_interactions_recovers_when_queued_click_path_shifted(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    shifted = (
        "<!doctype html><html><body><main><button>Inserted earlier</button>"
        "<button>Original target</button></main></body></html>"
    )
    store.save("demo-tool", shifted)
    mutation = _mutation_reply({
        "decision": "mutate",
        "intent": "Add the requested result after the original target",
        "mutations": [{"op": "after", "target_ref": "click-1", "html": "<p>Correct place</p>"}],
    })
    ipc = _IPC([mutation])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions("demo-tool", [{
        "tag": "button",
        "text": "Original target",
        # This was button 1 before an earlier queued batch inserted another button.
        "dom_path": "body > main:nth-of-type(1) > button:nth-of-type(1)",
    }])

    assert result["content"].index("Original target") < result["content"].index("Correct place")
    assert 'button:nth-of-type(2)' in ipc.requests[0]["messages"][0]["content"]


def test_process_html_interactions_retries_unsafe_synthesized_document(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    unsafe = _mutation_reply({
        "decision": "mutate",
        "intent": "Add live data",
        "mutations": [{
            "op": "append",
            "target_ref": "document-body",
            "html": "<script>fetch('/private')</script>",
        }],
    })
    no_change = _final_reply({
        "decision": "no_change",
        "intent": "Network access is not permitted",
        "mutations": [],
    })
    ipc = _IPC([unsafe, no_change])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions("demo-tool", [{"tag": "button", "text": "Run"}])

    assert result["generated"] is False
    assert result["iterations"] == 2
    assert "network_api" in ipc.requests[1]["messages"][-1]["content"]
    assert "fetch(" not in store.load("demo-tool")["content"]


def test_mutation_protocol_rejects_complete_documents_and_malformed_schema():
    complete = _mutation_payload({
        "decision": "mutate",
        "mutations": [{
            "op": "replace_inner",
            "target_ref": "document-body",
            "html": HTML_V2,
        }],
    })
    response = frontend_agent._parse_mutation_response(complete)
    context, soup, references = frontend_agent._build_interaction_context(
        HTML_V1,
        [frontend_agent._clean_click_event({"tag": "button", "text": "Run"}, 0)],
    )
    assert context["protocol"] == "spore-html-mutation-v1"
    try:
        frontend_agent._apply_mutations(soup, references, response["mutations"])
    except ValueError as exc:
        assert "fragment" in str(exc)
    else:
        raise AssertionError("complete HTML was accepted as a mutation fragment")

    try:
        frontend_agent._parse_mutation_response('{"decision":"mutate","mutations":[]}')
    except ValueError as exc:
        assert "at least one mutation" in str(exc)
    else:
        raise AssertionError("empty mutate response was accepted")

    try:
        frontend_agent._fragment_nodes("<section><p>broken</section>")
    except ValueError as exc:
        assert "Invalid HTML fragment syntax" in str(exc)
    else:
        raise AssertionError("mismatched mutation fragment was accepted")

def test_mutation_protocol_requires_interrupt_but_not_spore_lifecycle_marker():
    payload = {
        "decision": "mutate",
        "intent": "Add result",
        "mutations": [{"op": "append", "target_ref": "document-body", "html": "<p>Ready</p>"}],
    }

    try:
        frontend_agent._parse_mutation_response(json.dumps(payload))
    except ValueError as exc:
        assert "start with interrupt" in str(exc)
    else:
        raise AssertionError("mutation without interrupt was accepted")

    response = frontend_agent._parse_mutation_response(_mutation_payload(payload))
    assert response["interrupt"] is True
    assert "stop_reason" not in response

    try:
        frontend_agent._parse_mutation_response(
            "interrupt\n" + json.dumps({"decision": "no_change", "intent": "done", "mutations": []})
        )
    except ValueError as exc:
        assert "must not start with interrupt" in str(exc)
    else:
        raise AssertionError("no_change with interrupt was accepted")


def test_process_html_interactions_waits_for_spore_agent_completion(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    payload = {
        "decision": "mutate",
        "intent": "Add result",
        "mutations": [{"op": "append", "target_ref": "document-body", "html": "<p>Ready</p>"}],
    }
    ipc = _IPC([
        _mutation_payload(payload),
        _mutation_reply(payload, "frontend_agent_finished"),
    ])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [{"event_type": "click", "tag": "button", "text": "Run"}],
    )

    assert result["generated"] is True
    assert result["iterations"] == 2
    assert result["stop_reason"] == "frontend_agent_finished"
    assert "has not ended this operation" in ipc.requests[1]["messages"][-1]["content"]


def test_process_html_interactions_publishes_freeze_validate_complete_states(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    ipc = _IPC([_mutation_reply({
        "decision": "mutate",
        "intent": "Add result",
        "mutations": [{"op": "append", "target_ref": "document-body", "html": "<p>Ready</p>"}],
    })])
    states = []
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)
    monkeypatch.setattr(
        frontend_agent,
        "publish_html_interaction_state",
        lambda artifact_id, **state: states.append({"artifact_id": artifact_id, **state}),
    )

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [{"event_type": "click", "tag": "button", "text": "Run"}],
    )

    assert result["generated"] is True
    assert any(state["phase"] == "frozen" and state["frozen"] is True for state in states)
    assert any(state["phase"] == "validating" and state["frozen"] is True for state in states)
    assert states[-1]["phase"] == "completed"
    assert states[-1]["frozen"] is False
    assert states[-1]["stop_reason"] == "html_update_complete"
