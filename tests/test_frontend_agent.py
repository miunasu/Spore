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
        '<!doctype html><html><body><main data-spore-mutation-ref="interaction-output">'
        '<p>Transport Layer Security</p>'
        '<button data-spore-target="details">Open details</button></main></body></html>'
    )
    store.save("demo-tool", initial)
    mutation = _mutation_reply({
        "decision": "mutate",
        "intent": "Show the selected item and materialize the requested detail view",
        "mutations": [
            {
                "op": "after",
                "target_ref": "mutation-target-1",
                "html": '<aside class="term-selection">Selected item: Transport</aside>',
            },
            {
                "op": "after",
                "target_ref": "mutation-target-1",
                "html": '<section id="details">Generated details</section>',
            },
        ],
    })
    ipc = _IPC([mutation])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [
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
        ],
        intent_snapshot={
            "focuses": [{"object_name": "Transport"}],
            "mutation_target_ref": "interaction-output",
        },
    )

    assert result["generated"] is True
    assert result["decision"] == "updated"
    assert result["event_count"] == 2
    assert result["mutation_count"] == 2
    assert 'id="details"' in result["content"]
    assert "Selected item: Transport" in result["content"]
    assert len(ipc.requests) == 1
    request_content = ipc.requests[0]["messages"][0]["content"]
    assert '"clicked_word": "Transport"' in request_content
    assert '"ref": "click-1"' in request_content
    assert '"ref": "click-2"' in request_content
    assert '"mutation_target_ref": "mutation-target-1"' in request_content
    assert '"allowed_mutation_refs": [' in request_content
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
    initial = HTML_V1.replace("<button", '<button data-spore-mutation-ref="run-output"')
    store.save("demo-tool", initial)
    invalid = _mutation_reply({
        "decision": "mutate",
        "intent": "Add details",
        "mutations": [{"op": "after", "target_ref": "invented", "html": "<p>Wrong</p>"}],
    })
    valid = _mutation_reply({
        "decision": "mutate",
        "intent": "Add details",
        "mutations": [{"op": "after", "target_ref": "mutation-target-1", "html": "<p>Ready</p>"}],
    })
    ipc = _IPC([invalid, valid])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [{
            "tag": "button",
            "text": "Run",
            "dom_path": "body > button:nth-of-type(1)",
        }],
        intent_snapshot={
            "focuses": [{"object_name": "Run"}],
            "mutation_target_ref": "run-output",
        },
    )

    assert result["iterations"] == 2
    assert "Ready" in result["content"]
    assert "Wrong" not in result["content"]
    assert "not an approved mutation reference: invented" in ipc.requests[1]["messages"][-1]["content"]


def test_process_html_interactions_recovers_when_queued_click_path_shifted(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    shifted = (
        "<!doctype html><html><body><main><button>Inserted earlier</button>"
        '<button data-spore-mutation-ref="original-output">Original target</button>'
        "</main></body></html>"
    )
    store.save("demo-tool", shifted)
    mutation = _mutation_reply({
        "decision": "mutate",
        "intent": "Add the requested result after the original target",
        "mutations": [{"op": "after", "target_ref": "mutation-target-1", "html": "<p>Correct place</p>"}],
    })
    ipc = _IPC([mutation])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions(
        "demo-tool",
        [{
            "tag": "button",
            "text": "Original target",
            # This was button 1 before an earlier queued batch inserted another button.
            "dom_path": "body > main:nth-of-type(1) > button:nth-of-type(1)",
        }],
        intent_snapshot={
            "focuses": [{"object_name": "Original target"}],
            "mutation_target_ref": "original-output",
        },
    )

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
    abort = _final_reply({
        "decision": "abort_after_barrier",
        "intent": "Network access is not permitted; abort the frozen transaction",
        "mutations": [],
    })
    ipc = _IPC([unsafe, abort])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.process_html_interactions("demo-tool", [{"tag": "button", "text": "Run"}])

    assert result["generated"] is False
    assert result["iterations"] == 2
    assert result["decision"] == "aborted"
    assert result["operation_outcome"] == "abort_after_barrier"
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

def test_mutation_protocol_requires_exact_interrupt_and_keeps_lifecycle_separate():
    payload = {
        "decision": "mutate",
        "intent": "Add result",
        "mutations": [{"op": "append", "target_ref": "document-body", "html": "<p>Ready</p>"}],
    }

    try:
        frontend_agent._parse_mutation_response(json.dumps(payload))
    except ValueError as exc:
        assert "exact lowercase standalone interrupt" in str(exc)
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


def test_mutation_protocol_rejects_nonexact_interrupt_and_json_fences():
    payload = {
        "decision": "mutate",
        "intent": "Add result",
        "mutations": [{"op": "append", "target_ref": "document-body", "html": "<p>Ready</p>"}],
    }

    for raw in (
        "Interrupt\n" + json.dumps(payload),
        "interrupt now\n" + json.dumps(payload),
        "prefix\ninterrupt\n" + json.dumps(payload),
        "interrupt\n```json\n" + json.dumps(payload) + "\n```",
    ):
        try:
            frontend_agent._parse_mutation_response(raw)
        except ValueError:
            pass
        else:
            raise AssertionError(f"non-exact mutation protocol was accepted: {raw!r}")


def test_frontend_stop_reason_must_be_unique_and_terminal():
    payload = {
        "decision": "no_change",
        "intent": "already satisfied",
        "mutations": [],
    }
    reply = _final_reply(payload, "already_satisfied")
    assert frontend_agent._strip_spore_stop_reason(reply) == json.dumps(payload)

    invalid_replies = (
        "@SPORE:STOP_REASON=too_early\n" + json.dumps(payload),
        reply + "\ntrailing business output",
        reply + "\n@SPORE:STOP_REASON=duplicate",
    )
    for invalid in invalid_replies:
        try:
            frontend_agent._strip_spore_stop_reason(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"non-terminal or duplicate stop reason was accepted: {invalid!r}")


def test_abort_after_barrier_payload_is_explicit_and_has_no_interrupt():
    response = frontend_agent._parse_mutation_response(json.dumps({
        "decision": "abort_after_barrier",
        "intent": "Cannot produce a valid mutation",
        "mutations": [],
    }))

    assert response["decision"] == "abort_after_barrier"
    assert response["mutations"] == []
    assert response["interrupt"] is False


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
    assert result["agent_stop_reason"] == "frontend_agent_finished"
    assert "stop_reason" not in result
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
    assert states[-1]["agent_stop_reason"] == "html_update_complete"
    assert "stop_reason" not in states[-1]
