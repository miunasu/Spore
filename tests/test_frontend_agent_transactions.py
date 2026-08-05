import json
import threading
import time

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from AutoAgent import frontend_agent
from base.html_artifacts import HtmlArtifactStore
from base.html_interaction_state import (
    _reset_html_interaction_state_for_tests,
    get_html_interaction_state,
    publish_html_interaction_state,
)
from desktop_app.backend.routes import html as html_routes


HTML_V1 = "<!doctype html><html><body><button>Run</button></body></html>"
HTML_V2 = "<!doctype html><html><body><main><button>New</button></main></body></html>"


def _final(payload, reason="agent_output_finished"):
    return json.dumps(payload) + f"\n@SPORE:STOP_REASON={reason}"


def _mutation(reason="agent_output_finished", text="Ready"):
    return (
        "interrupt\n"
        + json.dumps({
            "decision": "mutate",
            "intent": "Add the requested result",
            "mutations": [{
                "op": "append",
                "target_ref": "document-body",
                "html": f"<p>{text}</p>",
            }],
        })
        + f"\n@SPORE:STOP_REASON={reason}"
    )


class _Config:
    frontend_agent_timeout = 30
    frontend_agent_max_iterations = 3
    frontend_agent_freeze_lease_seconds = 30

    def resolve_agent_llm(self, profile):
        assert profile == "frontend"
        return {"model": "frontend-model"}

    def get_model(self):
        return "main-agent-model"


class _SequenceIPC:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []
        self._lock = threading.Lock()

    def send_chat_request(self, **kwargs):
        with self._lock:
            self.requests.append(kwargs)
            return f"provider-{len(self.requests)}"

    def get_chat_response(self, request_id, timeout):
        with self._lock:
            reply = self.replies.pop(0)
            request = self.requests[int(request_id.split("-")[-1]) - 1]
        callback = request.get("stream_callback")
        if callback:
            callback({"event": "delta", "delta": reply, "content": reply})
        return {"status": "success", "data": {"content": reply}}

    def cancel_request(self, request_id):
        return True




class _RequestAwareKnowledgeIPC(_SequenceIPC):
    def __init__(self, frontend_reply, *, transform_packet=None):
        super().__init__([])
        self.frontend_reply = frontend_reply
        self.transform_packet = transform_packet

    def get_chat_response(self, request_id, timeout):
        request = self.requests[int(request_id.split("-")[-1]) - 1]
        if request.get("agent_profile") is None:
            request_payload = json.loads(request["messages"][0]["content"].partition("\n")[2])
            source = next(item for item in request_payload["approved_sources"] if item["type"] == "main_agent")
            packet = {
                "status": "grounded",
                "answer": "The field controls execution.",
                "facts": [{
                    "id": "fact-run",
                    "claim": "Run starts execution.",
                    "evidence": "Declared behavior.",
                    "source_ids": [source["id"]],
                }],
                "uncertainties": [],
                "sources": [source],
            }
            if self.transform_packet is not None:
                packet = self.transform_packet(packet, request_payload)
            reply = json.dumps(packet)
        else:
            reply = self.frontend_reply
        callback = request.get("stream_callback")
        if callback:
            callback({"event": "delta", "delta": reply, "content": reply})
        return {"status": "success", "data": {"content": reply}}


class _LateCancelledIPC:
    def __init__(self, newer_reply):
        self.requests = []
        self.first_started = threading.Event()
        self.first_cancelled = threading.Event()
        self.newer_reply = newer_reply

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return f"provider-{len(self.requests)}"

    def cancel_request(self, request_id):
        if request_id == "provider-1":
            self.first_cancelled.set()
        return True

    def get_chat_response(self, request_id, timeout):
        request = self.requests[int(request_id.split("-")[-1]) - 1]
        callback = request.get("stream_callback")
        if request_id == "provider-1":
            self.first_started.set()
            assert self.first_cancelled.wait(5)
            # Simulate a provider that emits a stale late mutation even after cancellation.
            stale = _mutation(text="STALE")
            if callback:
                callback({"event": "delta", "delta": stale, "content": stale})
            return {"status": "success", "data": {"content": stale}}
        if callback:
            callback({"event": "delta", "delta": self.newer_reply, "content": self.newer_reply})
        return {"status": "success", "data": {"content": self.newer_reply}}


@pytest.fixture(autouse=True)
def _reset_runtime():
    frontend_agent._reset_frontend_interaction_runtime_for_tests()
    _reset_html_interaction_state_for_tests()
    yield
    frontend_agent._reset_frontend_interaction_runtime_for_tests()
    _reset_html_interaction_state_for_tests()


def _patch_runtime(monkeypatch, store, ipc):
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)




def _ready_kwargs(committed, *, ready=True, state_revision=None):
    restore_requested = False
    return {
        "agent_request_id": committed["agent_request_id"],
        "html_sha256": committed["html_sha256"],
        "state_revision": committed["state_revision"] if state_revision is None else state_revision,
        "document_generation_id": committed["document_generation_id"],
        "restore_attempt_id": committed["restore_attempt_id"],
        "bridge_capability": committed["bridge_capability"],
        "readiness_report": {
            "ready": ready,
            "bridge_installed": True,
            "core_interactions_ready": True,
            "document_generation_id": committed["document_generation_id"],
            "restore_attempt_id": committed["restore_attempt_id"],
            "restore_requested": restore_requested,
            "restored": False,
            "restore_report": {"requested": restore_requested, "success": False, "failures": []},
            "initialization_pending": False,
            "document_ready_state": "complete" if ready else "loading",
        },
        "ready": ready,
    }

def test_latest_wins_cancels_pre_barrier_and_ignores_stale_interrupt(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("latest-wins", HTML_V1)
    newer = _final({"decision": "no_change", "intent": "Latest intent is already satisfied", "mutations": []})
    ipc = _LateCancelledIPC(newer)
    _patch_runtime(monkeypatch, store, ipc)
    results = {}

    first = threading.Thread(target=lambda: results.setdefault(
        "first",
        frontend_agent.process_html_interactions(
            "latest-wins", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=1
        ),
    ))
    first.start()
    assert ipc.first_started.wait(5)

    second = threading.Thread(target=lambda: results.setdefault(
        "second",
        frontend_agent.process_html_interactions(
            "latest-wins", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=2
        ),
    ))
    second.start()
    first.join(5)
    second.join(5)

    assert not first.is_alive() and not second.is_alive()
    assert results["first"]["decision"] == "superseded"
    assert results["second"]["decision"] == "no_change"
    assert "STALE" not in store.load("latest-wins")["content"]
    state = get_html_interaction_state("latest-wins")
    assert state["frozen"] is False
    assert state["intent_epoch"] == 2


def test_barrier_holds_latest_pending_until_interaction_ready_ack(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("ready-ack", HTML_V1)
    ipc = _SequenceIPC([
        _mutation(reason="agent_done"),
        _final({"decision": "no_change", "intent": "Pending intent done", "mutations": []}),
    ])
    _patch_runtime(monkeypatch, store, ipc)

    committed = frontend_agent.process_html_interactions(
        "ready-ack",
        [{"event_type": "click", "tag": "button", "text": "Run"}],
        intent_epoch=1,
        require_interaction_ready_ack=True,
    )
    assert committed["requires_interaction_ready_ack"] is True
    assert committed["operation_outcome"] == "artifact_committed"
    frozen = get_html_interaction_state("ready-ack")
    assert frozen["phase"] == "reloading"
    assert frozen["frozen"] is True
    assert frozen["agent_stop_reason"] == "agent_done"
    assert frozen["operation_outcome"] == "artifact_committed"

    pending_result = {}
    pending_done = threading.Event()

    def run_pending():
        pending_result["value"] = frontend_agent.process_html_interactions(
            "ready-ack",
            [{"event_type": "click", "tag": "button", "text": "Run"}],
            intent_epoch=2,
        )
        pending_done.set()

    pending = threading.Thread(target=run_pending)
    pending.start()
    time.sleep(0.1)
    assert not pending_done.is_set()

    ready = frontend_agent.acknowledge_interaction_ready(
        "ready-ack", committed["operation_id"], **_ready_kwargs(committed)
    )
    assert ready["phase"] == "interaction_ready"
    assert ready["frozen"] is False
    assert ready["document_load_result"] == "ready"

    pending.join(5)
    assert pending_done.is_set()
    assert pending_result["value"]["intent_epoch"] == 2
    assert pending_result["value"]["decision"] == "no_change"


def test_commit_uses_atomic_sha_cas_and_preserves_newer_html(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("cas-artifact", HTML_V1)

    class _ConflictingIPC(_SequenceIPC):
        def get_chat_response(self, request_id, timeout):
            request = self.requests[0]
            reply = self.replies.pop(0)
            callback = request.get("stream_callback")
            if callback:
                callback({"event": "delta", "delta": reply, "content": reply})
            store.save("cas-artifact", HTML_V2)
            return {"status": "success", "data": {"content": reply}}

    _patch_runtime(monkeypatch, store, _ConflictingIPC([_mutation(text="OLD RESULT")]))

    with pytest.raises(frontend_agent.InteractionConflictError):
        frontend_agent.process_html_interactions(
            "cas-artifact", [{"event_type": "click", "tag": "button", "text": "Run"}]
        )

    assert store.load("cas-artifact")["content"].find("New") >= 0
    assert "OLD RESULT" not in store.load("cas-artifact")["content"]
    state = get_html_interaction_state("cas-artifact")
    assert state["phase"] == "failed_after_barrier"
    assert state["frozen"] is True
    assert state["operation_outcome"] == "revision_conflict"
    assert state["lease_owner"] == state["operation_id"]
    assert state["lease_expires_at"] is not None

    recovered = frontend_agent.recover_html_interaction_operation(
        "cas-artifact",
        operation_id=state["operation_id"],
        agent_request_id=state["agent_request_id"],
        expected_state_revision=state["state_revision"],
        now=state["lease_expires_at"] + 0.01,
    )
    assert recovered["recovered"] is True
    assert recovered["state"]["frozen"] is False


def test_protocol_retry_remains_frozen_and_stop_reason_is_not_outcome(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("retry-state", HTML_V1)
    incomplete = _mutation(reason="unused").split("\n@SPORE:STOP_REASON", 1)[0]
    ipc = _SequenceIPC([incomplete, _mutation(reason="agent_lifecycle_finished")])
    _patch_runtime(monkeypatch, store, ipc)
    transitions = []
    original_publish = frontend_agent.publish_html_interaction_state

    def capture(artifact_id, **kwargs):
        transitions.append(dict(kwargs))
        return original_publish(artifact_id, **kwargs)

    monkeypatch.setattr(frontend_agent, "publish_html_interaction_state", capture)
    result = frontend_agent.process_html_interactions(
        "retry-state", [{"event_type": "click", "tag": "button", "text": "Run"}]
    )

    assert result["iterations"] == 2
    assert any(item["phase"] == "protocol_retry_frozen" and item["frozen"] for item in transitions)
    assert result["agent_stop_reason"] == "agent_lifecycle_finished"
    assert result["operation_outcome"] == "completed"
    assert result["agent_stop_reason"] != result["operation_outcome"]


def test_expired_orphan_recovery_unfreezes_and_records_distinct_outcome():
    state = publish_html_interaction_state(
        "orphaned",
        phase="reloading",
        frozen=True,
        intent_epoch=7,
        active_intent_epoch=7,
        agent_request_id="agent-request-7",
        operation_id="html-operation-7",
        operation_outcome="artifact_committed",
        document_load_result="awaiting_ack",
        lease_seconds=1,
    )

    recovered = frontend_agent.recover_html_interaction_operation(
        "orphaned",
        operation_id=state["operation_id"],
        agent_request_id=state["agent_request_id"],
        expected_state_revision=state["state_revision"],
        now=state["lease_expires_at"] + 0.01,
    )

    assert recovered["recovered"] is True
    final = recovered["state"]
    assert final["phase"] == "failed_after_barrier"
    assert final["frozen"] is False
    assert final["operation_outcome"] == "orphan_recovered"
    assert final["document_load_result"] == "unknown"


def test_regular_save_route_supports_expected_sha256(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    initial = store.save("route-cas", HTML_V1)
    monkeypatch.setattr(html_routes, "get_html_artifact_store", lambda: store)

    saved = html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
        id="route-cas",
        content=HTML_V2,
        expected_sha256=initial["artifact"]["sha256"],
    ))
    assert saved["artifact"]["sha256"] != initial["artifact"]["sha256"]

    with pytest.raises(HTTPException) as error:
        html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
            id="route-cas",
            content=HTML_V1,
            expected_sha256=initial["artifact"]["sha256"],
        ))
    assert error.value.status_code == 409


def test_stale_intent_epoch_is_rejected_without_agent_call(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("epoch", HTML_V1)
    ipc = _SequenceIPC([
        _final({"decision": "no_change", "intent": "done", "mutations": []}),
    ])
    _patch_runtime(monkeypatch, store, ipc)

    first = frontend_agent.process_html_interactions(
        "epoch", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=3
    )
    stale = frontend_agent.process_html_interactions(
        "epoch", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=2
    )

    assert first["decision"] == "no_change"
    assert stale["decision"] == "superseded"
    assert len(ipc.requests) == 1



def _register_direct_operation(artifact_id, *, intent_epoch=1, agent_request_id=None, operation_id=None):
    return frontend_agent._register_interaction_operation(
        artifact_id,
        [{"event_type": "click", "tag": "button", "text": "Run"}],
        intent_epoch=intent_epoch,
        agent_request_id=agent_request_id,
        operation_id=operation_id,
        base_html_sha256=None,
        base_html_revision=None,
        state_revision=None,
        intent_snapshot=None,
        require_interaction_ready_ack=False,
    )


@pytest.mark.parametrize(
    "chunks",
    [
        ["  Do not interrupt the current analysis.\n"],
        ["interruption\n"],
        ['{"decision":"no_change","intent":"the word interrupt is data","mutations":[]}'],
        ["\n", "analysis first\n", "interrupt\n"],
    ],
    ids=["negation", "interruption", "json-content", "not-first-output"],
)
def test_stream_interrupt_false_positives_do_not_commit_barrier(chunks):
    operation = _register_direct_operation("stream-false-positive")
    callback = frontend_agent._interaction_stream_callback(operation, 30)
    accumulated = ""

    for chunk in chunks:
        accumulated += chunk
        callback({"event": "delta", "delta": chunk, "content": accumulated})

    assert operation.barrier_committed is False
    state = get_html_interaction_state("stream-false-positive")
    assert state["frozen"] is False
    assert state["phase"] == "idle"


def test_stream_partial_interrupt_prefix_does_not_freeze_when_completed_as_interruption():
    operation = _register_direct_operation("stream-partial-word")
    callback = frontend_agent._interaction_stream_callback(operation, 30)

    callback({"event": "delta", "delta": "interrupt", "content": "interrupt"})
    assert operation.barrier_committed is False
    callback({"event": "delta", "delta": "ion\n", "content": "interruption\n"})

    assert operation.barrier_committed is False
    assert get_html_interaction_state("stream-partial-word")["frozen"] is False


def test_stream_standalone_interrupt_across_chunks_commits_barrier_once(monkeypatch):
    operation = _register_direct_operation("stream-split")
    commits = []
    original_commit = frontend_agent._commit_interaction_barrier

    def counted_commit(current, lease_seconds):
        commits.append((current.operation_id, lease_seconds))
        return original_commit(current, lease_seconds)

    monkeypatch.setattr(frontend_agent, "_commit_interaction_barrier", counted_commit)
    callback = frontend_agent._interaction_stream_callback(operation, 45)
    chunks = [" \nint", "errupt\n", '{"decision":"mutate"}']
    accumulated = ""
    for chunk in chunks:
        accumulated += chunk
        callback({"event": "delta", "delta": chunk, "content": accumulated})

    assert commits == [(operation.operation_id, 45)]
    assert operation.barrier_committed is True
    state = get_html_interaction_state("stream-split")
    assert state["phase"] == "frozen"
    assert state["frozen"] is True
    assert state["operation_id"] == operation.operation_id


def test_superseded_old_stream_cannot_freeze_from_late_interrupt():
    operation = _register_direct_operation(
        "stale-stream",
        intent_epoch=1,
        agent_request_id="request-old",
        operation_id="operation-old",
    )
    callback = frontend_agent._interaction_stream_callback(operation, 30)

    cancelled = frontend_agent.supersede_html_interaction_operation(
        "stale-stream",
        operation_id="operation-old",
        agent_request_id="request-old",
        intent_epoch=2,
        reason="newer intent",
    )
    callback({"event": "delta", "delta": "interrupt\n", "content": "interrupt\n"})

    assert cancelled["superseded"] is True
    assert operation.superseded is True
    assert operation.barrier_committed is False
    state = get_html_interaction_state("stale-stream")
    assert state["frozen"] is False
    assert state["phase"] == "superseded"


class _ExplicitCancelIPC:
    def __init__(self):
        self.requests = []
        self.started = threading.Event()
        self.cancelled = threading.Event()
        self.cancelled_ids = []

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return "provider-explicit-cancel"

    def cancel_request(self, request_id):
        self.cancelled_ids.append(request_id)
        self.cancelled.set()
        return True

    def get_chat_response(self, request_id, timeout):
        self.started.set()
        assert self.cancelled.wait(5)
        stale = _mutation(text="LATE STALE")
        callback = self.requests[0].get("stream_callback")
        if callback:
            callback({"event": "delta", "delta": stale, "content": stale})
        return {"status": "success", "data": {"content": stale}}


class _BarrierBlockingIPC:
    def __init__(self):
        self.requests = []
        self.barrier_seen = threading.Event()
        self.release = threading.Event()
        self.cancelled_ids = []

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return "provider-after-barrier"

    def cancel_request(self, request_id):
        self.cancelled_ids.append(request_id)
        return True

    def get_chat_response(self, request_id, timeout):
        callback = self.requests[0].get("stream_callback")
        if callback:
            callback({"event": "delta", "delta": "interrupt\n", "content": "interrupt\n"})
        self.barrier_seen.set()
        assert self.release.wait(5)
        reply = _mutation(text="BARRIER OWNED")
        if callback:
            callback({"event": "delta", "delta": reply[len("interrupt\n"):], "content": reply})
        return {"status": "success", "data": {"content": reply}}


def test_explicit_pre_barrier_supersede_cancels_provider_and_late_interrupt_is_stale(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("explicit-cancel", HTML_V1)
    ipc = _ExplicitCancelIPC()
    _patch_runtime(monkeypatch, store, ipc)
    result = {}

    worker = threading.Thread(target=lambda: result.setdefault(
        "value",
        frontend_agent.process_html_interactions(
            "explicit-cancel",
            [{"event_type": "click", "tag": "button", "text": "Run"}],
            intent_epoch=1,
            agent_request_id="request-explicit",
            operation_id="operation-explicit",
        ),
    ))
    worker.start()
    assert ipc.started.wait(5)

    superseded = frontend_agent.supersede_html_interaction_operation(
        "explicit-cancel",
        operation_id="operation-explicit",
        agent_request_id="request-explicit",
        intent_epoch=2,
        reason="user changed focus",
    )
    worker.join(5)

    assert not worker.is_alive()
    assert superseded["superseded"] is True
    assert ipc.cancelled_ids == ["provider-explicit-cancel"]
    assert result["value"]["decision"] == "superseded"
    assert "LATE STALE" not in store.load("explicit-cancel")["content"]
    state = get_html_interaction_state("explicit-cancel")
    assert state["frozen"] is False
    assert state["phase"] == "superseded"


def test_explicit_supersede_is_rejected_after_interrupt_barrier(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("barrier-reject", HTML_V1)
    ipc = _BarrierBlockingIPC()
    _patch_runtime(monkeypatch, store, ipc)
    result = {}

    worker = threading.Thread(target=lambda: result.setdefault(
        "value",
        frontend_agent.process_html_interactions(
            "barrier-reject",
            [{"event_type": "click", "tag": "button", "text": "Run"}],
            intent_epoch=1,
            agent_request_id="request-barrier",
            operation_id="operation-barrier",
        ),
    ))
    worker.start()
    assert ipc.barrier_seen.wait(5)

    rejected = frontend_agent.supersede_html_interaction_operation(
        "barrier-reject",
        operation_id="operation-barrier",
        agent_request_id="request-barrier",
        intent_epoch=2,
        reason="too late",
    )
    frozen = get_html_interaction_state("barrier-reject")
    ipc.release.set()
    worker.join(5)

    assert rejected["superseded"] is False
    assert rejected["reason"] == "barrier_committed"
    assert frozen["frozen"] is True
    assert frozen["operation_id"] == "operation-barrier"
    assert ipc.cancelled_ids == []
    assert not worker.is_alive()
    assert result["value"]["decision"] == "updated"
    assert "BARRIER OWNED" in store.load("barrier-reject")["content"]


def test_explicit_supersede_advances_epoch_before_active_registration(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("epoch-ahead", HTML_V1)
    ipc = _SequenceIPC([_final({"decision": "no_change", "intent": "unused", "mutations": []})])
    _patch_runtime(monkeypatch, store, ipc)

    advanced = frontend_agent.supersede_html_interaction_operation(
        "epoch-ahead",
        operation_id="not-yet-active",
        agent_request_id="request-not-yet-active",
        intent_epoch=9,
    )
    stale = frontend_agent.process_html_interactions(
        "epoch-ahead",
        [{"event_type": "click", "tag": "button", "text": "Run"}],
        intent_epoch=8,
        agent_request_id="request-old",
        operation_id="operation-old",
    )

    assert advanced["superseded"] is False
    assert advanced["reason"] == "operation_not_active"
    assert stale["decision"] == "superseded"
    assert ipc.requests == []
    assert get_html_interaction_state("epoch-ahead")["frozen"] is False


def _commit_awaiting_ready(monkeypatch, tmp_path, artifact_id):
    store = HtmlArtifactStore(tmp_path / artifact_id)
    store.save(artifact_id, HTML_V1)
    _patch_runtime(monkeypatch, store, _SequenceIPC([_mutation(text=artifact_id)]))
    committed = frontend_agent.process_html_interactions(
        artifact_id,
        [{"event_type": "click", "tag": "button", "text": "Run"}],
        intent_epoch=1,
        agent_request_id=f"request-{artifact_id}",
        operation_id=f"operation-{artifact_id}",
        require_interaction_ready_ack=True,
    )
    return store, committed


def test_ready_false_is_terminal_until_expired_cas_recovery(monkeypatch, tmp_path):
    _, committed = _commit_awaiting_ready(monkeypatch, tmp_path, "ready-retry")
    before = get_html_interaction_state("ready-retry")

    failed = frontend_agent.acknowledge_interaction_ready(
        "ready-retry", committed["operation_id"],
        **_ready_kwargs(committed, ready=False),
        error="iframe initialization failed",
    )

    assert failed["phase"] == "failed_after_barrier"
    assert failed["frozen"] is True
    assert failed["document_load_result"] == "failed"
    assert failed["lease_owner"] == committed["operation_id"]
    assert failed["lease_expires_at"] < before["lease_expires_at"]
    assert failed["heartbeat_at"] >= before["heartbeat_at"]

    with pytest.raises(RuntimeError, match="not awaiting"):
        frontend_agent.acknowledge_interaction_ready(
            "ready-retry", committed["operation_id"],
            **_ready_kwargs(committed, state_revision=failed["state_revision"]),
        )


def test_http_transaction_models_require_complete_identity_and_sha256():
    valid_sha = "a" * 64
    ready = html_routes.HtmlInteractionReadyRequest(
        operation_id="operation", agent_request_id="request", html_sha256=valid_sha, state_revision=0,
        document_generation_id="generation", restore_attempt_id="restore",
        bridge_capability="c" * 32, readiness_report={"ready": True},
    )
    assert ready.html_sha256 == valid_sha

    with pytest.raises(ValidationError):
        html_routes.HtmlInteractionReadyRequest(operation_id="operation")
    with pytest.raises(ValidationError):
        html_routes.HtmlInteractionReadyRequest(
            operation_id="operation", agent_request_id="request", html_sha256="not-a-sha", state_revision=0,
            document_generation_id="generation", restore_attempt_id="restore", bridge_capability="c" * 32,
        )
    with pytest.raises(ValidationError):
        html_routes.HtmlInteractionRequest(events=[{"event_type": "click"}])


def test_ready_false_preserves_lease_until_expired_cas_recovery(monkeypatch, tmp_path):
    _, committed = _commit_awaiting_ready(monkeypatch, tmp_path, "ready-recover")
    failed = frontend_agent.acknowledge_interaction_ready(
        "ready-recover", committed["operation_id"], **_ready_kwargs(committed, ready=False)
    )
    lease_expiry = failed["lease_expires_at"]

    with pytest.raises(RuntimeError, match="has not expired"):
        frontend_agent.recover_html_interaction_operation(
            "ready-recover",
            operation_id=committed["operation_id"],
            agent_request_id=committed["agent_request_id"],
            expected_state_revision=failed["state_revision"],
            now=lease_expiry - 0.01,
        )
    recovered = frontend_agent.recover_html_interaction_operation(
        "ready-recover",
        operation_id=committed["operation_id"],
        agent_request_id=committed["agent_request_id"],
        expected_state_revision=failed["state_revision"],
        now=lease_expiry + 0.01,
    )

    assert lease_expiry is not None
    assert recovered["recovered"] is True
    assert recovered["operation_id"] == committed["operation_id"]
    assert recovered["state"]["phase"] == "failed_after_barrier"
    assert recovered["state"]["frozen"] is False
    assert recovered["state"]["operation_outcome"] == "orphan_recovered"
    assert recovered["state"]["lease_owner"] is None
    assert recovered["state"]["lease_expires_at"] is None
    with pytest.raises(RuntimeError, match="not awaiting"):
        frontend_agent.acknowledge_interaction_ready(
            "ready-recover", committed["operation_id"],
            **_ready_kwargs(committed, state_revision=failed["state_revision"]),
        )


def test_backend_reparses_semantic_presentation_and_mutation_refs_without_trusting_iframe_selector():
    current = """<!doctype html><html><body>
    <section id="semantic-node" data-spore-semantic-ref="semantic-token" aria-controls="presentation-node"><span id="actual-click">Field</span></section>
    <section id="selector-decoy"><span id="decoy-click">Field</span></section>
    <aside id="presentation-node" data-spore-presentation-ref="presentation-token">
      <div id="mutation-node" data-spore-mutation-ref="mutation-token"></div>
    </aside>
    </body></html>"""
    event = frontend_agent._clean_click_event({
        "event_type": "dblclick",
        "tag": "span",
        "element_id": "actual-click",
        "text": "Field",
        "dom_path": "body > section:nth-of-type(2) > span:nth-of-type(1)",
        "semantic_ref": "#selector-decoy",
        "trust_level": "trusted",
    }, 0)
    snapshot = frontend_agent.normalize_semantic_intent_snapshot({
        "semantic_focus_ref": "semantic-token",
        "presentation_target_ref": "presentation-token",
        "mutation_target_ref": "mutation-token",
        "focus": {
            "ref": "semantic-token",
            "inspector_ref": "selector-decoy",
            "container_ref": "body > section:nth-of-type(2)",
        },
        "candidate_intents": ["explain_field"],
    })

    context, _, references = frontend_agent._build_interaction_context(current, [event], snapshot)
    targets = context["reference_targets"][0]

    assert references["click-1"].get("id") == "actual-click"
    assert references[targets["semantic_focus_ref"]].get("id") == "semantic-node"
    assert references[targets["presentation_target_ref"]].get("id") == "presentation-node"
    assert references[targets["mutation_target_ref"]].get("id") == "mutation-node"
    assert targets["iframe_candidates_trusted"] is False
    assert context["interactions"][0]["trust_level"] == "iframe_bridge_candidate"
    assert "dom_path" not in context["interactions"][0]
    backend_click_ref = next(item for item in context["references"] if item["ref"] == "click-1")
    assert backend_click_ref["selector"] == "body > section:nth-of-type(1) > span:nth-of-type(1)"


def _knowledge_snapshot():
    return {
        "episode_id": "knowledge-episode",
        "intent_epoch": 1,
        "semantic_focus_ref": "button-ref",
        "focus": {"ref": "button-ref", "label": "Run"},
        "candidate_intents": ["explain_field"],
        "confidence": "high",
    }


def test_knowledge_chain_uses_main_agent_config_and_injects_packet_into_frontend_message(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("knowledge-chain", HTML_V1)
    ipc = _RequestAwareKnowledgeIPC(
        _final({"decision": "no_change", "intent": "Explanation is already present", "mutations": []}),
    )
    _patch_runtime(monkeypatch, store, ipc)

    result = frontend_agent.process_html_interactions(
        "knowledge-chain",
        [{"event_type": "click", "tag": "button", "text": "Run"}],
        intent_snapshot=_knowledge_snapshot(),
    )

    assert result["decision"] == "no_change"
    assert len(ipc.requests) == 2
    knowledge_request, frontend_request = ipc.requests
    assert knowledge_request["model"] == "main-agent-model"
    assert knowledge_request["agent_profile"] is None
    assert knowledge_request["use_sub_agent_config"] is False
    assert knowledge_request["stream"] is False
    request_payload = json.loads(knowledge_request["messages"][0]["content"].partition("\n")[2])
    knowledge_request_id = request_payload["knowledge_request_id"]
    assert knowledge_request_id.startswith("knowledge-")
    assert all(source["id"].endswith(":" + knowledge_request_id) for source in request_payload["approved_sources"])
    assert all((":request:" + knowledge_request_id) in source["locator"] for source in request_payload["approved_sources"])
    assert frontend_request["model"] == "frontend-model"
    assert frontend_request["agent_profile"] == "frontend"
    frontend_content = frontend_request["messages"][0]["content"]
    context = json.loads(frontend_content.partition("Interaction context:\n")[2])
    packet = context["knowledge_packet"]
    assert packet["provider"] == "main_agent"
    assert packet["authority"] == "host_attested"
    assert packet["status"] == "grounded"
    assert packet["knowledge_request_id"] == knowledge_request_id
    assert len(packet["authority_digest"]) == 64
    assert packet["facts"][0]["id"].startswith("fact-")
    assert packet["facts"][0]["id"] != "fact-run"
    assert packet["facts"][0]["source_ids"][0].endswith(":" + knowledge_request_id)
    assert context["semantic_intent_episode"]["knowledge_requirement"]["required"] is True

def test_grounded_knowledge_without_source_linkage_is_downgraded():
    packet = frontend_agent._normalize_knowledge_packet({
        "status": "grounded",
        "answer": "A material answer",
        "facts": [{"claim": "A material fact", "evidence": "Unlinked evidence", "source_ids": []}],
        "sources": [{"id": "declared-source", "title": "Declared"}],
    })

    assert packet["status"] == "uncertain"
    assert packet["facts"] == []
    assert any("did not fully ground" in item for item in packet["uncertainties"])


def test_knowledge_packet_omits_invalid_sources_and_unsupported_facts():
    registry = {
        "good": {"id": "good", "type": "approved_knowledge_source", "title": "Approved", "locator": "registry"},
    }
    packet = frontend_agent._normalize_knowledge_packet({
        "status": "grounded",
        "answer": "Potential answer",
        "sources": [{"id": "bad"}, {"id": "good", "locator": "provider-controlled"}],
        "facts": [
            {"id": "bad-fact", "claim": "Bad source", "evidence": "text", "source_ids": ["bad"]},
            {"id": "empty-evidence", "claim": "No evidence", "evidence": "", "source_ids": ["good"]},
            {"id": "good-fact", "claim": "Grounded", "evidence": "quoted context", "source_ids": ["good"]},
        ],
    }, source_registry=registry)

    assert packet["status"] == "uncertain"
    assert [source["id"] for source in packet["sources"]] == ["good"]
    assert packet["sources"][0]["locator"] == "registry"
    assert packet["facts"] == [{
        "id": "good-fact", "claim": "Grounded", "evidence": "quoted context", "source_ids": ["good"],
    }]


def test_runtime_knowledge_contract_rejects_static_ids_tampered_metadata_and_extra_keys():
    request_id = "knowledge-" + "b" * 32
    registry = frontend_agent._approved_knowledge_source_registry(
        {"component_id": "strict", "semantic_intent_episode": {"episode_id": "episode-strict"}},
        request_id,
    )
    approved = next(item for item in registry.values() if item["type"] == "main_agent")

    def normalize(source, source_id, **extra):
        return frontend_agent._normalize_knowledge_packet({
            "status": "grounded",
            "answer": "An answer",
            "facts": [{
                "id": "provider-fact",
                "claim": "A claim",
                "evidence": "Evidence",
                "source_ids": [source_id],
            }],
            "uncertainties": [],
            "sources": [source],
            **extra,
        }, source_registry=registry, knowledge_request_id=request_id, strict_contract=True)

    static = normalize({"id": "main-agent-knowledge"}, "main-agent-knowledge")
    tampered_source = dict(approved, locator="provider-controlled")
    tampered = normalize(tampered_source, approved["id"])
    extra_key = normalize(approved, approved["id"], provider="forged")

    assert static["status"] == "uncertain"
    assert static["facts"] == []
    assert tampered["status"] == "uncertain"
    assert tampered["sources"] == []
    assert extra_key["status"] == "unavailable"
    assert extra_key["authority"] == "host_attested"
    assert frontend_agent._knowledge_packet_authority_is_valid(extra_key) is True


def test_runtime_knowledge_json_requires_one_unfenced_object_without_duplicate_keys():
    with pytest.raises((json.JSONDecodeError, ValueError)):
        frontend_agent._strict_json_object('```json\n{"status":"unavailable"}\n```')
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        frontend_agent._strict_json_object('{"status":"unavailable","status":"grounded"}')
    with pytest.raises(ValueError, match="one JSON object"):
        frontend_agent._strict_json_object('[]')


@pytest.mark.parametrize("status", ["unavailable", "error"])
def test_unavailable_or_error_knowledge_clears_unsupported_content(status):
    packet = frontend_agent._normalize_knowledge_packet({
        "status": status,
        "answer": "Must not reach the Frontend Agent as an answer",
        "facts": [{"claim": "Must be cleared", "source_ids": ["source-1"]}],
        "sources": [{"id": "source-1", "title": "Source"}],
    })

    assert packet["status"] == status
    assert packet["answer"] == ""
    assert packet["facts"] == []


class _BlockingKnowledgeIPC:
    def __init__(self):
        self.requests = []
        self.knowledge_started = threading.Event()
        self.cancelled = threading.Event()
        self.cancelled_ids = []

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return "provider-knowledge"

    def cancel_request(self, request_id):
        self.cancelled_ids.append(request_id)
        self.cancelled.set()
        return True

    def get_chat_response(self, request_id, timeout):
        self.knowledge_started.set()
        assert self.cancelled.wait(5)
        return {"status": "cancelled", "error": "superseded"}


def test_knowledge_request_can_be_cancelled_before_barrier(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("knowledge-cancel", HTML_V1)
    ipc = _BlockingKnowledgeIPC()
    _patch_runtime(monkeypatch, store, ipc)
    result = {}

    worker = threading.Thread(target=lambda: result.setdefault(
        "value",
        frontend_agent.process_html_interactions(
            "knowledge-cancel",
            [{"event_type": "click", "tag": "button", "text": "Run"}],
            intent_epoch=1,
            agent_request_id="request-knowledge",
            operation_id="operation-knowledge",
            intent_snapshot=_knowledge_snapshot(),
        ),
    ))
    worker.start()
    assert ipc.knowledge_started.wait(5)

    superseded = frontend_agent.supersede_html_interaction_operation(
        "knowledge-cancel",
        operation_id="operation-knowledge",
        agent_request_id="request-knowledge",
        intent_epoch=2,
        reason="newer semantic focus",
    )
    worker.join(5)

    assert not worker.is_alive()
    assert superseded["superseded"] is True
    assert ipc.cancelled_ids == ["provider-knowledge"]
    assert len(ipc.requests) == 1
    assert ipc.requests[0]["model"] == "main-agent-model"
    assert result["value"]["decision"] == "superseded"
    state = get_html_interaction_state("knowledge-cancel")
    assert state["frozen"] is False
    assert state["phase"] == "superseded"


def test_public_recovery_contract_rejects_force_and_requires_expired_identity_cas():
    with pytest.raises(ValidationError):
        html_routes.HtmlInteractionRecoverRequest(force=True)

    state = publish_html_interaction_state(
        "strict-recovery",
        phase="reloading",
        frozen=True,
        agent_request_id="request-strict",
        operation_id="operation-strict",
        lease_seconds=1,
    )
    expired = state["lease_expires_at"] + 0.01
    for overrides in (
        {"operation_id": "wrong"},
        {"agent_request_id": "wrong"},
        {"expected_state_revision": state["state_revision"] + 1},
    ):
        kwargs = {
            "operation_id": state["operation_id"],
            "agent_request_id": state["agent_request_id"],
            "expected_state_revision": state["state_revision"],
            "now": expired,
            **overrides,
        }
        with pytest.raises(RuntimeError):
            frontend_agent.recover_html_interaction_operation("strict-recovery", **kwargs)


def test_missing_or_cross_namespace_mutation_ref_never_falls_back():
    current = """<!doctype html><html><body>
    <section data-spore-semantic-ref="shared"><span id="clicked">Field</span></section>
    <aside data-spore-presentation-ref="shared"></aside>
    </body></html>"""
    event = frontend_agent._clean_click_event({
        "event_type": "dblclick", "tag": "span", "element_id": "clicked", "text": "Field",
    }, 0)
    snapshot = frontend_agent.normalize_semantic_intent_snapshot({
        "semantic_focus_ref": "shared",
        "presentation_target_ref": "shared",
        "mutation_target_ref": "shared",
        "focus": {"ref": "shared", "inspector_ref": "shared"},
    })

    context, _, references = frontend_agent._build_interaction_context(current, [event], snapshot)
    targets = context["reference_targets"][0]
    assert targets["semantic_focus_ref"] is not None
    assert targets["presentation_target_ref"] is not None
    assert targets["mutation_target_ref"] is None
    assert "click-1" not in context["allowed_mutation_refs"]
    assert frontend_agent._validate_mutation_target_refs(
        [{"op": "append", "target_ref": targets["semantic_focus_ref"], "html": "<p>x</p>"}],
        context["allowed_mutation_refs"],
    )["errors"][0]["code"] == "mutation_reference_namespace"
    assert targets["semantic_focus_ref"] in references


def test_domain_mutation_requires_valid_fact_and_approved_source_linkage():
    snapshot = {"knowledge_requirement": {"required": True}}
    request_id = "knowledge-" + "a" * 32
    registry = frontend_agent._approved_knowledge_source_registry(
        {"component_id": "grounding", "semantic_intent_episode": {"episode_id": "episode-1"}},
        request_id,
    )
    source = next(item for item in registry.values() if item["type"] == "main_agent")
    packet = frontend_agent._normalize_knowledge_packet({
        "status": "grounded",
        "answer": "Run starts execution.",
        "facts": [{
            "id": "fact-1",
            "claim": "Run starts execution.",
            "evidence": "Main Agent analysis.",
            "source_ids": [source["id"]],
        }],
        "uncertainties": [],
        "sources": [source],
    }, source_registry=registry, knowledge_request_id=request_id, strict_contract=True)
    fact_id = packet["facts"][0]["id"]
    source_id = packet["sources"][0]["id"]
    base = {"decision": "mutate", "intent": "Explain the field", "mutations": []}

    missing = frontend_agent._validate_knowledge_grounding(
        {**base, "fact_ids": [], "source_ids": []}, snapshot, packet,
    )
    unknown = frontend_agent._validate_knowledge_grounding(
        {**base, "fact_ids": ["fact-x"], "source_ids": ["source-x"]}, snapshot, packet,
    )
    valid = frontend_agent._validate_knowledge_grounding(
        {**base, "fact_ids": [fact_id], "source_ids": [source_id]}, snapshot, packet,
    )
    tampered = dict(packet, answer="Tampered answer")
    invalid_authority = frontend_agent._validate_knowledge_grounding(
        {**base, "fact_ids": [fact_id], "source_ids": [source_id]}, snapshot, tampered,
    )

    assert missing["errors"][0]["code"] == "knowledge_linkage_required"
    assert {item["code"] for item in unknown["errors"]} == {"unknown_fact_id", "unknown_source_id"}
    assert valid is None
    assert invalid_authority["errors"][0]["code"] == "knowledge_authority_invalid"


def test_frozen_transaction_blocks_regular_save_route(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    initial = store.save("frozen-save", HTML_V1)
    monkeypatch.setattr(html_routes, "get_html_artifact_store", lambda: store)
    publish_html_interaction_state(
        "frozen-save", phase="reloading", frozen=True,
        agent_request_id="request-save", operation_id="operation-save", lease_seconds=30,
    )

    with pytest.raises(HTTPException) as error:
        html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
            id="frozen-save", content=HTML_V2, expected_sha256=initial["artifact"]["sha256"],
        ))
    assert error.value.status_code == 409
    assert store.load("frozen-save")["artifact"]["sha256"] == initial["artifact"]["sha256"]


def test_ready_ack_rejects_capability_and_readiness_report_spoofing(monkeypatch, tmp_path):
    _, committed = _commit_awaiting_ready(monkeypatch, tmp_path, "ready-spoof")
    baseline = get_html_interaction_state("ready-spoof")

    bad_capability = _ready_kwargs(committed)
    bad_capability["bridge_capability"] = "wrong-capability-" + "x" * 32
    with pytest.raises(RuntimeError, match="capability"):
        frontend_agent.acknowledge_interaction_ready(
            "ready-spoof", committed["operation_id"], **bad_capability,
        )

    bad_report = _ready_kwargs(committed)
    bad_report["readiness_report"] = dict(bad_report["readiness_report"], document_generation_id="stale")
    with pytest.raises(RuntimeError, match="report document generation"):
        frontend_agent.acknowledge_interaction_ready(
            "ready-spoof", committed["operation_id"], **bad_report,
        )

    restore_incomplete = _ready_kwargs(committed)
    restore_incomplete["readiness_report"] = dict(
        restore_incomplete["readiness_report"],
        restore_requested=True, restored=False,
        restore_report={"requested": True, "success": False, "failures": [{"reason": "ref_not_found"}]},
    )
    with pytest.raises(RuntimeError, match="restoration"):
        frontend_agent.acknowledge_interaction_ready(
            "ready-spoof", committed["operation_id"], **restore_incomplete,
        )

    still_frozen = get_html_interaction_state("ready-spoof")
    assert still_frozen["frozen"] is True
    assert still_frozen["state_revision"] == baseline["state_revision"]
    accepted = frontend_agent.acknowledge_interaction_ready(
        "ready-spoof", committed["operation_id"], **_ready_kwargs(committed),
    )
    assert accepted["frozen"] is False
    assert accepted["document_load_result"] == "ready"


def test_strict_identity_rejects_every_mismatched_layer_before_agent_call(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    saved = store.save("strict-identity", HTML_V1)
    ipc = _SequenceIPC([_final({"decision": "no_change", "intent": "unused", "mutations": []})])
    _patch_runtime(monkeypatch, store, ipc)
    identity = {
        "episode_id": "episode-strict", "intent_epoch": 4,
        "agent_request_id": "request-strict", "operation_id": "operation-strict",
        "base_html_revision": 0, "base_sha256": saved["artifact"]["sha256"], "state_revision": 0,
    }
    snapshot = {
        "episode_id": identity["episode_id"], "intent_epoch": identity["intent_epoch"],
        "request_identity": dict(identity), "focus": {"ref": "document-body"},
    }
    event = {"event_type": "click", "tag": "button", **identity}

    mismatch_cases = [
        ({**snapshot, "episode_id": "wrong"}, event),
        ({**snapshot, "intent_epoch": 5}, event),
        ({**snapshot, "request_identity": {**identity, "operation_id": "wrong"}}, event),
        (snapshot, {**event, "agent_request_id": "wrong"}),
        (snapshot, {**event, "base_sha256": "b" * 64}),
    ]
    for bad_snapshot, bad_event in mismatch_cases:
        with pytest.raises(ValueError, match="does not match"):
            frontend_agent.process_html_interactions(
                "strict-identity", [bad_event],
                episode_id=identity["episode_id"], intent_epoch=identity["intent_epoch"],
                agent_request_id=identity["agent_request_id"], operation_id=identity["operation_id"],
                base_html_revision=identity["base_html_revision"],
                base_html_sha256=identity["base_sha256"], state_revision=identity["state_revision"],
                intent_snapshot=bad_snapshot, require_interaction_ready_ack=True,
            )
    assert ipc.requests == []


def test_heartbeat_does_not_invalidate_ready_cas_and_stops_at_reloading(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("heartbeat-cas", HTML_V1)
    _patch_runtime(monkeypatch, store, _SequenceIPC([_mutation(text="heartbeat")]))
    operation = _register_direct_operation(
        "heartbeat-cas", intent_epoch=1, agent_request_id="request-heartbeat", operation_id="operation-heartbeat",
    )
    assert frontend_agent._commit_interaction_barrier(operation, 30) is True
    before = get_html_interaction_state("heartbeat-cas")
    renewed = frontend_agent.heartbeat_interaction_operation(
        "heartbeat-cas", operation.operation_id, agent_request_id=operation.agent_request_id,
    )
    assert renewed["state_revision"] == before["state_revision"]
    assert renewed["lease_expires_at"] >= before["lease_expires_at"]

    publish_html_interaction_state(
        "heartbeat-cas", phase="reloading", frozen=True,
        agent_request_id=operation.agent_request_id, operation_id=operation.operation_id,
        document_load_result="awaiting_ack", preserve_lease=True,
    )
    with pytest.raises(RuntimeError, match="no longer heartbeat-renewable"):
        frontend_agent.heartbeat_interaction_operation(
            "heartbeat-cas", operation.operation_id, agent_request_id=operation.agent_request_id,
        )
    frontend_agent._finish_interaction_operation(operation, force=True)


def test_regular_save_and_freeze_barrier_are_atomically_serialized(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    initial = store.save("save-barrier-race", HTML_V1)
    entered_save = threading.Event()
    release_save = threading.Event()
    save_done = threading.Event()
    barrier_done = threading.Event()
    result = {}

    class BlockingStore:
        def save_if_sha256(self, *args, **kwargs):
            entered_save.set()
            assert release_save.wait(5)
            return store.save_if_sha256(*args, **kwargs)

        def save(self, *args, **kwargs):
            entered_save.set()
            assert release_save.wait(5)
            return store.save(*args, **kwargs)

    monkeypatch.setattr(html_routes, "get_html_artifact_store", lambda: BlockingStore())

    def run_save():
        result["saved"] = html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
            id="save-barrier-race", content=HTML_V2, expected_sha256=initial["artifact"]["sha256"],
        ))
        save_done.set()

    def run_barrier():
        result["barrier"] = publish_html_interaction_state(
            "save-barrier-race", phase="barrier_committed", frozen=True,
            agent_request_id="request-race", operation_id="operation-race", lease_seconds=30,
        )
        barrier_done.set()

    save_thread = threading.Thread(target=run_save)
    barrier_thread = threading.Thread(target=run_barrier)
    save_thread.start()
    assert entered_save.wait(5)
    barrier_thread.start()
    time.sleep(0.05)
    assert not barrier_done.is_set()
    release_save.set()
    save_thread.join(5)
    barrier_thread.join(5)

    assert save_done.is_set() and barrier_done.is_set()
    assert result["saved"]["artifact"]["sha256"] != initial["artifact"]["sha256"]
    assert result["barrier"]["frozen"] is True
    assert get_html_interaction_state("save-barrier-race")["operation_id"] == "operation-race"


def test_frozen_transaction_blocks_all_ordinary_write_routes(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    initial = store.save("frozen-all-writes", HTML_V1)
    monkeypatch.setattr(html_routes, "get_html_artifact_store", lambda: store)
    publish_html_interaction_state(
        "frozen-all-writes", phase="reloading", frozen=True,
        agent_request_id="request-all-writes", operation_id="operation-all-writes", lease_seconds=30,
    )

    with pytest.raises(HTTPException) as save_error:
        html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
            id="frozen-all-writes", content=HTML_V2,
        ))
    assert save_error.value.status_code == 409

    with pytest.raises(HTTPException) as generate_error:
        html_routes.generate_html_artifact(html_routes.HtmlGenerateRequest(
            id="frozen-all-writes", description="replace it", force=True,
        ))
    assert generate_error.value.status_code == 409

    with pytest.raises(HTTPException) as delete_error:
        html_routes.remove_html_artifact("frozen-all-writes")
    assert delete_error.value.status_code == 409
    assert store.load("frozen-all-writes")["artifact"]["sha256"] == initial["artifact"]["sha256"]


def test_frozen_state_without_matching_durable_owner_rejects_new_interaction():
    publish_html_interaction_state(
        "owner-mismatch", phase="frozen", frozen=True,
        agent_request_id="request-orphan", operation_id="operation-orphan", lease_seconds=30,
    )

    with pytest.raises(RuntimeError, match="ownership journal"):
        _register_direct_operation(
            "owner-mismatch", intent_epoch=2,
            agent_request_id="request-new", operation_id="operation-new",
        )


def test_element_id_cannot_override_conflicting_semantic_evidence():
    soup = frontend_agent.BeautifulSoup(
        "<!doctype html><html><body><span id='field-a'>Alpha</span><span id='field-b'>Beta</span></body></html>",
        "html.parser",
    )
    click = {
        "event_type": "dblclick",
        "tag": "span",
        "element_id": "field-b",
        "dom_path": "body > span:nth-of-type(1)",
        "text": "Alpha",
    }

    assert frontend_agent._resolve_click_node(soup, click) is None
def test_analyzing_phase_freezes_the_artifact_before_the_barrier(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("dispatch-freeze", HTML_V1)
    _patch_runtime(monkeypatch, store, _SequenceIPC([_mutation(text="Dispatched")]))
    transitions = []
    original_publish = frontend_agent.publish_html_interaction_state

    def capture(artifact_id, **kwargs):
        transitions.append(dict(kwargs))
        return original_publish(artifact_id, **kwargs)

    monkeypatch.setattr(frontend_agent, "publish_html_interaction_state", capture)
    result = frontend_agent.process_html_interactions(
        "dispatch-freeze", [{"event_type": "click", "tag": "button", "text": "Run"}]
    )

    analyzing = [item for item in transitions if item["phase"] == "analyzing"]
    assert analyzing, "dispatch must publish an analyzing transition"
    # The page is frozen from dispatch, not from the barrier, so user edits cannot race
    # the mutation the Agent is deriving from this exact DOM.
    assert all(item["frozen"] is True for item in analyzing)
    assert all(item.get("lease_seconds") for item in analyzing)
    assert result["decision"] == "updated"


def test_stale_intent_epoch_rejection_reports_the_admitted_epoch(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("epoch-feedback", HTML_V1)
    ipc = _SequenceIPC([_final({"decision": "no_change", "intent": "done", "mutations": []})])
    _patch_runtime(monkeypatch, store, ipc)

    frontend_agent.process_html_interactions(
        "epoch-feedback", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=5
    )
    stale = frontend_agent.process_html_interactions(
        "epoch-feedback", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=2
    )

    # A stale rejection publishes no state transition, so the admitted high-water mark
    # must travel back on the result or a drifted client loses every later intent.
    assert stale["decision"] == "superseded"
    assert stale["coordinator_latest_epoch"] == 5
    assert len(ipc.requests) == 1


def test_published_state_exposes_the_admitted_coordinator_epoch(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("epoch-state", HTML_V1)
    _patch_runtime(monkeypatch, store, _SequenceIPC([
        _final({"decision": "no_change", "intent": "done", "mutations": []}),
    ]))

    frontend_agent.process_html_interactions(
        "epoch-state", [{"event_type": "click", "tag": "button", "text": "Run"}], intent_epoch=4
    )

    assert get_html_interaction_state("epoch-state")["coordinator_latest_epoch"] == 4


def test_pre_barrier_freeze_without_live_owner_admits_a_newer_intent():
    # A pre-barrier freeze is only ever backed by an in-process owner. Once that owner is
    # gone nothing it guarded can be resumed, so a newer intent must be able to take over
    # instead of leaving the artifact permanently unresponsive.
    publish_html_interaction_state(
        "pre-barrier-takeover", phase="analyzing", frozen=True,
        agent_request_id="request-gone", operation_id="operation-gone", lease_seconds=30,
    )

    operation = _register_direct_operation(
        "pre-barrier-takeover", intent_epoch=2,
        agent_request_id="request-new", operation_id="operation-new",
    )

    assert operation.status == "active"
    assert operation.superseded is False


def test_committed_barrier_without_matching_owner_still_rejects_new_interaction():
    publish_html_interaction_state(
        "barrier-owner-mismatch", phase="barrier_committed", frozen=True,
        agent_request_id="request-orphan", operation_id="operation-orphan", lease_seconds=30,
    )

    with pytest.raises(RuntimeError, match="ownership journal"):
        _register_direct_operation(
            "barrier-owner-mismatch", intent_epoch=2,
            agent_request_id="request-new", operation_id="operation-new",
        )


def test_pre_barrier_orphan_recovery_does_not_claim_a_committed_document():
    state = publish_html_interaction_state(
        "pre-barrier-orphan",
        phase="analyzing",
        frozen=True,
        intent_epoch=3,
        active_intent_epoch=3,
        agent_request_id="agent-request-3",
        operation_id="html-operation-3",
        operation_outcome="analyzing",
        lease_seconds=1,
    )

    recovered = frontend_agent.recover_html_interaction_operation(
        "pre-barrier-orphan",
        operation_id=state["operation_id"],
        agent_request_id=state["agent_request_id"],
        expected_state_revision=state["state_revision"],
        now=state["lease_expires_at"] + 0.01,
    )

    final = recovered["state"]
    assert recovered["recovered"] is True
    assert final["frozen"] is False
    # Nothing was persisted or loaded before the barrier, so the recovery must not report
    # a post-barrier document failure.
    assert final["phase"] == "failed_before_barrier"
    assert final["document_load_result"] is None
    assert final["operation_outcome"] == "orphan_recovered"