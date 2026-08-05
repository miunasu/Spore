import hashlib
import json

import pytest
from fastapi import HTTPException

from AutoAgent import frontend_agent
from base.html_artifacts import HtmlArtifactStore
from base.html_interaction_state import (
    _reset_html_interaction_state_for_tests,
    _set_html_interaction_state_journal_for_tests,
    get_html_interaction_state,
    publish_html_interaction_state,
    record_html_interaction_coordinator,
)
from desktop_app.backend.routes import html as html_routes


def _operation_snapshot(artifact_id, *, barrier, awaiting=False, epoch=1):
    return {
        "artifact_id": artifact_id,
        "events": [{"event_type": "click", "tag": "button"}],
        "intent_epoch": epoch,
        "agent_request_id": f"request-{artifact_id}-{epoch}",
        "operation_id": f"operation-{artifact_id}-{epoch}",
        "episode_id": f"episode-{artifact_id}-{epoch}",
        "supplied_base_sha256": "a" * 64,
        "supplied_base_revision": 1,
        "supplied_state_revision": 1,
        "intent_snapshot": {"episode_id": f"episode-{artifact_id}-{epoch}"},
        "require_interaction_ready_ack": True,
        "status": "awaiting_ready_ack" if awaiting else ("barrier_committed" if barrier else "active"),
        "barrier_committed": barrier,
        "superseded": False,
        "awaiting_ready_ack": awaiting,
        "base_html_sha256": "a" * 64,
        "base_html_revision": 1,
        "created_at": 1.0,
    }


def test_restart_restores_only_frozen_owner_and_strict_recovery(tmp_path):
    journal = tmp_path / "interaction-state.json"
    raw_capability = "raw-secret-capability-that-must-never-be-persisted"
    capability_hash = hashlib.sha256(raw_capability.encode("utf-8")).hexdigest()
    artifact_id = "persisted-frozen"
    active = _operation_snapshot(artifact_id, barrier=True, awaiting=True, epoch=7)
    pending = _operation_snapshot(artifact_id, barrier=False, epoch=8)

    _set_html_interaction_state_journal_for_tests(journal)
    try:
        state = publish_html_interaction_state(
            artifact_id, phase="reloading", frozen=True, intent_epoch=7, active_intent_epoch=7,
            latest_pending_intent_epoch=8, agent_request_id=active["agent_request_id"],
            operation_id=active["operation_id"], episode_id=active["episode_id"],
            operation_outcome="artifact_committed", document_load_result="awaiting_ack",
            document_generation_id="generation-persisted", restore_attempt_id="restore-persisted",
            bridge_capability_hash=capability_hash, lease_seconds=1,
        )
        record_html_interaction_coordinator(artifact_id, {
            "latest_epoch": 8, "active": active, "latest_pending": pending, "updated_at": 1.0,
        })

        persisted_text = journal.read_text(encoding="utf-8")
        persisted_json = json.loads(persisted_text)
        assert raw_capability not in persisted_text
        assert capability_hash in persisted_text
        assert persisted_json["coordinators"][artifact_id]["latest_pending"]["operation_id"] == pending["operation_id"]
        assert "_bridge_capability_hash" not in get_html_interaction_state(artifact_id)

        # Simulate process restart without deleting the journal.
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _set_html_interaction_state_journal_for_tests(journal)
        restored_state = get_html_interaction_state(artifact_id)
        assert restored_state["frozen"] is True
        assert restored_state["operation_id"] == active["operation_id"]
        assert restored_state["lease_owner"] == active["operation_id"]
        assert restored_state["state_revision"] == state["state_revision"]
        assert "_bridge_capability_hash" not in restored_state

        coordinator = frontend_agent._get_coordinator(artifact_id)
        assert coordinator.active is not None
        assert coordinator.active.operation_id == active["operation_id"]
        # Pending provider work cannot survive restart and is not promoted as ghost work.
        assert coordinator.latest_pending is None

        recovered = frontend_agent.recover_html_interaction_operation(
            artifact_id, operation_id=active["operation_id"], agent_request_id=active["agent_request_id"],
            expected_state_revision=restored_state["state_revision"],
            now=restored_state["lease_expires_at"] + 0.01,
        )
        assert recovered["recovered"] is True
        assert recovered["state"]["frozen"] is False
        assert recovered["state"]["operation_outcome"] == "orphan_recovered"
        assert frontend_agent._get_coordinator(artifact_id).active is None
    finally:
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _reset_html_interaction_state_for_tests()
        _set_html_interaction_state_journal_for_tests(None)


def test_restart_does_not_resurrect_pre_barrier_provider_work(tmp_path):
    journal = tmp_path / "pre-barrier-state.json"
    artifact_id = "persisted-pre-barrier"
    active = _operation_snapshot(artifact_id, barrier=False, epoch=3)

    _set_html_interaction_state_journal_for_tests(journal)
    try:
        publish_html_interaction_state(
            artifact_id, phase="analyzing", frozen=False, intent_epoch=3,
            agent_request_id=active["agent_request_id"], operation_id=active["operation_id"],
        )
        record_html_interaction_coordinator(artifact_id, {
            "latest_epoch": 3, "active": active, "latest_pending": None, "updated_at": 1.0,
        })

        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _set_html_interaction_state_journal_for_tests(journal)
        coordinator = frontend_agent._get_coordinator(artifact_id)
        assert coordinator.latest_epoch == 3
        assert coordinator.active is None
        assert coordinator.latest_pending is None
        assert get_html_interaction_state(artifact_id)["frozen"] is False
    finally:
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _reset_html_interaction_state_for_tests()
        _set_html_interaction_state_journal_for_tests(None)


def test_corrupt_journal_quarantines_writes_and_new_interactions(monkeypatch, tmp_path):
    journal = tmp_path / "corrupt-interaction-state.json"
    journal.write_text('{"version": 1, "states": ', encoding="utf-8")
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("quarantined", "<!doctype html><html><body>safe</body></html>")
    monkeypatch.setattr(html_routes, "get_html_artifact_store", lambda: store)

    _set_html_interaction_state_journal_for_tests(journal)
    try:
        # Reading state may remain observable, but no action may infer that it is safe
        # to mutate or establish a new owner from the damaged journal.
        get_html_interaction_state("quarantined")
        for action in (
            lambda: html_routes.save_html_artifact(html_routes.HtmlSaveRequest(
                id="quarantined", content="<!doctype html><html><body>changed</body></html>",
            )),
            lambda: html_routes.generate_html_artifact(html_routes.HtmlGenerateRequest(
                id="quarantined", description="replace", force=True,
            )),
            lambda: html_routes.remove_html_artifact("quarantined"),
        ):
            with pytest.raises(HTTPException) as error:
                action()
            assert error.value.status_code == 409

        with pytest.raises(RuntimeError, match="journal is compromised"):
            frontend_agent._register_interaction_operation(
                "quarantined", [{"event_type": "click", "tag": "body"}],
                intent_epoch=1, agent_request_id="request-quarantine", operation_id="operation-quarantine",
                base_html_sha256=None, base_html_revision=None, state_revision=None,
                intent_snapshot=None, require_interaction_ready_ack=True,
            )
    finally:
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _reset_html_interaction_state_for_tests()
        _set_html_interaction_state_journal_for_tests(None)


def test_coordinator_journal_omits_raw_events_and_intent_snapshot(tmp_path):
    journal = tmp_path / "privacy-minimal-state.json"
    artifact_id = "privacy-minimal"
    secret_email = "private.person@example.com"
    secret_token = "token-super-secret-123"

    _set_html_interaction_state_journal_for_tests(journal)
    try:
        operation = frontend_agent._register_interaction_operation(
            artifact_id,
            [{"event_type": "selection", "selected_text": secret_email, "control": {"value": secret_token}}],
            episode_id="episode-privacy", intent_epoch=1,
            agent_request_id="request-privacy", operation_id="operation-privacy",
            base_html_sha256="a" * 64, base_html_revision=1, state_revision=0,
            intent_snapshot={"selected_text": secret_email, "private_token": secret_token},
            require_interaction_ready_ack=True,
        )
        assert frontend_agent._commit_interaction_barrier(operation, 30) is True

        persisted_text = journal.read_text(encoding="utf-8")
        persisted = json.loads(persisted_text)
        active = persisted["coordinators"][artifact_id]["active"]
        assert secret_email not in persisted_text
        assert secret_token not in persisted_text
        assert "events" not in active
        assert "intent_snapshot" not in active
        assert persisted["coordinators"][artifact_id]["latest_pending"] is None
    finally:
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _reset_html_interaction_state_for_tests()
        _set_html_interaction_state_journal_for_tests(None)


def test_awaiting_ready_owner_survives_immediate_restart(tmp_path):
    journal = tmp_path / "awaiting-ready-state.json"
    artifact_id = "awaiting-restart"

    _set_html_interaction_state_journal_for_tests(journal)
    try:
        operation = frontend_agent._register_interaction_operation(
            artifact_id, [{"event_type": "click", "tag": "button"}],
            episode_id="episode-awaiting", intent_epoch=4,
            agent_request_id="request-awaiting", operation_id="operation-awaiting",
            base_html_sha256="b" * 64, base_html_revision=2, state_revision=0,
            intent_snapshot=None, require_interaction_ready_ack=True,
        )
        assert frontend_agent._commit_interaction_barrier(operation, 30) is True
        coordinator = frontend_agent._get_coordinator(artifact_id)
        with coordinator.condition:
            operation.awaiting_ready_ack = True
            operation.status = "awaiting_ready_ack"
            frontend_agent._persist_coordinator(coordinator, artifact_id)
        state = publish_html_interaction_state(
            artifact_id, phase="reloading", frozen=True, intent_epoch=4,
            agent_request_id=operation.agent_request_id, operation_id=operation.operation_id,
            document_load_result="awaiting_ack", lease_seconds=30,
        )

        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _set_html_interaction_state_journal_for_tests(journal)
        restored = frontend_agent._get_coordinator(artifact_id)
        assert restored.active is not None
        assert restored.active.operation_id == operation.operation_id
        assert restored.active.awaiting_ready_ack is True
        assert restored.active.status == "awaiting_ready_ack"
        assert get_html_interaction_state(artifact_id)["state_revision"] == state["state_revision"]
    finally:
        frontend_agent._reset_frontend_interaction_runtime_for_tests()
        _reset_html_interaction_state_for_tests()
        _set_html_interaction_state_journal_for_tests(None)
