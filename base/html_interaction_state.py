"""Thread-safe runtime state for Frontend Agent HTML interaction transactions.

The state revision in this module is a broadcast/order token.  It is deliberately
separate from the persisted HTML revision and SHA-256 used for mutation CAS.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional


_DEFAULT_LEASE_SECONDS = 300.0
_FAILED_READY_LEASE_SECONDS = 8.0
# Phases that freeze the artifact before any mutation barrier is committed. Recovering
# one of them must not claim a commit happened: no document was ever persisted or loaded.
_PRE_BARRIER_FROZEN_PHASES = frozenset({"analyzing"})
# Phases added by the two-round assess/resume flow (never frozen).
_ASSESS_PHASES = frozenset({"awaiting_user_decision", "implementing", "discarded"})
_lock = threading.RLock()
_states: Dict[str, Dict[str, Any]] = {}
_state_revisions: Dict[str, int] = {}
_html_revisions: Dict[str, int] = {}
_html_sha256: Dict[str, str] = {}
_coordinator_journal: Dict[str, Dict[str, Any]] = {}
_journal_loaded = False
_journal_path_override: Optional[Path] = None
_journal_compromised = False
_journal_compromise_reason: Optional[str] = None


class HtmlArtifactWriteBlockedError(RuntimeError):
    """An ordinary artifact write cannot safely proceed."""


def _journal_path() -> Optional[Path]:
    if _journal_path_override is not None:
        return _journal_path_override
    configured = os.environ.get("SPORE_HTML_INTERACTION_STATE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    # Unit tests opt into persistence explicitly with the test helper below.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    return (Path.cwd() / ".spore" / "html_interaction_state.json").resolve()


def _ensure_loaded_locked() -> None:
    global _journal_loaded, _journal_compromised, _journal_compromise_reason
    if _journal_loaded:
        return
    _journal_loaded = True
    path = _journal_path()
    if path is None or not path.is_file():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or int(payload.get("version") or 0) != 1:
            raise ValueError("unsupported or malformed journal envelope")
        required_maps = ("states", "state_revisions", "html_revisions", "html_sha256", "coordinators")
        if any(not isinstance(payload.get(key), dict) for key in required_maps):
            raise ValueError("journal sections must be JSON objects")
        for target, source in (
            (_states, payload.get("states")),
            (_state_revisions, payload.get("state_revisions")),
            (_html_revisions, payload.get("html_revisions")),
            (_html_sha256, payload.get("html_sha256")),
            (_coordinator_journal, payload.get("coordinators")),
        ):
            if isinstance(source, dict):
                target.update(source)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        # Never infer idle/unfrozen ownership from a journal that exists but cannot
        # be trusted. Ordinary writes and new interactions remain quarantined until
        # an operator repairs/removes the journal and restarts the process.
        _journal_compromised = True
        _journal_compromise_reason = f"HTML interaction journal is compromised: {exc}"


def _persist_locked() -> None:
    if _journal_compromised:
        raise HtmlArtifactWriteBlockedError(_journal_compromise_reason or "HTML interaction journal is compromised")
    path = _journal_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "written_at": time.time(),
        "states": _states,
        "state_revisions": _state_revisions,
        "html_revisions": _html_revisions,
        "html_sha256": _html_sha256,
        "coordinators": _coordinator_journal,
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def assert_html_interaction_persistence_healthy() -> None:
    """Fail closed when the on-disk ownership journal cannot be trusted."""

    with _lock:
        _ensure_loaded_locked()
        if _journal_compromised:
            raise RuntimeError(_journal_compromise_reason or "HTML interaction journal is compromised")


def record_html_interaction_coordinator(artifact_id: str, snapshot: Optional[Dict[str, Any]]) -> None:
    """Persist the serializable active/latest-pending coordinator ownership journal."""
    with _lock:
        _ensure_loaded_locked()
        if snapshot is None:
            _coordinator_journal.pop(artifact_id, None)
        else:
            _coordinator_journal[artifact_id] = json.loads(json.dumps(snapshot, ensure_ascii=False))
        _persist_locked()


def get_html_interaction_coordinator_journal(artifact_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        _ensure_loaded_locked()
        snapshot = _coordinator_journal.get(artifact_id)
        return json.loads(json.dumps(snapshot, ensure_ascii=False)) if snapshot is not None else None


def _default_state(artifact_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    timestamp = time.time() if now is None else now
    state_revision = _state_revisions.get(artifact_id, 0)
    return {
        "artifact_id": artifact_id,
        "phase": "idle",
        "frozen": False,
        # `revision` is retained for existing clients; new clients should use state_revision.
        "revision": state_revision,
        "state_revision": state_revision,
        "intent_epoch": None,
        "active_intent_epoch": None,
        "latest_pending_intent_epoch": None,
        # Highest epoch the coordinator has admitted. Clients lift their local epoch
        # baseline from it so a reattached or restarted UI cannot keep emitting epochs
        # the backend already rejects as stale.
        "coordinator_latest_epoch": None,
        "agent_request_id": None,
        "operation_id": None,
        "episode_id": None,
        "base_html_revision": None,
        "base_html_sha256": None,
        "html_revision": _html_revisions.get(artifact_id, 0),
        "html_sha256": _html_sha256.get(artifact_id),
        "agent_stop_reason": None,
        "operation_outcome": None,
        "validation_result": None,
        "artifact_commit_result": None,
        "document_load_result": None,
        "readiness_report": None,
        "document_generation_id": None,
        "restore_attempt_id": None,
        "_bridge_capability_hash": None,
        "lease_owner": None,
        "lease_expires_at": None,
        "heartbeat_at": None,
        "error": None,
        "updated_at": timestamp,
    }


def _public_snapshot(state: Dict[str, Any]) -> Dict[str, Any]:
    """Return the external transaction shape without generic Spore protocol aliases."""

    snapshot = dict(state)
    snapshot.pop("stop_reason", None)
    snapshot.pop("_bridge_capability_hash", None)
    return snapshot


def _broadcast(snapshot: Dict[str, Any]) -> None:
    snapshot = _public_snapshot(snapshot)
    try:
        from desktop_app.backend.websocket.ipc_bridge import send_ws_message

        send_ws_message({"type": "html_interaction_state", "data": snapshot})
    except Exception:
        # State polling remains available even if the desktop WS process is not running.
        pass


@contextmanager
def unfrozen_html_artifact_write(artifact_id: str):
    """Serialize ordinary artifact writes against freeze-barrier publication.

    Holding the state RLock across the filesystem commit closes the check-then-save
    race: either the ordinary write completes before a barrier is published, or it
    observes the frozen owner and is rejected. Transaction-owned CAS writes bypass
    this guard because they intentionally execute after their own barrier.
    """

    with _lock:
        _ensure_loaded_locked()
        if _journal_compromised:
            raise HtmlArtifactWriteBlockedError(_journal_compromise_reason or "HTML interaction journal is compromised")
        state = _states.get(artifact_id)
        if state is not None and state.get("frozen"):
            raise HtmlArtifactWriteBlockedError("HTML artifact is owned by a frozen Frontend Agent transaction")
        yield


def get_html_interaction_state(artifact_id: str) -> Dict[str, Any]:
    """Return the latest state snapshot for one HTML artifact."""

    with _lock:
        _ensure_loaded_locked()
        return _public_snapshot(_states.get(artifact_id) or _default_state(artifact_id))


def observe_html_artifact_revision(artifact_id: str, sha256: Optional[str]) -> int:
    """Observe a persisted artifact without inventing a new revision on every load."""

    normalized = (sha256 or "").strip().lower()
    with _lock:
        _ensure_loaded_locked()
        changed = False
        if normalized and _html_sha256.get(artifact_id) != normalized:
            _html_revisions[artifact_id] = _html_revisions.get(artifact_id, 0) + 1
            _html_sha256[artifact_id] = normalized
            changed = True
        revision = _html_revisions.get(artifact_id, 0)
        state = _states.get(artifact_id)
        if state is not None:
            state["html_revision"] = revision
            state["html_sha256"] = _html_sha256.get(artifact_id)
            changed = True
        if changed:
            _persist_locked()
        return revision


def record_html_artifact_commit(artifact_id: str, sha256: Optional[str]) -> Dict[str, Any]:
    """Record a successful persisted HTML write and advance its independent revision."""

    normalized = (sha256 or "").strip().lower()
    with _lock:
        _ensure_loaded_locked()
        if normalized and _html_sha256.get(artifact_id) != normalized:
            _html_revisions[artifact_id] = _html_revisions.get(artifact_id, 0) + 1
            _html_sha256[artifact_id] = normalized
        state = dict(_states.get(artifact_id) or _default_state(artifact_id))
        state.pop("stop_reason", None)
        revision = _state_revisions.get(artifact_id, 0) + 1
        _state_revisions[artifact_id] = revision
        state.update({
            "revision": revision,
            "state_revision": revision,
            "html_revision": _html_revisions.get(artifact_id, 0),
            "html_sha256": _html_sha256.get(artifact_id),
            "updated_at": time.time(),
        })
        _states[artifact_id] = state
        _persist_locked()
        snapshot = _public_snapshot(state)
    _broadcast(snapshot)
    return snapshot


def publish_html_interaction_state(
    artifact_id: str,
    *,
    phase: str,
    frozen: bool,
    stop_reason: Optional[str] = None,
    error: Optional[str] = None,
    intent_epoch: Optional[int] = None,
    active_intent_epoch: Optional[int] = None,
    latest_pending_intent_epoch: Optional[int] = None,
    coordinator_latest_epoch: Optional[int] = None,
    agent_request_id: Optional[str] = None,
    operation_id: Optional[str] = None,
    episode_id: Optional[str] = None,
    base_html_revision: Optional[int] = None,
    base_html_sha256: Optional[str] = None,
    agent_stop_reason: Optional[str] = None,
    operation_outcome: Optional[str] = None,
    validation_result: Optional[Any] = None,
    artifact_commit_result: Optional[Any] = None,
    document_load_result: Optional[Any] = None,
    readiness_report: Optional[Any] = None,
    document_generation_id: Optional[str] = None,
    restore_attempt_id: Optional[str] = None,
    bridge_capability_hash: Optional[str] = None,
    lease_seconds: Optional[float] = None,
    reset_operation: bool = False,
    preserve_lease: bool = False,
) -> Dict[str, Any]:
    """Persist and best-effort broadcast one transaction state transition."""

    now = time.time()
    with _lock:
        _ensure_loaded_locked()
        previous = _states.get(artifact_id) or _default_state(artifact_id, now)
        state = dict(previous)
        state.pop("stop_reason", None)
        revision = _state_revisions.get(artifact_id, 0) + 1
        _state_revisions[artifact_id] = revision

        if reset_operation:
            for key in (
                "agent_stop_reason", "operation_outcome", "validation_result",
                "artifact_commit_result", "document_load_result", "readiness_report", "error", "lease_owner",
                "lease_expires_at", "heartbeat_at", "document_generation_id", "restore_attempt_id",
                "_bridge_capability_hash",
            ):
                state[key] = None

        state.update({
            "artifact_id": artifact_id,
            "phase": phase,
            "frozen": bool(frozen),
            "revision": revision,
            "state_revision": revision,
            "error": error,
            "updated_at": now,
            "html_revision": _html_revisions.get(artifact_id, state.get("html_revision", 0)),
            "html_sha256": _html_sha256.get(artifact_id, state.get("html_sha256")),
        })
        optional_updates = {
            "intent_epoch": intent_epoch,
            "active_intent_epoch": active_intent_epoch,
            "latest_pending_intent_epoch": latest_pending_intent_epoch,
            "coordinator_latest_epoch": coordinator_latest_epoch,
            "agent_request_id": agent_request_id,
            "operation_id": operation_id,
            "episode_id": episode_id,
            "base_html_revision": base_html_revision,
            "base_html_sha256": base_html_sha256,
            "operation_outcome": operation_outcome,
            "validation_result": validation_result,
            "artifact_commit_result": artifact_commit_result,
            "document_load_result": document_load_result,
            "readiness_report": readiness_report,
            "document_generation_id": document_generation_id,
            "restore_attempt_id": restore_attempt_id,
            "_bridge_capability_hash": bridge_capability_hash,
        }
        for key, value in optional_updates.items():
            if value is not None or key == "latest_pending_intent_epoch":
                state[key] = value

        resolved_stop_reason = agent_stop_reason if agent_stop_reason is not None else stop_reason
        if resolved_stop_reason is not None:
            state["agent_stop_reason"] = resolved_stop_reason

        if frozen:
            owner = operation_id or state.get("operation_id")
            lease_is_current = (
                preserve_lease
                and owner
                and state.get("lease_owner") == owner
                and state.get("lease_expires_at") is not None
            )
            if not lease_is_current:
                ttl = max(1.0, float(lease_seconds or _DEFAULT_LEASE_SECONDS))
                state["lease_owner"] = owner
                state["heartbeat_at"] = now
                state["lease_expires_at"] = now + ttl if owner else None
        else:
            state["lease_owner"] = None
            state["heartbeat_at"] = None
            state["lease_expires_at"] = None

        _states[artifact_id] = state
        _persist_locked()
        snapshot = _public_snapshot(state)

    _broadcast(snapshot)
    return snapshot



def update_html_interaction_pending_epoch(
    artifact_id: str,
    operation_id: str,
    latest_pending_intent_epoch: Optional[int],
) -> Dict[str, Any]:
    """Publish Latest-Wins queue metadata without invalidating ready/recovery CAS."""

    now = time.time()
    with _lock:
        _ensure_loaded_locked()
        state = _states.get(artifact_id)
        if state is None or state.get("operation_id") != operation_id:
            raise RuntimeError("HTML interaction operation is no longer current")
        state = dict(state)
        state["latest_pending_intent_epoch"] = latest_pending_intent_epoch
        state["updated_at"] = now
        _states[artifact_id] = state
        _persist_locked()
        snapshot = _public_snapshot(state)
    _broadcast(snapshot)
    return snapshot


def heartbeat_html_interaction(
    artifact_id: str,
    operation_id: str,
    *,
    agent_request_id: Optional[str] = None,
    lease_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Renew the freeze lease owned by the current committed operation."""

    now = time.time()
    with _lock:
        _ensure_loaded_locked()
        state = _states.get(artifact_id)
        if state is None or not state.get("frozen"):
            raise RuntimeError("HTML interaction is not frozen")
        if state.get("operation_id") != operation_id or state.get("lease_owner") != operation_id:
            raise RuntimeError("HTML interaction lease is owned by another operation")
        if agent_request_id and state.get("agent_request_id") != agent_request_id:
            raise RuntimeError("Frontend Agent request is no longer active")
        expiry = state.get("lease_expires_at")
        if expiry is not None and expiry <= now:
            raise RuntimeError("HTML interaction lease has expired")
        if state.get("phase") in {"reloading", "failed_after_barrier"} or state.get("document_load_result") in {"awaiting_ack", "failed"}:
            raise RuntimeError("HTML interaction lease is no longer heartbeat-renewable")
        # Heartbeats are liveness-only updates. They must not advance the semantic
        # state revision used as the exact ready/recovery CAS token.
        revision = int(state.get("state_revision") or _state_revisions.get(artifact_id, 0))
        state = dict(state)
        state.pop("stop_reason", None)
        state.update({
            "revision": revision,
            "state_revision": revision,
            "heartbeat_at": now,
            "lease_expires_at": now + max(1.0, float(lease_seconds or _DEFAULT_LEASE_SECONDS)),
            "updated_at": now,
        })
        _states[artifact_id] = state
        _persist_locked()
        snapshot = _public_snapshot(state)
    _broadcast(snapshot)
    return snapshot


def _validate_readiness_report(
    report: Any,
    *,
    ready: bool,
    document_generation_id: str,
    restore_attempt_id: str,
) -> Dict[str, Any]:
    if not isinstance(report, dict):
        raise RuntimeError("Document readiness acknowledgement requires a structured readiness report")
    normalized = dict(report)
    if normalized.get("document_generation_id") != document_generation_id:
        raise RuntimeError("Readiness report document generation does not match")
    if normalized.get("restore_attempt_id") != restore_attempt_id:
        raise RuntimeError("Readiness report restore attempt does not match")
    if bool(normalized.get("ready")) != bool(ready):
        raise RuntimeError("Readiness report outcome does not match the acknowledgement")
    if ready:
        if normalized.get("bridge_installed") is not True:
            raise RuntimeError("Trusted bridge did not report successful installation")
        if normalized.get("core_interactions_ready") is not True:
            raise RuntimeError("Core interaction monitoring is not ready")
        if normalized.get("initialization_pending") is True:
            raise RuntimeError("Document initialization is still pending")
        if str(normalized.get("document_ready_state") or "").lower() not in {"interactive", "complete"}:
            raise RuntimeError("Document did not reach an interactive ready state")
        if normalized.get("restore_requested") is True:
            restore_report = normalized.get("restore_report")
            if normalized.get("restored") is not True or not isinstance(restore_report, dict) or restore_report.get("success") is not True:
                raise RuntimeError("Runtime state restoration did not complete successfully")
    return normalized


def acknowledge_html_interaction_ready(
    artifact_id: str,
    operation_id: str,
    *,
    agent_request_id: Optional[str] = None,
    html_sha256: Optional[str] = None,
    state_revision: Optional[int] = None,
    document_generation_id: Optional[str] = None,
    restore_attempt_id: Optional[str] = None,
    bridge_capability_hash: Optional[str] = None,
    readiness_report: Optional[Any] = None,
    ready: bool = True,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Acknowledge the committed document's successful or failed initialization."""

    # Identity validation and the state transition are one RLock transaction. This
    # prevents a late ready ACK from racing lease recovery and reviving an orphaned
    # operation after it has already been released.
    with _lock:
        _ensure_loaded_locked()
        state = _states.get(artifact_id)
        if state is None:
            raise RuntimeError("No HTML interaction operation is awaiting readiness")
        if state.get("operation_id") != operation_id:
            raise RuntimeError("HTML interaction operation is no longer current")
        if agent_request_id and state.get("agent_request_id") != agent_request_id:
            raise RuntimeError("Frontend Agent request is no longer current")
        if state.get("phase") != "reloading" or state.get("document_load_result") != "awaiting_ack" or not state.get("frozen"):
            raise RuntimeError("HTML interaction is not awaiting this document readiness acknowledgement")
        if state_revision is None or int(state_revision) != int(state.get("state_revision") or 0):
            raise RuntimeError("Acknowledgement state revision conflict")
        if not document_generation_id or document_generation_id != state.get("document_generation_id"):
            raise RuntimeError("Document generation is no longer current")
        if not restore_attempt_id or restore_attempt_id != state.get("restore_attempt_id"):
            raise RuntimeError("Runtime restore attempt is no longer current")
        expected_capability_hash = str(state.get("_bridge_capability_hash") or "")
        if not bridge_capability_hash or bridge_capability_hash != expected_capability_hash:
            raise RuntimeError("Trusted bridge capability does not match the committed document")
        expected_sha = str(state.get("html_sha256") or "").strip().lower()
        resolved_sha = str(html_sha256 or "").strip().lower()
        if not resolved_sha or not expected_sha or resolved_sha != expected_sha:
            raise RuntimeError("Loaded HTML SHA-256 does not match the committed artifact")
        normalized_readiness_report = _validate_readiness_report(
            readiness_report,
            ready=ready,
            document_generation_id=document_generation_id,
            restore_attempt_id=restore_attempt_id,
        )
        intent_epoch = state.get("intent_epoch")
        agent_id = state.get("agent_request_id")
        agent_reason = state.get("agent_stop_reason")

        if ready:
            return publish_html_interaction_state(
                artifact_id,
                phase="interaction_ready",
                frozen=False,
                intent_epoch=intent_epoch,
                active_intent_epoch=intent_epoch,
                agent_request_id=agent_id,
                operation_id=operation_id,
                agent_stop_reason=agent_reason,
                operation_outcome="completed",
                document_load_result="ready",
                readiness_report=normalized_readiness_report,
                document_generation_id=document_generation_id,
                restore_attempt_id=restore_attempt_id,
                bridge_capability_hash=bridge_capability_hash,
            )
        return publish_html_interaction_state(
            artifact_id,
            phase="failed_after_barrier",
            frozen=True,
            intent_epoch=intent_epoch,
            active_intent_epoch=intent_epoch,
            agent_request_id=agent_id,
            operation_id=operation_id,
            agent_stop_reason=agent_reason,
            operation_outcome="document_load_failed",
            document_load_result="failed",
            readiness_report=normalized_readiness_report,
            document_generation_id=document_generation_id,
            restore_attempt_id=restore_attempt_id,
            bridge_capability_hash=bridge_capability_hash,
            lease_seconds=_FAILED_READY_LEASE_SECONDS,
            error=(error or "Committed HTML failed to load or initialize")[:500],
        )


def recover_orphaned_html_interaction(
    artifact_id: str,
    *,
    operation_id: str,
    agent_request_id: str,
    expected_state_revision: int,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """CAS-recover one expired freeze lease owned by the named operation.

    Recovery is intentionally strict: callers cannot force an active lease open, and
    stale UI/process snapshots cannot recover a newer transaction.
    """

    current_time = time.time() if now is None else float(now)
    expected_revision = int(expected_state_revision)
    if expected_revision < 0:
        raise RuntimeError("Recovery state revision must be non-negative")
    if not operation_id or not agent_request_id:
        raise RuntimeError("Recovery requires operation_id and agent_request_id")

    # Identity, revision and expiry validation plus all recovery phases are one
    # RLock transaction. A ready ACK or heartbeat cannot cross this CAS boundary.
    with _lock:
        _ensure_loaded_locked()
        state = _states.get(artifact_id)
        if state is None or not state.get("frozen"):
            raise RuntimeError("No frozen HTML interaction is eligible for recovery")
        if state.get("operation_id") != operation_id:
            raise RuntimeError("HTML interaction operation is no longer current")
        if state.get("agent_request_id") != agent_request_id:
            raise RuntimeError("Frontend Agent request is no longer current")
        if state.get("lease_owner") != operation_id:
            raise RuntimeError("HTML interaction lease is not owned by the requested operation")
        if int(state.get("state_revision") or 0) != expected_revision:
            raise RuntimeError("HTML interaction state revision conflict")
        expiry = state.get("lease_expires_at")
        if expiry is None or float(expiry) > current_time:
            raise RuntimeError("HTML interaction lease has not expired")

        intent_epoch = state.get("intent_epoch")
        agent_reason = state.get("agent_stop_reason")
        pre_barrier = str(state.get("phase") or "") in _PRE_BARRIER_FROZEN_PHASES
        orphaned = publish_html_interaction_state(
            artifact_id,
            phase="orphaned",
            frozen=True,
            intent_epoch=intent_epoch,
            active_intent_epoch=intent_epoch,
            agent_request_id=agent_request_id,
            operation_id=operation_id,
            agent_stop_reason=agent_reason,
            operation_outcome="orphaned",
            lease_seconds=1.0,
            error="HTML interaction freeze lease expired",
        )
        publish_html_interaction_state(
            artifact_id,
            phase="recovering",
            frozen=True,
            intent_epoch=intent_epoch,
            active_intent_epoch=intent_epoch,
            agent_request_id=agent_request_id,
            operation_id=operation_id,
            agent_stop_reason=agent_reason,
            operation_outcome="recovering",
            lease_seconds=1.0,
            error=orphaned.get("error"),
        )
        recovered = publish_html_interaction_state(
            artifact_id,
            # A pre-barrier freeze never committed an artifact, so reporting it as failing
            # after the barrier would overstate what happened to the document.
            phase="failed_before_barrier" if pre_barrier else "failed_after_barrier",
            frozen=False,
            intent_epoch=intent_epoch,
            active_intent_epoch=intent_epoch,
            agent_request_id=agent_request_id,
            operation_id=operation_id,
            agent_stop_reason=agent_reason,
            operation_outcome="orphan_recovered",
            document_load_result=None if pre_barrier else "unknown",
            error="Orphaned HTML interaction was recovered and unfrozen",
        )
        return {
            "recovered": True,
            "operation_id": operation_id,
            "agent_request_id": agent_request_id,
            "recovered_state_revision": expected_revision,
            "state": recovered,
        }
def _set_html_interaction_state_journal_for_tests(path: Optional[Path]) -> None:
    global _journal_loaded, _journal_path_override, _journal_compromised, _journal_compromise_reason
    with _lock:
        _journal_path_override = Path(path).resolve() if path is not None else None
        _journal_loaded = False
        _journal_compromised = False
        _journal_compromise_reason = None
        _states.clear()
        _state_revisions.clear()
        _html_revisions.clear()
        _html_sha256.clear()
        _coordinator_journal.clear()


def _reset_html_interaction_state_for_tests() -> None:
    global _journal_loaded, _journal_compromised, _journal_compromise_reason
    with _lock:
        _states.clear()
        _state_revisions.clear()
        _html_revisions.clear()
        _html_sha256.clear()
        _coordinator_journal.clear()
        _journal_loaded = True
        _journal_compromised = False
        _journal_compromise_reason = None
        path = _journal_path()
        if _journal_path_override is not None and path is not None and path.exists():
            path.unlink()
