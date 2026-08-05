"""One-shot frontend Agent for generating sandboxed HTML artifacts."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Doctype, Tag

from base.config import get_config
from base.html_artifacts import (
    get_html_artifact_store,
    validate_artifact_id,
    validate_html,
)
from base.html_semantic_intent import (
    DYNAMIC_WINDOW_POLICY,
    normalize_candidate_event,
    normalize_semantic_intent_snapshot,
    sanitize_observed_url,
)
from base.html_interaction_state import (
    acknowledge_html_interaction_ready as acknowledge_html_interaction_ready_state,
    assert_html_interaction_persistence_healthy,
    get_html_interaction_state,
    get_html_interaction_coordinator_journal,
    heartbeat_html_interaction,
    observe_html_artifact_revision,
    publish_html_interaction_state,
    record_html_artifact_commit,
    record_html_interaction_coordinator,
    recover_orphaned_html_interaction,
    update_html_interaction_pending_epoch,
)
from base.logger import log_error, log_frontend_agent, log_frontend_agent_raw
from base.prompt_loader import load_system_prompt
from base.text_protocol import ProtocolManager, extract_stop_reason_blocks


_ipc_manager = None
_HTML_FENCE = re.compile(r"```html\s*\r?\n([\s\S]*?)\r?\n```", re.IGNORECASE)
_JSON_FENCE = re.compile(r"```(?:json)?\s*\r?\n([\s\S]*?)\r?\n```", re.IGNORECASE)
_HTML_DOCUMENT = re.compile(r"(?:<!doctype\s+html\b|<html\b)", re.IGNORECASE)
_INTERRUPT_PREFIX = re.compile(r"^interrupt$")
_REPLY_START_MARKER = "@SPORE:REPLY_START"
_REPLY_END_MARKER = "@SPORE:REPLY_END"
_DOM_PATH = re.compile(
    r"^body(?:\s*>\s*[a-z][a-z0-9-]*:nth-of-type\([1-9][0-9]{0,3}\))*$",
    re.IGNORECASE,
)
_ATTRIBUTE_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_.:-]{0,99}$")
_CONTENT_MUTATIONS = {"append", "prepend", "before", "after", "replace_inner", "replace_outer"}
_ALLOWED_MUTATIONS = _CONTENT_MUTATIONS | {"set_attributes", "remove"}
_MAX_MUTATIONS = 24
_MAX_MUTATION_BYTES = 128 * 1024
_MAX_MUTATION_RESPONSE_BYTES = 256 * 1024
_MAX_CONTEXT_SNIPPET_BYTES = 20 * 1024
_VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
_coordinators: Dict[str, "_ArtifactCoordinator"] = {}
_coordinators_guard = threading.Lock()
_KNOWLEDGE_AUTHORITY_SECRET = secrets.token_bytes(32)
# Round-1 (ASSESS) protocol keyword — distinct from "interrupt" so the stream
# callback never accidentally triggers a barrier during the assess round.
_ASSESS_PAUSE_KEYWORD = "assess_pause"


class InteractionConflictError(RuntimeError):
    """The interaction result can no longer be committed against its base artifact."""


class InteractionSupersededError(RuntimeError):
    """An interaction request lost Latest-Wins arbitration before its barrier."""


@dataclass
class _InteractionOperation:
    artifact_id: str
    events: List[Dict[str, Any]]
    intent_epoch: int
    agent_request_id: str
    operation_id: str
    episode_id: Optional[str] = None
    supplied_base_sha256: Optional[str] = None
    supplied_base_revision: Optional[int] = None
    supplied_state_revision: Optional[int] = None
    intent_snapshot: Optional[Dict[str, Any]] = None
    require_interaction_ready_ack: bool = False
    status: str = "pending"
    barrier_committed: bool = False
    superseded: bool = False
    awaiting_ready_ack: bool = False
    provider_request_id: Optional[str] = None
    base_html_sha256: Optional[str] = None
    base_html_revision: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    # Pending confirmation: agent-computed candidate held until user accepts
    pending_candidate: Optional[str] = None
    pending_intent: Optional[str] = None
    # Round-1 (ASSESS) output: question/suggestion held for user decision
    pending_question: Optional[str] = None
    awaiting_user_response: bool = False
    user_response: Optional[str] = None  # populated by resume_html_interaction


# Phases that freeze the artifact before any mutation barrier is committed. Their
# ownership is memory-only: it is never persisted for cross-process recovery, because
# the provider work they guard cannot be resumed after the process exits.
_PRE_BARRIER_FROZEN_PHASES = frozenset({"analyzing"})


@dataclass
class _ArtifactCoordinator:
    condition: threading.Condition = field(default_factory=lambda: threading.Condition(threading.RLock()))
    latest_epoch: int = 0
    active: Optional[_InteractionOperation] = None
    latest_pending: Optional[_InteractionOperation] = None


def set_ipc_manager(ipc_manager):
    global _ipc_manager
    _ipc_manager = ipc_manager


def extract_html_response(response: str) -> Optional[str]:
    fenced = _HTML_FENCE.search(response or "")
    if fenced:
        return fenced.group(1).strip()

    match = _HTML_DOCUMENT.search(response or "")
    if not match:
        return None
    candidate = response[match.start():].strip()
    closing = re.search(r"</html\s*>", candidate, re.IGNORECASE)
    if closing:
        candidate = candidate[:closing.end()]
    return candidate


def _call_frontend_agent(
    messages,
    timeout: int,
    stream_callback=None,
    request_started_callback=None,
) -> str:
    if _ipc_manager is None:
        raise RuntimeError("Frontend Agent IPC is not initialized")

    config = get_config()
    resolved = config.resolve_agent_llm("frontend")
    request_id = _ipc_manager.send_chat_request(
        messages=messages,
        model=resolved["model"],
        system=load_system_prompt("prompt/frontend_prompt.md"),
        agent_profile="frontend",
        tool_calls=False,
        stream=stream_callback is not None,
        stream_callback=stream_callback,
    )
    if request_started_callback is not None:
        request_started_callback(request_id)
    response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
    if response is None or response.get("status") != "success":
        status = response.get("status") if isinstance(response, dict) else None
        detail = response.get("error") if isinstance(response, dict) else "timeout"
        if status == "cancelled":
            raise InteractionSupersededError("Frontend Agent request was cancelled")
        raise RuntimeError(f"Frontend Agent request failed: {detail}")
    content = (response.get("data") or {}).get("content", "")
    log_frontend_agent_raw(content)
    if stream_callback is not None:
        # Some providers do not expose deltas even when streaming was requested.
        # Feeding the final snapshot keeps the interrupt protocol deterministic.
        stream_callback({"event": "final", "delta": "", "content": content})
    return content


_APPROVED_KNOWLEDGE_SOURCE_REGISTRY: Dict[str, Dict[str, str]] = {
    "artifact-context": {
        "id": "artifact-context",
        "title": "Persisted HTML artifact context",
        "type": "provided_context",
        "locator": "artifact-context",
    },
    "semantic-intent": {
        "id": "semantic-intent",
        "title": "Normalized semantic intent episode",
        "type": "provided_context",
        "locator": "semantic-intent",
    },
    "main-agent-knowledge": {
        "id": "main-agent-knowledge",
        "title": "Main Agent domain analysis",
        "type": "main_agent",
        "locator": "main-agent",
    },
}
_KNOWLEDGE_PACKET_KEYS = {"status", "answer", "facts", "uncertainties", "sources"}
_KNOWLEDGE_FACT_KEYS = {"id", "claim", "evidence", "source_ids"}


def _approved_knowledge_source_registry(
    context: Optional[Dict[str, Any]] = None,
    knowledge_request_id: Optional[str] = None,
) -> Dict[str, Dict[str, str]]:
    component_id = str((context or {}).get("component_id") or "").strip()[:120]
    episode = (context or {}).get("semantic_intent_episode")
    episode_id = str(episode.get("episode_id") if isinstance(episode, dict) else "").strip()[:120]
    registry: Dict[str, Dict[str, str]] = {}
    for base_id, template in _APPROVED_KNOWLEDGE_SOURCE_REGISTRY.items():
        source = dict(template)
        if knowledge_request_id:
            scoped_id = f"{base_id}:{knowledge_request_id}"
            source["id"] = scoped_id
            source["locator"] = f"{source['locator']}:request:{knowledge_request_id}"
        if component_id and base_id == "artifact-context":
            source["locator"] = f"artifact:{component_id}"
            if knowledge_request_id:
                source["locator"] += f":request:{knowledge_request_id}"
        elif component_id and base_id == "semantic-intent":
            source["locator"] = f"artifact:{component_id}:semantic-intent"
            if episode_id:
                source["locator"] += f":episode:{episode_id}"
            if knowledge_request_id:
                source["locator"] += f":request:{knowledge_request_id}"
        registry[source["id"]] = source
    return registry


def _knowledge_authority_digest(packet: Dict[str, Any]) -> str:
    signed = {
        "knowledge_request_id": packet.get("knowledge_request_id"),
        "provider": packet.get("provider"),
        "authority": packet.get("authority"),
        "status": packet.get("status"),
        "answer": packet.get("answer"),
        "facts": packet.get("facts"),
        "uncertainties": packet.get("uncertainties"),
        "sources": packet.get("sources"),
    }
    canonical = json.dumps(signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_KNOWLEDGE_AUTHORITY_SECRET, canonical, hashlib.sha256).hexdigest()


def _seal_knowledge_packet(packet: Dict[str, Any], knowledge_request_id: Optional[str]) -> Dict[str, Any]:
    sealed = dict(packet)
    if knowledge_request_id:
        sealed["knowledge_request_id"] = knowledge_request_id
        sealed["authority_digest"] = _knowledge_authority_digest(sealed)
    return sealed


def _strict_json_object(content: str) -> Dict[str, Any]:
    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    parsed = json.loads(content, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(parsed, dict):
        raise ValueError("Knowledge provider output must be one JSON object")
    return parsed


def _normalize_knowledge_packet(
    payload: Any,
    *,
    source_registry: Optional[Dict[str, Dict[str, str]]] = None,
    knowledge_request_id: Optional[str] = None,
    strict_contract: bool = False,
) -> Dict[str, Any]:
    registry = source_registry or _approved_knowledge_source_registry(
        knowledge_request_id=knowledge_request_id,
    )
    fallback = {
        "provider": "main_agent",
        "authority": "host_attested" if knowledge_request_id else "advisory",
        "status": "unavailable",
        "answer": "",
        "facts": [],
        "uncertainties": ["The semantic knowledge provider returned an invalid payload."],
        "sources": [],
    }
    if not isinstance(payload, dict):
        return _seal_knowledge_packet(fallback, knowledge_request_id)
    if strict_contract and (
        set(payload) != _KNOWLEDGE_PACKET_KEYS
        or not isinstance(payload.get("status"), str)
        or not isinstance(payload.get("answer"), str)
        or not isinstance(payload.get("facts"), list)
        or not isinstance(payload.get("uncertainties"), list)
        or not all(isinstance(item, str) for item in payload.get("uncertainties", []))
        or not isinstance(payload.get("sources"), list)
    ):
        return _seal_knowledge_packet(fallback, knowledge_request_id)

    status = str(payload.get("status") or "unavailable").strip().lower()
    if status not in {"grounded", "uncertain", "unavailable", "error"}:
        status = "unavailable"
    answer = str(payload.get("answer") or "").strip()[:4000]
    uncertainties = [
        str(item).strip()[:500]
        for item in (payload.get("uncertainties") if isinstance(payload.get("uncertainties"), list) else [])[:12]
        if str(item).strip()
    ]

    declared_source_ids: List[str] = []
    rejected_source_count = 0
    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list):
        raw_sources = [] if strict_contract else (
            payload.get("source_ids") if isinstance(payload.get("source_ids"), list) else []
        )
    for raw_source in raw_sources[:12]:
        source_id = str(raw_source.get("id") if isinstance(raw_source, dict) else raw_source or "").strip()[:160]
        source_is_exact = isinstance(raw_source, dict) and raw_source == registry.get(source_id)
        if source_id in registry and (not strict_contract or source_is_exact):
            if source_id not in declared_source_ids:
                declared_source_ids.append(source_id)
        else:
            rejected_source_count += 1
    sources = [dict(registry[source_id]) for source_id in declared_source_ids]
    source_ids = set(declared_source_ids)

    facts: List[Dict[str, Any]] = []
    seen_provider_fact_ids: set[str] = set()
    seen_fact_ids: set[str] = set()
    rejected_fact_count = 0
    raw_facts = payload.get("facts")
    if isinstance(raw_facts, list):
        for raw_fact in raw_facts[:16]:
            if not isinstance(raw_fact, dict) or (
                strict_contract and (
                    set(raw_fact) != _KNOWLEDGE_FACT_KEYS
                    or not isinstance(raw_fact.get("id"), str)
                    or not isinstance(raw_fact.get("claim"), str)
                    or not isinstance(raw_fact.get("evidence"), str)
                    or not isinstance(raw_fact.get("source_ids"), list)
                    or not all(isinstance(item, str) for item in raw_fact.get("source_ids", []))
                )
            ):
                rejected_fact_count += 1
                continue
            provider_fact_id = str(raw_fact.get("id") or "").strip()[:120]
            claim = str(raw_fact.get("claim") or "").strip()[:500]
            evidence = str(raw_fact.get("evidence") or "").strip()[:1000]
            linked_ids: List[str] = []
            for item in (raw_fact.get("source_ids") if isinstance(raw_fact.get("source_ids"), list) else [])[:8]:
                source_id = str(item).strip()[:160]
                if source_id in source_ids and source_id not in linked_ids:
                    linked_ids.append(source_id)
            if (
                not provider_fact_id
                or provider_fact_id in seen_provider_fact_ids
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", provider_fact_id)
                or not claim
                or not evidence
                or not linked_ids
            ):
                rejected_fact_count += 1
                continue
            seen_provider_fact_ids.add(provider_fact_id)
            fact_id = provider_fact_id
            if knowledge_request_id:
                fact_material = json.dumps(
                    [knowledge_request_id, provider_fact_id, claim, evidence, linked_ids],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                fact_id = "fact-" + hmac.new(
                    _KNOWLEDGE_AUTHORITY_SECRET,
                    fact_material,
                    hashlib.sha256,
                ).hexdigest()[:24]
            if fact_id in seen_fact_ids:
                rejected_fact_count += 1
                continue
            seen_fact_ids.add(fact_id)
            facts.append({"id": fact_id, "claim": claim, "evidence": evidence, "source_ids": linked_ids})

    if rejected_source_count:
        uncertainties.append(
            "One or more provider sources were omitted because their request-scoped metadata did not exactly match the Host registry."
        )
    if rejected_fact_count:
        uncertainties.append(
            "One or more provider facts were omitted because they lacked a unique fact ID, evidence, or an approved declared source."
        )
    if status == "grounded" and (not answer or not facts or rejected_fact_count or rejected_source_count):
        status = "uncertain"
        uncertainties.append("The provider packet did not fully ground every material fact in an approved source.")
    if status in {"unavailable", "error"}:
        answer = ""
        facts = []
        sources = []
    packet = {
        "provider": "main_agent",
        "authority": "host_attested" if knowledge_request_id else "advisory",
        "status": status,
        "answer": answer,
        "facts": facts,
        "uncertainties": uncertainties[:12],
        "sources": sources,
    }
    return _seal_knowledge_packet(packet, knowledge_request_id)


def _call_semantic_knowledge_provider(
    operation: "_InteractionOperation",
    context: Dict[str, Any],
    timeout: int,
) -> Optional[Dict[str, Any]]:
    requirement = (operation.intent_snapshot or {}).get("knowledge_requirement")
    if not isinstance(requirement, dict) or requirement.get("required") is not True:
        return None
    knowledge_request_id = f"knowledge-{uuid.uuid4().hex}"
    registry = _approved_knowledge_source_registry(context, knowledge_request_id)
    normalize = lambda payload: _normalize_knowledge_packet(
        payload,
        source_registry=registry,
        knowledge_request_id=knowledge_request_id,
        strict_contract=True,
    )
    if _ipc_manager is None:
        return normalize(None)

    config = get_config()
    request_payload = {
        "knowledge_request_id": knowledge_request_id,
        "component_id": context.get("component_id"),
        "semantic_intent_episode": context.get("semantic_intent_episode"),
        "interactions": context.get("interactions"),
        "reference_targets": context.get("reference_targets"),
        "document_outline": (context.get("document") or {}).get("outline"),
        "approved_sources": list(registry.values()),
        "packet_contract": {
            "top_level_keys": ["status", "answer", "facts", "uncertainties", "sources"],
            "sources": "Copy complete request-scoped source objects exactly from approved_sources.",
            "facts": "Each fact requires a provider-local unique id, evidence, and request-scoped approved source_ids; the Host will reissue fact IDs.",
        },
    }
    try:
        request_id = _ipc_manager.send_chat_request(
            messages=[{
                "role": "user",
                "content": "Provide one strict JSON semantic knowledge packet using only this request-scoped Host registry.\n"
                           + json.dumps(request_payload, ensure_ascii=False, indent=2),
            }],
            model=config.get_model(),
            system=load_system_prompt("prompt/semantic_knowledge_prompt.md"),
            agent_profile=None,
            use_sub_agent_config=False,
            tool_calls=False,
            stream=False,
        )
        _set_provider_request(operation, request_id)
        response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
        operation.provider_request_id = None
        if response is None or response.get("status") != "success":
            if isinstance(response, dict) and response.get("status") == "cancelled":
                raise InteractionSupersededError("Semantic knowledge request was cancelled")
            return normalize(None)
        content = str((response.get("data") or {}).get("content") or "").strip()
        return normalize(_strict_json_object(content))
    except InteractionSupersededError:
        raise
    except Exception as exc:
        operation.provider_request_id = None
        packet = normalize(None)
        packet["uncertainties"] = [f"Semantic knowledge provider unavailable: {str(exc)[:300]}"]
        packet["authority_digest"] = _knowledge_authority_digest(packet)
        return packet




def _serialize_operation(operation: Optional[_InteractionOperation]) -> Optional[Dict[str, Any]]:
    if operation is None:
        return None
    return {
        "artifact_id": operation.artifact_id,
        "intent_epoch": operation.intent_epoch,
        "agent_request_id": operation.agent_request_id,
        "operation_id": operation.operation_id,
        "episode_id": operation.episode_id,
        "supplied_base_sha256": operation.supplied_base_sha256,
        "supplied_base_revision": operation.supplied_base_revision,
        "supplied_state_revision": operation.supplied_state_revision,
        "require_interaction_ready_ack": operation.require_interaction_ready_ack,
        "status": operation.status,
        "barrier_committed": operation.barrier_committed,
        "superseded": operation.superseded,
        "awaiting_ready_ack": operation.awaiting_ready_ack,
        "base_html_sha256": operation.base_html_sha256,
        "base_html_revision": operation.base_html_revision,
        "created_at": operation.created_at,
    }


def _persist_coordinator(coordinator: _ArtifactCoordinator, artifact_id: str) -> None:
    with coordinator.condition:
        snapshot = {
            "latest_epoch": coordinator.latest_epoch,
            # Only a committed barrier owns durable recovery state. Provider inputs
            # and pending work are intentionally memory-only and privacy-minimized.
            "active": _serialize_operation(coordinator.active)
            if coordinator.active is not None and coordinator.active.barrier_committed
            else None,
            "latest_pending": None,
            "updated_at": time.time(),
        }
    record_html_interaction_coordinator(artifact_id, snapshot)


def _get_coordinator(artifact_id: str) -> _ArtifactCoordinator:
    with _coordinators_guard:
        existing = _coordinators.get(artifact_id)
        if existing is not None:
            return existing
        coordinator = _ArtifactCoordinator()
        journal = get_html_interaction_coordinator_journal(artifact_id) or {}
        try:
            coordinator.latest_epoch = max(0, int(journal.get("latest_epoch") or 0))
        except (TypeError, ValueError):
            coordinator.latest_epoch = 0
        # Only a persisted barrier has ownership after process restart. Pre-barrier
        # provider work cannot be resumed and is intentionally not resurrected.
        active_data = journal.get("active") if isinstance(journal.get("active"), dict) else None
        state = get_html_interaction_state(artifact_id)
        if active_data and state.get("frozen") and state.get("operation_id") == active_data.get("operation_id"):
            try:
                restored = _InteractionOperation(
                    artifact_id=artifact_id,
                    events=[],
                    intent_epoch=int(active_data.get("intent_epoch") or 0),
                    agent_request_id=str(active_data.get("agent_request_id") or ""),
                    operation_id=str(active_data.get("operation_id") or ""),
                    episode_id=active_data.get("episode_id"),
                    supplied_base_sha256=active_data.get("supplied_base_sha256"),
                    supplied_base_revision=active_data.get("supplied_base_revision"),
                    supplied_state_revision=active_data.get("supplied_state_revision"),
                    intent_snapshot=None,
                    require_interaction_ready_ack=bool(active_data.get("require_interaction_ready_ack")),
                    status=str(active_data.get("status") or "barrier_committed"),
                    barrier_committed=True,
                    awaiting_ready_ack=bool(active_data.get("awaiting_ready_ack")),
                    base_html_sha256=active_data.get("base_html_sha256"),
                    base_html_revision=active_data.get("base_html_revision"),
                    created_at=float(active_data.get("created_at") or time.time()),
                )
                if restored.agent_request_id and restored.operation_id:
                    coordinator.active = restored
            except (TypeError, ValueError):
                coordinator.active = None
        _coordinators[artifact_id] = coordinator
        return coordinator


def _new_identity(value: Optional[str], prefix: str) -> str:
    candidate = str(value or "").strip()
    if candidate:
        if len(candidate) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", candidate):
            raise ValueError(f"{prefix} must contain only safe identifier characters")
        return candidate
    return f"{prefix}-{uuid.uuid4().hex}"


def _cancel_provider_request(operation: _InteractionOperation) -> None:
    request_id = operation.provider_request_id
    if not request_id or _ipc_manager is None:
        return
    cancel = getattr(_ipc_manager, "cancel_request", None)
    if callable(cancel):
        try:
            cancel(request_id)
        except Exception:
            pass


def supersede_html_interaction_operation(
    artifact_id: str,
    *,
    operation_id: str,
    agent_request_id: Optional[str] = None,
    intent_epoch: int,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Supersede one matching pre-barrier operation and advance the Latest-Wins epoch."""

    safe_id = validate_artifact_id(artifact_id)
    safe_operation_id = _new_identity(operation_id, "html-operation")
    safe_agent_request_id = (
        _new_identity(agent_request_id, "agent-request") if agent_request_id is not None else None
    )
    try:
        resolved_epoch = int(intent_epoch)
    except (TypeError, ValueError) as exc:
        raise ValueError("intent_epoch must be a positive integer") from exc
    if resolved_epoch <= 0:
        raise ValueError("intent_epoch must be a positive integer")

    coordinator = _get_coordinator(safe_id)
    cancelled: Optional[_InteractionOperation] = None
    with coordinator.condition:
        coordinator.latest_epoch = max(coordinator.latest_epoch, resolved_epoch)
        active = coordinator.active
        if active is not None and active.operation_id == safe_operation_id:
            if safe_agent_request_id is not None and active.agent_request_id != safe_agent_request_id:
                raise RuntimeError("agent_request_id does not own the active HTML interaction")
            if resolved_epoch <= active.intent_epoch:
                state = get_html_interaction_state(safe_id)
                return {**state, "superseded": False, "reason": "stale_intent_epoch"}
            if active.barrier_committed:
                state = get_html_interaction_state(safe_id)
                return {**state, "superseded": False, "reason": "barrier_committed"}
            active.superseded = True
            active.status = "superseded"
            cancelled = active
        coordinator.condition.notify_all()

    if cancelled is None:
        state = get_html_interaction_state(safe_id)
        return {**state, "superseded": False, "reason": "operation_not_active"}

    _cancel_provider_request(cancelled)
    current_state = get_html_interaction_state(safe_id)
    if current_state.get("operation_id") in {None, cancelled.operation_id}:
        state = publish_html_interaction_state(
            safe_id,
            phase="superseded",
            frozen=False,
            operation_outcome="superseded",
            error=(str(reason).strip()[:500] if reason else None),
            **_operation_state_identity(cancelled, coordinator),
        )
    else:
        state = current_state
    return {**state, "superseded": True}


def _register_interaction_operation(
    artifact_id: str,
    events: List[Dict[str, Any]],
    *,
    intent_epoch: Optional[int],
    agent_request_id: Optional[str],
    operation_id: Optional[str],
    base_html_sha256: Optional[str],
    base_html_revision: Optional[int],
    state_revision: Optional[int],
    intent_snapshot: Optional[Dict[str, Any]],
    require_interaction_ready_ack: bool,
    episode_id: Optional[str] = None,
) -> _InteractionOperation:
    assert_html_interaction_persistence_healthy()
    coordinator = _get_coordinator(artifact_id)
    current_state = get_html_interaction_state(artifact_id)
    if current_state.get("frozen"):
        with coordinator.condition:
            owner = coordinator.active
            owner_identity_matches = (
                owner is not None
                and owner.operation_id == current_state.get("operation_id")
                and owner.agent_request_id == current_state.get("agent_request_id")
            )
            owner_matches = owner_identity_matches and owner is not None and owner.barrier_committed
            # A pre-barrier freeze is only ever backed by a live in-process owner. Either
            # that owner is still here and the newer intent supersedes it normally, or the
            # process that held it is gone and nothing it guarded can be resumed, so the
            # new intent legitimately takes the artifact over instead of being refused.
            pre_barrier_takeover = (
                str(current_state.get("phase") or "") in _PRE_BARRIER_FROZEN_PHASES
                and (owner_identity_matches or owner is None)
            )
        if not owner_matches and not pre_barrier_takeover:
            raise RuntimeError("Frozen HTML interaction ownership journal is missing or inconsistent")

    cancel_active: Optional[_InteractionOperation] = None
    with coordinator.condition:
        if intent_epoch is None:
            resolved_epoch = coordinator.latest_epoch + 1
        else:
            try:
                resolved_epoch = int(intent_epoch)
            except (TypeError, ValueError) as exc:
                raise ValueError("intent_epoch must be a positive integer") from exc
            if resolved_epoch <= 0:
                raise ValueError("intent_epoch must be a positive integer")
            if resolved_epoch <= coordinator.latest_epoch:
                operation = _InteractionOperation(
                    artifact_id=artifact_id,
                    events=events,
                    intent_epoch=resolved_epoch,
                    agent_request_id=_new_identity(agent_request_id, "agent-request"),
                    operation_id=_new_identity(operation_id, "html-operation"),
                    episode_id=_new_identity(episode_id, "intent-episode") if episode_id is not None else None,
                    status="superseded",
                    superseded=True,
                )
                return operation
        coordinator.latest_epoch = resolved_epoch
        operation = _InteractionOperation(
            artifact_id=artifact_id,
            events=events,
            intent_epoch=resolved_epoch,
            agent_request_id=_new_identity(agent_request_id, "agent-request"),
            operation_id=_new_identity(operation_id, "html-operation"),
            episode_id=_new_identity(episode_id, "intent-episode") if episode_id is not None else None,
            supplied_base_sha256=(base_html_sha256 or "").strip().lower() or None,
            supplied_base_revision=base_html_revision,
            supplied_state_revision=state_revision,
            intent_snapshot=normalize_semantic_intent_snapshot(intent_snapshot),
            require_interaction_ready_ack=bool(require_interaction_ready_ack),
        )
        if coordinator.active is None:
            operation.status = "active"
            coordinator.active = operation
            _persist_coordinator(coordinator, artifact_id)
            return operation

        previous_pending = coordinator.latest_pending
        if previous_pending is not None:
            previous_pending.superseded = True
            previous_pending.status = "superseded"
        coordinator.latest_pending = operation
        active = coordinator.active
        if active is not None and not active.barrier_committed:
            active.superseded = True
            active.status = "superseded"
            cancel_active = active
        coordinator.condition.notify_all()
        _persist_coordinator(coordinator, artifact_id)

    if cancel_active is not None:
        _cancel_provider_request(cancel_active)

    active_for_state = cancel_active
    if active_for_state is None:
        with coordinator.condition:
            active_for_state = coordinator.active
    if active_for_state is not None:
        current_state = get_html_interaction_state(artifact_id)
        if current_state.get("operation_id") == active_for_state.operation_id:
            if active_for_state.barrier_committed:
                # Queue metadata is observable, but must not invalidate the frozen
                # owner's exact ready/recovery state-revision token.
                update_html_interaction_pending_epoch(
                    artifact_id,
                    active_for_state.operation_id,
                    operation.intent_epoch,
                )
            else:
                publish_html_interaction_state(
                    artifact_id,
                    phase=str(current_state.get("phase") or "analyzing"),
                    frozen=bool(current_state.get("frozen")),
                    agent_stop_reason=current_state.get("agent_stop_reason"),
                    operation_outcome=current_state.get("operation_outcome"),
                    validation_result=current_state.get("validation_result"),
                    artifact_commit_result=current_state.get("artifact_commit_result"),
                    document_load_result=current_state.get("document_load_result"),
                    **_operation_state_identity(active_for_state, coordinator),
                )

    with coordinator.condition:
        while operation.status == "pending":
            coordinator.condition.wait()
        return operation


def _is_current_operation(operation: _InteractionOperation, *, require_barrier: bool = False) -> bool:
    coordinator = _get_coordinator(operation.artifact_id)
    with coordinator.condition:
        current = coordinator.active is operation and not operation.superseded
        return current and (operation.barrier_committed if require_barrier else True)


def _set_provider_request(operation: _InteractionOperation, provider_request_id: str) -> None:
    coordinator = _get_coordinator(operation.artifact_id)
    should_cancel = False
    with coordinator.condition:
        operation.provider_request_id = provider_request_id
        should_cancel = operation.superseded or coordinator.active is not operation
    if should_cancel:
        _cancel_provider_request(operation)


def _commit_interaction_barrier(operation: _InteractionOperation, lease_seconds: float) -> bool:
    """Commit the Latest-Wins coordination barrier.

    This is a coordination-only lock: it prevents newer intents from superseding
    this operation, but does NOT freeze the preview.  Freezing is deferred to the
    persisting phase so the user sees a live preview until they click Accept.
    """
    coordinator = _get_coordinator(operation.artifact_id)
    with coordinator.condition:
        if coordinator.active is not operation or operation.superseded:
            return False
        if operation.barrier_committed:
            return True
        operation.barrier_committed = True
        operation.status = "barrier_committed"
        _persist_coordinator(coordinator, operation.artifact_id)
        coordinator.condition.notify_all()
    return True


def _operation_state_identity(
    operation: _InteractionOperation,
    coordinator: Optional[_ArtifactCoordinator] = None,
) -> Dict[str, Any]:
    coordinator = coordinator or _get_coordinator(operation.artifact_id)
    with coordinator.condition:
        pending_epoch = (
            coordinator.latest_pending.intent_epoch
            if coordinator.latest_pending is not None and not coordinator.latest_pending.superseded
            else None
        )
        coordinator_epoch = coordinator.latest_epoch
    return {
        "intent_epoch": operation.intent_epoch,
        "active_intent_epoch": operation.intent_epoch,
        "latest_pending_intent_epoch": pending_epoch,
        # Publishing the admitted epoch high-water mark lets clients realign their
        # baseline instead of silently losing every intent to stale_intent_epoch.
        "coordinator_latest_epoch": coordinator_epoch,
        "agent_request_id": operation.agent_request_id,
        "operation_id": operation.operation_id,
        "episode_id": operation.episode_id,
        "base_html_revision": operation.base_html_revision,
        "base_html_sha256": operation.base_html_sha256,
    }


def _finish_interaction_operation(operation: _InteractionOperation, *, force: bool = False) -> None:
    coordinator = _get_coordinator(operation.artifact_id)
    with coordinator.condition:
        if coordinator.active is not operation:
            return
        if operation.awaiting_ready_ack and not force:
            return
        operation.status = "finished"
        coordinator.active = None
        pending = coordinator.latest_pending
        coordinator.latest_pending = None
        if pending is not None and not pending.superseded:
            pending.status = "active"
            coordinator.active = pending
        coordinator.condition.notify_all()
        _persist_coordinator(coordinator, operation.artifact_id)


def _superseded_result(operation: _InteractionOperation, event_count: int) -> Dict[str, Any]:
    coordinator = _get_coordinator(operation.artifact_id)
    with coordinator.condition:
        coordinator_epoch = coordinator.latest_epoch
    return {
        "artifact_id": operation.artifact_id,
        "generated": False,
        "decision": "superseded",
        "operation_outcome": "superseded",
        "event_count": event_count,
        "intent_epoch": operation.intent_epoch,
        "agent_request_id": operation.agent_request_id,
        "operation_id": operation.operation_id,
        # A stale-epoch rejection publishes no state transition, so the admitted
        # high-water mark travels back on the result itself. Without it a client whose
        # epoch baseline drifted low would silently lose every subsequent intent.
        "coordinator_latest_epoch": coordinator_epoch,
    }


def _clean_click_event(event: Any, index: int) -> Dict[str, Any]:
    raw = normalize_candidate_event(event)

    def text(key: str, limit: int) -> str:
        return str(raw.get(key) or "").strip()[:limit]

    def integer(value: Any, maximum: int) -> int:
        try:
            return max(0, min(int(value or 0), maximum))
        except (TypeError, ValueError):
            return 0

    ancestors = raw.get("ancestors") if isinstance(raw.get("ancestors"), list) else []
    control = raw.get("control") if isinstance(raw.get("control"), dict) else None
    viewport = raw.get("viewport") if isinstance(raw.get("viewport"), dict) else {}
    clean: Dict[str, Any] = {
        "sequence": index + 1,
        "elapsed_ms": integer(raw.get("elapsed_ms"), 120000),
        "event_type": text("event_type", 40) or "click",
        "tag": text("tag", 40),
        "element_id": text("element_id", 120),
        "role": text("role", 80),
        "text": text("text", 500),
        "clicked_word": text("clicked_word", 160),
        "selection_text": text("selection_text", 500),
        "key": text("key", 40),
        "pointer_type": text("pointer_type", 30),
        "semantic_ref": text("semantic_ref", 240),
        "trust_level": text("trust_level", 40) or "iframe_bridge_candidate",
        "aria_label": text("aria_label", 300),
        "title": text("title", 300),
        "href": text("href", 500),
        "spore_target": text("spore_target", 120),
        "spore_request": text("spore_request", 1000),
        "dom_path": text("dom_path", 500),
        "ancestors": [str(item).strip()[:300] for item in ancestors[:4]],
        "scroll_y": integer(raw.get("scroll_y"), 10_000_000),
        "viewport": {
            "width": integer(viewport.get("width"), 10000),
            "height": integer(viewport.get("height"), 10000),
        },
    }
    if isinstance(raw.get("semantic_context"), dict):
        clean["semantic_context"] = dict(raw["semantic_context"])
    if isinstance(raw.get("local_outcome"), dict):
        clean["local_outcome"] = dict(raw["local_outcome"])
    if control:
        clean["control"] = {
            "type": str(control.get("type") or "")[:40],
            "value": str(control.get("value") or "")[:500],
            "checked": bool(control.get("checked")),
            "redacted": bool(control.get("redacted")),
        }
    return clean


def _stable_selector(node: Tag) -> str:
    parts: List[str] = []
    current: Optional[Tag] = node
    while current is not None and current.name != "body":
        parent = current.parent
        if not isinstance(parent, Tag):
            return ""
        siblings = [child for child in parent.find_all(current.name, recursive=False)]
        position = next((index for index, sibling in enumerate(siblings, 1) if sibling is current), 0)
        if not position:
            return ""
        parts.insert(0, f"{current.name}:nth-of-type({position})")
        current = parent
    if current is None:
        return ""
    return "body" + (" > " + " > ".join(parts) if parts else "")


def _normalized_node_text(node: Tag) -> str:
    return " ".join(node.get_text(" ", strip=True).split())[:500]


def _matches_click(node: Tag, click: Dict[str, Any]) -> bool:
    tag = click.get("tag") or ""
    if tag and node.name.lower() != tag.lower():
        return False

    element_id = click.get("element_id") or ""
    if element_id and node.get("id") != element_id:
        return False

    target = click.get("spore_target") or ""
    if target:
        return node.get("data-spore-target") == target or node.get("href") == f"spore:{target}"

    strong_attributes = (
        ("role", "role"),
        ("aria_label", "aria-label"),
        ("title", "title"),
        ("href", "href"),
    )
    compared = False
    for click_key, attribute in strong_attributes:
        expected = click.get(click_key) or ""
        if expected:
            compared = True
            actual = str(node.get(attribute) or "")
            if attribute == "href":
                actual = sanitize_observed_url(actual, 500)
            if actual != expected:
                return False
    if compared:
        return True

    text = click.get("text") or ""
    return not text or _normalized_node_text(node) == text


def _resolve_click_node(soup: BeautifulSoup, click: Dict[str, Any]) -> Optional[Tag]:
    path = click.get("dom_path") or ""
    if _DOM_PATH.fullmatch(path):
        try:
            selected = soup.select_one(path)
            if isinstance(selected, Tag) and _matches_click(selected, click):
                return selected
        except Exception:
            pass

    element_id = click.get("element_id") or ""
    if element_id:
        selected = soup.find(id=element_id)
        if isinstance(selected, Tag) and _matches_click(selected, click):
            return selected

    href = click.get("href") or ""
    if href:
        matches = [
            candidate for candidate in soup.find_all("a", limit=50)
            if sanitize_observed_url(candidate.get("href"), 500) == href and _matches_click(candidate, click)
        ]
        if len(matches) == 1:
            return matches[0]

    target = click.get("spore_target") or ""
    if target:
        selected = soup.find(attrs={"data-spore-target": target})
        if not isinstance(selected, Tag):
            selected = soup.find("a", href=f"spore:{target}")
        if isinstance(selected, Tag):
            return selected

    tag = click.get("tag") or ""
    if tag and re.fullmatch(r"[a-z][a-z0-9-]{0,39}", tag, re.IGNORECASE):
        candidates = soup.find_all(tag, limit=50)
        matches = [candidate for candidate in candidates if _matches_click(candidate, click)]
        if len(matches) == 1:
            return matches[0]
    return None


def _tag_summary(node: Tag) -> Dict[str, Any]:
    attributes = {}
    for key in ("id", "class", "role", "aria-label", "title", "href", "data-spore-view", "data-spore-target"):
        value = node.get(key)
        if value:
            attributes[key] = sanitize_observed_url(value, 500) if key == "href" else value
    return {
        "tag": node.name,
        "attributes": attributes,
        "text": " ".join(node.get_text(" ", strip=True).split())[:300],
    }


def _resolve_declared_reference(
    soup: BeautifulSoup,
    candidates: List[Any],
    *,
    allowed_attributes: Tuple[str, ...],
    related_to: Optional[Tag] = None,
) -> Optional[Tag]:
    """Resolve one typed persisted reference without crossing reference namespaces."""

    attributes = allowed_attributes
    values: List[str] = []
    for candidate in candidates:
        if isinstance(candidate, list):
            source = candidate
        else:
            source = [candidate]
        for item in source:
            value = str(item or "").strip()[:240]
            if value and value not in values:
                values.append(value)
    for value in values:
        for attribute in attributes:
            node = soup.find(lambda tag, a=attribute, v=value: isinstance(tag, Tag) and str(tag.get(a) or "") == v)
            if isinstance(node, Tag) and (related_to is None or _nodes_reference_related(related_to, node)):
                return node
    return None


def _node_reference_values(node: Optional[Tag]) -> set[str]:
    values: set[str] = set()
    current = node
    for _ in range(5):
        if not isinstance(current, Tag) or current.name == "html":
            break
        for attribute in (
            "id", "aria-controls", "aria-describedby", "for",
            "data-spore-view", "data-spore-target", "data-spore-semantic-ref",
            "data-spore-inspector", "data-spore-presentation-ref", "data-spore-mutation-ref",
        ):
            raw = current.get(attribute)
            if isinstance(raw, list):
                items = raw
            else:
                items = re.split(r"\s+", str(raw or "").strip())
            values.update(str(item).strip()[:240] for item in items if str(item).strip())
        current = current.parent if isinstance(current.parent, Tag) else None
    return values


def _nodes_reference_related(anchor: Optional[Tag], candidate: Optional[Tag]) -> bool:
    """Allow only persisted references structurally or explicitly related to the observed node."""

    if not isinstance(anchor, Tag) or not isinstance(candidate, Tag):
        return False
    if anchor is candidate or candidate in anchor.parents or anchor in candidate.parents:
        return True
    return bool(_node_reference_values(anchor) & _node_reference_values(candidate))


def _nearest_presentation_container(node: Optional[Tag]) -> Optional[Tag]:
    current = node
    while isinstance(current, Tag) and current.name != "html":
        if any(current.has_attr(attribute) for attribute in (
            "data-spore-inspector", "data-spore-presentation-ref", "data-spore-view",
        )):
            return current
        current = current.parent if isinstance(current.parent, Tag) else None
    return None


def _privacy_safe_node_html(node: Tag, limit: int) -> str:
    """Sanitize URL metadata and default control values in Agent-facing snippets."""

    fragment = BeautifulSoup(str(node), "lxml")
    for tag in fragment.find_all(True):
        for attribute in ("href", "src", "action", "formaction"):
            if tag.has_attr(attribute):
                tag[attribute] = sanitize_observed_url(tag.get(attribute), 500)
        if tag.name in {"input", "button", "option"} and tag.has_attr("value"):
            tag["value"] = "[REDACTED]"
        if tag.name == "textarea" and tag.get_text():
            tag.clear()
            tag.append("[REDACTED]")
    container = fragment.body or fragment
    return "".join(str(child) for child in container.contents)[:limit]


def _build_interaction_context(
    current: str,
    clicks: List[Dict[str, Any]],
    intent_snapshot: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], BeautifulSoup, Dict[str, Tag]]:
    soup = BeautifulSoup(current, "lxml")
    if not isinstance(soup.html, Tag) or not isinstance(soup.body, Tag):
        raise ValueError("Persisted HTML has no usable html/body structure")
    if not isinstance(soup.head, Tag):
        soup.html.insert(0, soup.new_tag("head"))

    references: Dict[str, Tag] = {
        "document-head": soup.head,
        "document-body": soup.body,
    }
    reference_context: List[Dict[str, Any]] = [
        {"ref": "document-head", **_tag_summary(soup.head)},
        {"ref": "document-body", **_tag_summary(soup.body)},
    ]
    seen_nodes = {id(soup.head): "document-head", id(soup.body): "document-body"}
    snippet_budget = _MAX_CONTEXT_SNIPPET_BYTES

    def add_reference(ref: str, node: Tag, snippet_limit: int) -> None:
        nonlocal snippet_budget
        references[ref] = node
        prior = seen_nodes.get(id(node))
        if prior:
            reference_context.append({"ref": ref, "same_as": prior})
            return
        seen_nodes[id(node)] = ref
        record = {"ref": ref, "selector": _stable_selector(node), **_tag_summary(node)}
        if snippet_budget > 0:
            limit = min(snippet_limit, snippet_budget)
            record["html"] = _privacy_safe_node_html(node, limit)
            snippet_budget -= len(record["html"].encode("utf-8"))
        reference_context.append(record)

    observations: List[Dict[str, Any]] = []
    click_nodes: List[Optional[Tag]] = []
    for index, click in enumerate(clicks):
        node = _resolve_click_node(soup, click)
        click_nodes.append(node)
        target_ref = None
        if node is not None:
            target_ref = f"click-{index + 1}"
            add_reference(target_ref, node, 1000)
            parent = node.parent
            for level in range(1, 3):
                if not isinstance(parent, Tag) or parent.name == "html":
                    break
                add_reference(f"{target_ref}-parent-{level}", parent, 700)
                parent = parent.parent

        observation = {
            key: click[key]
            for key in (
                "sequence", "elapsed_ms", "event_type", "tag", "element_id", "role", "text",
                "clicked_word", "selection_text", "key", "pointer_type", "semantic_ref",
                "semantic_context", "aria_label", "title", "href", "spore_target", "spore_request", "control",
                "local_outcome", "trust_level", "scroll_y", "viewport",
            )
            if click.get(key) not in (None, "", [], {})
        }
        observation["target_ref"] = target_ref
        observations.append(observation)

    snapshot = intent_snapshot if isinstance(intent_snapshot, dict) else {}
    focus_items = snapshot.get("focuses") if isinstance(snapshot.get("focuses"), list) else []
    if not focus_items and isinstance(snapshot.get("focus"), dict):
        focus_items = [{**snapshot["focus"], "ref": snapshot.get("semantic_focus_ref")}]
    reference_targets: List[Dict[str, Any]] = []
    for index, raw_focus in enumerate(focus_items[:4]):
        focus = raw_focus if isinstance(raw_focus, dict) else {}
        semantic_candidates = [
            focus.get("ref"), focus.get("semantic_path"), focus.get("object_name"),
            snapshot.get("semantic_focus_ref") if index == 0 else None,
        ]
        fallback = click_nodes[index] if index < len(click_nodes) else (click_nodes[0] if click_nodes else None)
        declared_semantic = _resolve_declared_reference(
            soup,
            semantic_candidates,
            allowed_attributes=("data-spore-semantic-ref",),
            related_to=fallback,
        )
        # The click node is a backend-resolved semantic observation fallback only.
        semantic_node = declared_semantic or fallback

        presentation_candidates = [
            focus.get("inspector_ref"), focus.get("container_ref"), focus.get("related_refs"),
            snapshot.get("presentation_target_ref") if index == 0 else None,
        ]
        declared_presentation = _resolve_declared_reference(
            soup,
            presentation_candidates,
            allowed_attributes=(
                "data-spore-inspector", "data-spore-presentation-ref", "data-spore-view",
            ),
            related_to=semantic_node,
        )
        presentation_node = declared_presentation or _nearest_presentation_container(semantic_node)

        mutation_candidates = [snapshot.get("mutation_target_ref") if index == 0 else None]
        mutation_anchor = presentation_node or semantic_node
        mutation_node = _resolve_declared_reference(
            soup,
            mutation_candidates,
            allowed_attributes=("data-spore-mutation-ref",),
            related_to=mutation_anchor,
        )

        semantic_ref = presentation_ref = mutation_ref = None
        if isinstance(semantic_node, Tag):
            semantic_ref = f"semantic-focus-{index + 1}"
            add_reference(semantic_ref, semantic_node, 1200)
        if isinstance(presentation_node, Tag):
            presentation_ref = f"presentation-target-{index + 1}"
            add_reference(presentation_ref, presentation_node, 1400)
        if isinstance(mutation_node, Tag):
            mutation_ref = f"mutation-target-{index + 1}"
            add_reference(mutation_ref, mutation_node, 1600)
        target_record = {
            "focus_index": index + 1,
            "semantic_focus_ref": semantic_ref,
            "presentation_target_ref": presentation_ref,
            "mutation_target_ref": mutation_ref,
            "iframe_candidates_trusted": False,
        }
        reference_targets.append(target_record)
        if index < len(observations):
            observations[index].update({key: value for key, value in target_record.items() if key != "focus_index"})

    if not reference_targets and observations:
        fallback_ref = observations[0].get("target_ref")
        reference_targets.append({
            "focus_index": 1,
            "semantic_focus_ref": fallback_ref,
            "presentation_target_ref": None,
            "mutation_target_ref": None,
            "iframe_candidates_trusted": False,
        })
        observations[0].update(reference_targets[0])

    outline = []
    for node in soup.select("main, nav, header, footer, section, article, aside, h1, h2, h3, details, [data-spore-view]")[:40]:
        outline.append({"selector": _stable_selector(node), **_tag_summary(node)})

    style_context = "\n".join((node.string or node.get_text()) for node in soup.find_all("style"))[:3000]
    script_context = "\n".join((node.string or node.get_text()) for node in soup.find_all("script"))[:2000]
    context = {
        "protocol": "spore-html-mutation-v1",
        "window_policy": DYNAMIC_WINDOW_POLICY,
        "event_count": len(clicks),
        "interactions": observations,
        "reference_targets": reference_targets,
        "allowed_mutation_refs": list(dict.fromkeys(filter(None, [
            "document-head",
            "document-body",
            # Explicitly declared mutation targets (highest priority).
            *[item["mutation_target_ref"] for item in reference_targets if item.get("mutation_target_ref")],
            # Semantic focus and presentation targets resolved from data-spore-* attributes.
            *[item["semantic_focus_ref"] for item in reference_targets if item.get("semantic_focus_ref")],
            *[item["presentation_target_ref"] for item in reference_targets if item.get("presentation_target_ref")],
            # Clicked nodes and their immediate parents — the user pointed at these explicitly.
            *[f"click-{i + 1}" for i in range(len(clicks)) if click_nodes[i] is not None],
            *[
                f"click-{i + 1}-parent-1"
                for i in range(len(clicks))
                if click_nodes[i] is not None
                and isinstance(getattr(click_nodes[i], "parent", None), Tag)
                and click_nodes[i].parent.name != "html"
            ],
        ]))),
        "references": reference_context,
        "document": {
            "bytes": len(current.encode("utf-8")),
            "outline": outline,
            "inline_css_excerpt": style_context,
            "inline_script_excerpt": script_context,
        },
    }
    return context, soup, references


def _split_mutation_protocol(raw: str) -> Tuple[str, bool]:
    """Legacy helper — retained for backward compatibility; no longer called internally."""

    content = (raw or "").strip()
    if len(content.encode("utf-8")) > _MAX_MUTATION_RESPONSE_BYTES:
        raise ValueError(f"Mutation response exceeds {_MAX_MUTATION_RESPONSE_BYTES} bytes")

    lines = content.splitlines()
    first_nonempty = next((index for index, line in enumerate(lines) if line.strip()), None)
    starts_with_interrupt = bool(
        first_nonempty is not None and _INTERRUPT_PREFIX.fullmatch(lines[first_nonempty].strip())
    )
    if starts_with_interrupt and first_nonempty is not None:
        lines.pop(first_nonempty)

    return "\n".join(lines).strip(), starts_with_interrupt


_ATTR_PAIR_RE = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_.:-]{0,99})(?:="([^"]*)")?')


def _parse_mutation_blocks(text: str) -> List[Dict[str, Any]]:
    """Parse line-based mutation blocks separated by === delimiters.

    Each block header line is ``op ref``.
    Content follows on subsequent lines until the === delimiter.
    HTML fragments are written verbatim; set_attributes content uses key="value" pairs.
    """
    raw_blocks = re.split(r"(?m)^===\s*$", text)
    mutations: List[Dict[str, Any]] = []
    total_bytes = 0

    for raw_block in raw_blocks:
        block = raw_block.strip()
        if not block:
            continue
        block_lines = block.splitlines()
        header_parts = block_lines[0].strip().split()
        if len(header_parts) < 2:
            raise ValueError(
                f"Mutation block header must be 'op ref', got: {block_lines[0]!r}"
            )
        op = header_parts[0]
        ref = header_parts[1]
        if op not in _ALLOWED_MUTATIONS:
            raise ValueError(f"Unsupported mutation op: {op!r}")
        if not isinstance(ref, str) or not ref or len(ref) > 100:
            raise ValueError(f"Invalid target_ref: {ref!r}")

        content = "\n".join(block_lines[1:]).strip()
        mutation: Dict[str, Any] = {"op": op, "target_ref": ref}

        if op in _CONTENT_MUTATIONS:
            if not content:
                raise ValueError(f"Mutation op {op!r} requires a non-empty HTML fragment")
            total_bytes += len(content.encode("utf-8"))
            mutation["html"] = content
        elif op == "set_attributes":
            attrs: Dict[str, Any] = {}
            for match in _ATTR_PAIR_RE.finditer(content):
                name = match.group(1)
                value = match.group(2) if match.group(2) is not None else ""
                if not _ATTRIBUTE_NAME.fullmatch(name):
                    raise ValueError(f"Invalid attribute name: {name!r}")
                if len(attrs) >= 32:
                    raise ValueError("set_attributes: at most 32 attributes per mutation")
                attrs[name] = value
                total_bytes += len(name.encode("utf-8")) + len(str(value).encode("utf-8"))
            if not attrs:
                raise ValueError("set_attributes requires at least one key=\"value\" pair")
            mutation["attributes"] = attrs
        # op == "remove": no content required

        if len(mutations) >= _MAX_MUTATIONS:
            raise ValueError(f"At most {_MAX_MUTATIONS} mutations are allowed")
        mutations.append(mutation)

    if not mutations:
        raise ValueError("mutate response requires at least one mutation block")
    if total_bytes > _MAX_MUTATION_BYTES:
        raise ValueError(f"Mutation payload exceeds {_MAX_MUTATION_BYTES} bytes")
    return mutations


def _strip_spore_stop_reason(raw: str) -> str:
    """Accept exactly one terminal Spore stop block and remove only that suffix.

    The generic lifecycle protocol remains separate from the HTML transaction, but the
    Frontend Agent profile tightens its placement: the accepted stop block must be the
    final non-whitespace protocol unit. This prevents business output from being hidden
    after an otherwise valid lifecycle marker.
    """

    content = raw or ""
    blocks, error = extract_stop_reason_blocks(content)
    if error:
        raise ValueError(error)
    if len(blocks) != 1:
        raise ValueError("Frontend Agent response must contain exactly one terminal SPORE STOP_REASON block")
    block = blocks[0]
    if content[block["end"]:].strip():
        raise ValueError("SPORE STOP_REASON must be the final non-whitespace protocol unit")
    return content[:block["start"]].strip()


def _strip_reply_wrapper(payload: str) -> str:
    """Strip optional @SPORE:REPLY_START / @SPORE:REPLY_END wrapper.

    The mutation payload is enclosed in a REPLY block so that the protocol
    does not emit content outside reply markers.  Strip only the outer marker
    lines; inner content is left unchanged.  If no wrapper is present the
    payload is returned as-is so callers remain backward-compatible.
    """
    lines = payload.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip()), None)
    if start is None:
        return payload
    if lines[start].strip() == _REPLY_START_MARKER:
        end = None
        for i in range(len(lines) - 1, start, -1):
            if lines[i].strip() == _REPLY_END_MARKER:
                end = i
                break
        if end is not None:
            return "\n".join(lines[start + 1 : end]).strip()
    return payload


def _parse_mutation_response(raw: str) -> Dict[str, Any]:
    """Parse the line-based mutation format emitted by the Frontend Agent.

    All variants are wrapped in a @SPORE:REPLY_START / @SPORE:REPLY_END block
    so the protocol is satisfied; the wrapper is stripped before parsing.

    no_change::

        @SPORE:REPLY_START
        no_change <reason>
        @SPORE:REPLY_END
        @SPORE:STOP_REASON=...

    mutate::

        @SPORE:REPLY_START
        interrupt
        <reason — single line>

        op ref
        <HTML fragment or attribute pairs>
        ===
        [further blocks…]
        @SPORE:REPLY_END
        @SPORE:STOP_REASON=...

    abort_after_barrier::

        @SPORE:REPLY_START
        abort_after_barrier <reason>
        @SPORE:REPLY_END
        @SPORE:STOP_REASON=...
    """
    if len((raw or "").encode("utf-8")) > _MAX_MUTATION_RESPONSE_BYTES:
        raise ValueError(f"Mutation response exceeds {_MAX_MUTATION_RESPONSE_BYTES} bytes")

    payload = _strip_reply_wrapper(_strip_spore_stop_reason(raw))
    lines = payload.splitlines()
    first_idx = next((i for i, l in enumerate(lines) if l.strip()), None)
    if first_idx is None:
        raise ValueError("Empty mutation response")

    first_line = lines[first_idx].strip()
    keyword = first_line.split(None, 1)[0].lower() if first_line else ""

    # ── no_change ──────────────────────────────────────────────────────────────
    if keyword == "no_change":
        parts = first_line.split(None, 1)
        intent = parts[1].strip() if len(parts) > 1 else "no change needed"
        return {
            "decision": "no_change",
            "intent": intent[:500],
            "mutations": [],
            "fact_ids": [],
            "source_ids": [],
            "interrupt": False,
        }

    # ── abort_after_barrier ────────────────────────────────────────────────────
    if keyword == "abort_after_barrier":
        parts = first_line.split(None, 1)
        intent = parts[1].strip() if len(parts) > 1 else "aborted"
        return {
            "decision": "abort_after_barrier",
            "intent": intent[:500],
            "mutations": [],
            "fact_ids": [],
            "source_ids": [],
            "interrupt": False,
        }

    # ── mutate (starts with standalone "interrupt") ────────────────────────────
    if first_line != "interrupt":
        raise ValueError(
            "Mutation response first line must be 'interrupt', "
            "'no_change <reason>', or 'abort_after_barrier <reason>'"
        )

    rest = lines[first_idx + 1:]
    reason_idx = next((i for i, l in enumerate(rest) if l.strip()), None)
    intent = rest[reason_idx].strip() if reason_idx is not None else "mutation required"
    mutation_text = "\n".join(rest[reason_idx + 1:] if reason_idx is not None else rest).strip()
    mutations = _parse_mutation_blocks(mutation_text)

    return {
        "decision": "mutate",
        "intent": intent[:500],
        "mutations": mutations,
        "fact_ids": [],
        "source_ids": [],
        "interrupt": True,
    }

    def normalize_grounding_ids(values: List[Any], field_name: str) -> List[str]:
        normalized_ids: List[str] = []
        for raw_id in values[:16]:
            value = str(raw_id or "").strip()[:120]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", value):
                raise ValueError(f"{field_name} contains an invalid identifier")
            if value not in normalized_ids:
                normalized_ids.append(value)
        return normalized_ids

    fact_ids = normalize_grounding_ids(raw_fact_ids, "fact_ids")
    source_ids = normalize_grounding_ids(raw_source_ids, "source_ids")
    total_bytes = 0
    normalized = []
    for index, mutation in enumerate(mutations):
        if not isinstance(mutation, dict):
            raise ValueError(f"Mutation {index + 1} must be an object")
        op = mutation.get("op")
        target_ref = mutation.get("target_ref")
        if op not in _ALLOWED_MUTATIONS:
            raise ValueError(f"Mutation {index + 1} uses unsupported op")
        if not isinstance(target_ref, str) or not target_ref or len(target_ref) > 100:
            raise ValueError(f"Mutation {index + 1} requires target_ref")
        allowed_fields = {"op", "target_ref"}
        item = {"op": op, "target_ref": target_ref}
        if op in _CONTENT_MUTATIONS:
            allowed_fields.add("html")
            fragment = mutation.get("html")
            if not isinstance(fragment, str) or not fragment.strip():
                raise ValueError(f"Mutation {index + 1} requires a non-empty html fragment")
            total_bytes += len(fragment.encode("utf-8"))
            item["html"] = fragment
        elif op == "set_attributes":
            allowed_fields.add("attributes")
            attributes = mutation.get("attributes")
            if not isinstance(attributes, dict) or not attributes or len(attributes) > 32:
                raise ValueError(f"Mutation {index + 1} requires 1-32 attributes")
            clean_attributes = {}
            for name, value in attributes.items():
                if not isinstance(name, str) or not _ATTRIBUTE_NAME.fullmatch(name):
                    raise ValueError(f"Mutation {index + 1} has an invalid attribute name")
                if value is not None and not isinstance(value, (str, int, float, bool)):
                    raise ValueError(f"Mutation {index + 1} has an invalid attribute value")
                clean_attributes[name] = value
                total_bytes += len(name.encode("utf-8")) + len(str(value or "").encode("utf-8"))
            item["attributes"] = clean_attributes
        if set(mutation) - allowed_fields:
            raise ValueError(f"Mutation {index + 1} contains unsupported fields")
        normalized.append(item)

    if total_bytes > _MAX_MUTATION_BYTES:
        raise ValueError(f"Mutation payload exceeds {_MAX_MUTATION_BYTES} bytes")
    return {
        "decision": decision,
        "intent": (intent or "").strip()[:500],
        "mutations": normalized,
        "fact_ids": fact_ids,
        "source_ids": source_ids,
        "interrupt": starts_with_interrupt,
    }


def _parse_assess_response(raw: str) -> Optional[str]:
    """Extract the user-facing question from an INTERACTION_ASSESS LLM response.

    Expects ``assess_pause`` as the first non-whitespace token inside the REPLY
    block, followed by one line of natural-language text.  Returns the question
    string (possibly empty) on success, or None when the format is invalid.
    """
    content = (raw or "").strip()

    # Unwrap the optional REPLY_START / REPLY_END protocol markers.
    start_idx = content.find(_REPLY_START_MARKER)
    end_idx = content.find(_REPLY_END_MARKER)
    if start_idx >= 0 and end_idx > start_idx:
        inner = content[start_idx + len(_REPLY_START_MARKER):end_idx].strip()
    else:
        inner = content

    lines = [line.rstrip() for line in inner.splitlines()]
    non_empty = [(i, line) for i, line in enumerate(lines) if line.strip()]
    if not non_empty:
        return None

    first_idx, first_line = non_empty[0]
    if first_line.strip() != _ASSESS_PAUSE_KEYWORD:
        return None

    # The very next non-empty line is the user-facing question.
    rest = [line for i, line in non_empty if i > first_idx]
    return rest[0].strip()[:1000] if rest else ""


# Only these intent classes assert domain facts beyond the artifact itself. Materializing a
# declared empty region, building a missing control affordance, or expanding data already
# present in the page is page expression, so demanding a grounded packet there would force
# no_change instead of the requested interface.
_GROUNDED_INTENT_CATEGORIES = {"explain", "compare"}


def _requires_domain_grounding(
    response: Dict[str, Any],
    intent_snapshot: Optional[Dict[str, Any]],
) -> bool:
    """Decide grounding from the structured intent classification only.

    Scanning the Agent's own free-text `intent` for words like "explain" made grounding depend
    on wording: an interface-building mutation that merely described itself as explaining a
    structure was pushed into requiring a knowledge packet, and then rejected as ungrounded.
    The host-computed `intent_categories` is the authoritative signal.
    """

    snapshot = intent_snapshot or {}
    requirement = snapshot.get("knowledge_requirement")
    if not (isinstance(requirement, dict) and requirement.get("required") is True):
        return False
    categories = snapshot.get("intent_categories")
    if isinstance(categories, list) and categories:
        return any(category in _GROUNDED_INTENT_CATEGORIES for category in categories)
    reasons = requirement.get("reasons")
    if isinstance(reasons, list) and reasons and set(reasons) <= {"declared_region_awaiting_content"}:
        return False
    return True


def _knowledge_packet_authority_is_valid(packet: Dict[str, Any]) -> bool:
    request_id = str(packet.get("knowledge_request_id") or "")
    digest = str(packet.get("authority_digest") or "")
    if (
        packet.get("authority") != "host_attested"
        or not re.fullmatch(r"knowledge-[0-9a-f]{32}", request_id)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not hmac.compare_digest(digest, _knowledge_authority_digest(packet))
    ):
        return False
    request_suffix = f":{request_id}"
    locator_suffix = f":request:{request_id}"
    source_ids = set()
    for source in packet.get("sources", []):
        if not isinstance(source, dict):
            return False
        source_id = str(source.get("id") or "")
        locator = str(source.get("locator") or "")
        if not source_id.endswith(request_suffix) or locator_suffix not in locator:
            return False
        source_ids.add(source_id)
    for fact in packet.get("facts", []):
        if not isinstance(fact, dict) or not re.fullmatch(r"fact-[0-9a-f]{24}", str(fact.get("id") or "")):
            return False
        linked = fact.get("source_ids")
        if not isinstance(linked, list) or not linked or any(source_id not in source_ids for source_id in linked):
            return False
    return True


def _validate_knowledge_grounding(
    response: Dict[str, Any],
    intent_snapshot: Optional[Dict[str, Any]],
    knowledge_packet: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if response.get("decision") != "mutate":
        return None
    # Any mutation that cites authority is validated even when grounding is not mandatory,
    # so relaxing the trigger can never let invented fact or source IDs through.
    cites_authority = bool(response.get("fact_ids") or response.get("source_ids"))
    if not cites_authority and not _requires_domain_grounding(response, intent_snapshot):
        return None
    if not isinstance(knowledge_packet, dict) or knowledge_packet.get("status") != "grounded":
        return {
            "valid": False,
            "errors": [{
                "code": "knowledge_grounding_required",
                "message": "Domain-explanatory mutations require a grounded approved knowledge packet.",
            }],
        }
    if not _knowledge_packet_authority_is_valid(knowledge_packet):
        return {
            "valid": False,
            "errors": [{
                "code": "knowledge_authority_invalid",
                "message": "The knowledge packet is missing a valid request-scoped Host authority attestation.",
            }],
        }

    facts = {str(item.get("id")): item for item in knowledge_packet.get("facts", []) if isinstance(item, dict)}
    sources = {str(item.get("id")): item for item in knowledge_packet.get("sources", []) if isinstance(item, dict)}
    fact_ids = response.get("fact_ids") or []
    source_ids = response.get("source_ids") or []
    errors: List[Dict[str, str]] = []
    if not fact_ids or not source_ids:
        errors.append({
            "code": "knowledge_linkage_required",
            "message": "Domain-explanatory mutations must declare fact_ids and source_ids.",
        })
    unknown_facts = [fact_id for fact_id in fact_ids if fact_id not in facts]
    unknown_sources = [source_id for source_id in source_ids if source_id not in sources]
    if unknown_facts:
        errors.append({
            "code": "unknown_fact_id",
            "message": "Mutation cites unknown fact IDs: " + ", ".join(unknown_facts),
        })
    if unknown_sources:
        errors.append({
            "code": "unknown_source_id",
            "message": "Mutation cites unapproved source IDs: " + ", ".join(unknown_sources),
        })
    if not unknown_facts and not unknown_sources and fact_ids and source_ids:
        declared_sources = set(source_ids)
        for fact_id in fact_ids:
            linked = set(facts[fact_id].get("source_ids") or [])
            if not linked or not (linked & declared_sources):
                errors.append({
                    "code": "ungrounded_authoritative_content",
                    "message": f"Fact {fact_id} is not linked to a declared approved source.",
                })
    return {"valid": False, "errors": errors} if errors else None


def _validate_mutation_target_refs(
    mutations: List[Dict[str, Any]],
    allowed_mutation_refs: List[str],
) -> Optional[Dict[str, Any]]:
    allowed = set(allowed_mutation_refs)
    invalid = sorted({item.get("target_ref") for item in mutations if item.get("target_ref") not in allowed})
    if not invalid:
        return None
    return {
        "valid": False,
        "errors": [{
            "code": "mutation_reference_namespace",
            "message": "Mutation target_ref is not an approved mutation reference: " + ", ".join(invalid),
        }],
    }


class _StrictFragmentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.stack: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        names = [name.lower() for name, _value in attrs]
        if len(names) != len(set(names)):
            raise ValueError(f"HTML fragment has duplicate attributes on <{tag}>")
        if tag.lower() not in _VOID_ELEMENTS:
            self.stack.append(tag.lower())

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag.lower() not in _VOID_ELEMENTS:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in _VOID_ELEMENTS:
            raise ValueError(f"Void element <{tag}> must not have an end tag")
        if not self.stack or self.stack[-1] != lowered:
            expected = self.stack[-1] if self.stack else "no open element"
            raise ValueError(f"Mismatched </{tag}>; expected {expected}")
        self.stack.pop()

    def close(self) -> None:
        super().close()
        if self.stack:
            raise ValueError(f"Unclosed HTML element: <{self.stack[-1]}>")


def _fragment_nodes(fragment: str) -> List[Any]:
    syntax = _StrictFragmentParser()
    try:
        syntax.feed(fragment)
        syntax.close()
    except (ValueError, AssertionError) as exc:
        raise ValueError(f"Invalid HTML fragment syntax: {exc}") from exc
    parsed = BeautifulSoup(fragment, "html.parser")
    if parsed.find(("html", "head", "body")) or any(isinstance(item, Doctype) for item in parsed.contents):
        raise ValueError("Mutation html must be a fragment, not a complete document")
    nodes = list(parsed.contents)
    if not nodes:
        raise ValueError("Mutation html fragment is empty")
    return nodes


def _is_attached(node: Tag, soup: BeautifulSoup) -> bool:
    current: Any = node
    while current is not None:
        if current is soup:
            return True
        current = current.parent
    return False


def _apply_mutations(
    soup: BeautifulSoup,
    references: Dict[str, Tag],
    mutations: List[Dict[str, Any]],
) -> str:
    for index, mutation in enumerate(mutations):
        target = references.get(mutation["target_ref"])
        if target is None:
            raise ValueError(f"Mutation {index + 1} references an unknown target_ref")
        if not _is_attached(target, soup):
            raise ValueError(f"Mutation {index + 1} targets an element removed by an earlier mutation")

        op = mutation["op"]
        if target.name in {"html", "head", "body"} and op in {"before", "after", "replace_outer", "remove"}:
            raise ValueError(f"Mutation {index + 1} cannot remove or replace document structure")
        if op == "set_attributes":
            for name, value in mutation["attributes"].items():
                if value is None or value is False:
                    target.attrs.pop(name, None)
                elif value is True:
                    target.attrs[name] = name
                else:
                    target.attrs[name] = str(value)
            continue
        if op == "remove":
            target.decompose()
            continue

        nodes = _fragment_nodes(mutation["html"])
        if op == "append":
            for node in nodes:
                target.append(node)
        elif op == "prepend":
            for node in reversed(nodes):
                target.insert(0, node)
        elif op == "before":
            for node in nodes:
                target.insert_before(node)
        elif op == "after":
            anchor = target
            for node in nodes:
                anchor.insert_after(node)
                anchor = node
        elif op == "replace_inner":
            target.clear()
            for node in nodes:
                target.append(node)
        elif op == "replace_outer":
            for node in nodes:
                target.insert_before(node)
            target.decompose()

    return str(soup)


def _interaction_stream_callback(operation: _InteractionOperation, lease_seconds: float):
    """Commit the barrier only for a monotonic, exact first output line.

    Provider streams may send cumulative snapshots, deltas, or both. Once the first
    non-whitespace token is invalid, later text can never reset the parser and create a
    barrier. This deliberately rejects `Interrupt`, prose before interrupt, JSON/string
    occurrences, and `interruption`, while accepting chunked `inter` + `rupt\n`.

    The response may open with `@SPORE:REPLY_START` to satisfy the protocol rule that
    all content lives inside reply markers.  When that wrapper is present the barrier
    is committed on the second line being exactly `interrupt`; partial streaming of
    either line is handled correctly.
    """

    seen_interrupt = False
    prefix_invalid = False
    stream_prefix = ""

    def handle(event: Dict[str, Any]) -> None:
        nonlocal seen_interrupt, prefix_invalid, stream_prefix
        content = str(event.get("content") or "")
        delta = str(event.get("delta") or "")
        if not prefix_invalid:
            if content:
                if not stream_prefix:
                    stream_prefix = content
                elif content.startswith(stream_prefix):
                    stream_prefix = content
                elif stream_prefix.startswith(content):
                    pass
                elif delta:
                    stream_prefix += delta
                else:
                    prefix_invalid = True
            elif delta:
                stream_prefix += delta
            stream_prefix = stream_prefix[:2048]

        event_kind = str(event.get("event") or "").strip().lower()
        if not seen_interrupt and not prefix_invalid:
            stripped = stream_prefix.lstrip()
            if stripped:
                first_line, separator, _rest = stripped.partition("\n")
                candidate = first_line.rstrip(" \t\r")

                # Resolve through the optional REPLY_START wrapper: if the
                # first complete line is @SPORE:REPLY_START, step past it and
                # examine the next token as the real first payload line.
                if candidate == _REPLY_START_MARKER and separator:
                    rest_stripped = _rest.lstrip()
                    if rest_stripped:
                        inner_line, inner_sep, _inner = rest_stripped.partition("\n")
                        candidate = inner_line.rstrip(" \t\r")
                        separator = inner_sep
                    else:
                        # Wrapper line is complete but inner content has not
                        # arrived yet — hold off, do not invalidate.
                        candidate = _REPLY_START_MARKER
                        separator = ""

                if candidate == _REPLY_START_MARKER:
                    # Still waiting for the inner first line — keep accumulating.
                    pass
                elif separator:
                    if candidate == "interrupt":
                        seen_interrupt = _commit_interaction_barrier(operation, lease_seconds)
                    else:
                        prefix_invalid = True
                elif event_kind == "final":
                    if candidate == "interrupt":
                        seen_interrupt = _commit_interaction_barrier(operation, lease_seconds)
                    else:
                        prefix_invalid = True
                elif not (
                    "interrupt".startswith(candidate)
                    or candidate == "interrupt"
                    or _REPLY_START_MARKER.startswith(candidate)
                ):
                    prefix_invalid = True

        if operation.barrier_committed and _is_current_operation(operation, require_barrier=True):
            try:
                heartbeat_html_interaction(
                    operation.artifact_id,
                    operation.operation_id,
                    agent_request_id=operation.agent_request_id,
                    lease_seconds=lease_seconds,
                )
            except RuntimeError:
                pass

    return handle




def _validate_strict_interaction_identity(
    artifact_id: str,
    raw_events: List[Any],
    intent_snapshot: Optional[Dict[str, Any]],
    *,
    episode_id: Optional[str],
    intent_epoch: Optional[int],
    agent_request_id: Optional[str],
    operation_id: Optional[str],
    base_html_revision: Optional[int],
    base_html_sha256: Optional[str],
    state_revision: Optional[int],
) -> None:
    """Validate the HTTP transaction identity before Latest-Wins registration.

    The bridge payload is untrusted evidence, but request identity is Host-owned. Every
    duplicated identity field must agree exactly so a stale episode/event cannot be
    rebound to a newer operation. Legacy direct Python callers omit episode_id and retain
    their compatibility path; the HTTP route requires it.
    """

    if episode_id is None:
        return
    resolved_episode = _new_identity(episode_id, "intent-episode")
    required = {
        "intent_epoch": intent_epoch,
        "agent_request_id": agent_request_id,
        "operation_id": operation_id,
        "base_html_revision": base_html_revision,
        "base_sha256": (base_html_sha256 or "").strip().lower(),
        "state_revision": state_revision,
    }
    if any(value is None or value == "" for value in required.values()):
        raise ValueError("Strict HTML interaction identity is incomplete")
    snapshot = intent_snapshot if isinstance(intent_snapshot, dict) else {}
    if str(snapshot.get("episode_id") or "") != resolved_episode:
        raise ValueError("intent_snapshot episode_id does not match the request")
    if int(snapshot.get("intent_epoch") or -1) != int(intent_epoch):
        raise ValueError("intent_snapshot intent_epoch does not match the request")
    snapshot_identity = snapshot.get("request_identity") if isinstance(snapshot.get("request_identity"), dict) else {}
    expected_snapshot_identity = {**required, "episode_id": resolved_episode}
    for key, expected in expected_snapshot_identity.items():
        actual = snapshot_identity.get(key)
        if key == "base_sha256":
            actual = str(actual or "").strip().lower()
        if str(actual) != str(expected):
            raise ValueError(f"intent_snapshot request_identity.{key} does not match the request")
    for index, event in enumerate(raw_events):
        if not isinstance(event, dict):
            raise ValueError(f"events[{index}] must be an object")
        expected_event = {**required, "episode_id": resolved_episode}
        for key, expected in expected_event.items():
            actual = event.get(key)
            if key == "base_sha256":
                actual = str(actual or "").strip().lower()
            if str(actual) != str(expected):
                raise ValueError(f"events[{index}].{key} does not match the request")
    current_state = get_html_interaction_state(artifact_id)
    if int(current_state.get("state_revision") or 0) != int(state_revision):
        raise InteractionConflictError("Interaction state revision is stale")

def process_html_interactions(
    artifact_id: str,
    events: Any,
    *,
    intent_epoch: Optional[int] = None,
    agent_request_id: Optional[str] = None,
    operation_id: Optional[str] = None,
    episode_id: Optional[str] = None,
    base_html_sha256: Optional[str] = None,
    base_html_revision: Optional[int] = None,
    state_revision: Optional[int] = None,
    intent_snapshot: Optional[Dict[str, Any]] = None,
    require_interaction_ready_ack: bool = False,
) -> Dict[str, Any]:
    """Run Latest-Wins intent analysis and a CAS-protected HTML mutation transaction.

    Direct Python callers retain the legacy auto-ready behavior unless they request an
    interaction-ready acknowledgement.  The HTTP route always requests the acknowledgement.
    """

    safe_id = validate_artifact_id(artifact_id)
    raw_events = events if isinstance(events, list) else []
    if not raw_events:
        raise ValueError("At least one HTML interaction event is required")
    log_frontend_agent("interaction_start", {
        "artifact_id": safe_id,
        "event_count": len(raw_events),
        "operation_id": operation_id,
        "agent_request_id": agent_request_id,
        "intent_epoch": intent_epoch,
        "episode_id": episode_id,
    })
    if base_html_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", str(base_html_sha256).strip()):
        raise ValueError("base_html_sha256 must be a 64-character SHA-256 digest")

    _recover_expired_html_interaction_if_current(safe_id)
    _validate_strict_interaction_identity(
        safe_id, raw_events[:64], intent_snapshot,
        episode_id=episode_id, intent_epoch=intent_epoch,
        agent_request_id=agent_request_id, operation_id=operation_id,
        base_html_revision=base_html_revision, base_html_sha256=base_html_sha256,
        state_revision=state_revision,
    )
    interactions = [_clean_click_event(item, index) for index, item in enumerate(raw_events[:64])]
    operation = _register_interaction_operation(
        safe_id,
        interactions,
        intent_epoch=intent_epoch,
        agent_request_id=agent_request_id,
        operation_id=operation_id,
        episode_id=episode_id,
        base_html_sha256=base_html_sha256,
        base_html_revision=base_html_revision,
        state_revision=state_revision,
        intent_snapshot=intent_snapshot,
        require_interaction_ready_ack=require_interaction_ready_ack,
    )
    if operation.superseded or operation.status == "superseded":
        return _superseded_result(operation, len(interactions))

    validation: Dict[str, Any] = {}
    final_reason: Optional[str] = None
    lease_seconds = 30.0
    release_operation = True
    try:
        if not _is_current_operation(operation):
            raise InteractionSupersededError("Interaction was superseded before analysis")

        store = get_html_artifact_store()
        loaded = store.load(safe_id)
        current = loaded["content"]
        current_sha256 = str(loaded.get("artifact", {}).get("sha256") or validate_html(current)["sha256"])
        current_revision = observe_html_artifact_revision(safe_id, current_sha256)
        operation.base_html_sha256 = current_sha256
        operation.base_html_revision = current_revision

        if operation.supplied_base_sha256 and operation.supplied_base_sha256 != current_sha256:
            raise InteractionConflictError(
                f"HTML artifact revision conflict for {safe_id}: client base SHA-256 is stale"
            )
        if (
            operation.supplied_base_revision is not None
            and int(operation.supplied_base_revision) != current_revision
        ):
            raise InteractionConflictError(
                f"HTML artifact revision conflict for {safe_id}: client base revision is stale"
            )
        current_interaction_state = get_html_interaction_state(safe_id)
        if (
            operation.episode_id is None
            and operation.supplied_state_revision is not None
            and int(operation.supplied_state_revision) > int(current_interaction_state.get("state_revision") or 0)
        ):
            raise InteractionConflictError("Interaction references a future state revision")

        config = get_config()
        max_iterations = max(1, int(getattr(config, "frontend_agent_max_iterations", 3)))
        timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
        lease_seconds = max(
            30.0,
            float(getattr(config, "frontend_agent_freeze_lease_seconds", timeout + 60)),
        )
        context, soup, references = _build_interaction_context(current, interactions, operation.intent_snapshot)
        context.update({
            "component_id": safe_id,
            "intent_epoch": operation.intent_epoch,
            "agent_request_id": operation.agent_request_id,
            "operation_id": operation.operation_id,
            "base_html_revision": current_revision,
            "base_html_sha256": current_sha256,
            "observed_state_revision": current_interaction_state.get("state_revision", 0),
        })
        if operation.intent_snapshot is not None:
            context["semantic_intent_episode"] = operation.intent_snapshot

        # ── Round 1: ASSESS ──────────────────────────────────────────────────
        # One fast LLM call to gauge intent and ask the user a focused question.
        # No mutations, no barrier, no freeze.  The mutation round runs only if
        # the user agrees via resume_html_interaction().
        publish_html_interaction_state(
            safe_id,
            phase="analyzing",
            frozen=False,
            lease_seconds=lease_seconds,
            reset_operation=True,
            **_operation_state_identity(operation),
        )

        if not _is_current_operation(operation):
            raise InteractionSupersededError("Interaction was superseded before assess round")

        _lang = config.system_language  # "zh" or "en"
        _lang_instruction = (
            "Reply in Simplified Chinese (简体中文)." if _lang == "zh"
            else "Reply in English."
        )
        assess_message = {
            "role": "user",
            "content": (
                "INTERACTION_ASSESS mode. Quickly assess this interaction intent and ask the user "
                "ONE focused question about what they want to build or expand. "
                "Do NOT generate any HTML mutations.\n\n"
                f"Language: {_lang_instruction}\n\n"
                "OUTPUT FORMAT — the only valid response:\n\n"
                "@SPORE:REPLY_START\n"
                "assess_pause\n"
                "<one sentence: brief recommendation + one focused question>\n"
                "@SPORE:REPLY_END\n"
                "@SPORE:STOP_REASON=awaiting_user_decision\n\n"
                "Rules:\n"
                "- 'assess_pause' must be the first non-whitespace line inside the REPLY block.\n"
                "- The second line is a single natural-language sentence describing what you think "
                "the user wants, plus one question to confirm or refine it.\n"
                "- Write the sentence in the language specified above.\n"
                "- Never output 'interrupt', mutation blocks, code fences, or a full HTML document.\n\n"
                "Interaction context:\n" + json.dumps(context, ensure_ascii=False, indent=2)
            ),
        }
        log_frontend_agent("assess_call", {
            "artifact_id": safe_id,
            "operation_id": operation.operation_id,
            "agent_request_id": operation.agent_request_id,
        })
        raw_assess = _call_frontend_agent(
            [assess_message],
            timeout,
            stream_callback=None,
            request_started_callback=lambda request_id: _set_provider_request(operation, request_id),
        ).strip()
        operation.provider_request_id = None
        # _call_frontend_agent already calls log_frontend_agent_raw internally.

        if not _is_current_operation(operation):
            raise InteractionSupersededError("Interaction was superseded after assess round")

        question = _parse_assess_response(raw_assess)
        if question is None:
            # Tolerate a malformed assess response: surface an empty question
            # rather than crashing, so the user still gets a decision prompt.
            question = ""
            log_frontend_agent("assess_protocol_error", {
                "artifact_id": safe_id,
                "operation_id": operation.operation_id,
                "raw_length": len(raw_assess),
            })

        # Freeze nothing; stay alive until the user responds.
        _crd = _get_coordinator(safe_id)
        with _crd.condition:
            operation.pending_question = question
            operation.awaiting_user_response = True
            operation.status = "awaiting_user_decision"
        release_operation = False  # operation lives until resume or discard

        awaiting_state = publish_html_interaction_state(
            safe_id,
            phase="awaiting_user_decision",
            frozen=False,
            operation_outcome="awaiting_user_decision",
            **_operation_state_identity(operation),
        )
        log_frontend_agent("assess_awaiting_user_decision", {
            "artifact_id": safe_id,
            "operation_id": operation.operation_id,
            "question": question,
        })
        return {
            **loaded,
            "generated": False,
            "decision": "awaiting_user_decision",
            "question": question,
            "operation_outcome": "awaiting_user_decision",
            "intent_epoch": operation.intent_epoch,
            "agent_request_id": operation.agent_request_id,
            "operation_id": operation.operation_id,
            "base_html_revision": current_revision,
            "base_html_sha256": current_sha256,
            "state_revision": awaiting_state.get("state_revision") if isinstance(awaiting_state, dict) else None,
            "requires_interaction_ready_ack": False,
        }

        # Unreachable: the ASSESS round always returns above.  This marker keeps
        # static analysers from flagging the except/finally below as dead code.
        raise InteractionSupersededError("unreachable")  # pragma: no cover
    except InteractionSupersededError:
        log_frontend_agent("interaction_superseded", {
            "artifact_id": safe_id,
            "operation_id": operation.operation_id,
            "barrier_committed": operation.barrier_committed,
        })
        if operation.barrier_committed:
            # Barrier operations are never superseded by newer intent. Reaching this branch means ownership
            # was lost through recovery/cancellation, so do not let any late token or result change state.
            return _superseded_result(operation, len(interactions))
        publish_html_interaction_state(
            safe_id,
            phase="superseded",
            frozen=False,
            operation_outcome="superseded",
            **_operation_state_identity(operation),
        )
        return _superseded_result(operation, len(interactions))
    except InteractionConflictError as exc:
        log_frontend_agent("interaction_conflict", {
            "artifact_id": safe_id,
            "operation_id": operation.operation_id,
            "barrier_committed": operation.barrier_committed,
            "error": str(exc),
        })
        phase = "failed_after_barrier" if operation.barrier_committed else "failed_before_barrier"
        publish_html_interaction_state(
            safe_id,
            phase=phase,
            frozen=False,  # barrier no longer freezes; only persisting does
            agent_stop_reason=final_reason,
            operation_outcome="revision_conflict",
            validation_result=validation or None,
            error=str(exc)[:500],
            **_operation_state_identity(operation),
        )
        raise
    except Exception as exc:
        log_frontend_agent("interaction_error", {
            "artifact_id": safe_id,
            "operation_id": operation.operation_id,
            "barrier_committed": operation.barrier_committed,
            "superseded": operation.superseded,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        })
        if operation.superseded and not operation.barrier_committed:
            publish_html_interaction_state(
                safe_id,
                phase="cancelled",
                frozen=False,
                operation_outcome="superseded",
                error=str(exc)[:500],
                **_operation_state_identity(operation),
            )
            return _superseded_result(operation, len(interactions))
        phase = "failed_after_barrier" if operation.barrier_committed else "failed_before_barrier"
        publish_html_interaction_state(
            safe_id,
            phase=phase,
            frozen=False,  # barrier no longer freezes; only persisting does
            agent_stop_reason=final_reason,
            operation_outcome="failed",
            validation_result=validation or None,
            error=str(exc)[:500],
            **_operation_state_identity(operation),
        )
        raise
    finally:
        if release_operation:
            _finish_interaction_operation(operation)


def acknowledge_interaction_ready(
    artifact_id: str,
    operation_id: str,
    *,
    agent_request_id: Optional[str] = None,
    html_sha256: Optional[str] = None,
    state_revision: Optional[int] = None,
    document_generation_id: Optional[str] = None,
    restore_attempt_id: Optional[str] = None,
    bridge_capability: Optional[str] = None,
    readiness_report: Optional[Any] = None,
    ready: bool = True,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Complete a frozen mutation transaction after trusted bridge readiness acknowledgement."""

    safe_id = validate_artifact_id(artifact_id)
    capability_hash = hashlib.sha256(str(bridge_capability or "").encode("utf-8")).hexdigest() if bridge_capability else None
    state = acknowledge_html_interaction_ready_state(
        safe_id,
        operation_id,
        agent_request_id=agent_request_id,
        html_sha256=html_sha256,
        state_revision=state_revision,
        document_generation_id=document_generation_id,
        restore_attempt_id=restore_attempt_id,
        bridge_capability_hash=capability_hash,
        readiness_report=readiness_report,
        ready=ready,
        error=error,
    )
    coordinator = _get_coordinator(safe_id)
    with coordinator.condition:
        active = coordinator.active
    if ready and active is not None and active.operation_id == operation_id:
        active.awaiting_ready_ack = False
        _finish_interaction_operation(active, force=True)
    return state


def heartbeat_interaction_operation(
    artifact_id: str,
    operation_id: str,
    *,
    agent_request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Renew the active operation lease while the document reload is in progress."""

    safe_id = validate_artifact_id(artifact_id)
    config = get_config()
    timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
    lease_seconds = max(
        30.0,
        float(getattr(config, "frontend_agent_freeze_lease_seconds", timeout + 60)),
    )
    return heartbeat_html_interaction(
        safe_id,
        operation_id,
        agent_request_id=agent_request_id,
        lease_seconds=lease_seconds,
    )


def recover_html_interaction_operation(
    artifact_id: str,
    *,
    operation_id: str,
    agent_request_id: str,
    expected_state_revision: int,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """CAS-recover an expired barrier and release its coordinator ownership."""

    safe_id = validate_artifact_id(artifact_id)
    recovered = recover_orphaned_html_interaction(
        safe_id,
        operation_id=operation_id,
        agent_request_id=agent_request_id,
        expected_state_revision=expected_state_revision,
        now=now,
    )
    if recovered.get("recovered"):
        coordinator = _get_coordinator(safe_id)
        with coordinator.condition:
            active = coordinator.active
        if (
            active is not None
            and active.operation_id == operation_id
            and active.agent_request_id == agent_request_id
        ):
            active.awaiting_ready_ack = False
            active.superseded = True
            _cancel_provider_request(active)
            _finish_interaction_operation(active, force=True)
    return recovered


def confirm_html_interaction(
    artifact_id: str,
    *,
    operation_id: str,
    agent_request_id: str,
) -> Dict[str, Any]:
    """Apply the pending mutation candidate after user confirmation.

    Called when the user clicks "Accept" on the confirmation toast.  Runs the
    persistence phase that was deferred when process_html_interactions returned
    'pending_confirmation'.
    """
    safe_id = validate_artifact_id(artifact_id)
    config = get_config()
    timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
    lease_seconds = max(
        30.0,
        float(getattr(config, "frontend_agent_freeze_lease_seconds", timeout + 60)),
    )

    coordinator = _get_coordinator(safe_id)
    with coordinator.condition:
        active = coordinator.active
        if active is None:
            raise RuntimeError("No active operation to confirm")
        if active.operation_id != operation_id:
            raise RuntimeError(
                f"Operation ID mismatch: expected {active.operation_id!r}, got {operation_id!r}"
            )
        if active.agent_request_id != agent_request_id:
            raise RuntimeError("Agent request ID mismatch")
        if getattr(active, "status", None) != "pending_confirmation":
            raise RuntimeError(
                f"Operation is not in pending_confirmation state (status={getattr(active, 'status', None)!r})"
            )
        candidate = active.pending_candidate
        intent = active.pending_intent or ""
        base_sha256 = active.base_html_sha256

    if not candidate:
        raise RuntimeError("No pending candidate to confirm")

    store = get_html_artifact_store()
    try:
        loaded = store.load(safe_id)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Artifact {safe_id!r} not found") from exc

    publish_html_interaction_state(
        safe_id,
        phase="persisting",
        frozen=False,
        lease_seconds=lease_seconds,
        operation_outcome="persisting",
        **_operation_state_identity(active),
    )

    try:
        saved = store.save_if_sha256(
            safe_id,
            candidate,
            expected_sha256=base_sha256,
            title=loaded["artifact"].get("title"),
            semantic_label=loaded["artifact"].get("semantic_label"),
            conversation_id=loaded["artifact"].get("conversation_id"),
        )
    except RuntimeError as exc:
        publish_html_interaction_state(
            safe_id,
            phase="failed_after_barrier",
            frozen=False,
            operation_outcome="revision_conflict",
            error=str(exc)[:500],
            **_operation_state_identity(active),
        )
        raise InteractionConflictError(str(exc)) from exc

    committed_sha = saved["artifact"]["sha256"]
    committed_revision = observe_html_artifact_revision(safe_id, committed_sha)
    record_html_artifact_commit(safe_id, committed_sha)
    document_generation_id = f"document-generation-{uuid.uuid4().hex}"
    restore_attempt_id = f"restore-attempt-{uuid.uuid4().hex}"
    bridge_capability = secrets.token_urlsafe(32)
    bridge_capability_hash = hashlib.sha256(bridge_capability.encode("utf-8")).hexdigest()
    commit_result = {
        "status": "committed",
        "sha256": committed_sha,
        "html_revision": committed_revision,
    }
    publish_html_interaction_state(
        safe_id,
        phase="artifact_committed",
        frozen=True,
        lease_seconds=lease_seconds,
        operation_outcome="artifact_committed",
        artifact_commit_result=commit_result,
        document_load_result="pending",
        document_generation_id=document_generation_id,
        restore_attempt_id=restore_attempt_id,
        bridge_capability_hash=bridge_capability_hash,
        **_operation_state_identity(active),
    )

    requires_ack = active.require_interaction_ready_ack
    if requires_ack:
        with coordinator.condition:
            active.awaiting_ready_ack = True
            active.status = "awaiting_ready_ack"
            _persist_coordinator(coordinator, safe_id)
        ready_state = publish_html_interaction_state(
            safe_id,
            phase="reloading",
            frozen=True,
            lease_seconds=lease_seconds,
            operation_outcome="artifact_committed",
            artifact_commit_result=commit_result,
            document_load_result="awaiting_ack",
            document_generation_id=document_generation_id,
            restore_attempt_id=restore_attempt_id,
            bridge_capability_hash=bridge_capability_hash,
            **_operation_state_identity(active),
        )
    else:
        ready_state = publish_html_interaction_state(
            safe_id,
            phase="completed",
            frozen=False,
            operation_outcome="completed",
            artifact_commit_result=commit_result,
            document_load_result="legacy_assumed_ready",
            **_operation_state_identity(active),
        )
        _finish_interaction_operation(active, force=True)

    return {
        **saved,
        "generated": True,
        "decision": "updated",
        "intent": intent,
        "operation_outcome": (
            ready_state.get("operation_outcome", "artifact_committed")
            if isinstance(ready_state, dict) else "artifact_committed"
        ),
        "operation_id": operation_id,
        "agent_request_id": agent_request_id,
        "html_revision": committed_revision,
        "html_sha256": committed_sha,
        "base_html_sha256": base_sha256,
        "state_revision": ready_state.get("state_revision") if isinstance(ready_state, dict) else None,
        "requires_interaction_ready_ack": requires_ack,
        "document_generation_id": document_generation_id if requires_ack else None,
        "restore_attempt_id": restore_attempt_id if requires_ack else None,
        "bridge_capability": bridge_capability if requires_ack else None,
    }


def _recover_expired_html_interaction_if_current(artifact_id: str) -> Dict[str, Any]:
    """Best-effort automatic recovery using a snapshot as a strict CAS token."""

    state = get_html_interaction_state(artifact_id)
    expiry = state.get("lease_expires_at")
    if (
        not state.get("frozen")
        or not state.get("operation_id")
        or not state.get("agent_request_id")
        or expiry is None
        or float(expiry) > time.time()
    ):
        return {"recovered": False, "state": state}
    try:
        return recover_html_interaction_operation(
            artifact_id,
            operation_id=str(state["operation_id"]),
            agent_request_id=str(state["agent_request_id"]),
            expected_state_revision=int(state.get("state_revision") or 0),
        )
    except RuntimeError:
        # A heartbeat, ready ACK or another recovery won the revision/expiry race.
        return {"recovered": False, "state": get_html_interaction_state(artifact_id)}

def get_html_interaction_runtime_state(artifact_id: str) -> Dict[str, Any]:
    """Poll state after first recovering an expired freeze lease."""

    safe_id = validate_artifact_id(artifact_id)
    _recover_expired_html_interaction_if_current(safe_id)
    try:
        loaded = get_html_artifact_store().load(safe_id)
        observe_html_artifact_revision(safe_id, loaded.get("artifact", {}).get("sha256"))
    except FileNotFoundError:
        pass
    return get_html_interaction_state(safe_id)


def _reset_frontend_interaction_runtime_for_tests() -> None:
    with _coordinators_guard:
        _coordinators.clear()

def _build_mutation_retry_message(
    validation: Dict[str, Any],
    context: Dict[str, Any],
    lang_instruction: str,
) -> str:
    """Build a targeted correction prompt from a failed-validation result.

    Generic retry messages produce generic (wrong) corrections.  Mapping each
    known error code to a concrete fix instruction significantly reduces the
    number of iterations needed to reach a valid mutation.
    """
    errors = validation.get("errors") or []
    codes = {e.get("code", "") for e in errors}
    allowed_refs = context.get("allowed_mutation_refs") or []

    lines: List[str] = [
        f"Language: {lang_instruction}",
        "",
        "Your previous output was REJECTED. Read the rejection carefully and correct it.",
        "",
        "REJECTION DETAILS:",
        json.dumps(validation, ensure_ascii=False, indent=2),
        "",
    ]

    # ── Per-error-code targeted guidance ──────────────────────────────────────
    if "mutation_reference_namespace" in codes:
        lines += [
            "FIX REQUIRED — Invalid target_ref:",
            "  You used a ref that is not on the approved list.",
            "  The ONLY valid mutation targets for this operation are:",
            f"    {json.dumps(allowed_refs)}",
            "  In 'op ref', write the exact ref string from this list.",
            "  Never write a CSS selector (e.g. 'body > div:nth-of-type(1)') as the ref.",
            "",
        ]

    if "mutation_apply" in codes:
        msg = " ".join(e.get("message", "") for e in errors if e.get("code") == "mutation_apply")
        if "document structure" in msg:
            lines += [
                "FIX REQUIRED — Illegal op on structural element:",
                "  document-head and document-body only accept: append, prepend, replace_inner.",
                "  before / after / replace_outer / remove are ALWAYS rejected on them.",
                "  To add content inside the page body: use  append document-body",
                "  To add content at the start of body:  use  prepend document-body",
                "",
            ]
        else:
            lines += [
                "FIX REQUIRED — Mutation could not be applied:",
                f"  {msg}",
                "  Check that the targeted element still exists and that the HTML fragment is valid.",
                "",
            ]

    if "spore_protocol" in codes or "frontend_operation_incomplete" in codes:
        lines += [
            "FIX REQUIRED — Protocol format error:",
            "  ALL mutation output MUST be wrapped exactly like this:",
            "    @SPORE:REPLY_START",
            "    interrupt",
            "    <single-line reason>",
            "    op ref",
            "    <html fragment or key=\"value\" pairs>",
            "    ===",
            "    @SPORE:REPLY_END",
            "    @SPORE:STOP_REASON=<reason>",
            "  @SPORE:REPLY_START must come first; @SPORE:STOP_REASON must come last.",
            "",
        ]

    if "mutation_schema" in codes:
        lines += [
            "FIX REQUIRED — Mutation block schema error:",
            "  Each block: one 'op ref' line, then raw HTML content, then === on its own line.",
            "  Do NOT use JSON objects, code fences, or a complete HTML document.",
            "",
        ]

    if "empty_mutation_after_barrier" in codes:
        lines += [
            "FIX REQUIRED — Mutation produced no change:",
            "  The HTML after applying your mutations is identical to the original.",
            "  Either add meaningful new content, or use abort_after_barrier if the intent is satisfied.",
            "",
        ]

    # ── Reminder of available refs (always shown on retry) ────────────────────
    lines += [
        f"AVAILABLE MUTATION REFS: {json.dumps(allowed_refs)}",
        "",
        "OUTPUT FORMAT — two options only:",
        "  Option A: @SPORE:REPLY_START",
        "            no_change <reason>",
        "            @SPORE:REPLY_END",
        "            @SPORE:STOP_REASON=<reason>",
        "",
        "  Option B: @SPORE:REPLY_START",
        "            interrupt",
        "            <single-line reason>",
        "            op ref",
        "            <raw HTML or key=\"value\" pairs>",
        "            ===",
        "            [more blocks…]",
        "            @SPORE:REPLY_END",
        "            @SPORE:STOP_REASON=<reason>",
    ]

    return "\n".join(lines)


def _run_mutation_round(
    safe_id: str,
    operation: "_InteractionOperation",
    loaded: Dict[str, Any],
    current: str,
    current_sha256: str,
    current_revision: int,
    context: Dict[str, Any],
    soup: Any,
    references: Dict[str, Any],
    interactions: List[Dict[str, Any]],
    *,
    max_iterations: int,
    timeout: int,
    lease_seconds: float,
    user_response: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the mutation iteration loop (Round 2) for an active operation.

    This is the extraction of the old in-process mutation loop so that both
    ``resume_html_interaction`` (user-confirmed path) and future direct callers
    can reuse it without duplicating logic.

    Returns the same dict shape as ``process_html_interactions``.
    Raises ``InteractionSupersededError`` or ``InteractionConflictError`` on the
    usual failure paths; the caller is responsible for error-state publication.
    """
    protocol_manager = ProtocolManager()
    validation: Dict[str, Any] = {}
    final_reason: Optional[str] = None

    # Initial mutation message — inject the user's decision response when present.
    config_for_lang = get_config()
    _mut_lang = config_for_lang.system_language
    _mut_lang_instruction = (
        "Reply in Simplified Chinese (简体中文) — the intervention reason line must be in Chinese."
        if _mut_lang == "zh"
        else "Reply in English — the intervention reason line must be in English."
    )
    mutation_prompt = (
        "INTERACTION_MUTATION mode. "
        + (f"The user confirmed they want to proceed: {user_response.strip()}\n\n" if user_response else "")
        + f"Language: {_mut_lang_instruction}\n\n"
        + "Infer the user's current intent from the supplied semantic intent episode and "
        "compact chronological evidence. Decide whether the page already satisfies the "
        "intent or needs the smallest coherent persisted mutation. You are given compact "
        "element references and excerpts, not the complete document.\n\n"
        "OUTPUT FORMAT — two options only:\n\n"
        "Option A — no change needed:\n"
        "  no_change <brief reason>\n"
        "  @SPORE:STOP_REASON=<reason>\n\n"
        "Option B — mutation required:\n"
        "  interrupt\n"
        "  <single-line intervention reason shown to the user>\n\n"
        "  op ref\n"
        "  <raw HTML fragment — no JSON encoding>\n"
        "  ===\n"
        "  [additional blocks in the same format…]\n\n"
        "  @SPORE:STOP_REASON=<reason>\n\n"
        "Rules:\n"
        "- 'interrupt' must be the first non-whitespace output, on its own line, for a mutation.\n"
        "- The line immediately after 'interrupt' is the user-facing intervention reason.\n"
        "- Each mutation block: first line is 'op ref', then raw content, then === on its own line.\n"
        "- Allowed ops: append, prepend, before, after, replace_inner, replace_outer, "
        "set_attributes, remove.\n"
        "- For set_attributes the content is space-separated key=\"value\" pairs.\n"
        "- For remove the content block is empty (just ===).\n"
        "- HTML fragments are written verbatim — no escaping, no JSON encoding.\n"
        "- Never output a code fence, a JSON object, or a complete HTML document.\n"
        "- Only target refs from the supplied reference list. "
        "Use document-head or document-body only when focused references are insufficient.\n\n"
        "Interaction context:\n" + json.dumps(context, ensure_ascii=False, indent=2)
    )
    messages: List[Dict[str, Any]] = [{"role": "user", "content": mutation_prompt}]

    publish_html_interaction_state(
        safe_id,
        phase="implementing",
        frozen=False,
        operation_outcome="implementing",
        **_operation_state_identity(operation),
    )

    for iteration in range(1, max_iterations + 1):
        if not _is_current_operation(operation):
            raise InteractionSupersededError("Interaction was superseded before the commit barrier")
        log_frontend_agent("agent_call", {
            "artifact_id": safe_id,
            "iteration": iteration,
            "operation_id": operation.operation_id,
            "agent_request_id": operation.agent_request_id,
        })
        raw = _call_frontend_agent(
            messages,
            timeout,
            stream_callback=_interaction_stream_callback(operation, lease_seconds),
            request_started_callback=lambda request_id: _set_provider_request(operation, request_id),
        ).strip()
        operation.provider_request_id = None
        log_frontend_agent("agent_response", {
            "artifact_id": safe_id,
            "iteration": iteration,
            "operation_id": operation.operation_id,
            "agent_request_id": operation.agent_request_id,
            "response_length": len(raw),
        })
        if not _is_current_operation(operation):
            raise InteractionSupersededError("Late Frontend Agent result is no longer current")

        parsed = protocol_manager.parse_response(raw)
        final_reason = None
        response: Optional[Dict[str, Any]] = None

        if parsed.response_type == "protocol_error":
            error = parsed.protocol_error
            validation = {
                "valid": False,
                "errors": [{"code": "spore_protocol",
                    "message": error.message if error else "Invalid Spore protocol response"}],
            }
        elif parsed.response_type == "action":
            validation = {
                "valid": False,
                "errors": [{"code": "spore_protocol",
                    "message": "Frontend Agent interaction mode does not accept tool actions"}],
            }
        elif parsed.response_type != "final":
            validation = {
                "valid": False,
                "errors": [{"code": "frontend_operation_incomplete",
                    "message": (
                        "Frontend Agent has not ended this operation through the Spore protocol. "
                        "Continue the operation and emit @SPORE:STOP_REASON only when the final "
                        "mutation decision is ready."
                    )}],
            }
        else:
            final_reason = (parsed.final_content or "completed").strip()[:500]
            try:
                response = _parse_mutation_response(raw)
            except ValueError as exc:
                validation = {"valid": False, "errors": [{"code": "mutation_schema", "message": str(exc)}]}

        if response is not None:
            if response["decision"] == "abort_after_barrier":
                if not operation.barrier_committed:
                    validation = {"valid": False, "errors": [{"code": "abort_without_barrier",
                        "message": "abort_after_barrier is only valid after this operation committed the interrupt barrier"}]}
                    response = None
                else:
                    terminal_state = publish_html_interaction_state(
                        safe_id, phase="failed_after_barrier", frozen=False,
                        agent_stop_reason=final_reason, operation_outcome="abort_after_barrier",
                        validation_result={"valid": True, "explicit_abort": True},
                        artifact_commit_result="not_committed", document_load_result="not_required",
                        error=(response.get("intent") or "Frontend Agent explicitly aborted after barrier")[:500],
                        **_operation_state_identity(operation),
                    )
                    log_frontend_agent("decision_abort_after_barrier", {
                        "artifact_id": safe_id, "iteration": iteration,
                        "operation_id": operation.operation_id,
                        "intent": response.get("intent"), "agent_stop_reason": final_reason,
                    })
                    return {
                        **loaded, "generated": False, "iterations": iteration,
                        "event_count": len(interactions), "decision": "aborted",
                        "intent": response.get("intent"), "agent_stop_reason": final_reason,
                        "operation_outcome": "abort_after_barrier",
                        "intent_epoch": operation.intent_epoch,
                        "agent_request_id": operation.agent_request_id,
                        "operation_id": operation.operation_id,
                        "base_html_revision": current_revision, "base_html_sha256": current_sha256,
                        "state_revision": terminal_state.get("state_revision"),
                        "requires_interaction_ready_ack": False,
                    }

            if response is not None and response["decision"] == "no_change":
                if operation.barrier_committed:
                    validation = {"valid": False, "errors": [{"code": "no_change_after_barrier",
                        "message": "A committed interrupt barrier cannot be released by ordinary no_change; use mutate or explicit abort_after_barrier"}]}
                    response = None
                else:
                    phase = "completed" if not operation.require_interaction_ready_ack else "interaction_ready"
                    publish_html_interaction_state(
                        safe_id, phase=phase, frozen=False,
                        agent_stop_reason=final_reason, operation_outcome="no_change",
                        validation_result={"valid": True, "not_required": True},
                        artifact_commit_result="not_required", document_load_result="not_required",
                        **_operation_state_identity(operation),
                    )
                    log_frontend_agent("decision_no_change", {
                        "artifact_id": safe_id, "iteration": iteration,
                        "operation_id": operation.operation_id,
                        "intent": response.get("intent"), "agent_stop_reason": final_reason,
                    })
                    return {
                        **loaded, "generated": False, "iterations": iteration,
                        "event_count": len(interactions), "decision": "no_change",
                        "intent": response["intent"], "agent_stop_reason": final_reason,
                        "operation_outcome": "no_change",
                        "intent_epoch": operation.intent_epoch,
                        "agent_request_id": operation.agent_request_id,
                        "operation_id": operation.operation_id,
                        "base_html_revision": current_revision, "base_html_sha256": current_sha256,
                        "requires_interaction_ready_ack": False,
                    }

            if not operation.barrier_committed:
                if response.get("interrupt"):
                    _commit_interaction_barrier(operation, lease_seconds)
                if not operation.barrier_committed:
                    validation = {"valid": False, "errors": [{"code": "interrupt_barrier",
                        "message": "Current active request did not establish the interrupt barrier"}]}
                    response = None
            if response is not None:
                reference_error = _validate_mutation_target_refs(
                    response["mutations"], context.get("allowed_mutation_refs") or [])
                if reference_error:
                    validation = {"valid": False, "errors": reference_error.get("errors") or []}
                    response = None
            if response is not None:
                if not _is_current_operation(operation, require_barrier=True):
                    raise InteractionSupersededError("Mutation result is not owned by the active operation")
                publish_html_interaction_state(
                    safe_id, phase="validating", frozen=False,
                    lease_seconds=lease_seconds, agent_stop_reason=final_reason,
                    operation_outcome="validating", **_operation_state_identity(operation),
                )
                try:
                    candidate = _apply_mutations(soup, references, response["mutations"])
                    validation = validate_html(candidate)
                except ValueError as exc:
                    validation = {"valid": False, "errors": [{"code": "mutation_apply", "message": str(exc)}]}

                if validation.get("valid") and candidate.strip() == current.strip():
                    validation = {"valid": False, "errors": [{"code": "empty_mutation_after_barrier",
                        "message": "Mutations produced no artifact change after the interrupt barrier; correct the mutation or use abort_after_barrier"}]}
                    response = None

                if response is not None and validation.get("valid"):
                    if not _is_current_operation(operation, require_barrier=True):
                        raise InteractionSupersededError("Mutation lost ownership before confirmation")
                    _crd = _get_coordinator(safe_id)
                    with _crd.condition:
                        operation.pending_candidate = candidate
                        operation.pending_intent = response.get("intent", "")
                        operation.status = "pending_confirmation"
                    pending_state = publish_html_interaction_state(
                        safe_id, phase="pending_confirmation", frozen=False,
                        lease_seconds=lease_seconds, agent_stop_reason=final_reason,
                        operation_outcome="pending_confirmation", validation_result=validation,
                        **_operation_state_identity(operation),
                    )
                    log_frontend_agent("decision_pending_confirmation", {
                        "artifact_id": safe_id, "iteration": iteration,
                        "operation_id": operation.operation_id,
                        "intent": response.get("intent"), "agent_stop_reason": final_reason,
                        "mutation_count": len(response.get("mutations") or []),
                    })
                    return {
                        **loaded, "generated": False, "iterations": iteration,
                        "event_count": len(interactions), "decision": "pending_confirmation",
                        "reason": response.get("intent", ""), "agent_stop_reason": final_reason,
                        "operation_outcome": "pending_confirmation",
                        "intent_epoch": operation.intent_epoch,
                        "agent_request_id": operation.agent_request_id,
                        "operation_id": operation.operation_id,
                        "base_html_revision": current_revision, "base_html_sha256": current_sha256,
                        "state_revision": pending_state.get("state_revision") if isinstance(pending_state, dict) else None,
                        "requires_interaction_ready_ack": False,
                    }

        if iteration < max_iterations:
            log_frontend_agent("iteration_validation_failed", {
                "artifact_id": safe_id, "iteration": iteration,
                "operation_id": operation.operation_id,
                "barrier_committed": operation.barrier_committed, "validation": validation,
            })
            if operation.barrier_committed:
                publish_html_interaction_state(
                    safe_id, phase="protocol_retry", frozen=False,
                    lease_seconds=lease_seconds, agent_stop_reason=final_reason,
                    operation_outcome="retrying", validation_result=validation,
                    **_operation_state_identity(operation),
                )
            context, soup, references = _build_interaction_context(current, interactions, operation.intent_snapshot)
            context.update({
                "component_id": safe_id, "intent_epoch": operation.intent_epoch,
                "agent_request_id": operation.agent_request_id,
                "operation_id": operation.operation_id,
                "base_html_revision": current_revision, "base_html_sha256": current_sha256,
            })
            if operation.intent_snapshot is not None:
                context["semantic_intent_episode"] = operation.intent_snapshot
            messages.extend([
                {"role": "assistant", "content": raw},
                {"role": "user", "content": _build_mutation_retry_message(
                    validation, context, _mut_lang_instruction,
                )},
            ])

    log_frontend_agent("max_iterations_exceeded", {
        "artifact_id": safe_id, "max_iterations": max_iterations,
        "operation_id": operation.operation_id, "last_validation": validation,
    })
    raise RuntimeError("Frontend Agent did not complete a valid interaction mutation operation")


def resume_html_interaction(
    artifact_id: str,
    operation_id: str,
    *,
    agent_request_id: str,
    user_agreed: bool,
    user_response: Optional[str] = None,
) -> Dict[str, Any]:
    """Resume an operation that is waiting in ``awaiting_user_decision`` state.

    Called after the user responds to the Round-1 assess question:
    - ``user_agreed=True``  → run the mutation round and return the result.
    - ``user_agreed=False`` → discard the session, return ``{"decision": "discarded"}``.
    """
    safe_id = validate_artifact_id(artifact_id)
    safe_operation_id = _new_identity(operation_id, "html-operation")
    safe_agent_request_id = _new_identity(agent_request_id, "agent-request")

    coordinator = _get_coordinator(safe_id)
    with coordinator.condition:
        active = coordinator.active
        if active is None or active.operation_id != safe_operation_id:
            raise RuntimeError(f"No awaiting_user_decision operation found for {safe_id!r}")
        if active.agent_request_id != safe_agent_request_id:
            raise RuntimeError("agent_request_id does not match the active operation")
        if getattr(active, "status", None) != "awaiting_user_decision":
            raise RuntimeError(
                f"Operation is not in awaiting_user_decision state (status={active.status!r})"
            )

    if not user_agreed:
        # Discard: release the operation without any artifact change.
        publish_html_interaction_state(
            safe_id, phase="discarded", frozen=False, operation_outcome="discarded",
            **_operation_state_identity(active),
        )
        _finish_interaction_operation(active, force=True)
        log_frontend_agent("resume_discarded", {
            "artifact_id": safe_id, "operation_id": safe_operation_id,
        })
        return {
            "artifact_id": safe_id,
            "generated": False,
            "decision": "discarded",
            "operation_outcome": "discarded",
            "intent_epoch": active.intent_epoch,
            "agent_request_id": active.agent_request_id,
            "operation_id": active.operation_id,
        }

    # User agreed — run the mutation round.
    config = get_config()
    timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
    lease_seconds = max(30.0, float(getattr(config, "frontend_agent_freeze_lease_seconds", timeout + 60)))

    with coordinator.condition:
        active.user_response = str(user_response or "").strip()[:1000]
        active.awaiting_user_response = False
        active.status = "implementing"

    store = get_html_artifact_store()
    try:
        loaded = store.load(safe_id)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Artifact {safe_id!r} not found") from exc

    current = loaded["content"]
    current_sha256 = str(loaded.get("artifact", {}).get("sha256") or validate_html(current)["sha256"])
    current_revision = observe_html_artifact_revision(safe_id, current_sha256)

    # Verify the CAS token is still valid.
    if active.base_html_sha256 and active.base_html_sha256 != current_sha256:
        publish_html_interaction_state(
            safe_id, phase="failed_before_barrier", frozen=False,
            operation_outcome="revision_conflict",
            error="HTML artifact was modified while awaiting user decision",
            **_operation_state_identity(active),
        )
        _finish_interaction_operation(active, force=True)
        raise InteractionConflictError(
            f"HTML artifact revision conflict for {safe_id}: artifact changed while waiting for user"
        )

    max_iterations = max(1, int(getattr(config, "frontend_agent_max_iterations", 3)))
    context, soup, references = _build_interaction_context(current, active.events, active.intent_snapshot)
    context.update({
        "component_id": safe_id,
        "intent_epoch": active.intent_epoch,
        "agent_request_id": active.agent_request_id,
        "operation_id": active.operation_id,
        "base_html_revision": current_revision,
        "base_html_sha256": current_sha256,
    })
    if active.intent_snapshot is not None:
        context["semantic_intent_episode"] = active.intent_snapshot
    if active.pending_question:
        context["assess_question"] = active.pending_question

    log_frontend_agent("resume_implementing", {
        "artifact_id": safe_id, "operation_id": safe_operation_id,
        "user_response": active.user_response,
    })

    release_on_exit = True
    try:
        result = _run_mutation_round(
            safe_id, active, loaded, current, current_sha256, current_revision,
            context, soup, references, active.events,
            max_iterations=max_iterations, timeout=timeout, lease_seconds=lease_seconds,
            user_response=active.user_response,
        )
        if result.get("decision") == "pending_confirmation":
            release_on_exit = False  # operation held until confirm
        return result
    except InteractionSupersededError:
        log_frontend_agent("resume_superseded", {"artifact_id": safe_id, "operation_id": safe_operation_id})
        publish_html_interaction_state(
            safe_id, phase="superseded", frozen=False, operation_outcome="superseded",
            **_operation_state_identity(active),
        )
        return {
            "artifact_id": safe_id, "generated": False, "decision": "superseded",
            "operation_outcome": "superseded",
            "intent_epoch": active.intent_epoch, "agent_request_id": active.agent_request_id,
            "operation_id": active.operation_id,
        }
    except InteractionConflictError as exc:
        log_frontend_agent("resume_conflict", {"artifact_id": safe_id, "error": str(exc)[:300]})
        phase = "failed_after_barrier" if active.barrier_committed else "failed_before_barrier"
        publish_html_interaction_state(
            safe_id, phase=phase, frozen=False, operation_outcome="revision_conflict",
            error=str(exc)[:500], **_operation_state_identity(active),
        )
        raise
    except Exception as exc:
        log_frontend_agent("resume_error", {"artifact_id": safe_id, "error": str(exc)[:300]})
        phase = "failed_after_barrier" if active.barrier_committed else "failed_before_barrier"
        publish_html_interaction_state(
            safe_id, phase=phase, frozen=False, operation_outcome="failed",
            error=str(exc)[:500], **_operation_state_identity(active),
        )
        raise
    finally:
        if release_on_exit:
            _finish_interaction_operation(active)


def assess_html_interaction(
    artifact_id: str,
    *,
    intent_epoch: Optional[int] = None,
    agent_request_id: Optional[str] = None,
    operation_id: Optional[str] = None,
    episode_id: Optional[str] = None,
    intent_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Agent-initiated trigger path (Path 2).

    Proactively assess the current HTML artifact and ask the user whether they
    want to build or expand something — without requiring a prior user click.
    Uses a synthetic single-event to satisfy the coordinator registration path,
    then runs the same Round-1 ASSESS logic as ``process_html_interactions``.
    """
    # Synthetic proactive event — no real DOM interaction; tells the agent this
    # is a proactive check rather than a user-driven click.
    synthetic_event = {
        "event_type": "proactive_assess",
        "tag": "body",
        "spore_target": "",
        "spore_request": "proactive_assess",
        "role": "assess",
    }
    return process_html_interactions(
        artifact_id,
        [synthetic_event],
        intent_epoch=intent_epoch,
        agent_request_id=agent_request_id,
        operation_id=operation_id,
        episode_id=episode_id,
        intent_snapshot=intent_snapshot,
        require_interaction_ready_ack=False,
    )


def expand_html(
    artifact_id: str,
    target: str,
    request: str,
    *,
    action: str = "click",
    trigger_text: str = "",
) -> Dict[str, Any]:
    """Compatibility wrapper for callers using the earlier missing-target protocol."""

    return process_html_interactions(artifact_id, [{
        "tag": "button",
        "text": trigger_text,
        "spore_target": target,
        "spore_request": request,
        "role": action,
    }])
