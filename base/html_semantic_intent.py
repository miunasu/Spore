"""Normalization and privacy boundaries for HTML semantic intent episodes.

The iframe bridge is an observation source, not an authentication boundary.  This module
therefore treats every payload as untrusted candidate evidence, bounds it, strips sensitive
control values, and exposes the dynamic-window policy as named behavior classes rather than
one fixed collection cadence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit


ALLOWED_EVENT_TYPES = {
    "click", "dblclick", "selection", "selection_clear", "copy", "input", "change", "submit",
    "keyboard_activate", "keyboard_navigate", "touch_long_press",
}
DYNAMIC_WINDOW_POLICY: Dict[str, Dict[str, Any]] = {
    "immediate": {"signals": ["explicit_request", "submit"], "settle_ms": 80},
    "short_stable": {"signals": ["dblclick", "keyboard_activate"], "settle_ms": [120, 220]},
    "input_silence": {"signals": ["input", "change"], "settle_ms": [320, 700]},
    "ambiguous_selection": {"signals": ["selection"], "settle_ms": [300, 650]},
    "local_outcome_observation": {"signals": ["click"], "settle_ms": [500, 900]},
    "maximum_lifetime": {"signals": ["all"], "max_ms": 2400},
}
_SECRET_PATTERN = re.compile(
    r"(?:bearer\s+[a-z0-9._~-]+|(?:api[_-]?key|access[_-]?token|secret|password|passwd|cvv|cvc)\s*[:=]\s*\S+)",
    re.IGNORECASE,
)


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").strip().split())[:limit]


def _integer(value: Any, maximum: int) -> int:
    try:
        return max(0, min(int(value or 0), maximum))
    except (TypeError, ValueError):
        return 0


def _redact_text(value: Any, limit: int) -> str:
    text = _text(value, limit)
    return _SECRET_PATTERN.sub("[REDACTED]", text)


def sanitize_observed_url(value: Any, limit: int = 500) -> str:
    """Remove query/fragment data from untrusted observed URLs before Agent use."""

    text = _text(value, limit)
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))[:limit]
    except (TypeError, ValueError):
        # Malformed URL-like input is safer to omit than to forward with opaque data.
        return ""


# Structural intent classes. The Agent decides what to build; these only say what class of
# result the interaction is asking for, so knowledge supply no longer hinges on wording.
INTENT_CATEGORIES: Dict[str, str] = {
    "fulfill_explicit_page_request": "fulfill",
    "materialize_declared_empty_region": "materialize",
    # A control the user can operate that produced no change promises an interface the page
    # never built. Building that affordance is page expression, not a domain assertion.
    "build_missing_control_affordance": "build",
    "restructure_presentation_surface": "build",
    "expand_semantic_object_details": "expand",
    "compare_semantic_objects": "compare",
    "explain_semantic_object": "explain",
    "explain_selected_content": "explain",
    "explain_repeatedly_unresponsive_object": "explain",
    "copy_content_without_page_change": "observe",
    "complete_requested_action": "act",
    "respond_to_control_change": "act",
    "activate_focused_semantic_object": "act",
    "inspect_or_navigate_semantic_object": "inspect",
}
# Categories whose result is interface structure the Frontend Agent can express itself, rather
# than a domain assertion. Having one of these means the Agent has real work it can do.
PAGE_EXPRESSION_CATEGORIES = {"build", "materialize", "expand", "fulfill", "act"}
# Categories whose result cannot be produced from page text alone. These overlap with page
# expression on purpose: materializing a declared region is the Agent's own structural work,
# but something still has to supply what goes inside it.
CONTENT_BEARING_CATEGORIES = {"explain", "compare", "materialize", "expand"}
# Categories that assert domain facts beyond the artifact and therefore need a grounded packet.
GROUNDING_REQUIRED_CATEGORIES = {"explain", "compare"}
# Pure interface construction: page expression that carries no content of its own, so the Agent
# needs nothing from anyone else. Materialize and expand are deliberately excluded -- the Agent
# builds their structure, but the content owner still has to fill them.
SELF_SUFFICIENT_CATEGORIES = PAGE_EXPRESSION_CATEGORIES - CONTENT_BEARING_CATEGORIES


def _intent_category(candidate: str) -> str:
    known = INTENT_CATEGORIES.get(candidate)
    if known:
        return known
    # Unrecognized or host-supplied names still classify, so the taxonomy stays open.
    return "explain" if _explicit_knowledge_request(candidate.replace("_", " ")) else "inspect"


def _explicit_knowledge_request(text: str) -> bool:
    lowered = text.casefold()
    if not lowered:
        return False
    phrases = (
        "explain", "compare", "what does", "what is", "why", "meaning", "difference",
        "interpret", "understand", "describe", "说明", "解释", "含义", "什么意思",
        "比较", "对比", "区别", "差异", "作用", "为什么",
    )
    return any(phrase in lowered for phrase in phrases)


def normalize_semantic_context(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    result: Dict[str, Any] = {}
    for key, limit in (
        ("object_name", 240), ("object_type", 80), ("domain", 120),
        ("semantic_path", 500), ("container_ref", 240), ("current_value", 300),
        ("instance_data", 500), ("inspector_ref", 120),
    ):
        text = _redact_text(value.get(key), limit)
        if text:
            result[key] = text
    related = value.get("related_refs") if isinstance(value.get("related_refs"), list) else []
    result["related_refs"] = [_redact_text(item, 120) for item in related[:6] if _text(item, 120)]
    result["explanation_present"] = bool(value.get("explanation_present"))
    result["annotated"] = bool(value.get("annotated"))
    return result


def normalize_local_outcome(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    result = {
        "observed": bool(value.get("observed")),
        "changed": bool(value.get("changed")),
        "satisfied": bool(value.get("satisfied")),
        "reveal_succeeded": bool(value.get("reveal_succeeded")),
        "target_visible": bool(value.get("target_visible")),
        "target_has_content": bool(value.get("target_has_content")),
        # A declared region that became visible while still empty is an unmet need.
        "placeholder_revealed": bool(value.get("placeholder_revealed")),
    }
    before = _text(value.get("before_signature"), 1200)
    after = _text(value.get("after_signature"), 1200)
    if before:
        result["before_signature"] = before
    if after:
        result["after_signature"] = after
    return result


def normalize_candidate_event(event: Any) -> Dict[str, Any]:
    """Bound one iframe-observed candidate event and redact private control input."""

    raw = event if isinstance(event, dict) else {}
    event_type = _text(raw.get("event_type"), 40) or "click"
    if event_type not in ALLOWED_EVENT_TYPES:
        event_type = "click"
    ancestors = raw.get("ancestors") if isinstance(raw.get("ancestors"), list) else []
    viewport = raw.get("viewport") if isinstance(raw.get("viewport"), dict) else {}
    clean: Dict[str, Any] = {
        "timestamp_ms": _integer(raw.get("timestamp_ms"), 10**16),
        "elapsed_ms": _integer(raw.get("elapsed_ms"), 120_000),
        "event_type": event_type,
        "tag": _text(raw.get("tag"), 40),
        "element_id": _text(raw.get("element_id"), 120),
        "role": _text(raw.get("role"), 80),
        "text": _redact_text(raw.get("text"), 500),
        "clicked_word": _redact_text(raw.get("clicked_word"), 160),
        "selection_text": _redact_text(raw.get("selection_text"), 500),
        "key": _text(raw.get("key"), 40),
        "pointer_type": _text(raw.get("pointer_type"), 30),
        "aria_label": _redact_text(raw.get("aria_label"), 300),
        "title": _redact_text(raw.get("title"), 300),
        "href": sanitize_observed_url(raw.get("href"), 500),
        "spore_target": _text(raw.get("spore_target"), 120),
        "spore_request": _redact_text(raw.get("spore_request"), 1000),
        "semantic_ref": _text(raw.get("semantic_ref"), 240),
        "dom_path": _text(raw.get("dom_path"), 500),
        "ancestors": [_redact_text(item, 300) for item in ancestors[:4]],
        "scroll_y": _integer(raw.get("scroll_y"), 10_000_000),
        "viewport": {
            "width": _integer(viewport.get("width"), 10_000),
            "height": _integer(viewport.get("height"), 10_000),
        },
        "trust_level": "iframe_bridge_candidate",
    }
    semantic_context = normalize_semantic_context(raw.get("semantic_context"))
    if semantic_context is not None:
        clean["semantic_context"] = semantic_context
    outcome = normalize_local_outcome(raw.get("local_outcome"))
    if outcome is not None:
        clean["local_outcome"] = outcome
    control = raw.get("control") if isinstance(raw.get("control"), dict) else None
    if control is not None:
        control_type = _text(control.get("type"), 40).lower()
        raw_value = str(control.get("value") or "")
        # Control values are private by default, not only for a sensitive-type denylist.
        redact = bool(raw_value) or bool(control.get("redacted"))
        clean["control"] = {
            "type": control_type,
            "value": "[REDACTED]" if redact else "",
            "checked": bool(control.get("checked")),
            "redacted": redact,
        }
    return clean


def _normalize_ref(value: Any) -> str:
    return _text(value, 500)


def _normalize_focus(value: Any, fallback_ref: Any = "") -> Dict[str, Any]:
    """Normalize one semantic focus into the bounded Agent-facing schema."""

    raw = value if isinstance(value, dict) else {}
    related = raw.get("related_refs") if isinstance(raw.get("related_refs"), list) else []
    return {
        "ref": _normalize_ref(raw.get("ref") or fallback_ref),
        "label": _redact_text(raw.get("label") or raw.get("object_name"), 240),
        "object_type": _redact_text(raw.get("object_type"), 80),
        "domain": _redact_text(raw.get("domain"), 120),
        "semantic_path": _redact_text(raw.get("semantic_path"), 500),
        "current_value": _redact_text(raw.get("current_value"), 300),
        "instance_data": _redact_text(raw.get("instance_data"), 500),
        "explanation_present": bool(raw.get("explanation_present")),
        "inspector_ref": _redact_text(raw.get("inspector_ref"), 120),
        "container_ref": _redact_text(raw.get("container_ref"), 240),
        "related_refs": [
            _redact_text(item, 120) for item in related[:6] if _text(item, 120)
        ],
    }


def normalize_semantic_intent_snapshot(value: Any) -> Optional[Dict[str, Any]]:
    """Normalize the semantic episode sent to the Agent; never pass arbitrary nested input."""

    if not isinstance(value, dict):
        return None
    focus_raw = value.get("focus") if isinstance(value.get("focus"), dict) else {}
    focuses_raw = value.get("focuses") if isinstance(value.get("focuses"), list) else []
    evidence_raw = value.get("evidence") if isinstance(value.get("evidence"), list) else []
    candidates_raw = value.get("candidate_intents") if isinstance(value.get("candidate_intents"), list) else []

    evidence: List[Dict[str, Any]] = []
    for item in evidence_raw[:48]:
        if len(evidence) >= 12:
            break
        if not isinstance(item, dict):
            continue
        event_type = _text(item.get("event_type"), 40)
        # selection_clear is a bridge cancellation/control signal, not Agent evidence.
        if event_type not in ALLOWED_EVENT_TYPES or event_type == "selection_clear":
            continue
        record: Dict[str, Any] = {
            "event_type": event_type,
            "elapsed_ms": _integer(item.get("elapsed_ms"), 120_000),
            "focus_ref": _normalize_ref(item.get("focus_ref")),
        }
        for key, limit in (("word", 160), ("selection", 500), ("key", 40), ("spore_request", 1000), ("request", 1000)):
            text = _redact_text(item.get(key), limit)
            if text:
                record[key] = text
        semantic_context = normalize_semantic_context(item.get("semantic_context"))
        if semantic_context is not None:
            record["semantic_context"] = semantic_context
        outcome = normalize_local_outcome(item.get("local_outcome"))
        if outcome is not None:
            record["local_outcome"] = outcome
        # Whether the user could operate this element. Combined with an unchanged outcome it
        # identifies a dead control, which is the clearest signal of an unbuilt affordance.
        if "operable" in item:
            record["operable"] = bool(item.get("operable"))
        evidence.append(record)

    focuses: List[Dict[str, Any]] = []
    focus_sources: List[Dict[str, Any]] = []
    for item in focuses_raw:
        if len(focuses) >= 4:
            break
        if not isinstance(item, dict):
            continue
        focus_sources.append(item)
        focuses.append(_normalize_focus(item))

    semantic_focus_ref = _normalize_ref(value.get("semantic_focus_ref"))
    if not focus_raw and focus_sources:
        focus_raw = next(
            (item for item in focus_sources if _normalize_ref(item.get("ref")) == semantic_focus_ref),
            focus_sources[-1],
        )
    primary_focus = _normalize_focus(focus_raw, semantic_focus_ref)
    context_raw = focus_raw.get("context") if isinstance(focus_raw.get("context"), list) else []
    primary_focus["context"] = [_redact_text(item, 300) for item in context_raw[:4]]
    selected_text = _redact_text(focus_raw.get("selected_text"), 500)
    if selected_text:
        primary_focus["selected_text"] = selected_text

    candidates = []
    for candidate in candidates_raw[:4]:
        text = _text(candidate, 120)
        if text and text not in candidates:
            candidates.append(text)
    confidence = _text(value.get("confidence"), 20).lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"
    local_outcome = _text(value.get("local_outcome"), 30).lower()
    if local_outcome not in {"satisfied", "not_satisfied", "unknown"}:
        local_outcome = "unknown"
    disposition = _text(value.get("disposition"), 20).lower()
    if disposition not in {"discard", "disambiguate", "dispatch"}:
        disposition = "dispatch"

    explicit_request = _redact_text(
        value.get("explicit_request") or value.get("spore_request") or value.get("request"), 1000
    )
    request_texts = [explicit_request]
    request_texts.extend(
        str(item.get("spore_request") or item.get("request") or "") for item in evidence
    )
    intent_categories: List[str] = []
    for candidate in candidates:
        category = _intent_category(candidate)
        if category not in intent_categories:
            intent_categories.append(category)
    page_expression_available = any(
        category in PAGE_EXPRESSION_CATEGORIES for category in intent_categories
    )
    grounding_categories = [
        category for category in intent_categories if category in GROUNDING_REQUIRED_CATEGORIES
    ]
    # Priority, not OR. A stray explain candidate must not drag an episode the Agent could
    # complete on its own into requiring a knowledge packet, otherwise buildable interface
    # work degrades into no_change. Only ask for domain facts when no self-sufficient
    # page-expression category is available.
    candidate_requires_knowledge = bool(grounding_categories) and not page_expression_available
    explicit_requires_knowledge = any(_explicit_knowledge_request(item) for item in request_texts)
    semantic_descriptor_present = bool(
        primary_focus.get("domain")
        or primary_focus.get("object_type")
        or primary_focus.get("semantic_path")
        or primary_focus.get("current_value")
    )
    explanatory_gesture = any(
        item.get("event_type") in {"dblclick", "selection", "copy"} for item in evidence
    )
    outcomes = [item.get("local_outcome") for item in evidence]
    # A declared region that only became visible is still waiting for its content.
    placeholder_pending = any(
        isinstance(item, dict) and item.get("placeholder_revealed") for item in outcomes
    )
    annotated_without_explanation = any(
        isinstance(item.get("semantic_context"), dict)
        and item["semantic_context"].get("annotated")
        and not item["semantic_context"].get("explanation_present")
        for item in evidence
    )
    content_gap = bool(
        (semantic_descriptor_present or annotated_without_explanation)
        and not primary_focus.get("explanation_present")
        and (
            local_outcome == "not_satisfied"
            or placeholder_pending
            or explanatory_gesture
            or explicit_requires_knowledge
        )
    )
    reasons: List[str] = []
    if candidate_requires_knowledge:
        reasons.append("candidate_intent")
    if explicit_requires_knowledge:
        reasons.append("explicit_explain_or_compare_request")
    if content_gap:
        reasons.append("page_content_gap")
    if placeholder_pending:
        reasons.append("declared_region_awaiting_content")
    # An episode whose only work is pure interface construction is the Frontend Agent's own:
    # it builds from artifact data and must not wait on a knowledge packet. Content-bearing
    # page expression does not qualify, because declaring a region is not the same as knowing
    # what belongs in it -- that still reports an unmet content need to the host.
    self_sufficient = (
        any(category in SELF_SUFFICIENT_CATEGORIES for category in intent_categories)
        and not grounding_categories
        and not explicit_requires_knowledge
    )
    knowledge_required = bool(reasons) and not self_sufficient
    return {
        "episode_id": _text(value.get("episode_id"), 128),
        "intent_epoch": _integer(value.get("intent_epoch"), 2**31 - 1),
        "started_at_ms": _integer(value.get("started_at_ms"), 10**16),
        "ended_at_ms": _integer(value.get("ended_at_ms"), 10**16),
        "semantic_focus_ref": semantic_focus_ref,
        "presentation_target_ref": _normalize_ref(value.get("presentation_target_ref")),
        "mutation_target_ref": _normalize_ref(value.get("mutation_target_ref")),
        "focus": primary_focus,
        "focuses": focuses,
        "evidence": evidence,
        "candidate_intents": candidates,
        "intent_categories": intent_categories,
        "explicit_request": explicit_request,
        "confidence": confidence,
        "local_outcome": local_outcome,
        "disposition": disposition,
        "page_expression_available": page_expression_available,
        "trust_level": "iframe_bridge_candidate",
        "knowledge_requirement": {
            "required": knowledge_required,
            "content_owner": "main_or_specialist_agent" if knowledge_required else "frontend_agent",
            "frontend_agent_role": "intent_resolution_and_page_expression",
            "reasons": reasons,
        },
        "window_policy": DYNAMIC_WINDOW_POLICY,
    }
