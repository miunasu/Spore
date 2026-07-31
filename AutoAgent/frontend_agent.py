"""One-shot frontend Agent for generating sandboxed HTML artifacts."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from base.config import get_config
from base.html_artifacts import (
    get_html_artifact_store,
    has_dynamic_target,
    validate_artifact_id,
    validate_dynamic_target,
    validate_html,
)
from base.logger import log_error
from base.prompt_loader import load_system_prompt


_ipc_manager = None
_HTML_FENCE = re.compile(r"```html\s*\r?\n([\s\S]*?)\r?\n```", re.IGNORECASE)
_HTML_DOCUMENT = re.compile(r"(?:<!doctype\s+html\b|<html\b)", re.IGNORECASE)


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


def _call_frontend_agent(messages, timeout: int) -> str:
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
    )
    response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
    if response is None or response.get("status") != "success":
        detail = response.get("error") if isinstance(response, dict) else "timeout"
        raise RuntimeError(f"Frontend Agent request failed: {detail}")
    return (response.get("data") or {}).get("content", "")


def generate_html(
    artifact_id: str,
    description: str,
    *,
    semantic_label: str = "interactive-html",
    data: Optional[Any] = None,
    title: Optional[str] = None,
    conversation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate, review, validate, and persist one complete HTML document."""

    safe_id = validate_artifact_id(artifact_id)
    config = get_config()
    max_iterations = max(2, int(getattr(config, "frontend_agent_max_iterations", 3)))
    timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
    request = {
        "component_id": safe_id,
        "title": title or safe_id,
        "semantic_label": semantic_label,
        "description": description,
        "data": data,
    }
    messages = [{
        "role": "user",
        "content": "Create this HTML artifact. Return only the complete HTML document.\n"
                   + json.dumps(request, ensure_ascii=False, indent=2),
    }]

    last_valid: Optional[str] = None
    reviewed = False
    validation: Dict[str, Any] = {}

    try:
        for iteration in range(1, max_iterations + 1):
            raw = _call_frontend_agent(messages, timeout)
            candidate = extract_html_response(raw)
            validation = validate_html(candidate or "")

            if validation["valid"] and candidate:
                last_valid = candidate
                if not reviewed and iteration < max_iterations:
                    reviewed = True
                    messages.extend([
                        {"role": "assistant", "content": candidate},
                        {
                            "role": "user",
                            "content": (
                                "Audit this artifact for responsive layout, text overflow, accessibility, "
                                "clear interaction states, and functional inline JavaScript. Return the full "
                                "corrected HTML document only. Do not add external resources or network calls."
                            ),
                        },
                    ])
                    continue

                saved = get_html_artifact_store().save(
                    safe_id,
                    candidate,
                    title=title,
                    semantic_label=semantic_label,
                    conversation_id=conversation_id,
                )
                return {**saved, "generated": True, "iterations": iteration, "reviewed": reviewed}

            messages.extend([
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": (
                        "The HTML failed validation. Correct every issue and return only one complete HTML "
                        "document. Validation:\n" + json.dumps(validation, ensure_ascii=False, indent=2)
                    ),
                },
            ])

        if last_valid:
            saved = get_html_artifact_store().save(
                safe_id,
                last_valid,
                title=title,
                semantic_label=semantic_label,
                conversation_id=conversation_id,
            )
            return {**saved, "generated": True, "iterations": max_iterations, "reviewed": reviewed}
        raise RuntimeError("Frontend Agent did not produce valid HTML")
    except Exception as exc:
        log_error(
            "FRONTEND_AGENT_ERROR",
            "Frontend Agent generation failed",
            exc,
            context={"artifact_id": safe_id, "validation": validation},
        )
        raise


def expand_html(
    artifact_id: str,
    target: str,
    request: str,
    *,
    action: str = "click",
    trigger_text: str = "",
) -> Dict[str, Any]:
    """Materialize one missing interactive target in an existing artifact."""

    safe_id = validate_artifact_id(artifact_id)
    safe_target = validate_dynamic_target(target)
    store = get_html_artifact_store()
    loaded = store.load(safe_id)
    current = loaded["content"]
    if has_dynamic_target(current, safe_target):
        return {**loaded, "generated": False, "target": safe_target}

    config = get_config()
    max_iterations = max(1, int(getattr(config, "frontend_agent_max_iterations", 3)))
    timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
    interaction = {
        "component_id": safe_id,
        "missing_target": safe_target,
        "request": (request or "").strip()[:2000],
        "action": (action or "click").strip()[:40],
        "trigger_text": (trigger_text or "").strip()[:300],
    }
    messages = [{
        "role": "user",
        "content": (
            "Update this existing HTML artifact for a user interaction. Preserve all useful existing "
            "content and behavior. Materialize the missing target as an element whose id or "
            "data-spore-view exactly matches missing_target. Return only the complete updated HTML.\n\n"
            "Interaction:\n" + json.dumps(interaction, ensure_ascii=False, indent=2)
            + "\n\nCurrent HTML:\n" + current
        ),
    }]
    validation: Dict[str, Any] = {}

    try:
        for iteration in range(1, max_iterations + 1):
            raw = _call_frontend_agent(messages, timeout)
            candidate = extract_html_response(raw)
            validation = validate_html(candidate or "")
            target_present = bool(candidate and has_dynamic_target(candidate, safe_target))
            if validation["valid"] and candidate and target_present:
                saved = store.save(
                    safe_id,
                    candidate,
                    title=loaded["artifact"].get("title"),
                    semantic_label=loaded["artifact"].get("semantic_label"),
                    conversation_id=loaded["artifact"].get("conversation_id"),
                )
                return {
                    **saved,
                    "content": saved["content"],
                    "generated": True,
                    "iterations": iteration,
                    "target": safe_target,
                }

            feedback = dict(validation)
            if not target_present:
                feedback.setdefault("errors", []).append({
                    "code": "missing_dynamic_target",
                    "message": f"Add id or data-spore-view exactly equal to {safe_target}",
                })
                feedback["valid"] = False
            messages.extend([
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": (
                        "Correct every validation issue while preserving the existing artifact. "
                        "Return only the full HTML document. Validation:\n"
                        + json.dumps(feedback, ensure_ascii=False, indent=2)
                    ),
                },
            ])
        raise RuntimeError(f"Frontend Agent did not materialize target: {safe_target}")
    except Exception as exc:
        log_error(
            "FRONTEND_AGENT_INTERACTION_ERROR",
            "Frontend Agent interaction update failed",
            exc,
            context={"artifact_id": safe_id, "target": safe_target, "validation": validation},
        )
        raise
