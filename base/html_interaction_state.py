"""Thread-safe runtime state for Frontend Agent HTML interaction updates."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional


_lock = threading.RLock()
_states: Dict[str, Dict[str, Any]] = {}
_revisions: Dict[str, int] = {}


def get_html_interaction_state(artifact_id: str) -> Dict[str, Any]:
    """Return the latest state snapshot for one HTML artifact."""

    with _lock:
        state = _states.get(artifact_id)
        if state is not None:
            return dict(state)
        return {
            "artifact_id": artifact_id,
            "phase": "idle",
            "frozen": False,
            "revision": _revisions.get(artifact_id, 0),
            "stop_reason": None,
            "error": None,
            "updated_at": time.time(),
        }


def publish_html_interaction_state(
    artifact_id: str,
    *,
    phase: str,
    frozen: bool,
    stop_reason: Optional[str] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist and best-effort broadcast an HTML interaction state transition."""

    with _lock:
        revision = _revisions.get(artifact_id, 0) + 1
        _revisions[artifact_id] = revision
        state = {
            "artifact_id": artifact_id,
            "phase": phase,
            "frozen": bool(frozen),
            "revision": revision,
            "stop_reason": stop_reason,
            "error": error,
            "updated_at": time.time(),
        }
        _states[artifact_id] = state
        snapshot = dict(state)

    try:
        from desktop_app.backend.websocket.ipc_bridge import send_ws_message

        send_ws_message({"type": "html_interaction_state", "data": snapshot})
    except Exception:
        # State polling remains available even if the desktop WS process is not running.
        pass
    return snapshot
