"""HTML artifact API."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from base.html_artifacts import get_html_artifact_store, validate_html
from base.html_interaction_state import (
    HtmlArtifactWriteBlockedError,
    get_html_interaction_state,
    observe_html_artifact_revision,
    record_html_artifact_commit,
    unfrozen_html_artifact_write,
)


router = APIRouter()


class HtmlSaveRequest(BaseModel):
    id: str
    content: str
    title: Optional[str] = None
    semantic_label: Optional[str] = None
    conversation_id: Optional[str] = None
    expected_sha256: Optional[str] = None


class HtmlValidateRequest(BaseModel):
    content: str



class HtmlInteractionRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(min_length=1, max_length=16)
    episode_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    intent_epoch: int = Field(ge=1)
    agent_request_id: str = Field(min_length=1, max_length=200)
    operation_id: str = Field(min_length=1, max_length=200)
    base_html_revision: int = Field(ge=0)
    base_html_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")
    state_revision: int = Field(ge=0)
    intent_snapshot: Dict[str, Any]


class HtmlInteractionCancelRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)
    intent_epoch: int = Field(ge=0)
    reason: Optional[str] = Field(default=None, max_length=500)


class HtmlInteractionHeartbeatRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)


class HtmlInteractionReadyRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)
    html_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$")
    state_revision: int = Field(ge=0)
    document_generation_id: str = Field(min_length=1, max_length=200)
    restore_attempt_id: str = Field(min_length=1, max_length=200)
    bridge_capability: str = Field(min_length=32, max_length=256)
    readiness_report: Dict[str, Any]
    ready: bool = True
    error: Optional[str] = Field(default=None, max_length=500)


class HtmlInteractionConfirmRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)


class HtmlInteractionResumeRequest(BaseModel):
    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)
    user_agreed: bool
    user_response: Optional[str] = Field(default=None, max_length=2000)


class HtmlInteractionAssessRequest(BaseModel):
    episode_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    intent_epoch: Optional[int] = Field(default=None, ge=1)
    agent_request_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    operation_id: Optional[str] = Field(default=None, min_length=1, max_length=200)
    intent_snapshot: Optional[dict] = None


class HtmlInteractionRecoverRequest(BaseModel):
    model_config = {"extra": "forbid"}

    operation_id: str = Field(min_length=1, max_length=200)
    agent_request_id: str = Field(min_length=1, max_length=200)
    expected_state_revision: int = Field(ge=0)


@router.get("")
def list_html_artifacts():
    return {"artifacts": get_html_artifact_store().list()}


@router.get("/{artifact_id}")
def load_html_artifact(artifact_id: str):
    try:
        loaded = get_html_artifact_store().load(artifact_id)
        html_revision = observe_html_artifact_revision(
            artifact_id, loaded.get("artifact", {}).get("sha256")
        )
        return {
            **loaded,
            "html_revision": html_revision,
            "html_sha256": loaded.get("artifact", {}).get("sha256"),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("")
def save_html_artifact(request: HtmlSaveRequest):
    try:
        store = get_html_artifact_store()
        with unfrozen_html_artifact_write(request.id):
            if request.expected_sha256:
                saved = store.save_if_sha256(
                    request.id,
                    request.content,
                    expected_sha256=request.expected_sha256,
                    title=request.title,
                    semantic_label=request.semantic_label,
                    conversation_id=request.conversation_id,
                )
            else:
                saved = store.save(
                    request.id,
                    request.content,
                    title=request.title,
                    semantic_label=request.semantic_label,
                    conversation_id=request.conversation_id,
                )
            state = record_html_artifact_commit(request.id, saved["artifact"].get("sha256"))
        return {
            **saved,
            "html_revision": state.get("html_revision"),
            "html_sha256": state.get("html_sha256"),
            "state_revision": state.get("state_revision"),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/validate")
def validate_html_artifact(request: HtmlValidateRequest):
    return validate_html(request.content)



@router.get("/{artifact_id}/interaction-state")
def load_html_interaction_state(artifact_id: str):
    try:
        from AutoAgent.frontend_agent import get_html_interaction_runtime_state

        return get_html_interaction_runtime_state(artifact_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{artifact_id}/interact")
def interact_with_html_artifact(artifact_id: str, request: HtmlInteractionRequest):
    try:
        from AutoAgent.frontend_agent import InteractionConflictError, process_html_interactions

        return process_html_interactions(
            artifact_id,
            request.events,
            intent_epoch=request.intent_epoch,
            agent_request_id=request.agent_request_id,
            operation_id=request.operation_id,
            episode_id=request.episode_id,
            base_html_revision=request.base_html_revision,
            base_html_sha256=request.base_html_sha256,
            state_revision=request.state_revision,
            intent_snapshot=request.intent_snapshot,
            require_interaction_ready_ack=False,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InteractionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-cancel")
def cancel_html_interaction(artifact_id: str, request: HtmlInteractionCancelRequest):
    try:
        from AutoAgent.frontend_agent import supersede_html_interaction_operation

        return supersede_html_interaction_operation(
            artifact_id,
            operation_id=request.operation_id,
            agent_request_id=request.agent_request_id,
            intent_epoch=request.intent_epoch,
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-heartbeat")
def heartbeat_html_interaction(artifact_id: str, request: HtmlInteractionHeartbeatRequest):
    try:
        from AutoAgent.frontend_agent import heartbeat_interaction_operation

        return heartbeat_interaction_operation(
            artifact_id,
            request.operation_id,
            agent_request_id=request.agent_request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-ready")
def acknowledge_html_interaction_ready(artifact_id: str, request: HtmlInteractionReadyRequest):
    try:
        from AutoAgent.frontend_agent import acknowledge_interaction_ready

        return acknowledge_interaction_ready(
            artifact_id,
            request.operation_id,
            agent_request_id=request.agent_request_id,
            html_sha256=request.html_sha256,
            state_revision=request.state_revision,
            document_generation_id=request.document_generation_id,
            restore_attempt_id=request.restore_attempt_id,
            bridge_capability=request.bridge_capability,
            readiness_report=request.readiness_report,
            ready=request.ready,
            error=request.error,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-confirm")
def confirm_html_interaction_route(artifact_id: str, request: HtmlInteractionConfirmRequest):
    try:
        from AutoAgent.frontend_agent import InteractionConflictError, confirm_html_interaction

        return confirm_html_interaction(
            artifact_id,
            operation_id=request.operation_id,
            agent_request_id=request.agent_request_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InteractionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-recover")
def recover_html_interaction(artifact_id: str, request: HtmlInteractionRecoverRequest):
    try:
        from AutoAgent.frontend_agent import recover_html_interaction_operation

        return recover_html_interaction_operation(
            artifact_id,
            operation_id=request.operation_id,
            agent_request_id=request.agent_request_id,
            expected_state_revision=request.expected_state_revision,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-resume")
def resume_html_interaction_route(artifact_id: str, request: HtmlInteractionResumeRequest):
    """Round-2 trigger: user responded to the assess question.

    Pass ``user_agreed=true`` with an optional ``user_response`` to run the
    mutation round, or ``user_agreed=false`` to discard the session.
    """
    try:
        from AutoAgent.frontend_agent import (
            InteractionConflictError,
            resume_html_interaction,
        )

        return resume_html_interaction(
            artifact_id,
            request.operation_id,
            agent_request_id=request.agent_request_id,
            user_agreed=request.user_agreed,
            user_response=request.user_response,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InteractionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{artifact_id}/interaction-assess")
def assess_html_interaction_route(artifact_id: str, request: HtmlInteractionAssessRequest):
    """Path-2 trigger: agent-initiated proactive assessment.

    Starts a Round-1 ASSESS session without requiring real user click events.
    Returns ``{"decision": "awaiting_user_decision", "question": "..."}``; the
    caller should show the question to the user and then call
    ``interaction-resume`` with their decision.
    """
    try:
        from AutoAgent.frontend_agent import InteractionConflictError, assess_html_interaction

        return assess_html_interaction(
            artifact_id,
            intent_epoch=request.intent_epoch,
            agent_request_id=request.agent_request_id,
            operation_id=request.operation_id,
            episode_id=request.episode_id,
            intent_snapshot=request.intent_snapshot,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InteractionConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.delete("/{artifact_id}")
def remove_html_artifact(artifact_id: str):
    try:
        with unfrozen_html_artifact_write(artifact_id):
            return get_html_artifact_store().remove(artifact_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HtmlArtifactWriteBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
