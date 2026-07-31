"""HTML artifact API."""

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from base.html_artifacts import get_html_artifact_store, validate_html


router = APIRouter()


class HtmlSaveRequest(BaseModel):
    id: str
    content: str
    title: Optional[str] = None
    semantic_label: Optional[str] = None
    conversation_id: Optional[str] = None


class HtmlValidateRequest(BaseModel):
    content: str


class HtmlGenerateRequest(BaseModel):
    id: str
    description: str
    semantic_label: str = "interactive-html"
    data: Optional[Any] = None
    title: Optional[str] = None
    conversation_id: Optional[str] = None
    force: bool = False


class HtmlInteractionRequest(BaseModel):
    target: str
    request: str = ""
    action: str = "click"
    trigger_text: str = ""


@router.get("")
def list_html_artifacts():
    return {"artifacts": get_html_artifact_store().list()}


@router.get("/{artifact_id}")
def load_html_artifact(artifact_id: str):
    try:
        return get_html_artifact_store().load(artifact_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("")
def save_html_artifact(request: HtmlSaveRequest):
    try:
        return get_html_artifact_store().save(
            request.id,
            request.content,
            title=request.title,
            semantic_label=request.semantic_label,
            conversation_id=request.conversation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/validate")
def validate_html_artifact(request: HtmlValidateRequest):
    return validate_html(request.content)


@router.post("/generate")
def generate_html_artifact(request: HtmlGenerateRequest):
    store = get_html_artifact_store()
    if not request.force:
        try:
            return {**store.load(request.id), "generated": False}
        except FileNotFoundError:
            pass
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        from AutoAgent.frontend_agent import generate_html

        return generate_html(
            request.id,
            request.description,
            semantic_label=request.semantic_label,
            data=request.data,
            title=request.title,
            conversation_id=request.conversation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/{artifact_id}/interact")
def interact_with_html_artifact(artifact_id: str, request: HtmlInteractionRequest):
    try:
        from AutoAgent.frontend_agent import expand_html

        return expand_html(
            artifact_id,
            request.target,
            request.request,
            action=request.action,
            trigger_text=request.trigger_text,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.delete("/{artifact_id}")
def remove_html_artifact(artifact_id: str):
    try:
        return get_html_artifact_store().remove(artifact_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
