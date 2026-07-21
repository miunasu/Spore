"""
Thread-local conversation context for desktop side-channel events.

Conversation loops can run in worker threads while the UI switches the global
active session. Side channels such as TODO updates, logs, agent output, and
confirmation prompts must use the request's conversation id rather than the
currently selected UI session.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional


_conversation_id: ContextVar[Optional[str]] = ContextVar(
    "spore_conversation_id",
    default=None,
)
_task_source: ContextVar[Optional[str]] = ContextVar(
    "spore_task_source",
    default=None,
)
_task_epoch: ContextVar[Optional[int]] = ContextVar(
    "spore_task_epoch",
    default=None,
)


def get_current_conversation_id() -> Optional[str]:
    """Return the conversation id bound to the current execution context."""
    return _conversation_id.get()


def set_current_conversation_id(conversation_id: Optional[str]):
    """Set the current context id and return the token needed to reset it."""
    return _conversation_id.set(conversation_id)


def reset_current_conversation_id(token) -> None:
    """Reset the current context id using a token returned by set."""
    _conversation_id.reset(token)


def get_current_task_source() -> Optional[str]:
    """Return the source of the task currently driving the conversation loop."""
    return _task_source.get()


def get_current_task_epoch() -> Optional[int]:
    """Return the interrupt epoch captured when the current task was accepted."""
    return _task_epoch.get()


@contextmanager
def task_source_context(source: Optional[str], epoch: Optional[int] = None) -> Iterator[None]:
    source_token = _task_source.set(source)
    epoch_token = _task_epoch.set(epoch)
    try:
        yield
    finally:
        _task_epoch.reset(epoch_token)
        _task_source.reset(source_token)


@contextmanager
def conversation_context(conversation_id: Optional[str]) -> Iterator[None]:
    """Temporarily bind side-channel events to a conversation id."""
    token = set_current_conversation_id(conversation_id)
    try:
        yield
    finally:
        reset_current_conversation_id(token)
