"""One-shot frontend Agent for generating sandboxed HTML artifacts."""

from __future__ import annotations

import json
import re
import threading
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Doctype, Tag

from base.config import get_config
from base.html_artifacts import (
    get_html_artifact_store,
    validate_artifact_id,
    validate_html,
)
from base.html_interaction_state import publish_html_interaction_state
from base.logger import log_error
from base.prompt_loader import load_system_prompt
from base.text_protocol import ProtocolManager, extract_stop_reason_blocks


_ipc_manager = None
_HTML_FENCE = re.compile(r"```html\s*\r?\n([\s\S]*?)\r?\n```", re.IGNORECASE)
_HTML_DOCUMENT = re.compile(r"(?:<!doctype\s+html\b|<html\b)", re.IGNORECASE)
_JSON_FENCE = re.compile(r"^\s*```json\s*\r?\n([\s\S]*?)\r?\n```\s*$", re.IGNORECASE)
_INTERRUPT_PREFIX = re.compile(r"^\s*interrupt\b", re.IGNORECASE)
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
_interaction_locks: Dict[str, threading.Lock] = {}
_interaction_locks_guard = threading.Lock()


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


def _call_frontend_agent(messages, timeout: int, stream_callback=None) -> str:
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
    response = _ipc_manager.get_chat_response(request_id=request_id, timeout=timeout)
    if response is None or response.get("status") != "success":
        detail = response.get("error") if isinstance(response, dict) else "timeout"
        raise RuntimeError(f"Frontend Agent request failed: {detail}")
    content = (response.get("data") or {}).get("content", "")
    if stream_callback is not None:
        # Some providers do not expose deltas even when streaming was requested.
        # Feeding the final snapshot keeps the interrupt protocol deterministic.
        stream_callback({"event": "final", "delta": "", "content": content})
    return content


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


def _get_interaction_lock(artifact_id: str) -> threading.Lock:
    with _interaction_locks_guard:
        return _interaction_locks.setdefault(artifact_id, threading.Lock())


def _clean_click_event(event: Any, index: int) -> Dict[str, Any]:
    raw = event if isinstance(event, dict) else {}

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
    if control:
        clean["control"] = {
            "type": str(control.get("type") or "")[:40],
            "value": str(control.get("value") or "")[:500],
            "checked": bool(control.get("checked")),
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
    if element_id:
        return node.get("id") == element_id

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
            if str(node.get(attribute) or "") != expected:
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
        if isinstance(selected, Tag):
            return selected

    href = click.get("href") or ""
    if href:
        selected = soup.find("a", href=href)
        if isinstance(selected, Tag) and _matches_click(selected, click):
            return selected

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
            attributes[key] = value
    return {
        "tag": node.name,
        "attributes": attributes,
        "text": " ".join(node.get_text(" ", strip=True).split())[:300],
    }


def _build_interaction_context(
    current: str,
    clicks: List[Dict[str, Any]],
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
            snippet = str(node)
            limit = min(snippet_limit, snippet_budget)
            record["html"] = snippet[:limit]
            snippet_budget -= len(record["html"].encode("utf-8"))
        reference_context.append(record)

    observations: List[Dict[str, Any]] = []
    for index, click in enumerate(clicks):
        node = _resolve_click_node(soup, click)
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
                "clicked_word", "aria_label", "title", "href", "spore_target",
                "spore_request", "control", "scroll_y", "viewport",
            )
            if click.get(key) not in (None, "", [], {})
        }
        observation["target_ref"] = target_ref
        observations.append(observation)

    outline = []
    for node in soup.select("main, nav, header, footer, section, article, aside, h1, h2, h3, details, [data-spore-view]")[:40]:
        outline.append({"selector": _stable_selector(node), **_tag_summary(node)})

    style_context = "\n".join((node.string or node.get_text()) for node in soup.find_all("style"))[:3000]
    script_context = "\n".join((node.string or node.get_text()) for node in soup.find_all("script"))[:2000]
    context = {
        "protocol": "spore-html-mutation-v1",
        "window_ms": 5000,
        "event_count": len(clicks),
        "interactions": observations,
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
    """Split the frontend-only interrupt signal from the mutation JSON payload.

    Spore lifecycle markers are deliberately not handled here. They belong to
    ProtocolManager and are removed before this mutation-specific parser runs.
    """

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


def _strip_spore_stop_reason(raw: str) -> str:
    """Remove the generic Spore terminal block after ProtocolManager accepts it."""

    blocks, error = extract_stop_reason_blocks(raw or "")
    if error:
        raise ValueError(error)
    content = raw or ""
    for block in reversed(blocks):
        content = content[:block["start"]] + content[block["end"]:]
    return content.strip()


def _parse_mutation_response(raw: str) -> Dict[str, Any]:
    payload, starts_with_interrupt = _split_mutation_protocol(raw)
    fenced = _JSON_FENCE.fullmatch(payload)
    if fenced:
        payload = fenced.group(1).strip()
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Response is not valid JSON: {exc.msg}") from exc
    if not isinstance(result, dict):
        raise ValueError("Mutation response must be a JSON object")
    if set(result) - {"decision", "intent", "mutations"}:
        raise ValueError("Mutation response contains unsupported top-level fields")

    decision = result.get("decision")
    intent = result.get("intent")
    mutations = result.get("mutations", [])
    if decision not in {"no_change", "mutate"}:
        raise ValueError("decision must be no_change or mutate")
    if intent is not None and not isinstance(intent, str):
        raise ValueError("intent must be a string")
    if not isinstance(mutations, list):
        raise ValueError("mutations must be an array")
    if len(mutations) > _MAX_MUTATIONS:
        raise ValueError(f"At most {_MAX_MUTATIONS} mutations are allowed")
    if decision == "no_change" and mutations:
        raise ValueError("no_change cannot include mutations")
    if decision == "mutate" and not mutations:
        raise ValueError("mutate requires at least one mutation")
    if decision == "mutate" and not starts_with_interrupt:
        raise ValueError("mutate response must start with interrupt")
    if decision == "no_change" and starts_with_interrupt:
        raise ValueError("no_change response must not start with interrupt")

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
        "interrupt": starts_with_interrupt,
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


def _interaction_stream_callback(artifact_id: str):
    seen_interrupt = False

    def handle(event: Dict[str, Any]) -> None:
        nonlocal seen_interrupt
        content = str(event.get("content") or "")
        if not seen_interrupt and "interrupt" in content.lower():
            seen_interrupt = True
            publish_html_interaction_state(
                artifact_id,
                phase="frozen",
                frozen=True,
            )

    return handle


def process_html_interactions(artifact_id: str, events: Any) -> Dict[str, Any]:
    """Infer intent from an interaction batch and atomically apply validated local mutations."""

    safe_id = validate_artifact_id(artifact_id)
    raw_events = events if isinstance(events, list) else []
    if not raw_events:
        raise ValueError("At least one HTML interaction event is required")
    clicks = [_clean_click_event(item, index) for index, item in enumerate(raw_events[:64])]

    with _get_interaction_lock(safe_id):
        store = get_html_artifact_store()
        loaded = store.load(safe_id)
        current = loaded["content"]
        config = get_config()
        max_iterations = max(1, int(getattr(config, "frontend_agent_max_iterations", 3)))
        timeout = max(30, int(getattr(config, "frontend_agent_timeout", 180)))
        context, soup, references = _build_interaction_context(current, clicks)
        context["component_id"] = safe_id
        messages = [{
            "role": "user",
            "content": (
                "INTERACTION_MUTATION mode. Infer the user's intent from the complete chronological "
                "five-second interaction batch. Decide whether the user wants a word explanation, structure "
                "expansion, missing page/navigation, comparison, or whether existing local behavior "
                "already satisfies the interactions. You are given only compact element references and excerpts, "
                "not the complete document. The mutation payload and the Spore lifecycle protocol are separate. "
                "For no_change, output one strict JSON object and then terminate this Frontend Agent operation "
                "with the existing @SPORE:STOP_REASON=<natural language reason> protocol marker. For mutate, the "
                "first non-whitespace streamed output must be the standalone word interrupt, followed by one "
                "strict JSON object; terminate the operation with the same generic Spore STOP_REASON marker. "
                "Do not emit interrupt for no_change. The STOP_REASON marker is not part of the mutation JSON "
                "schema and is interpreted by the host protocol manager.\n\n"
                "Use {\"decision\":\"no_change\",\"intent\":\"short reason\",\"mutations\":[]} when "
                "no persisted change is needed. Otherwise use decision=mutate and the smallest coherent "
                "ordered mutation list. Each mutation must target one supplied ref. Allowed forms are: "
                "{op:append|prepend|before|after|replace_inner|replace_outer,target_ref,html}, "
                "{op:set_attributes,target_ref,attributes}, or {op:remove,target_ref}. HTML values must be "
                "fragments, never full documents. Preserve existing useful behavior and use document-head "
                "or document-body only when clicked references are insufficient. Do not invent refs.\n\n"
                "Interaction context:\n" + json.dumps(context, ensure_ascii=False, indent=2)
            ),
        }]
        validation: Dict[str, Any] = {}
        protocol_manager = ProtocolManager()
        publish_html_interaction_state(safe_id, phase="analyzing", frozen=False)

        try:
            for iteration in range(1, max_iterations + 1):
                raw = _call_frontend_agent(
                    messages,
                    timeout,
                    stream_callback=_interaction_stream_callback(safe_id),
                ).strip()
                parsed = protocol_manager.parse_response(raw)
                final_reason: Optional[str] = None
                response: Optional[Dict[str, Any]] = None

                if parsed.response_type == "protocol_error":
                    error = parsed.protocol_error
                    validation = {
                        "valid": False,
                        "errors": [{
                            "code": "spore_protocol",
                            "message": error.message if error else "Invalid Spore protocol response",
                        }],
                    }
                elif parsed.response_type == "action":
                    validation = {
                        "valid": False,
                        "errors": [{
                            "code": "spore_protocol",
                            "message": "Frontend Agent interaction mode does not accept tool actions",
                        }],
                    }
                elif parsed.response_type != "final":
                    validation = {
                        "valid": False,
                        "errors": [{
                            "code": "frontend_operation_incomplete",
                            "message": (
                                "Frontend Agent has not ended this operation through the Spore protocol. "
                                "Continue the operation and emit @SPORE:STOP_REASON only when the final "
                                "mutation decision is ready."
                            ),
                        }],
                    }
                else:
                    final_reason = (parsed.final_content or "completed").strip()[:500]
                    try:
                        payload = _strip_spore_stop_reason(raw)
                        response = _parse_mutation_response(payload)
                    except ValueError as exc:
                        validation = {
                            "valid": False,
                            "errors": [{"code": "mutation_schema", "message": str(exc)}],
                        }

                if response is not None:
                    if response["decision"] == "no_change":
                        publish_html_interaction_state(
                            safe_id,
                            phase="completed",
                            frozen=False,
                            stop_reason=final_reason or response["intent"] or "no_change",
                        )
                        return {
                            **loaded,
                            "generated": False,
                            "iterations": iteration,
                            "event_count": len(clicks),
                            "decision": "no_change",
                            "intent": response["intent"],
                            "stop_reason": final_reason,
                        }

                    # ProtocolManager has confirmed that the Frontend Agent ended its operation.
                    # Keep the document frozen while structural application and validation run.
                    publish_html_interaction_state(
                        safe_id,
                        phase="validating",
                        frozen=True,
                        stop_reason=final_reason,
                    )
                    try:
                        candidate = _apply_mutations(soup, references, response["mutations"])
                        validation = validate_html(candidate)
                    except ValueError as exc:
                        validation = {
                            "valid": False,
                            "errors": [{"code": "mutation_apply", "message": str(exc)}],
                        }

                    if validation["valid"]:
                        if candidate.strip() == current.strip():
                            publish_html_interaction_state(
                                safe_id,
                                phase="completed",
                                frozen=False,
                                stop_reason=final_reason,
                            )
                            return {
                                **loaded,
                                "generated": False,
                                "iterations": iteration,
                                "event_count": len(clicks),
                                "decision": "no_change",
                                "intent": response["intent"] or "Mutations did not change the artifact",
                                "stop_reason": final_reason,
                            }
                        saved = store.save(
                            safe_id,
                            candidate,
                            title=loaded["artifact"].get("title"),
                            semantic_label=loaded["artifact"].get("semantic_label"),
                            conversation_id=loaded["artifact"].get("conversation_id"),
                        )
                        publish_html_interaction_state(
                            safe_id,
                            phase="completed",
                            frozen=False,
                            stop_reason=final_reason,
                        )
                        return {
                            **saved,
                            "generated": True,
                            "iterations": iteration,
                            "event_count": len(clicks),
                            "decision": "updated",
                            "intent": response["intent"],
                            "mutation_count": len(response["mutations"]),
                            "stop_reason": final_reason,
                        }

                if iteration < max_iterations:
                    # Rebuild from persisted HTML so a rejected partial application cannot leak into a retry.
                    context, soup, references = _build_interaction_context(current, clicks)
                    context["component_id"] = safe_id
                    messages.extend([
                        {"role": "assistant", "content": raw},
                        {
                            "role": "user",
                            "content": (
                                "Continue or correct the Frontend Agent operation. Return the final mutation "
                                "decision using only supplied target_ref values and allowed operations. A mutate "
                                "payload MUST start with the standalone word interrupt and then contain exactly "
                                "one strict JSON object. A no_change payload is only the strict JSON object and "
                                "must not emit interrupt. When the final decision is ready, end the Agent operation "
                                "using the existing @SPORE:STOP_REASON=<natural language reason> protocol marker. "
                                "That marker is handled by the Spore protocol layer, not by the mutation schema. "
                                "Do not return a complete HTML document. Rejection or continuation reason:\n"
                                + json.dumps(validation, ensure_ascii=False, indent=2)
                            ),
                        },
                    ])

            raise RuntimeError("Frontend Agent did not complete a valid interaction mutation operation")
        except Exception as exc:
            publish_html_interaction_state(
                safe_id,
                phase="failed",
                frozen=False,
                error=str(exc)[:500],
            )
            log_error(
                "FRONTEND_AGENT_INTERACTION_ERROR",
                "Frontend Agent interaction batch failed",
                exc,
                context={"artifact_id": safe_id, "event_count": len(clicks), "validation": validation},
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
    """Compatibility wrapper for callers using the earlier missing-target protocol."""

    return process_html_interactions(artifact_id, [{
        "tag": "button",
        "text": trigger_text,
        "spore_target": target,
        "spore_request": request,
        "role": action,
    }])
