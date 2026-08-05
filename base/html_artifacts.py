"""Persistent HTML artifacts stored under .spore/html."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional


ARTIFACT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
DYNAMIC_TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,79}$")
HTML_DOCUMENT_PATTERN = re.compile(
    r"^\s*<!doctype\s+html\b[\s\S]*<html\b[\s\S]*<body\b[\s\S]*</body\s*>[\s\S]*</html\s*>\s*$",
    re.IGNORECASE,
)
MAX_HTML_BYTES = 2 * 1024 * 1024

_UNSAFE_PATTERNS = (
    ("external_script", re.compile(r"<script\b[^>]*\bsrc\s*=", re.IGNORECASE)),
    ("external_stylesheet", re.compile(r"<link\b[^>]*\bhref\s*=", re.IGNORECASE)),
    ("embedded_frame", re.compile(r"<(?:iframe|frame|object|embed|portal)\b", re.IGNORECASE)),
    ("base_url", re.compile(r"<base\b", re.IGNORECASE)),
    ("meta_refresh", re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh\b", re.IGNORECASE)),
    ("network_api", re.compile(
        r"\b(?:fetch\s*\(|XMLHttpRequest\b|WebSocket\s*\(|EventSource\s*\(|navigator\.sendBeacon\s*\(|"
        r"window\.open\s*\(|(?:window\.)?location\s*(?:=|\.|\[))",
        re.IGNORECASE,
    )),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_artifact_id(artifact_id: str) -> str:
    value = (artifact_id or "").strip()
    if not ARTIFACT_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "HTML ID must be 1-80 lowercase letters, digits, dots, underscores, or hyphens "
            "and must start with a letter or digit"
        )
    return value


def validate_dynamic_target(target: str) -> str:
    value = (target or "").strip()
    if not DYNAMIC_TARGET_PATTERN.fullmatch(value):
        raise ValueError(
            "Dynamic target must be 1-80 letters, digits, dots, underscores, colons, or hyphens"
        )
    return value


class _DynamicTargetParser(HTMLParser):
    def __init__(self, target: str):
        super().__init__(convert_charrefs=True)
        self.target = target
        self.found = False

    def handle_starttag(self, _tag: str, attrs) -> None:
        values = dict(attrs)
        if values.get("id") == self.target or values.get("data-spore-view") == self.target:
            self.found = True

    handle_startendtag = handle_starttag


def has_dynamic_target(content: str, target: str) -> bool:
    parser = _DynamicTargetParser(validate_dynamic_target(target))
    try:
        parser.feed(content)
    except Exception:
        return False
    return parser.found


def stamp_artifact_id(content: str, artifact_id: str) -> str:
    safe_id = validate_artifact_id(artifact_id)
    html_tag = re.compile(r"<html\b([^>]*)>", re.IGNORECASE)
    match = html_tag.search(content)
    if not match:
        return content
    attributes = match.group(1)
    identity = re.compile(r"\sdata-spore-artifact-id\s*=\s*(['\"])[^'\"]*\1", re.IGNORECASE)
    if identity.search(attributes):
        attributes = identity.sub(f' data-spore-artifact-id="{safe_id}"', attributes, count=1)
    else:
        attributes = f' data-spore-artifact-id="{safe_id}"' + attributes
    return content[:match.start()] + f"<html{attributes}>" + content[match.end():]


def validate_html(content: str) -> Dict[str, Any]:
    encoded = content.encode("utf-8")
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []

    if not content.strip():
        errors.append({"code": "empty", "message": "HTML content is empty"})
    if len(encoded) > MAX_HTML_BYTES:
        errors.append({"code": "too_large", "message": f"HTML exceeds {MAX_HTML_BYTES} bytes"})
    if content.strip() and not HTML_DOCUMENT_PATTERN.match(content):
        errors.append({"code": "incomplete_document", "message": "HTML must be one complete doctype/html/body document"})

    for code, pattern in _UNSAFE_PATTERNS:
        if pattern.search(content):
            errors.append({"code": code, "message": f"Blocked HTML capability: {code}"})

    return {
        "valid": not errors,
        "size": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "errors": errors,
        "warnings": warnings,
    }


class HtmlArtifactStore:
    """Thread-safe artifact and index manager."""

    def __init__(self, root: Optional[Path] = None):
        self.root = (root or (Path.cwd() / ".spore" / "html")).resolve()
        self.index_path = self.root / "index.json"
        self._lock = threading.RLock()

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def _artifact_path(self, artifact_id: str) -> Path:
        safe_id = validate_artifact_id(artifact_id)
        path = (self.root / f"{safe_id}.html").resolve()
        path.relative_to(self.root)
        return path

    def _read_index(self) -> Dict[str, Any]:
        self._ensure_root()
        if not self.index_path.exists():
            return {"version": 1, "artifacts": {}}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            artifacts = data.get("artifacts") if isinstance(data, dict) else None
            if isinstance(artifacts, dict):
                return {"version": 1, "artifacts": artifacts}
        except (OSError, json.JSONDecodeError):
            pass
        return {"version": 1, "artifacts": {}}

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(path)

    def _write_index(self, index: Dict[str, Any]) -> None:
        payload = json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self._atomic_write(self.index_path, payload)

    def _metadata_from_file(
        self,
        artifact_id: str,
        path: Path,
        previous: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        content = path.read_text(encoding="utf-8")
        validation = validate_html(content)
        stat = path.stat()
        updated_at = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        previous = previous or {}
        return {
            "id": artifact_id,
            "file": path.name,
            "title": previous.get("title") or artifact_id,
            "semantic_label": previous.get("semantic_label") or "",
            "conversation_id": previous.get("conversation_id"),
            "created_at": previous.get("created_at") or updated_at,
            "updated_at": updated_at,
            "size": validation["size"],
            "sha256": validation["sha256"],
            "valid": validation["valid"],
        }

    def _sync_index(self) -> Dict[str, Any]:
        index = self._read_index()
        previous = index["artifacts"]
        artifacts: Dict[str, Dict[str, Any]] = {}
        for path in sorted(self.root.glob("*.html"), key=lambda item: item.name.lower()):
            artifact_id = path.stem
            if not ARTIFACT_ID_PATTERN.fullmatch(artifact_id):
                continue
            try:
                artifacts[artifact_id] = self._metadata_from_file(
                    artifact_id, path, previous.get(artifact_id)
                )
            except (OSError, UnicodeDecodeError):
                continue
        synced = {"version": 1, "artifacts": artifacts}
        if synced != index:
            self._write_index(synced)
        return synced

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            artifacts = self._sync_index()["artifacts"].values()
            return sorted(artifacts, key=lambda item: item["updated_at"], reverse=True)

    def load(self, artifact_id: str) -> Dict[str, Any]:
        with self._lock:
            path = self._artifact_path(artifact_id)
            if not path.is_file():
                raise FileNotFoundError(f"HTML artifact not found: {artifact_id}")
            index = self._sync_index()
            return {
                "artifact": index["artifacts"][artifact_id],
                "content": path.read_text(encoding="utf-8"),
            }

    def save(
        self,
        artifact_id: str,
        content: str,
        *,
        title: Optional[str] = None,
        semantic_label: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            safe_id = validate_artifact_id(artifact_id)
            content = stamp_artifact_id(content, safe_id)
            validation = validate_html(content)
            if not validation["valid"]:
                codes = ", ".join(item["code"] for item in validation["errors"])
                raise ValueError(f"HTML failed safety validation: {codes}")

            self._ensure_root()
            path = self._artifact_path(safe_id)
            index = self._read_index()
            previous = index["artifacts"].get(safe_id, {})
            now = utc_now()
            self._atomic_write(path, content)
            metadata = {
                "id": safe_id,
                "file": path.name,
                "title": (title or previous.get("title") or safe_id).strip(),
                "semantic_label": (semantic_label or previous.get("semantic_label") or "").strip(),
                "conversation_id": conversation_id or previous.get("conversation_id"),
                "created_at": previous.get("created_at") or now,
                "updated_at": now,
                "size": validation["size"],
                "sha256": validation["sha256"],
                "valid": True,
            }
            index["artifacts"][safe_id] = metadata
            self._write_index(index)
            return {"artifact": metadata, "validation": validation, "content": content}

    def save_if_sha256(
        self,
        artifact_id: str,
        content: str,
        *,
        expected_sha256: str,
        title: Optional[str] = None,
        semantic_label: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically save only while the persisted artifact still matches the caller's base.

        The comparison and write share the store lock, so a Frontend Agent result based on an
        older document cannot overwrite a newer manual or agent save.
        """

        with self._lock:
            safe_id = validate_artifact_id(artifact_id)
            expected = (expected_sha256 or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("expected_sha256 must be a lowercase 64-character SHA-256 digest")

            path = self._artifact_path(safe_id)
            if not path.is_file():
                raise FileNotFoundError(f"HTML artifact not found: {safe_id}")

            current_content = path.read_text(encoding="utf-8")
            current_sha256 = validate_html(current_content)["sha256"]
            if current_sha256 != expected:
                raise RuntimeError(
                    f"HTML artifact revision conflict for {safe_id}: "
                    f"expected {expected}, found {current_sha256}"
                )

            # RLock intentionally permits reuse of the regular validation/stamping save path.
            return self.save(
                safe_id,
                content,
                title=title,
                semantic_label=semantic_label,
                conversation_id=conversation_id,
            )

    def remove(self, artifact_id: str) -> Dict[str, Any]:
        with self._lock:
            safe_id = validate_artifact_id(artifact_id)
            path = self._artifact_path(safe_id)
            if not path.is_file():
                raise FileNotFoundError(f"HTML artifact not found: {safe_id}")
            path.unlink()
            index = self._read_index()
            removed = index["artifacts"].pop(safe_id, None)
            self._write_index(index)
            return {"id": safe_id, "removed": removed is not None}


_default_store: Optional[HtmlArtifactStore] = None
_default_store_lock = threading.Lock()


def get_html_artifact_store() -> HtmlArtifactStore:
    global _default_store
    with _default_store_lock:
        if _default_store is None or _default_store.root != (Path.cwd() / ".spore" / "html").resolve():
            _default_store = HtmlArtifactStore()
        return _default_store
