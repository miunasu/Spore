#!/usr/bin/env python3
"""Manage Spore HTML artifacts under .spore/html."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
MAX_BYTES = 2 * 1024 * 1024
UNSAFE_PATTERNS = (
    ("external_script", re.compile(r"<script\b[^>]*\bsrc\s*=", re.I)),
    ("external_stylesheet", re.compile(r"<link\b[^>]*\bhref\s*=", re.I)),
    ("embedded_frame", re.compile(r"<(?:iframe|frame|object|embed|portal)\b", re.I)),
    ("base_url", re.compile(r"<base\b", re.I)),
    ("meta_refresh", re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh\b", re.I)),
    ("network_api", re.compile(
        r"\b(?:fetch\s*\(|XMLHttpRequest\b|WebSocket\s*\(|EventSource\s*\(|navigator\.sendBeacon\s*\(|"
        r"window\.open\s*\(|(?:window\.)?location\s*(?:=|\.|\[))",
        re.I,
    )),
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fail(message: str, code: int = 2) -> None:
    print(json.dumps({"success": False, "error": message}, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(code)


def safe_id(value: str) -> str:
    value = (value or "").strip()
    if not ID_PATTERN.fullmatch(value):
        fail("ID must be 1-80 lowercase letters, digits, dots, underscores, or hyphens and start alphanumeric")
    return value


def stamp_artifact_id(content: str, artifact_id: str) -> str:
    artifact_id = safe_id(artifact_id)
    match = re.search(r"<html\b([^>]*)>", content, re.I)
    if not match:
        return content
    attributes = match.group(1)
    identity = re.compile(r"\sdata-spore-artifact-id\s*=\s*(['\"])[^'\"]*\1", re.I)
    if identity.search(attributes):
        attributes = identity.sub(f' data-spore-artifact-id="{artifact_id}"', attributes, count=1)
    else:
        attributes = f' data-spore-artifact-id="{artifact_id}"' + attributes
    return content[:match.start()] + f"<html{attributes}>" + content[match.end():]


def validate(content: str) -> Dict[str, Any]:
    encoded = content.encode("utf-8")
    errors = []
    warnings = []
    if not content.strip():
        errors.append({"code": "empty", "message": "HTML content is empty"})
    if len(encoded) > MAX_BYTES:
        errors.append({"code": "too_large", "message": f"HTML exceeds {MAX_BYTES} bytes"})
    if content.strip() and not re.match(
        r"^\s*<!doctype\s+html\b[\s\S]*<html\b[\s\S]*<body\b[\s\S]*</body\s*>[\s\S]*</html\s*>\s*$",
        content,
        re.I,
    ):
        errors.append({"code": "incomplete_document", "message": "HTML must be one complete doctype/html/body document"})
    for name, pattern in UNSAFE_PATTERNS:
        if pattern.search(content):
            errors.append({"code": name, "message": f"Blocked HTML capability: {name}"})
    return {
        "valid": not errors,
        "size": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "errors": errors,
        "warnings": warnings,
    }


class Store:
    def __init__(self, project_root: Path):
        self.root = project_root.resolve() / ".spore" / "html"
        self.index = self.root / "index.json"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, artifact_id: str) -> Path:
        path = (self.root / f"{safe_id(artifact_id)}.html").resolve()
        try:
            path.relative_to(self.root.resolve())
        except ValueError:
            fail("Artifact path escaped .spore/html")
        return path

    def read_index(self) -> Dict[str, Any]:
        self.ensure()
        try:
            data = json.loads(self.index.read_text(encoding="utf-8"))
            if isinstance(data.get("artifacts"), dict):
                return {"version": 1, "artifacts": data["artifacts"]}
        except (FileNotFoundError, OSError, json.JSONDecodeError, AttributeError):
            pass
        return {"version": 1, "artifacts": {}}

    @staticmethod
    def atomic_write(path: Path, content: str) -> None:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)

    def write_index(self, index: Dict[str, Any]) -> None:
        self.atomic_write(self.index, json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n")

    def sync(self) -> Dict[str, Any]:
        index = self.read_index()
        previous = index["artifacts"]
        artifacts = {}
        for path in sorted(self.root.glob("*.html"), key=lambda item: item.name.lower()):
            if not ID_PATTERN.fullmatch(path.stem):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            check = validate(content)
            old = previous.get(path.stem, {})
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
            artifacts[path.stem] = {
                "id": path.stem,
                "file": path.name,
                "title": old.get("title") or path.stem,
                "semantic_label": old.get("semantic_label") or "",
                "conversation_id": old.get("conversation_id"),
                "created_at": old.get("created_at") or modified,
                "updated_at": modified,
                "size": check["size"],
                "sha256": check["sha256"],
                "valid": check["valid"],
            }
        synced = {"version": 1, "artifacts": artifacts}
        if synced != index:
            self.write_index(synced)
        return synced

    def load(self, artifact_id: str) -> Dict[str, Any]:
        path = self.path(artifact_id)
        if not path.is_file():
            fail(f"HTML artifact not found: {artifact_id}", 1)
        index = self.sync()
        return {"artifact": index["artifacts"][safe_id(artifact_id)], "content": path.read_text(encoding="utf-8")}

    def save(self, artifact_id: str, content: str, args) -> Dict[str, Any]:
        content = stamp_artifact_id(content, artifact_id)
        check = validate(content)
        if not check["valid"]:
            fail("HTML failed validation: " + ", ".join(item["code"] for item in check["errors"]), 1)
        artifact_id = safe_id(artifact_id)
        self.ensure()
        path = self.path(artifact_id)
        index = self.read_index()
        old = index["artifacts"].get(artifact_id, {})
        timestamp = now()
        self.atomic_write(path, content)
        metadata = {
            "id": artifact_id,
            "file": path.name,
            "title": args.title or old.get("title") or artifact_id,
            "semantic_label": args.label or old.get("semantic_label") or "",
            "conversation_id": args.conversation_id or old.get("conversation_id"),
            "created_at": old.get("created_at") or timestamp,
            "updated_at": timestamp,
            "size": check["size"],
            "sha256": check["sha256"],
            "valid": True,
        }
        index["artifacts"][artifact_id] = metadata
        self.write_index(index)
        return {"success": True, "artifact": metadata, "validation": check, "content": content}

    def remove(self, artifact_id: str) -> Dict[str, Any]:
        artifact_id = safe_id(artifact_id)
        path = self.path(artifact_id)
        if not path.is_file():
            fail(f"HTML artifact not found: {artifact_id}", 1)
        path.unlink()
        index = self.read_index()
        index["artifacts"].pop(artifact_id, None)
        self.write_index(index)
        return {"success": True, "id": artifact_id, "removed": True}


def read_input(args) -> str:
    if getattr(args, "stdin", False):
        return sys.stdin.read()
    if getattr(args, "file", None):
        return Path(args.file).read_text(encoding="utf-8")
    fail("Provide --file or --stdin")
    return ""


def command_generate(args) -> None:
    payload: Dict[str, Any] = {
        "id": safe_id(args.id),
        "description": args.description,
        "semantic_label": args.label,
        "title": args.title,
        "conversation_id": args.conversation_id,
        "force": args.force,
    }
    if args.data_file:
        payload["data"] = json.loads(Path(args.data_file).read_text(encoding="utf-8"))
    port = args.port or int(os.getenv("DESKTOP_API_PORT", "8765"))
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/html/generate",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            print(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        fail(f"Frontend Agent API returned {exc.code}: {exc.read().decode('utf-8', errors='replace')}", 1)
    except urllib.error.URLError as exc:
        fail(f"Cannot reach Spore frontend Agent API on port {port}: {exc.reason}", 1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Spore working directory (default: current directory)")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List all HTML artifacts")
    list_parser.add_argument("--json", action="store_true")

    load_parser = sub.add_parser("load", help="Load complete HTML by ID")
    load_parser.add_argument("id")
    load_parser.add_argument("--json", action="store_true", help="Include metadata in JSON")

    save_parser = sub.add_parser("save", help="Create or update an HTML artifact")
    save_parser.add_argument("id")
    source = save_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file")
    source.add_argument("--stdin", action="store_true")
    save_parser.add_argument("--title")
    save_parser.add_argument("--label")
    save_parser.add_argument("--conversation-id")

    validate_parser = sub.add_parser("validate", help="Validate existing or supplied HTML")
    validate_parser.add_argument("id", nargs="?")
    validate_source = validate_parser.add_mutually_exclusive_group()
    validate_source.add_argument("--file")
    validate_source.add_argument("--stdin", action="store_true")

    remove_parser = sub.add_parser("remove", help="Remove an HTML artifact")
    remove_parser.add_argument("id")
    remove_parser.add_argument("--yes", action="store_true", help="Confirm permanent deletion")

    generate_parser = sub.add_parser("generate", help="Generate with Spore's frontend AutoAgent")
    generate_parser.add_argument("id")
    generate_parser.add_argument("--description", required=True)
    generate_parser.add_argument("--label", default="interactive-html")
    generate_parser.add_argument("--title")
    generate_parser.add_argument("--conversation-id")
    generate_parser.add_argument("--data-file", help="UTF-8 JSON data file")
    generate_parser.add_argument("--force", action="store_true")
    generate_parser.add_argument("--port", type=int)
    generate_parser.add_argument("--timeout", type=int, default=600)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    store = Store(Path(args.root))

    if args.command == "list":
        artifacts = sorted(store.sync()["artifacts"].values(), key=lambda item: item["updated_at"], reverse=True)
        if args.json:
            print(json.dumps({"success": True, "artifacts": artifacts}, ensure_ascii=False, indent=2))
        elif not artifacts:
            print("No HTML artifacts")
        else:
            print("ID\tLABEL\tUPDATED\tSIZE")
            for item in artifacts:
                print(f"{item['id']}\t{item['semantic_label']}\t{item['updated_at']}\t{item['size']}")
    elif args.command == "load":
        result = store.load(args.id)
        print(json.dumps({"success": True, **result}, ensure_ascii=False, indent=2) if args.json else result["content"])
    elif args.command == "save":
        print(json.dumps(store.save(args.id, read_input(args), args), ensure_ascii=False, indent=2))
    elif args.command == "validate":
        if args.file or args.stdin:
            content = read_input(args)
        elif args.id:
            content = store.load(args.id)["content"]
        else:
            fail("Provide an artifact ID, --file, or --stdin")
        result = validate(content)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not result["valid"]:
            raise SystemExit(1)
    elif args.command == "remove":
        if not args.yes:
            fail("Refusing to remove without --yes")
        print(json.dumps(store.remove(args.id), ensure_ascii=False, indent=2))
    elif args.command == "generate":
        command_generate(args)


if __name__ == "__main__":
    main()
