import json

import pytest
from fastapi import HTTPException

from base.html_artifacts import (
    HtmlArtifactStore,
    has_dynamic_target,
    stamp_artifact_id,
    validate_artifact_id,
    validate_dynamic_target,
    validate_html,
)
from desktop_app.backend.routes.files import list_directory, validate_path


VALID_HTML = """<!doctype html>
<html><head><style>body { color: #222; }</style></head>
<body><button id="run">Run</button><script>document.querySelector('#run')</script></body></html>
"""


def test_artifact_lifecycle_and_index_sync(tmp_path):
    store = HtmlArtifactStore(tmp_path / ".spore" / "html")

    saved = store.save(
        "market-report",
        VALID_HTML,
        title="Market report",
        semantic_label="interactive-report",
        conversation_id="session-1",
    )
    assert saved["artifact"]["id"] == "market-report"
    assert saved["artifact"]["valid"] is True
    stored_content = store.load("market-report")["content"]
    assert 'data-spore-artifact-id="market-report"' in stored_content
    assert [item["id"] for item in store.list()] == ["market-report"]

    index = json.loads(store.index_path.read_text(encoding="utf-8"))
    assert index["version"] == 1
    assert index["artifacts"]["market-report"]["conversation_id"] == "session-1"

    artifact_path = store.root / "market-report.html"
    artifact_path.write_text(VALID_HTML.replace("Run", "Updated"), encoding="utf-8")
    assert store.list()[0]["sha256"] != saved["artifact"]["sha256"]

    removed = store.remove("market-report")
    assert removed == {"id": "market-report", "removed": True}
    assert store.list() == []


def test_validation_blocks_network_and_embedded_documents(tmp_path):
    unsafe = '<html><body><iframe src="https://example.com"></iframe><script>fetch("/x")</script></body></html>'
    validation = validate_html(unsafe)
    assert validation["valid"] is False
    assert {item["code"] for item in validation["errors"]} == {
        "embedded_frame",
        "network_api",
        "incomplete_document",
    }

    store = HtmlArtifactStore(tmp_path / "html")
    with pytest.raises(ValueError, match="failed safety validation"):
        store.save("unsafe", unsafe)


def test_validation_requires_complete_document():
    validation = validate_html("<body><p>fragment</p></body>")
    assert validation["valid"] is False
    assert {item["code"] for item in validation["errors"]} == {"incomplete_document"}


def test_dynamic_target_detection_and_artifact_identity():
    content = stamp_artifact_id(VALID_HTML, "market-report")
    content = content.replace("<button", '<button data-spore-view="packet-timeline"')

    assert 'data-spore-artifact-id="market-report"' in content
    assert has_dynamic_target(content, "packet-timeline") is True
    assert has_dynamic_target(content, "missing-view") is False
    with pytest.raises(ValueError):
        validate_dynamic_target("../escape")


def test_html_virtual_root_does_not_expose_other_spore_data(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    expected = (tmp_path / ".spore" / "html" / "demo.html").resolve()
    assert validate_path("html/demo.html").resolve() == expected

    with pytest.raises(HTTPException) as exc_info:
        validate_path(".spore/security_audit.jsonl")
    assert exc_info.value.status_code == 403


def test_html_virtual_root_is_created_and_hides_managed_index(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    empty_result = list_directory("html")
    html_root = tmp_path / ".spore" / "html"
    assert html_root.is_dir()
    assert empty_result == {"path": "html", "items": []}

    (html_root / "index.json").write_text('{"version": 1, "artifacts": {}}', encoding="utf-8")
    (html_root / "demo.html").write_text(VALID_HTML, encoding="utf-8")
    result = list_directory("html")
    assert [item["name"] for item in result["items"]] == ["demo.html"]


@pytest.mark.parametrize("artifact_id", ["../escape", "UPPER", "space here", "", "a" * 81])
def test_artifact_id_rejects_unsafe_values(artifact_id):
    with pytest.raises(ValueError):
        validate_artifact_id(artifact_id)
