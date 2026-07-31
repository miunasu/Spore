from base.html_artifacts import HtmlArtifactStore
from base.config import Config
from AutoAgent import frontend_agent


HTML_V1 = "<!doctype html><html><body><button>Run</button></body></html>"
HTML_V2 = "<!doctype html><html><body><main><button aria-label=\"Run\">Run</button></main></body></html>"


class _Config:
    frontend_agent_timeout = 60
    frontend_agent_max_iterations = 3

    def resolve_agent_llm(self, profile):
        assert profile == "frontend"
        return {"model": "frontend-model"}


class _IPC:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def send_chat_request(self, **kwargs):
        self.requests.append(kwargs)
        return f"request-{len(self.requests)}"

    def get_chat_response(self, request_id, timeout):
        return {"status": "success", "data": {"content": self.replies.pop(0)}}


def test_extract_html_response_supports_fences_and_wrapped_documents():
    assert frontend_agent.extract_html_response(f"```html\n{HTML_V1}\n```") == HTML_V1
    assert frontend_agent.extract_html_response(f"Here it is:\n{HTML_V1}\nDone") == HTML_V1
    assert frontend_agent.extract_html_response("No HTML") is None


def test_generate_html_reviews_and_persists(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    ipc = _IPC([HTML_V1, HTML_V2])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.generate_html(
        "demo-tool",
        "A small interactive tool",
        semantic_label="tool",
        title="Demo tool",
        conversation_id="session-1",
    )

    assert result["generated"] is True
    assert result["reviewed"] is True
    assert result["iterations"] == 2
    assert '<html data-spore-artifact-id="demo-tool">' in store.load("demo-tool")["content"]
    assert [request["agent_profile"] for request in ipc.requests] == ["frontend", "frontend"]
    assert all(request["model"] == "frontend-model" for request in ipc.requests)


def test_frontend_profile_overrides_sub_agent_model(monkeypatch):
    monkeypatch.setenv("LLM_SDK", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "main-model")
    monkeypatch.setenv("SUB_AGENT_OPENAI_MODEL", "sub-model")
    monkeypatch.setenv("AGENT_FRONTEND_OPENAI_MODEL", "frontend-model")

    resolved = Config().resolve_agent_llm("frontend")
    assert resolved["sdk"] == "openai"
    assert resolved["model"] == "frontend-model"


def test_expand_html_materializes_missing_target(monkeypatch, tmp_path):
    store = HtmlArtifactStore(tmp_path / "html")
    store.save("demo-tool", HTML_V1)
    expanded = (
        '<!doctype html><html><body><button data-spore-target="details">Open</button>'
        '<section id="details">Generated details</section></body></html>'
    )
    ipc = _IPC([expanded])
    monkeypatch.setattr(frontend_agent, "_ipc_manager", ipc)
    monkeypatch.setattr(frontend_agent, "get_config", lambda: _Config())
    monkeypatch.setattr(frontend_agent, "load_system_prompt", lambda _: "frontend prompt")
    monkeypatch.setattr(frontend_agent, "get_html_artifact_store", lambda: store)

    result = frontend_agent.expand_html(
        "demo-tool",
        "details",
        "Generate the detailed view",
        trigger_text="Open",
    )

    assert result["generated"] is True
    assert result["target"] == "details"
    assert 'id="details"' in result["content"]
    assert len(ipc.requests) == 1

    existing = frontend_agent.expand_html("demo-tool", "details", "Generate it again")
    assert existing["generated"] is False
    assert len(ipc.requests) == 1
