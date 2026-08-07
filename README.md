<div align="center">
  <img src="desktop_app/frontend/src-tauri/icons/icon_master.png" alt="Spore" width="100" height="100">

# Spore AI Agent

AI agent for Windows. Runs on your machine, touches your real files and system, and lets you stop or undo anything it does.

[Download](https://github.com/miunasu/Spore/releases) · [中文](README_zh.md) · <a href="changelog/spore-4-1-release-celebration.html" target="_blank">🎉 4.1 Release Celebration</a> · [Configuration](docs/en/CONFIGURATION.md) · [Frontend Guide](docs/en/FRONTEND.md) · [CLI Mode](docs/en/CLI.md) · [Build Guide](docs/en/BUILD.md)

</div>

---

![Spore main window](img/Spore.png)

---

Give it a task in plain text. It reads files, runs PowerShell, searches the web, edits documents. The left panel shows every step in plain language as it goes. Stop anytime. Roll back any file change from the backup panel.

Not sandboxed to a single folder — it works on the whole machine.

---

## Works for everyone, scales for power users

Every command the AI runs comes with a plain-language note in the chat — not the command itself, but what it's doing. No technical knowledge needed, no idea what PowerShell is required. Suspicious actions pause for your call; actually dangerous ones are handled automatically. You never need to look anything up or troubleshoot manually.

For users who want to go deeper: full logs in the left panel, expandable raw LLM output in the center, file backup history down to every individual write, and fine-grained per-tool permission policies. Zero barrier to get started, no ceiling for power users.

---

## Full transparency

The left panel logs every action in real time. In the center chat, expand any AI reply to see the complete raw LLM output — which tools it called, what they returned. No black box. Check anything, anytime.

![](img/OutPutDetail.png)

---

## Interface

Three panels: logs on the left, chat in the center, file system on the right. All settings have a GUI — model selection, API keys, tool permissions, security policy — click through everything without touching a config file.

The file manager is built right into the right panel. Browse and edit AI-generated files, project components, and reports without switching windows. The built-in notes editor supports Markdown. The TODO bar updates live with the task. One window handles everything.

---

## Security

Spore repeatedly instructs the LLM in its system prompt not to harm the host — that's the first line of defense.  
But LLMs can still make mistakes, so Spore doesn't rely on the model's self-restraint. The execution layer handles it: a background security agent monitors every command automatically. Normal commands pass with a one-line note. Suspicious ones pause and ask. Malicious ones are circuit-broken immediately — session interrupted, impact summarized, one-click auto-fix offered.  
And if the LLM somehow does cause damage, the file backup system can restore everything to exactly how it was before.

No manual monitoring needed. When something goes wrong, the system handles it and tells you what happened.

![](img/SecAgentFuse.png)

---

## File backup

Every file the AI touches is backed up automatically in real time, with a version for every individual write. The backup panel shows the full change history for any file — click to restore any version. "Rewind to checkpoint" goes further: if a whole phase went wrong, file changes, conversation history, and TODO state all roll back together to before it happened. Both humans and agents can operate freely, knowing there's always a way back.

![](img/FileBackUp.png)

---

## Mini mode and edge snap

![](img/MiniHide.png)

One click shrinks it to a 380×520 always-on-top panel. Drag it to a screen edge and it hides except for a thin strip; hover the edge to bring it back. Keep half an eye on a running task while working in another app.

---

## HTML artifacts and human-AI collaboration

After the main agent generates an HTML page, drag it into the center panel — the frontend agent starts monitoring your interactions in real time. It understands what you click, what text you select, what you fill in, and can expand or modify the HTML directly once you give the go-ahead.

This works especially well for learning: have the agent generate an explanation page, then click whatever you don't understand and tell the frontend agent to elaborate, add examples, or add exercises. Every interaction builds on the previous one. The page grows into an infinitely expandable knowledge base organized around your own thinking.

![](img/FrontendAgent.png)

---

## Multiple sessions

Each tab is fully independent. Run a slow task in one, open another for a quick question, switch back and forth freely — tasks keep running in tabs you're not watching. Each tab's main agent can dispatch sub-agents, making it a full agent team.

---

## Getting started

Download the installer from [Releases](https://github.com/miunasu/Spore/releases), run it, open Settings (⚙️ next to the input box), and enter your API key.

![Settings](img/MiddleOption.png)

Works with Anthropic, OpenAI, DeepSeek, and any OpenAI-compatible endpoint. Minimal `.env` for running from source:

```env
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat
LAUNCH_MODE=desktop
```

```bash
uv sync && uv run python main_entry.py
```

---

## CLI

```bash
uv run python main.py
```

Same capability from a terminal, no GUI needed. See [CLI docs](docs/en/CLI.md).

---

## Build

Windows 10/11 x64. Needs Python 3.10+, uv, Node 18/20 LTS, Rust, VS C++ Build Tools.

```
build_installer.bat
```

Full steps in the [Build Guide](docs/en/BUILD.md).

---

## Model recommendations

The main agent needs a capable model with solid instruction-following (Claude Opus, GPT-4o, DeepSeek-V3, etc.).

The frontend agent and security agent don't need high-intelligence models — fast, cheap models work fine (DeepSeek-V3-flash, Haiku, etc.). **Strongly recommend disabling thinking mode for both** — their job is fast response, and thinking mode only adds latency and cost with no real benefit. Each agent type can be configured with its own model in Settings.
> The AutoAgent system uses a lightweight short-context design, so token consumption is minimal.

---

AGPL-3.0. Commercial licensing: miunasu@foxmail.com
