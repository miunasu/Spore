# Frontend User Guide (v4.0)

> [中文](../FRONTEND.md)

This document introduces the features of each panel in the Spore desktop frontend. Frontend tech stack: React + TypeScript + Zustand + Tailwind + Tauri 1.x (borderless window + Mica effect).

> Panels can be resized by dragging; the editor supports saving with `Ctrl + S`.

---

## Overall Layout

| Area | Function |
|------|------|
| Title bar | Window controls, Mini mode, always-on-top, language switch (中/EN), theme switch |
| Left column | Log system (system / general / frontend) |
| Center column | Conversation tabs, mode, history, send/interrupt, TODO, confirmation, security prompts |
| Right column | File management, subsystem switching, agent monitor, Notes |

Backend: FastAPI (default `127.0.0.1:8765`) + a separate WebSocket push process (`8766`).  
Each session has an independent `ConversationLoop` instance; **tasks are driven by the backend**—after submitting, the task keeps progressing in the background even if you switch tabs or minimize the window; the frontend only renders the event stream and automatically restores state after reconnecting.

---

## Title Bar

- **Mini mode**: switch to the floating mini window (see below)
- **Always on top**: keep the window in front
- **中/EN**: switch the UI language (Chinese/English) and sync the backend `SYSTEM_LANGUAGE` (affects the language of auxiliary output such as command intent explanations and remediation suggestions)
- **Theme**: dark / light
- Drag to move, double-click to maximize (borderless custom title bar)

---

## Left Column - Log System

From top to bottom, it may include:

- **system**: System / validation errors
- **general**: Summaries of main-agent actions and tool executions (e.g., `Tool executed successfully`)
- **frontend**: The frontend's own logs (global, not isolated per session)

Backend logs (system / general) are **filtered by the current conversation session**; WebSocket routing uses `conversation_id`.

![Left column overview](../../img/Left.png)

### Viewing Details

Click a log entry to expand and view JSON details such as tool-call errors:

![Error details](../../img/ToolError.png)

### Fullscreen

Double-click a log area to make it fill the left column; double-click again to restore:

![Fullscreen display](../../img/LeftFull.png)

---

## Right Column - Files and Monitoring

### Switching Subsystems

Drag the slider to switch views: **Notes (note) / output / Agent monitor / prompt / skills / characters / history**.

![Subsystem switching](../../img/RightSystem.png)

### File Operations

- Create file / folder, rename, delete, open containing location
- Cut / copy / paste **interoperate with Windows Explorer** (native clipboard, implemented via Tauri)
- Accessible scope is the sandbox directories: `output` / `skills` / `prompt` / `history` / `characters` plus the root-level `note.txt` and `.env` (`prompt/skills/characters` are read-only)

![File operations](../../img/RightFile.png)

### Opening and Editing

- **Double-click a text file**: edit it as a tab in the center column
- **Double-click a folder**: enter the directory
- You can drag a file into the center editing area

### Agent Monitor (v4.0)

The "agents" page shows running sub-agents in real time (up to 5 panels): scrolling logs, JSON pretty-printing with syntax highlighting, and per-agent auto-scroll. Data comes from the WebSocket `agent_register/output/status` events.

### Notes (v4.0)

The "note" page edits the root-level `note.txt`; save with `Ctrl+S`, with an unsaved-changes indicator.

---

## Center Column - Conversation and Operations

### Header Area: Mode and Session

- **Mode dropdown**: `strong_context` / `long_context` / `auto` (with icons, applies to the current session)
- **Plus sign**: create a new session (browser-style tabs, can be mixed with file-editor tabs)
- **Clock**: history conversation list (`history/`, supports rename/delete/load)
- Token usage statistics refresh in real time along with the conversation

![Mode selection](../../img/MiddleMode.png)

![History conversations](../../img/MiddleHistory.png)

### Conversation Area

- Displays user and agent messages; during task execution, rounds are streamed as they happen (`round_reply` / tool calls / tool results)
- "View details" expands the underlying ACTION / RESULT and the raw messages sent to the LLM
- Command intent footnotes: the security agent (full mode) generates a one-sentence "what it wants to do" explanation for each shell command, attached under the corresponding message

![Conversation details](../../img/MiddleConversation.png)

Buttons for hiding the left and right columns can appear near the center-column edges:

![Hide buttons](../../img/MiddleHide.png)

Drag a file from the right column into the center to edit:

![Drag to edit](../../img/MiddleEdit.png)

### TODO Bar (v4.0)

Agent-declared TODOs are pushed via WebSocket and shown as a collapsible per-session progress bar (`✓/✗/○` + completion percentage).

### Send Bar

- **Options menu (⋮)**: settings, characters, intercept toggle, save mode, backup/rollback, etc. (see below)
- **Send**: Enter or the button (IME-safe, Shift+Enter for a new line)
- **Interrupt**: Stop the current session's response and its sub-agents (available only while a task is in progress)

![Options menu](../../img/MiddleOption.png)

### Agent Activity Bar (v4.0)

A non-blocking status bar above the send bar that shows security-agent activity in real time (contents depend on the security mode):

- 💡 Command intent explanation (`full` mode)
- 🚨 Malicious command alert (`full` mode)
- 🛡️ High-risk command risk scan in progress (`basic` mode)
- ⚡ Whitelist auto-pass (`basic` mode)

### Confirmation Bar and Security Modal (v4.0)

- **Confirmation bar (ConfirmBar)**: blocking confirmations for file deletion/overwrite; in `basic` security mode, high-risk command confirmations also appear here (in the default `full` mode commands never prompt — everything goes through async adjudication); multiple requests are queued
- **Security remediation modal (SecurityRemediationModal)**: when the security agent judges a command **malicious**, it circuit-breaks the current session (automatic interrupt + sub-agent termination); the modal shows the verdict rationale and remediation suggestions, with two options:
  - **Handle manually**: record the suggestions into the session and execute them yourself
  - **Auto-fix**: open a new session that automatically executes the remediation task per `auto_fix_prompt`

### Save Mode (savemode)

Reduces tokens: compresses multi-step intermediate steps, favoring the retention of user messages and the final response. Same concept as the CLI command `savemode`.

---

## Mini Mode (v4.0)

Click the Mini button in the title bar to enter a floating mini window (about 380×520, auto always-on-top, restores the original window geometry on exit):

- Shows the two most recent agent replies and live sub-agent activity
- Command intent footnotes are shown as usual
- The input bar appears on hover/focus, allowing you to send new tasks directly
- Perfect for parking Spore in a corner of the screen as a "background assistant"

---

## Settings (Options Menu ⋮)

### General

- Theme (dark / light)
- Character list / select / remove (same source as the CLI `char` command)
- Local preferences such as automatically cleaning up short logs at startup

### Environment Configuration

Reads and writes the `.env` in the working directory (the same set of variables as in [CONFIGURATION.md](CONFIGURATION.md)), and supports configuration profiles.

| Area | Description |
|------|------|
| **API configuration set** | Top: save / apply / delete profiles by the current SDK (`base/config_profiles.py`); switch the entire Key/URL/model set for the main agent and sub-agents with one click |
| **Basic configuration** | Always expanded; the minimal usable list: `LLM_SDK` + the Key / URL / model of the current SDK |
| **Advanced configuration** | Collapsed by default; Responses/Thinking, sub-agent and auxiliary-agent tiers, timeouts, logs, paths, security and intercept toggles, etc. |

Actions:

- **Open .env**: Open the file with the system-associated program
- **Save configuration**: Write back to `.env` and hot-apply (`/api/settings/env/apply`: reloads config, restarts the Chat process; items that can be hot-updated take effect immediately, otherwise a restart is required)

### Tool Policy (v4.0)

The "Tools" page visually toggles every tool and even **sub-tools** (e.g., allow only `file.read` while blocking `file.delete`; disable certain sub-agents by type):

- Scope can be **current session** or **global** (global is persisted to `tool_policy.json`)
- Disabled tools are hidden from the system prompt and intercepted again at runtime
- Supports one-click reset to the mode defaults

### Backup / Rollback (v4.0)

Two tabs:

- **Checkpoints**: lists the conversation points of the current session, with one-click `rewind` (files + conversation history + TODOs restored together; refused with a prompt while a task is generating)
- **File history**: view the version list of any file modified by the agent and restore it to a specific version

### Command Interception

The send-bar options menu offers a quick toggle for `COMMAND_INTERCEPT` (intercepts shell delete/file-write commands).

---

## Development Tips

```bash
cd desktop_app/frontend
npm install
npm run dev          # Vite http://localhost:1420
npm run tauri dev    # Debug with the shell (auto-launches the Python backend via uv)
```

- State management: `src/stores/*` (chat / editor / agent / todo / confirm / security / log / file / settings / miniMode / drag)
- API wrappers: `src/services/api.ts`; WebSocket: `src/services/websocket.ts` (batched events, 30s ping, exponential-backoff reconnection, snapshot restore after reconnecting)
- Internationalization: `src/i18n/` (Chinese/English, organized by component namespaces; `useT()` for reactive lookups, language persisted in `localStorage`)

For more on the architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).
