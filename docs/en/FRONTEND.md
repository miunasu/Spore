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

Backend: FastAPI plus a separate WebSocket push process. The REST endpoint defaults to `127.0.0.1:8765`, and the desktop shell reads `DESKTOP_API_PORT` dynamically at startup; the current frontend WebSocket URL is fixed at `ws://127.0.0.1:8766`.

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
- Cut / copy / paste in the file manager actually copies or moves files and **interoperates with Windows Explorer** through the native file clipboard implemented by Tauri
- Pasting files copied in Windows Explorer into the chat input only extracts their real paths and sends them as path attachments with the message; it does not copy them into the workspace, upload them, or read their contents
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

Command intent and malicious-command judgments are now attached directly below the corresponding assistant message; the send area no longer mounts the old `AgentActivityBar`. Mini mode shows the same footnotes inside its message cards.

### Confirmation Bar and Security Modal (v4.0)

- **Confirmation bar (ConfirmBar)**: blocking confirmations for file deletion/overwrite; in `basic` security mode, high-risk command confirmations also appear here (in the default `full` mode commands never prompt — everything goes through async adjudication); multiple requests are queued
- **Security remediation modal (SecurityRemediationModal)**: when the security agent judges a command **malicious**, it circuit-breaks the current session (automatic interrupt + sub-agent termination); the modal shows the verdict rationale and remediation suggestions, with two options:
  - **Handle manually**: record the suggestions into the session and execute them yourself
  - **Auto-fix**: open a new session that automatically executes the remediation task per `auto_fix_prompt`

### Save Mode (savemode)

Reduces tokens: compresses multi-step intermediate steps, favoring the retention of user messages and the final response. Same concept as the CLI command `savemode`.

---

## Mini Mode (v4.0)

Click the Mini button in the title bar to enter a floating mini window (about 380×520, automatically always-on-top; exiting restores the previous size, position, maximized state, and always-on-top state):

- `MiniModeView` shows the current session's two most recent assistant replies; if an older message carries the latest command intent, that message is also pinned into view
- Shows every sub-agent's current status and latest log in real time; terminal entries are removed later by the store timer
- Command intent and malicious-command reasons remain attached to the corresponding message card
- The input appears when the bottom hot zone is hovered, the input has focus, or a confirmation is pending; it uses the same `InputArea` as normal mode, including send, interrupt, confirmation handling, and pasted path attachments
- **Windows only** supports four-edge snapping. The toggle is enabled by default and can be switched off in the Mini title bar; dragging to the left, right, top, or bottom screen edge auto-hides the window, and moving the pointer to that edge reveals it
- Non-Windows platforms do not provide native four-edge snapping or auto-hide

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

- **Checkpoints**: lists the checkpoint kinds already created for the current session: `user_message` (created after adding user input in the CLI and direct `/api/chat/send` paths; the current desktop `/api/task/submit` main path does not create it) and `action` (created when an LLM reply first changes a file); one-click `rewind` restores files, truncates that session's conversation history, and clears TODOs (it is rejected with a prompt while that session is generating)
- **File history**: lists only files and versions tracked by the current session; a restore is itself recorded as a new version
- **Shared-file risk**: session backup metadata, checkpoints, and automatic short-term memory are isolated, but all sessions still operate on the same physical workspace files; when sessions modify the same path concurrently, restoring an old version can overwrite another session's result

### Session Backups and History

Each session's short-term memory is automatically overwritten at `history/autosave/session_<session_id>.mem`, and these autosaves can be loaded from the history panel; by default, roughly the 10 most recent sessions are retained. When short-term memory is evicted or manually deleted, the corresponding conversation checkpoints are also removed. Manually saved `history/*.mem` files are displayed separately from automatic session backups.

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
