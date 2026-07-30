# Spore AI Agent Architecture (v4.0)

> [中文](../ARCHITECTURE.md)

This document describes the actual code architecture of **Spore 4.0**. The entry point, conversation loop, text protocol, multi-session desktop backend, tool system, and the v4.0 additions — Security Agent / tool policy / backup & rollback — all reflect the current repository.

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User Interface Layer                         │
├─────────────────────────────────┬───────────────────────────────────┤
│        GUI Mode (Tauri)         │        CLI Mode (Terminal)        │
│  React + TypeScript + Zustand   │  Command-line interface           │
│  - Multi-tab multi-session chat │  - CLICommandHandler              │
│  - File mgmt / Mini mode / i18n │  - Separate log-monitor terminal  │
│  - Logs/TODO/confirm/security UI│  - Direct stdin conversation loop │
│  - WebSocket events (task_event)│                                   │
└─────────────┬───────────────────┴──────────────┬────────────────────┘
              │ HTTP :8765 + WS :8766            │ In-process call
┌─────────────┴──────────────────────────────────┴────────────────────┐
│                  Application Entry (main_entry.py)                  │
│  LAUNCH_MODE=cli|desktop → main.py | desktop_app.backend.server     │
│  Packaged env: resource_manager fixes cwd and resource paths        │
└─────────────┬──────────────────────────────────┬────────────────────┘
              │                                  │
    ┌─────────┴─────────┐              ┌─────────┴──────────┐
    │ Desktop Backend   │              │ CLI Main Loop      │
    │ FastAPI + WS proc │              │ ConversationLoop   │
    │ Self-driven tasks │              └─────────┬──────────┘
    └─────────┬─────────┘                        │
┌─────────────┴──────────────────────────────────┴────────────────────┐
│                        Business Logic Layer                         │
│  ConversationLoop (text-protocol driven)                            │
│  ├─ ConversationState / MultiSessionManager                         │
│  ├─ ProtocolManager + ActionParser                                  │
│  ├─ Tools + ToolPolicy (session/global filtering + runtime guard)   │
│  ├─ SecurityGuard (interception / risk assessment / circuit break)  │
│  ├─ BackupManager (session-scoped files + user/action checkpoints)  │
│  ├─ Learning (episodic retrieval/record, optional degrade)          │
│  ├─ ModeSelector / CharacterManager / TodoManager / RuleReminder    │
│  └─ multi_agent_dispatch → AgentProcessManager / SubAgentThread     │
└─────────────┬───────────────────────────────────────────────────────┘
              │ multiprocessing Queue IPC
┌─────────────┴───────────────────────────────────────────────────────┐
│  Chat Process (base/chat_process.py)                                │
│  - OpenAI / Anthropic SDK (shared by main, sub, and helper Agents)  │
│  - Per-profile cached clients (supervisor/mode_selector/security)   │
│  - Thread-pool requests (CHAT_MAX_WORKERS), streaming + resp cache  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory and Module Map

```
Spore/
├── main_entry.py              # Unified entry: cli / desktop
├── main.py                    # CLI main loop
├── pyproject.toml             # Python dependencies and version
├── build_installer.bat        # One-click packaging installer (6 stages)
├── spore_backend.spec         # PyInstaller onefile spec
├── tool_policy.json           # Global tool policy (effective when scope=global)
│
├── base/                      # Core runtime
│   ├── config.py              # .env → Config singleton; resolve_agent_llm profile resolution
│   ├── config_profiles.py     # API configuration profiles (.spore_config_profiles.json)
│   ├── client.py              # LLM client factory (incl. CleanHeadersTransport)
│   ├── chat_process.py        # Standalone Chat subprocess (multi-profile client cache)
│   ├── ipc_manager.py         # Main process ↔ Chat process IPC (request matching/cancel)
│   ├── conversation_loop.py   # Main conversation loop (protocol parsing + tool execution + checkpoints)
│   ├── state_manager.py       # ConversationState / MultiSessionManager
│   ├── session_context.py     # ContextVar: conversation_id / task_epoch
│   ├── memory_manager.py      # history/ and autosave persistence
│   ├── cli_commands.py        # CLI commands (incl. rollback/rewind/whitelist)
│   ├── tools.py               # TOOL_DEFINITIONS + handlers
│   ├── tool_policy.py         # Tool policy: mode baseline + sub-tool toggles + two-layer enforcement
│   ├── security_guard.py      # Command security guard: keyword rules/whitelist/audit
│   ├── backup_manager.py      # Backup & rollback: bsdiff4 file versions + conversation checkpoints
│   ├── agent_types.py         # Main Agent tool sets / predefined sub-Agent types
│   ├── agent_process.py       # Multi-Agent dispatch engine (incl. desktop async dispatch)
│   ├── agent_database.py      # Sub-Agent tasks and tool-call records
│   ├── character_manager.py   # Character selection (single character)
│   ├── todo_manager.py        # Declarative TODO (per session)
│   ├── rule_reminder.py       # Periodic rule reminders
│   ├── prompt_loader.py       # prompt / skills / characters assembly
│   ├── interrupt_handler.py   # Interruption and cascading termination
│   ├── event_signal.py        # Event signals
│   ├── logger.py / log_monitor.py / multi_agent_monitor.py
│   ├── text_protocol/         # Text protocol
│   │   ├── protocol_manager.py
│   │   ├── action_parser.py
│   │   ├── result_formatter.py
│   │   └── tool_doc_generator.py
│   └── utils/                 # Tool implementation details
│       ├── system_io.py       # File read/write/edit/delete + desktop confirm hooks
│       ├── shell.py / grep.py / web_browser.py / skills.py ...
│
├── AutoAgent/                 # Helper Agents (call Chat via IPC)
│   ├── mode_selector.py       # Selects strong/long in auto mode
│   ├── supervisor.py          # Loop / termination-decision helper
│   └── security_agent.py      # Security Agent: intent analysis / risk assessment / malicious circuit break
│
├── desktop_app/
│   ├── resource_manager.py    # Packaged-environment initialization
│   ├── backend/
│   │   ├── server.py          # FastAPI main service (:8765)
│   │   ├── standalone.py      # Multi-instance subprocess entry
│   │   ├── core.py            # Reuses CLI initialization logic; hot config reload
│   │   ├── conversation_loop_manager.py  # Independent ConversationLoop per session
│   │   ├── instance_manager.py
│   │   ├── routes/            # chat / task / commands / files / agents /
│   │   │                      # settings / instances / confirm / backup
│   │   └── websocket/         # WS push process (:8766), log bridge, confirm manager,
│   │                          # security circuit-break bridge, sub-Agent notifications
│   └── frontend/              # React + Tauri (incl. src/i18n, Chinese/English bilingual)
│
├── prompt/                    # System and per-Agent prompts
│   ├── prompt.md              # Main Agent system prompt
│   ├── model_prompt.md        # ModeSelector
│   ├── supervisor_prompt.md   # Supervisor
│   ├── security_prompt.md     # Risk assessment (basic+)
│   ├── security_intent_prompt.md      # Intent + malicious analysis (full)
│   ├── security_remediation_prompt.md # Post-circuit-break remediation advice (full)
│   └── <Type>_prompt.md       # Prompts for each sub-Agent type
│
├── skills/                    # Claude Skills-style skill packs
├── characters/                # Character Markdown
├── history/                   # Conversation archives and autosave
├── .spore/                    # Backup data and security audit (generated at runtime)
├── docs/                      # Documentation (this directory; en/ is the English version)
└── example/                   # Example outputs
```

---

## Startup and Runtime Paths

### 1. Unified Entry Point `main_entry.py`

1. `multiprocessing.freeze_support()` (Windows / PyInstaller)
2. If `sys.frozen`: call `desktop_app.resource_manager.initialize_app()`
3. `load_dotenv(.env)`
4. Read `LAUNCH_MODE`:
   - `cli` → `main.main()`
   - `desktop` → `desktop_app.backend.server.run_desktop_app()`

### 2. CLI Path `main.py`

1. Initialize logging / validate configuration
2. `initialize_ipc_system()` starts the Chat subprocess and wires up supervisor / mode_selector / security_agent
3. Create `ConversationState`, register the tool-policy session lookup, `CLICommandHandler`, `ConversationLoop`
4. Resolve the tool set according to `CONTEXT_MODE` and the tool policy, and inject the system prompt via `ProtocolManager.inject_protocol`
5. User input loop: command handling → (optional ModeSelector in auto mode) → LLM request → protocol validation → tool execution

### 3. Desktop Path

1. FastAPI lifespan: `initialize_desktop_backend()` (reuses the main initialization)
2. Start the standalone WebSocket push process: the backend derives its port as REST + 1, while the current React client still uses the fixed address `ws://127.0.0.1:8766`
3. `ConversationLoopManager` maintains an independent `ConversationState` and `SessionConversationLoop` for each session
4. **Backend self-driven task loop**: after the frontend submits a task with `POST /api/task/submit`, the backend automatically advances round by round inside a thread pool until a terminal state; the frontend only consumes the WebSocket `task_event` stream (`task_started / round_reply / tool_call / tool_result / todo_update / task_finished`, plus the asynchronous side-channel events `command_intent / security_malicious / security_remediation`). Closing the frontend page or switching tabs therefore does not affect task execution.

---

## Core Subsystems

### Conversation State

| Component | File | Responsibility |
|------|------|------|
| `ConversationState` | `base/state_manager.py` | Per-session messages, tokens, TODOs, context_mode, interrupt_epoch, session-level tool policy |
| `MultiSessionManager` | Same file | Multi-session creation / switching / deletion (desktop) |
| `session_context` | `base/session_context.py` | ContextVar binding conversation_id / task_source / task_epoch |

Desktop session isolation does not depend on the currently selected UI tab:

- Each session's `SessionConversationLoop` is permanently bound to its own `ConversationState` and owns a separate reentrant execution lock; complete rounds are serialized within one session, while different sessions can run concurrently
- Main LLM request IDs use `{conversation_id}_{uuid}`; IPC matches and logically cancels the exact request ID, while `interrupt_epoch` discards late results after interruption
- `conversation_context` binds logs, TODOs, confirmations, tool policy, and sub-Agent side channels to the requesting session, and `copy_context()` propagates the binding into parallel tools
- Cancellation is application-level logical cancellation and does not guarantee termination of a provider request already sent over the network

### Conversation Loop `ConversationLoop`

- Rebuilds the system prompt every round (dynamic TODOs / directory / character)
- Manages context length and oversized tool results (compression / truncation)
- Sends requests to the Chat process via IPC
- Parses `@SPORE:ACTION_*` and executes tools (single / sequence / parallel)
- Runtime tool-policy interception: even if the model calls a disabled tool or sub-tool, a rejection message is returned as the RESULT
- `execute_command` goes through SecurityGuard first; file writes/deletes hook into BackupManager checkpoints
- Writes back `@SPORE:RESULT` / handles `@SPORE:STOP_REASON=`
- The Supervisor helps decide whether consecutive rounds without an ACTION are stuck in a loop
- Supports interrupt cleanup (epoch validation) and TODO block updates

### Text Protocol `base/text_protocol`

**OpenAI Function Calling is not used**; a uniform, human-readable text protocol is used instead, compatible with OpenAI / Anthropic / third-party compatible interfaces.

Common markers:

```text
@SPORE:ACTION_SINGLE_START
file type=read file_path="C:/demo.txt"
@SPORE:ACTION_SINGLE_END

@SPORE:ACTION_SEQUENCE_START
... sequential multiple tools ...
@SPORE:ACTION_SEQUENCE_END

@SPORE:ACTION_PARALLEL_START
... parallel multiple tools ...
@SPORE:ACTION_PARALLEL_END

@SPORE:RESULT_START
... tool results ...
@SPORE:RESULT_END

@SPORE:STOP_REASON=Task completed
```

Components:

- `ProtocolManager`: protocol injection, response scanning, result / error formatting; hides the parallel / multi-Agent documentation according to the currently available tools
- `ActionParser`: parses the tool name and parameter DSL (including multi-line values via `@SPORE:CONTENT_START/END`)
- `ResultFormatter` / `ToolDocGenerator`: results and tool documentation

> The termination marker is **`STOP_REASON`** (a natural-language termination reason); intermediate replies go inside `@SPORE:REPLY_START/END`. The main Agent's reply language follows the language of the user's message.

### Tool System `base/tools.py` + `base/utils/`

Tools available to the main Agent (definition names):

| Tool | Sub-tools | Description |
|------|--------|------|
| `skill_query` | — | Query `skills/<name>/SKILL.md` |
| `execute_command` | — | PowerShell (EncodedCommand), configurable timeout / working_dir; governed by SecurityGuard |
| `file` | read / write / delete | File read / write / delete |
| `edit` | single / multi / line | Exact replacement / batch / line-based editing |
| `Grep` | — | Built-in ripgrep content search |
| `web_browser` | visit / search | Open a web page or search |
| `multi_agent_dispatch` | Per sub-Agent type | Dispatch sub-Agents (**long_context tool set only**) |
| `check_subagent_status` | — | Query async sub-Agent progress (desktop async dispatch scenario) |

Tool set baselines are defined in `base/agent_types.py`:

- `strong_context`: does not include `multi_agent_dispatch`
- `long_context`: includes `multi_agent_dispatch`
- `auto`: `AutoAgent.mode_selector` decides, then the corresponding tool set is loaded

### Tool Policy (v4.0) `base/tool_policy.py`

On top of the mode baseline, **every tool and even sub-tool** can be toggled individually:

- Granularity: `file.read/write/delete`, `edit.single/multi/line`, `web_browser.visit/search`, `multi_agent_dispatch.<AgentType>`, and every leaf tool
- Scope: `session` (policies stored in each session's `ConversationState.tool_policies`) or `global` (persisted to `tool_policy.json` in the project root), switched via `TOOL_POLICY_SCOPE` or the desktop UI
- Two-layer enforcement:
  1. **Prompt filtering**: `filter_tool_definitions` removes disabled items from the tool documentation and parameter enums, so the model never sees them
  2. **Runtime guard**: `check_action_allowed` validates again before execution; on rejection, an explanatory message is returned as the RESULT
- On the desktop, edit visually in the "Tools" page of the settings (`/api/settings/tools/*`)

### Multi-Agent

- `AgentProcessManager` / `SubAgentThread`: thread-level sub-Agents with independent logging and an optional monitoring terminal, registered per session, epoch-aware interruption
- `AgentDatabase`: tool-call records and task summaries
- Predefined types (prompts dynamically loaded from `prompt/<Type>_prompt.md`): `Coder`, `WebInfoCollector`, `FileContentAnalyzer`, `TextEditor`
- **Dispatch modes**:
  - CLI: synchronous blocking wait, Ctrl+C can cascade-terminate
  - Desktop: **asynchronous dispatch** (fire-and-forget); the main Agent can keep working on other things, the sub-Agent's completion is injected back into the conversation as a `[系统通知]` (system notification), and `check_subagent_status` can be used to query progress in the meantime

### Helper Agents `AutoAgent/`

| Module | Profile | Purpose |
|------|------|------|
| `mode_selector` | `mode_selector` | Selects strong/long from the user input when `CONTEXT_MODE=auto` |
| `supervisor` | `supervisor` | Decides whether a turn has ended / is repeating (YES/NO) |
| `security_agent` | `security` | Command intent analysis, risk assessment, malicious circuit break, and remediation advice (see next section) |

All three go through the Chat process via IPC, and can each be given **an independent model** via `AGENT_SUPERVISOR_*` / `AGENT_MODE_SELECTOR_*` / `AGENT_SECURITY_*` (fallback chain: profile-specific → `SUB_AGENT_*` → main configuration); see `Config.resolve_agent_llm`.

### Security System (v4.0)

Two parts: **static command interception** (always available) and **security-agent adjudication** (strategy selected by `SECURITY_AGENT_MODE`):

1. **Command interception** (static rules): the `COMMAND_INTERCEPT` master switch + `INTERCEPT_SHELL_DELETE` / `INTERCEPT_SHELL_WRITE` directly block shell file delete/write commands and steer the model toward the `file` tool (which has confirmation and backup).
2. **Security-agent adjudication**: `SECURITY_AGENT_MODE` has three levels; `basic` and `full` are **two mutually exclusive strategies** (not stacked):
   - `off`: no adjudication, everything passes
   - `basic` (up-front gatekeeping): `base/security_guard.py` pre-screens with a high-risk keyword rule table (services, HKLM registry, firewall, drivers, disks, Defender, startup items, volume shadow copies, scheduled tasks, execution policy, accounts, ACLs, power, critical processes, etc.); only hits are sent for AI risk assessment (`security_prompt.md`), and the outcome per risk level and `SECURITY_GUARD_MODE` (`strict`/`balanced`/`permissive`) is **auto-allow (low) / quick confirmation (medium) / forced detailed confirmation (high)**; the whitelist `security_whitelist.json` (added via the CLI `whitelist` command / at confirmation time) passes directly; confirmed high-risk operations are recorded in the audit log `.spore/security_audit.jsonl`
   - `full` (default, async out-of-band): **no keyword pre-screening and no confirmation prompts** — every `execute_command` is handed to `AutoAgent/security_agent.py` for asynchronous background adjudication without blocking execution:
     - **Asynchronous intent analysis**: generates a plain-language intent explanation (`command_intent` event, shown as a footnote in the frontend)
     - **Malicious circuit break**: when a command is judged malicious, it writes the audit record, **interrupts the current session** (epoch bump + sub-Agent termination), and pushes `security_malicious`
     - **Remediation advice**: after a circuit break, generates `security_remediation` (including `auto_fix_prompt`); the frontend modal offers "handle manually" or "auto-fix" (executed in a new session)
     - **Optional session command context**: `SECURITY_AGENT_SESSION_CONTEXT` is off by default; when enabled, the current command and up to `SECURITY_SESSION_CONTEXT_MAX_COMMANDS` (default 20) recently and successfully adjudicated commands from the same session are sent to the security model
     - Complete command history is held in process memory. Even with context disabled, full mode collects successfully adjudicated commands but does not include prior history in later requests. `clear_session_history()` exists but is not yet connected to the new-conversation, memory-clear, reset, or session-deletion lifecycle; only process exit naturally releases it
3. The user-facing text language follows `SYSTEM_LANGUAGE`.

### Backup and Rollback (v4.0) `base/backup_manager.py`

A two-layer "time machine" whose data is **session-scoped** under `.spore/`:

- **File level (session-isolated)**: files actually changed by `file write/delete` or `edit` through the main `ConversationLoop` are snapshotted (baseline + `bsdiff4` incremental patches); shell-command and direct sub-Agent writes are not guaranteed to be captured
  - Versions: `.spore/backups/<session_id>/<path_hash>/baseline.full` + `vNNNN.patch|full`
  - Metadata: `.spore/metadata/<session_id>_file_history.json`
  - CLI `rollback` / `filehistory` operate on the current session only. The desktop `/api/backup/files*` `conversation_id` is optional; when omitted it resolves to the backend's current session rather than being inferred from a running task, so callers should pass it explicitly
- **Conversation checkpoints (two kinds)**:
  1. `user_message`: created after a user message is queued; wired into CLI and direct `/api/chat/send`, but not yet created by the current desktop `/api/task/submit` main path
  2. `action`: created when an ACTION in an LLM reply first succeeds in recording a file version, allowing rewind to before that reply
  - `rewind [<checkpoint_id>|--turns N]` restores **files + conversation history + TODOs** together
  - Storage: `.spore/checkpoints/<session_id>.json`
- Desktop maps to `/api/backup/*` and the settings "Backup/Rollback" page (checkpoints and file backups are bound to the active session)
- Version chains and metadata are session-isolated, but all sessions still operate on the same physical workspace files. Rollback currently has no cross-session conflict detection; when sessions modify the same path, `rollback`, `rewind`, or file restore can overwrite newer work from another session
- Switches and limits: `BACKUP_ENABLED` / `BACKUP_DIR` / `BACKUP_MAX_FILE_BYTES` / `BACKUP_MAX_DELETE_FILES`

### Learning (episodic memory) `learning/`

- `EpisodeStore` uses SQLite (schema in `learning/schema.sql`), with episodes and embeddings in separate tables; the database is shared across sessions
- `ConversationLoop` / Desktop `SessionConversationLoop` attempt to initialize `EpisodicRetriever`
- Before an LLM request, an embedding is generated for the last user-role message; the latest 100 `general_task` episodes are scored by recency, cosine similarity, and salience, and up to 3 are injected
- When a task successfully ends with `STOP_REASON`, its query, tool calls, and outcome are recorded as a success episode when possible
- Embeddings use an OpenAI-compatible `/v1/embeddings` endpoint. Empty dedicated `EMBEDDING_*` settings fall back to `OPENAI_API_KEY` / `OPENAI_API_URL`; the default model is `text-embedding-3-small`
- Missing embedding configuration, timeout, or API failure is caught by the caller so the main conversation continues. This is not a local embedding or FTS fallback, and an embedding failure while recording skips the entire episode
- **DB path follows runtime root**: default `<runtime_root>/.spore/memory/episodic.db`
  - Override with `LEARNING_DB_PATH` / `EPISODIC_DB_PATH` (relative paths are resolved against the runtime root)
  - Source tree root = parent of `learning/`; packaged build = `Path.cwd()`
- `ConsolidationEngine` provides candidate discovery, pattern extraction, and semantic-knowledge writes, but currently has no startup hook, background thread, timer, or other runtime scheduler; consolidation does not run automatically

### IPC and Chat Process

- `IPCManager`: `multiprocessing` queues + a request-dispatch thread, matches responses by `request_id`, supports logical cancellation
- Chat process: dual-SDK calls, retry policy (0/5/15/25s), streaming output, expired-response cleanup, per-Agent-profile client caching
- Interruption: the main process sends a cancel signal that can cascade to terminate the current session's sub-Agents

### Desktop Backend

| Area | Description |
|------|------|
| REST routes | `/api/chat` (single round / interrupt / history / session management), `/api/task` (self-driven tasks), `/api/commands` (mode / memory / characters / history), `/api/files` (sandboxed file CRUD), `/api/agents`, `/api/settings` (.env / profiles / language / tool policy), `/api/backup`, `/api/instances`, `/api/confirm` |
| WebSocket (default :8766, standalone process) | The backend listens on REST + 1, but the React client currently connects to fixed `ws://127.0.0.1:8766`; events: `log` / `agent_register` / `agent_output` / `agent_status` / `todo_update` / `confirm_request` / `confirm_cancel` / `task_event`; batched delivery (5 messages or 50ms flush) |
| confirm_manager | File writes/deletes and high-risk commands block on a WS `confirm_request` awaiting frontend confirmation |
| security_interrupt | Malicious-command circuit-break bridge: session self-interrupts + synthesized `task_event` |
| settings / profiles | Read/write `.env`, configuration profiles, command-interception toggles, system language, tool policy |
| instance_manager | Multiple backend instances (port isolation) |

File-route sandbox: only `output` / `skills` / `prompt` / `history` / `characters` plus root-level `note.txt` and `.env` are allowed; `prompt/skills/characters` are read-only resource roots.

### Windows Mini-Mode Four-Edge Snap

- On Windows, `desktop_app/frontend/src-tauri/src/edge_snap.rs` computes geometry in **physical pixels** from the window outer frame, screen cursor position, and the Win32 work area of the monitor under or nearest the cursor; this is neither CSS/logical pixels nor Windows Snap Layout
- After the left mouse button is released and movement settles, if the window or pointer is within 40 px of a work-area edge, the state machine selects the nearest of left/right/top/bottom, docks there, then slides out while leaving 8 px inside that work area
- Once hidden, moving out of and then back into the 12 px edge trigger band, limited to the window's span, reveals it. After reveal, it starts hiding again once the pointer has remained outside for at least 650 ms. At shared multi-monitor boundaries, the hidden part may appear on the adjacent monitor
- The Tauri command `configure_edge_snap(mini_mode, enabled)` configures the native state machine; the native layer synchronizes React/Zustand `snapEdge` / `isSnappedHidden` through the window event `edge-snap-state` with payload `{ edge, hidden }`
- Non-Windows builds retain the same command interface, but `start`, `window_moved`, `configure`, and `shutdown` are no-ops

### Configuration

- Authoritative source: `base/config.py` + the project-root `.env`
- Desktop "Environment Configuration": Basic (SDK + Key/URL/model) and Advanced (collapsed) sections; profiles are defined in `config_profiles.py`
- Desktop hot-apply: `apply_runtime_config()` (reload `.env`, restart the Chat process, re-resolve tools per session)
- See [CONFIGURATION.md](CONFIGURATION.md) for details

### Logging and Push

- Persistence: `base/logger.py` writes to `logs/<startup time>/conversations/<id>/` based on `session_context`
- Push: `websocket/log_bridge.py` attaches `conversation_id`; the frontend `logStore` buckets logs by session
- The body does not embed `session_id` (only routing fields carry session information)
- Raw logging is enabled by default: after each LLM call (success, empty response, refusal, truncation, or error), the provider's complete response text, raw provider response body (`raw_payload`), and health metadata (`health`: `api_stop_reason`, `finish_state`, `truncated`, usage, etc.) are written to a rotating `raw.log`; not pushed to the desktop log panel
- Main requests whose session can be parsed from their request ID are written under that conversation; helper-Agent requests that cannot be resolved this way may go to the process-level `raw.log`
- Raw content is neither redacted nor encrypted and may include commands, file contents, paths, credentials, or personal data repeated by the model. Clearing or deleting a session does not remove existing logs; use `LOG_RAW_ENABLED=false` to disable them

### Memory and History

- Manual save: `history/YYYY-mm-dd_HHMMSS.mem`
- Automatic short-term memory: `history/autosave/session_<id>.mem` (upserted per session, capacity around 10)
- `savemode`: compresses multi-step intermediate processes, keeping mainly user messages and final replies

### Internationalization (v4.0)

- Backend: `SYSTEM_LANGUAGE=zh|en` determines the language of user-facing helper-Agent output (command intent, remediation advice); read/write via `/api/settings/language`
- Frontend: `src/i18n/` is a homegrown lightweight i18n (Zustand, 23+ Chinese/English namespaces), with a "中/EN" toggle in the title bar that syncs to the backend on switch
- The main Agent's reply language always follows the language of the user's message (rule 8 in `prompt/prompt.md`)

---

## Data Flow

### Single User Message Turn

```
User input (GUI/CLI)
  → ConversationLoop.send_chat_request
  → IPC → Chat process → LLM
  → ProtocolManager.parse_response
  → If ACTION_*: tool-policy validation → (execute_command goes through SecurityGuard first)
      → execute tools → BackupManager snapshot → format_result → request LLM again
  → If STOP_REASON: end this turn and display
```

### Desktop Self-Driven Task

```
Frontend POST /api/task/submit
  → Backend thread pool drives run_single_round round by round (1800s watchdog)
  → Each node pushes a WS task_event (round_reply / tool_call / ...)
  → Async side channel: command_intent / security_malicious / security_remediation
  → task_finished → frontend renders the terminal state; after a reconnect it can pull a snapshot to recover
```

### Multi-Agent (long_context)

```
Main Agent multi_agent_dispatch
  → AgentProcessManager.dispatch_tasks
  → SubAgentThread (independent tool loop + logging)
  → CLI: blocking aggregation → RESULT back to the main Agent
  → Desktop: async execution → on completion, a [系统通知] (system notification) is injected back into the conversation
```

---

## Extension Points

### New Tool

1. Implement the logic in `base/utils/`
2. Add a definition to `TOOL_DEFINITIONS` in `base/tools.py`
3. Add a `handle_*` handler and register it
4. Add it to `STRONG_CONTEXT_TOOLS` / `LONG_CONTEXT_TOOLS` or a sub-Agent's `tools_list` as needed; if fine-grained toggles are required, register the sub-tools in `base/tool_policy.py`

### New Skill

1. `skills/<skill-name>/SKILL.md`
2. Optional scripts / references / requirements.txt
3. The Agent loads it on demand via `skill_query`

### New Character

1. `characters/*.md`
2. CLI `char select` or desktop settings / `DEFAULT_CHARACTER`

### New Sub-Agent Type

1. Register the tool list in `PREDEFINED_AGENT_TYPES` in `base/agent_types.py`
2. `prompt/<Type>_prompt.md`
3. Use it by specifying the type name in `multi_agent_dispatch`

---

## Performance Notes

- Chat thread pool: `CHAT_MAX_WORKERS` (default 5)
- Sub-Agent concurrency: `MULTI_AGENT_MAX_COUNT` (default 5)
- Context: `CONTEXT_MAX_TOKENS` + compression / savemode / `LIMIT_WRITE_TOOL_RETURN`
- Skills are queried on demand, avoiding stuffing everything into the system prompt
- Batched WebSocket delivery; log rotation and expired-response cache cleanup
- Backups use hash deduplication + binary deltas, so disk usage stays manageable under normal use

---

## Version

This document corresponds to **Spore 4.0** (git commit `v4.0`).

All version fields (`pyproject.toml`, frontend `package.json`, `tauri.conf.json`, `Cargo.toml`, and the backend API `version`) are `4.0.0`.

More:

- [Configuration](CONFIGURATION.md)
- [CLI Mode](CLI.md)
- [Build Guide](BUILD.md)
- [Skill Development](SKILLS.md)
- [Frontend Usage](FRONTEND.md)
- [Silver Fox Case Study](SILVERFOX.md)
