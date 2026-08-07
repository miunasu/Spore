# Configuration Guide (v4.1)

> [中文](../CONFIGURATION.md)

The authoritative configuration source is the project-root `.env`, loaded by `Config` in `base/config.py`.  
The desktop GUI "Settings → Environment Configuration" ultimately reads and writes the same set of variables: the page is split into **Basic Configuration** (minimal viable setup) and **Advanced Configuration** (collapsed by default), and supports **configuration profiles**.

> Variable names follow the code. Names from older documentation such as `OPENAI_BASE_URL`, `MODEL_MAIN`, `MAX_CONTEXT_TOKENS`, `MAX_TOKENS_MAIN`, `DESKTOP_CONFIRM_ENABLED`, `LLM_API_KEY`, and `LLM_API_URL` are **no longer used**.

---

## Quick Start (Minimal Viable Setup)

```env
# Select the SDK
LLM_SDK=openai

# OpenAI-compatible interface (incl. DeepSeek, etc.)
OPENAI_API_KEY=sk-...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat

# Launch the desktop app
LAUNCH_MODE=desktop
DESKTOP_API_PORT=8765

# Context
CONTEXT_MODE=strong_context
CONTEXT_MAX_TOKENS=128000
```

Anthropic example:

```env
LLM_SDK=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514
# ANTHROPIC_EFFORT=medium
# ANTHROPIC_THINKING_MODE=adaptive
```

---

## LLM Configuration

### SDK Selection

| Variable | Default | Description |
|------|------|------|
| `LLM_SDK` | `openai` | `openai` or `anthropic` |
| `LLM_STREAM_ENABLED` | `true` | Stream main-agent output and update desktop chat as user-visible sections arrive; set to `false` for gateways without streaming support |

### OpenAI / Compatible Interfaces

| Variable | Default | Description |
|------|------|------|
| `OPENAI_API_KEY` | empty | Required (when SDK=openai) |
| `OPENAI_API_URL` | empty | Custom Base URL (DeepSeek, etc.) |
| `OPENAI_MODEL` | `gpt-4o-mini` | Main model name |
| `USE_RESPONSES_API` | `false` | When `true`, use the Responses API (o-series, etc.) |
| `OPENAI_REASONING_EFFORT` | empty | `low` / `medium` / `high` / `xhigh`; not sent when empty |

### Anthropic

| Variable | Default | Description |
|------|------|------|
| `ANTHROPIC_API_KEY` | empty | Required (when SDK=anthropic) |
| `ANTHROPIC_API_URL` | empty | Custom API URL |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-20250514` | Model name |
| `ANTHROPIC_EFFORT` | empty | `low`/`medium`/`high`/`xhigh`/`max` → `output_config.effort` |
| `ANTHROPIC_THINKING_MODE` | empty (automatic) | `adaptive` / `enabled` / `disabled` |
| `ANTHROPIC_THINKING_BUDGET_TOKENS` | empty | Used only in `enabled` mode |

### Proxy / Third-Party Gateway Compatibility

| Variable | Default | Description |
|------|------|------|
| `CLEAN_SDK_HEADERS` | `false` | Strip SDK headers such as x-stainless |
| `CLEAN_AUTH_HEADER` | `false` | Remove the redundant Authorization header in the Anthropic case |

### Embedding / Learning

Learning uses an OpenAI-compatible embeddings HTTP endpoint (`<base_url>/v1/embeddings`); it does not automatically switch to an Anthropic embedding API when `LLM_SDK=anthropic`:

| Variable | Default | Description |
|------|------|------|
| `EMBEDDING_API_KEY` | falls back to `OPENAI_API_KEY` | Embedding-service API key |
| `EMBEDDING_API_URL` | falls back to `OPENAI_API_URL` | Embedding-service base URL; the OpenAI default is used when empty |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model name |
| `LEARNING_DB_PATH` | `<runtime_root>/.spore/memory/episodic.db` | Learning SQLite path; relative paths resolve against the runtime root |
| `EPISODIC_DB_PATH` | same as above | Compatibility alias for the SQLite path; `LEARNING_DB_PATH` takes precedence |

If the main OpenAI-compatible model service does not support embeddings, or only an Anthropic key is configured, set `EMBEDDING_API_KEY` / `EMBEDDING_API_URL` / `EMBEDDING_MODEL` separately. Missing embedding configuration or request failures cause Learning retrieval/recording to be skipped while the main conversation continues; there is no local embedding or FTS fallback.

### Sub-Agent Dedicated LLM (optional; empty = inherit from the main Agent)

| Variable | Description |
|------|------|
| `SUB_AGENT_LLM_SDK` | Sub-Agent SDK |
| `SUB_AGENT_OPENAI_API_KEY` / `SUB_AGENT_OPENAI_API_URL` / `SUB_AGENT_OPENAI_MODEL` | Sub-Agent OpenAI |
| `SUB_AGENT_ANTHROPIC_API_KEY` / `SUB_AGENT_ANTHROPIC_API_URL` / `SUB_AGENT_ANTHROPIC_MODEL` | Sub-Agent Anthropic |

### Helper-Agent Dedicated LLM (v4.1, optional)

The four helper-Agent profiles can each specify their own model, with the fallback chain: **profile-specific → `SUB_AGENT_*` → main configuration** (field-by-field fallback; see `Config.resolve_agent_llm`):

| Prefix | Corresponding Agent |
|------|-----------|
| `AGENT_SUPERVISOR_*` | Supervisor (loop / termination decision) |
| `AGENT_MODE_SELECTOR_*` | ModeSelector (auto mode selection) |
| `AGENT_SECURITY_*` | Security Agent (intent / risk / circuit break) |
| `AGENT_FRONTEND_*` | Frontend Agent (HTML generation / review) |

Each prefix supports the same suffixes as the main configuration: `LLM_SDK`, `OPENAI_API_KEY/API_URL/MODEL`, `ANTHROPIC_API_KEY/API_URL/MODEL`, plus effort / thinking, etc.

Example — use a cheap small model for the Security Agent:

```env
AGENT_SECURITY_LLM_SDK=openai
AGENT_SECURITY_OPENAI_MODEL=gpt-4o-mini
```

### Output and Timeout

| Variable | Default | Description |
|------|------|------|
| `MAX_OUTPUT_TOKENS` | `15000` | Upper limit for a single LLM output |
| `FRONTEND_AGENT_TIMEOUT` | `180` | Timeout in seconds for each frontend Agent LLM request |
| `FRONTEND_AGENT_MAX_ITERATIONS` | `3` | Generation, review, and validation-correction iterations (minimum effective value: 2) |
| `API_TIMEOUT` | `300` | API timeout (seconds) |

### System Prompt Behavior

| Variable | Default | Description |
|------|------|------|
| `SYSTEM_PROMPT_FILE` | `prompt.md` | File name under `prompt/` |
| `SYSTEM_AS_USER` | `false` | Send the system prompt as the first user message (for gateway compatibility) |

---

## Startup and Desktop

| Variable | Default | Description |
|------|------|------|
| `LAUNCH_MODE` | `cli` | `cli` or `desktop` |
| `DESKTOP_API_HOST` | `127.0.0.1` | FastAPI listen address |
| `DESKTOP_API_PORT` | `8765` | REST port only. The backend derives its WebSocket listener as REST + 1, but the current React client still connects to fixed port `8766`; changing this value does not update the frontend WebSocket address |
| `SYSTEM_LANGUAGE` | `zh` | System language: `zh` or `en`. Affects user-facing helper-Agent output (command-intent explanations, circuit-break remediation advice). The desktop title-bar language switch syncs this automatically; the main Agent always follows the language of the user's message. |

The packaged runtime also uses environment variables (injected by Tauri / the installer):

- `SPORE_RESOURCE_DIR`: resource directory (prompt/skills/characters, etc.)
- `SPORE_DESKTOP_MODE`: desktop silent-mode flag
- `SPORE_INSTANCE_ID` / `SPORE_INSTANCE_PORT`: multi-instance subprocesses

---

## Context Modes

| Variable | Default | Description |
|------|------|------|
| `CONTEXT_MODE` | `strong_context` | Default mode for new sessions |
| `CONTEXT_MAX_TOKENS` | `128000` | Context token limit |
| `CONTEXT_WARNING_THRESHOLD` | `0.8` | Compression trigger threshold (ratio) |
| `MAX_SINGLE_MESSAGE_RATIO` | `0.3` | Relative upper limit for a single message |

### Mode Meanings

| Mode | Behavior |
|------|------|
| `strong_context` | Strongly-coupled single-Agent tool set, **without** `multi_agent_dispatch` |
| `long_context` | Long-context / multi-Agent oriented, **with** `multi_agent_dispatch` |
| `auto` | ModeSelector chooses strong or long on each turn |

At runtime, you can switch via CLI `mode ...` or the GUI mode dropdown; it applies to the **current session**.

---

## Security (v4.1)

### Security Agent

| Variable | Default | Description |
|------|------|------|
| `SECURITY_AGENT_MODE` | `full` | `off` disables completely; `basic` = up-front gatekeeping: AI risk assessment after a high-risk keyword hit, then auto-allow / confirm / block by risk level; `full` (default) = async out-of-band: **no keyword pre-screening and no confirmation prompts** — every command is adjudicated for intent and malice in the background, and a malicious verdict circuit-breaks the session and generates remediation advice. `basic` and `full` are mutually exclusive strategies |
| `SECURITY_GUARD_MODE` | `balanced` | `basic` mode only: `strict` = confirm on every hit / `balanced` = confirm medium and high risk / `permissive` = confirm high risk only |
| `SECURITY_LLM_TIMEOUT` | `30` | Risk-assessment LLM timeout (seconds) |
| `SECURITY_INTENT_TIMEOUT` | `45` | Intent-analysis LLM timeout (seconds) |
| `SECURITY_AGENT_SESSION_CONTEXT` | `false` | `full` mode only: include successfully adjudicated commands from the same session in later security-analysis requests |
| `SECURITY_SESSION_CONTEXT_MAX_COMMANDS` | `20` | Maximum number of recent historical commands included in context |

Session-context boundaries in `full` mode:

- With the default disabled setting, commands are still analyzed individually and complete successfully adjudicated commands are collected per session in process memory; prior history is simply not sent in later security-analysis requests
- When enabled, recent commands are sent with the current command to the configured security-model service. Commands may contain paths, arguments, tokens, or other secrets; assess the service's data-handling policy before enabling it
- History exists only in process memory; malicious events are separately written to `.spore/security_audit.jsonl`
- `clear_session_history()` is not yet connected to the new-conversation, memory-clear, reset, or session-deletion lifecycle; those operations do not clear this history, and it is naturally released only when the whole process exits

Related data files (auto-generated, git-ignored):

- `security_whitelist.json`: trusted-command whitelist (effective in `basic` mode; added via the CLI `whitelist` command or at confirmation time)
- `.spore/security_audit.jsonl`: security audit log

### Command Interception

The desktop menu "Interception Toggles" correspond to the following variables:

| Variable | Default | Description |
|------|------|------|
| `COMMAND_INTERCEPT` | `true` (falls back to the legacy name `BLOCK_SHELL_DELETE` if unset) | Master switch |
| `INTERCEPT_SHELL_DELETE` | enabled | Intercept del/rm/Remove-Item, etc. |
| `INTERCEPT_SHELL_WRITE` | enabled | Intercept Set-Content/Out-File, etc. (prefer `file type=write`) |

> On the desktop, file write/delete confirmation goes through `confirm_manager` over WebSocket; there is **no** `DESKTOP_CONFIRM_ENABLED` switch.

### Backup and Rollback

| Variable | Default | Description |
|------|------|------|
| `BACKUP_ENABLED` | `true` | Master switch for file snapshots + conversation checkpoints |
| `BACKUP_DIR` | `.spore` | Backup data directory |
| `BACKUP_MAX_FILE_BYTES` | 50MB | Files larger than this are not snapshotted |
| `BACKUP_MAX_DELETE_FILES` | `200` | Maximum number of files backed up per delete operation |

Corresponding CLI commands: `rollback` / `filehistory` / `checkpoints` / `rewind`, plus the desktop "Backup/Rollback" page.

### Tool Policy

| Variable | Default | Description |
|------|------|------|
| `TOOL_POLICY_SCOPE` | `session` | `session`: policies are independent per session; `global`: reads/writes `tool_policy.json` in the project root, affecting all sessions |

Toggles go down to sub-tool granularity (`file.read/write/delete`, `edit.single/multi/line`, `web_browser.visit/search`, `multi_agent_dispatch.<type>`). On the desktop, edit under "Settings → Tools"; see [ARCHITECTURE.md](ARCHITECTURE.md) for details.

---

## Character System

| Variable | Default | Description |
|------|------|------|
| `DEFAULT_CHARACTER` | empty | Character name to auto-`select` at startup |
| `CHARACTERS_DIR` | `characters` | Character directory |

- Character files: `characters/*.md`
- CLI: `char list|select <name>|remove`
- GUI: character management in the settings page

---

## Rule Reminders

| Variable | Default | Description |
|------|------|------|
| `RULE_REMINDER_INTERVAL` | `10` | Inject a reminder every N LLM replies; `0` disables |
| `RULE_REMINDER_SHORT` | `false` | Condensed reminders to save tokens |

---

## Multi-Agent

| Variable | Default | Description |
|------|------|------|
| `MULTI_AGENT_MAX_COUNT` | `5` | Maximum concurrent sub-Agents |
| `SUB_AGENT_MAX_ITERATIONS` | `100` | Maximum iterations per sub-Agent |
| `MULTI_AGENT_TIMEOUT` | empty | Wait timeout in seconds; empty = unlimited |
| `MULTI_AGENT_TOTAL_TIMEOUT` | `3600` | Total timeout for the whole dispatch batch (seconds) |
| `MULTI_AGENT_MONITOR_ENABLED` | `true` | Whether to open a dedicated monitoring terminal |
| `MULTI_AGENT_JOIN_INTERVAL` | `2.0` | Wait polling interval (seconds) |
| `CODER_MAX_ITERATIONS` | `1000` | Iteration limit for the Coder sub-Agent |

---

## Chat Process and IPC

| Variable | Default | Description |
|------|------|------|
| `CHAT_MAX_WORKERS` | `5` | Chat process thread-pool size |
| `CHAT_RESPONSE_EXPIRE` | `300` | Response cache expiry (seconds) |
| `CHAT_RESPONSE_CLEANUP_INTERVAL` | `60` | Cache cleanup interval |
| `IPC_CHECK_INTERVAL` | `0.1` | IPC polling interval |

---

## Tool Execution

| Variable | Default | Description |
|------|------|------|
| `TOOL_EXECUTION_TIMEOUT` | `120` | General tool timeout (seconds) |
| `SHELL_COMMAND_TIMEOUT` | `60` | Default shell timeout |
| `LIMIT_WRITE_TOOL_RETURN` | `true` | Limit write-tool return content to save tokens |
| `FILE_READ_DEFAULT_LIMIT` | `2000` | Default number of lines when reading a file |
| `FILE_MAX_LINE_LENGTH` | `2000` | Maximum length of a single line |
| `WEB_BROWSER_TIMEOUT` | `15` | Web page timeout |
| `WEB_PROXY_PORT` | `7897` | Proxy port for non-Chinese domains; `0` disables |
| `WEB_MAX_CONTENT_LENGTH` | `15000` | Web page body truncation length |

---

## Logging

| Variable | Default | Description |
|------|------|------|
| `LOG_TO_FILE` | `true` | Write file logs |
| `LOG_DIR` | `logs` | Directory |
| `LOG_FILE_MAX_SIZE` | 10MB | Size of a single file |
| `LOG_BACKUP_COUNT` | `5` | Number of backups |
| `LOG_ERROR_FILENAME` etc. | `error.log` etc. | File names for each log category |
| `LOG_MONITOR_TYPES` | `error,llm_validation,tool_execution` | Types displayed by the monitor |
| `LOG_MONITOR_CHECK_INTERVAL` | `0.5` | Monitor refresh interval |
| `LOG_MONITOR_MAX_LINE_LENGTH` | `200` | Monitor line truncation |
| `LOG_RAW_ENABLED` | `true` | Toggle for the raw LLM-response log |
| `LOG_RAW_FILENAME` | `raw.log` | Raw log file name |

Directory conventions:

- Process level: `logs/<startup time>/...`
- Conversation level: `logs/<startup time>/conversations/<conversation_id>/...` (persisted with per-session isolation)
- Raw log: `logs/<startup time>/conversations/<conversation_id>/raw.log`

Raw log (`LOG_RAW_ENABLED`):

- Every API attempt has one outer `===== API ATTEMPT START/END =====` block. RAW data, metadata, payload, and extracted text have their own nested START/END markers.
- Every API attempt within one user request gets a distinct `attempt_id` / `attempt_index`, so initial calls, retries, and analysis records can be paired directly.
- Non-streaming calls prefer the HTTP body before SDK parsing. Streaming calls store only the final aggregate containing every content block (`stream_final`), without expanding token/delta events.
- Block diagnostics report `visible_text_length` and `thinking_length` separately. `text_length` remains as a compatibility alias for `visible_text_length`.
- This covers main, sub-, and helper-Agent calls. Main requests whose session can be parsed from the request ID go to that conversation directory; other helper requests may go to the process-level `raw.log`
- **File only** — never pushed to the desktop log panel or the log monitor terminal; request messages and the system prompt are not logged, but replies may repeat commands, file contents, paths, credentials, or personal data
- Clearing or deleting a session does not remove existing raw logs. Set `LOG_RAW_ENABLED=false` explicitly when this data must not be persisted; do not rely on `LOG_TO_FILE=false`
- No `raw.log` is created while the raw-log toggle is off

Tool / general logs pushed to the desktop frontend:

- Use the WebSocket field `conversation_id` for session routing  
- **The log JSON body no longer contains `session_id`** (to avoid panel noise; unrelated to persistence isolation)

---

## Directory Paths

| Variable | Default |
|------|------|
| `SKILLS_DIR` | `skills` |
| `CHARACTERS_DIR` | `characters` |
| `PROMPT_DIR` | `prompt` |
| `LOG_DIR` | `logs` |
| `OUTPUT_DIR` | `output` |
| `UPLOAD_DIR` | `uploads` |

Conversation history always uses `history/` under the working directory (including `history/autosave/`); backup data always lives in `BACKUP_DIR` (default `.spore/`). Persistent HTML artifacts use `.spore/html/` and are exposed to the file UI only through the virtual `html/` root.

---

## Configuration Methods

### 1. Edit `.env` Directly

After saving:

- Most items require a process restart to take effect  
- The desktop "Apply Environment Configuration" invokes runtime hot-reload (`reload_config` / `apply_runtime_config`: reload `.env`, restart the Chat process, re-resolve tool sets per session)

### 2. GUI Settings (Desktop)

Path: **Settings → Environment Configuration** (`CommandMenu`).

1. **Basic Configuration (always expanded)**: fill in only the minimal viable items to run  
   - `LLM_SDK`  
   - OpenAI: `OPENAI_API_KEY` / `OPENAI_API_URL` / `OPENAI_MODEL`  
   - Anthropic: `ANTHROPIC_API_KEY` / `ANTHROPIC_API_URL` / `ANTHROPIC_MODEL`  
2. **Advanced Configuration (collapsed by default)**: Responses/Thinking, sub-Agent and helper-Agent profiles, context thresholds, SDK compatibility, logging, paths, multi-Agent, security and interception toggles, etc.  
3. **API Configuration Set**: save the current SDK's Key/URL/model and compatibility parameters as a profile for one-click switching  
4. Click **Save Configuration** to write back to `.env` and hot-apply; or **Open .env** to use an external editor  

The profile implementation is in `base/config_profiles.py` (persisted to `.spore_config_profiles.json`).

---

## FAQ

### How do I switch LLM providers?

```env
# OpenAI (official)
LLM_SDK=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# DeepSeek (OpenAI-compatible)
LLM_SDK=openai
OPENAI_API_KEY=...
OPENAI_API_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-chat

# Claude
LLM_SDK=anthropic
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

### How do I adjust the context length?

Change `CONTEXT_MAX_TOKENS`, and make sure it does not exceed the model's actual window. You can combine `savemode` and `LIMIT_WRITE_TOOL_RETURN` to control growth.

### How do I disable the Security Agent / interception?

```env
# Disable the Security Agent completely (not recommended)
SECURITY_AGENT_MODE=off

# Disable shell command interception only
COMMAND_INTERCEPT=false

# Or disable individual items only
INTERCEPT_SHELL_DELETE=false
INTERCEPT_SHELL_WRITE=false
```

You can also toggle "Interception Toggles" in the desktop menu, or trust specific commands with `whitelist add <command>`.

### My variable change doesn't take effect?

1. Confirm you edited the `.env` in the **working directory** (after packaging, this is the install directory, not the temporary extraction directory)  
2. In desktop mode, click "Apply Environment Configuration" or restart  
3. Check that `LLM_SDK` matches the corresponding Key  

### Legacy Variable Mapping

| Legacy name (do not use) | Current name |
|--------------|--------|
| `OPENAI_BASE_URL` | `OPENAI_API_URL` |
| `LLM_API_KEY` / `LLM_API_URL` | `OPENAI_API_KEY`+`OPENAI_API_URL` or `ANTHROPIC_API_KEY`+`ANTHROPIC_API_URL` |
| `MODEL_MAIN` | `OPENAI_MODEL` / `ANTHROPIC_MODEL` |
| `MAX_TOKENS_MAIN` | `MAX_OUTPUT_TOKENS` |
| `MAX_CONTEXT_TOKENS` | `CONTEXT_MAX_TOKENS` |
| `BLOCK_SHELL_DELETE` | `COMMAND_INTERCEPT` (still read for compatibility, but use the new name) |
| `DESKTOP_CONFIRM_ENABLED` | (removed; desktop confirmation is always available) |
| `MODEL_SUPERVISOR` | `AGENT_SUPERVISOR_*` profile configuration |

---

## Related Documentation

- [Architecture](ARCHITECTURE.md)
- [CLI Mode](CLI.md)
- [Build Guide](BUILD.md)
- [Frontend Usage](FRONTEND.md)
