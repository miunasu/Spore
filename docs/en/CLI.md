# CLI Mode User Guide (v4.0)

> [中文](../CLI.md)

> Note: The current product focus is the desktop GUI. The CLI still works, but some interaction features (confirmation UI, multiple sessions, async sub-agent notifications, etc.) are weaker than in desktop mode. Recommended: `LAUNCH_MODE=desktop`.

## Launching

```bash
# Make sure LAUNCH_MODE=cli in .env (cli is the default)

# Option 1: Unified entry point
uv run python main_entry.py

# Option 2: Direct CLI
uv run python main.py
```

Installing dependencies:

```bash
uv sync
```

The log-monitoring terminal opens automatically by default; you can also run `start_log_monitor.bat` or `uv run python base/log_monitor.py` manually.

The CLI has no command-line arguments; all behavior is determined by `.env`. Runtime commands are entered at the `User>` prompt.

---

## Command Reference

### System

```
prompt             - View the current system prompt (the effective prompt after protocol injection)
q / quit / exit    - Exit
cls                - Clear the screen
```

### Conversation and Memory

```
context / mem / memory - View conversation history (brief)
fullmem                - View the full conversation history
memclean / cleanmem    - Clear the current memory
save                   - Manually save to history/<timestamp>.mem
load <filename>        - Load from history/ (you can write autosave/xxx.mem)
continue               - Load the most recent history and continue
```

Automatic short-term memory:

- Path: `history/autosave/session_<session_id>.mem`
- Overwritten and updated per session; by default about 10 sessions are retained at most
- Restore with `load autosave/session_xxx.mem`

### Backup and Rollback (v4.0)

```
rollback <file_path> [--to <version>|--steps <N>]  - Roll a file back to a specific version / go back N versions
filehistory [<file_path>]                          - View a file's version history
checkpoints                                        - List the conversation checkpoints of the current session
rewind [<checkpoint_id>|--turns <N>]               - Roll back to a conversation checkpoint (files + conversation history + TODOs restored together)
```

- Before every write/delete, the agent automatically keeps a backup (`.spore/`, bsdiff4 delta storage)
- `rewind` is a "time machine": it rolls the workspace files and the conversation context back together to the point before a given task turn started
- For the master switch and limits, see [CONFIGURATION.md](CONFIGURATION.md), "Backup and Rollback"

### Security Whitelist (v4.0)

```
whitelist            - Usage help
whitelist list       - View the list of trusted commands
whitelist add <command> - Add a command to the whitelist (skips security-guard confirmation in basic mode)
```

The whitelist is stored in `security_whitelist.json` and takes effect in `basic` security mode (the default `full` mode does no up-front confirmation, so no whitelist is needed); the security audit log is in `.spore/security_audit.jsonl`. For the security agent levels (`off`/`basic`/`full`), see [CONFIGURATION.md](CONFIGURATION.md), "Security".

### Tools and Skills

```
skills             - Summarize the feature descriptions of each skill under skills/
```

> The `token` command is deprecated: context token usage is based on the exact usage returned by the LLM API (shown in the desktop UI).

### Modes and Characters

```
mode                           - View the context mode of the current session
mode strong_context|long_context|auto
char                           - Character help
char list                      - List characters/
char select <character_name>   - Select a character (only one at a time)
char remove                    - Remove the current character
```

Setting `DEFAULT_CHARACTER` in `.env` can automatically select a character at startup.

### Others

```
savemode           - Toggle context-saving mode (compress multi-step intermediate steps)
paste [note]       - Read multi-line text from the clipboard as user input
```

---

## Usage Examples

### Save / Load

```text
User> save
[Conversation saved] File: history/2026-07-14_153012.mem

User> load 2026-07-14_153012.mem
[Conversation loaded]

User> continue
[Conversation loaded] Continuing the most recent conversation: ...
```

### File Rollback

```text
User> filehistory output/report.md
[Version history] output/report.md
  v3  2026-07-20 14:22:01  (current)
  v2  2026-07-20 14:05:47
  v1  2026-07-20 13:58:12

User> rollback output/report.md --to 2
[Rolled back] output/report.md → v2

User> checkpoints
[Checkpoints] 1. cp_xxxx 2026-07-20 14:20 "Restructure the report"
User> rewind --turns 1
[Rolled back] Files and conversation history restored to the point before the previous task turn started
```

### Switching Modes

```text
User> mode
[Current mode] strong_context

User> mode long_context
[Mode switched] long_context
[Note] The new mode takes effect on the next conversation
```

Relationship between modes and tool sets:

- `strong_context`: A single agent with full file/command/network tools, **without** multi-agent dispatch
- `long_context`: Additionally enables `multi_agent_dispatch`
- `auto`: Decided by the ModeSelector each turn

### Pasting Multiple Lines

```text
# First copy the content to the clipboard
User> paste Please analyze the following code
[Read from clipboard ...]
```

---

## Interrupting

- Press **Ctrl+C** during an LLM response or tool execution
- This interrupts the current Chat request and attempts to terminate the session's sub-agents
- The main process usually continues, and you can enter the next command

---

## Multi-Process Architecture

The CLI and desktop share the same IPC architecture:

| Process | Responsibilities |
|------|------|
| Main process | User input, protocol parsing, tool execution, security guard, sub-agent coordination |
| Chat process | OpenAI / Anthropic API calls, streaming output (shared by main/sub/auxiliary agents) |

Initialization is done by `base.ipc_manager.initialize_ipc_system()`.

Logs: A log-monitoring terminal is opened by default (see `logs/` and the `LOG_MONITOR_*` configuration).

---

## Differences from Desktop Mode (Summary)

| Capability | CLI | Desktop |
|------|-----|---------|
| Multi-session tabs | Weak / mostly single session | Multiple sessions + an independent ConversationLoop per session |
| Task execution | Foreground synchronous loop | Backend self-driven task loop, closing the window does not interrupt it |
| Sub-agent dispatch | Synchronous blocking wait | Async dispatch + `[System notification]` re-injection |
| Dangerous-operation confirmation | Terminal confirmation + command interception | WebSocket confirmation bar + security popup |
| Real-time panels | Log terminal | Logs / TODO / Agent monitoring / File tree / Mini mode |
| Configuration profiles | Manually edit `.env` | GUI + profiles |
| Backup and rollback | `rollback` / `rewind` commands | Visual "Backup/Rollback" operations in the settings menu |

More:

- [Configuration Guide](CONFIGURATION.md)
- [Architecture Design](ARCHITECTURE.md)
- [Frontend Guide](FRONTEND.md)
