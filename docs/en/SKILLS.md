# Skill Development Guide (v4.0)

> [中文](../SKILLS.md)

Spore's extension skills follow the Claude Skills-style directory convention: one folder per skill, with `SKILL.md` at its core.  
The main agent / sub-agents read the documentation on demand through the **`skill_query`** tool, avoiding stuffing the full text of every skill into the system prompt.

---

## Skill Package Structure

```text
skills/your-skill/
├── SKILL.md              # Required: skill description (the agent's query entry point)
├── scripts/              # Optional: executable scripts
│   └── tool.py
├── references/           # Optional: reference materials
│   └── notes.md
└── requirements.txt      # Optional: extra Python dependencies
```

See `skills/agent_skills_spec.md` for the full specification.

Built-in examples in the current repository:

| Skill directory | Purpose |
|----------|------|
| `skills/docx` | Word creation / template filling / analysis |
| `skills/pdf` | PDF extraction, generation, merging/splitting, forms, etc. |
| `skills/pptx` | PowerPoint generation and processing |
| `skills/pcap-analyst` | PCAP traffic analysis, C2/Beacon detection, Snort/YARA rule generation |
| `skills/skill-creator` | Helps create new skill packages (includes a scaffolding script) |

Reverse-engineering (IDA, etc.) capabilities are usually accomplished through **host command tools + external toolchains + case directories**, and are not required to be built into `skills/`. See `example/MalwareAnalysis/` for cases, and [IDA-Skill](https://github.com/miunasu/IDA-Skill) for the companion skill (usage in the [SilverFox case](SILVERFOX.md)).

---

## Suggested SKILL.md Format

```markdown
---
name: your-skill
description: "A one-sentence description of when to use this skill"
---

# Skill Name

## Feature Overview

...

## Use Cases

- ...

## Tools / Scripts

### xxx

**Function**: ...

**Usage**:

```bash
python scripts/xxx.py --input a --output b
```

**Parameters**:

- `input`: ...

## Notes

...
```

The frontmatter supports `name` / `description` (required), plus optional `license` / `metadata` / `allowed-tools`.

The agent-side invocation form (text protocol):

```text
@SPORE:ACTION_SINGLE_START
skill_query skill_name="your-skill"
@SPORE:ACTION_SINGLE_END
```

For the implementation, see `base/tools.py` → `handle_skill_query`; for content retrieval, see `base/utils/skills.py`.

The skill directory summary in the system prompt is scanned and assembled by `prompt_loader.collect_skills_md_features()` into the `{skills}` placeholder of `prompt/prompt.md` (name + description only; the body is queried on demand).

---

## Development Steps

1. Create the directory: `skills/your-skill/`
2. Write `SKILL.md` (name/description + actionable instructions)
3. If scripts are needed: put them in `scripts/`, parameterize them, and support `--help`
4. Write extra dependencies into `requirements.txt` and install them yourself in the runtime environment; Spore discovers and reads skills but does not automatically install their external dependencies
5. Launch Spore and, in conversation, ask it to "query the your-skill skill" to verify `skill_query`

CLI self-check:

```text
User> skills
```

This prints the feature summaries of the discovered skills. On the desktop, the "skills" page in the right column also lets you browse the skill directories directly.

> Tip: in the installed desktop edition, the skills directory is `skills/` under the resource root (normally located through `SPORE_RESOURCE_DIR`); source runs normally use `skills/` under the repository root. If a deployment supplies `SKILLS_DIR`, resolve skills and scripts from that directory.

### Path and Dependency Conventions

- Write script and resource paths in `SKILL.md` relative to the current skill directory, such as `scripts/tool.py` and `references/notes.md`
- For commands intended to run from the repository root, use `skills/<skill-name>/...`; at runtime, use `SKILLS_DIR` when provided or `skills/` under `SPORE_RESOURCE_DIR` in the installed desktop edition
- Never put development-machine absolute paths, such as drive-letter paths or personal home directories, in skill documentation or script defaults
- Example inputs and outputs should use clear placeholder relative paths, such as `examples/input.docx` and `output/result.docx`
- `requirements.txt` only declares dependencies; Spore does not automatically run `pip`, `npm`, or system package installation

---

## Best Practices

1. **Write a clear decision table**: which command/script to use for which task  
2. **Scripts run independently**: do not depend on Spore's internal imports  
3. **Readable error messages**: non-zero exit code + stderr explanation  
4. **Use little context**: put details in references and keep SKILL.md a concise, searchable structure  
5. **Resolve paths relative to the skill directory or a declared resource root**: prefer skill-relative paths; when crossing skill boundaries, use `SKILLS_DIR` / `SPORE_RESOURCE_DIR` explicitly instead of development-machine absolute paths

---

## Relationship with the Tool System

Skills are **not** new tool names; skills teach the agent how to combine existing tools:

- `execute_command`: run scripts / PowerShell (governed by the security guard)
- `file` / `edit` / `Grep`: read, write, modify, search
- `web_browser`: online materials
- `multi_agent_dispatch` (long_context): parallel research and editing

Note: if a tool is disabled in the tool policy (see the "Tool Policy" section of [ARCHITECTURE.md](ARCHITECTURE.md)), skill steps that depend on that tool will not be executable.

For the protocol description, see the "Text Protocol" section of [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Contributing

1. Fork the repository  
2. Add a skill package under `skills/`  
3. Update the index on this page (if any)  
4. Submit a PR  

Related:

- [Configuration Guide](CONFIGURATION.md)
- [Architecture Design](ARCHITECTURE.md)
- [SilverFox Case](SILVERFOX.md)
