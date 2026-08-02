---
name: dynamic-html
description: Create, render, persist, inspect, update, validate, and remove interactive HTML artifacts in Spore, including runtime evolution from batched user interactions. Use when a response is better expressed as an interactive report, hierarchy, data explorer, dashboard, diagram, or one-off tool; when working with existing `.spore/html` assets; or when the user asks for HTML rendering, adaptive interaction, or a reusable visual component.
---

# Dynamic HTML

Create self-contained interactive HTML and manage its lifecycle under `.spore/html/` with `scripts/html_artifacts.py`.

## Choose the output

Use HTML when interaction, hierarchy, filtering, comparison, or non-linear navigation materially improves the result. Keep ordinary explanations, short answers, and simple tables as Markdown.

## Workflow

1. Run `list --json` before creating an artifact. Reuse an existing ID when it represents the same object.
2. Run `load <id>` before modifying an existing artifact. Preserve useful behavior and update the complete document.
3. Use a stable lowercase ID of at most 80 characters containing letters, digits, dots, underscores, and hyphens.
4. Prefer `generate` to delegate creation and review to Spore's frontend AutoAgent. Use `save` when the current Agent already has the complete HTML.
5. Run `validate` after manual edits. Fix every error before presenting the artifact.
6. Run `load <id>` and return the complete HTML as the sole response, optionally inside one `html` fence, when the user should see it immediately in the center panel. The user controls rendering with the visible HTML switch.
7. Run `remove <id> --yes` only when the user explicitly requests deletion.
8. Design ordinary controls to work locally. The render host observes trusted click, input, change, and submit operations, batches five seconds of activity, and asks the frontend AutoAgent whether the artifact should evolve.

## Commands

Run from the Spore working directory:

```text
python skills/dynamic-html/scripts/html_artifacts.py list --json
python skills/dynamic-html/scripts/html_artifacts.py load <id>
python skills/dynamic-html/scripts/html_artifacts.py save <id> --file <page.html> --title <title> --label <semantic-label>
python skills/dynamic-html/scripts/html_artifacts.py save <id> --stdin
python skills/dynamic-html/scripts/html_artifacts.py validate <id>
python skills/dynamic-html/scripts/html_artifacts.py validate --file <page.html>
python skills/dynamic-html/scripts/html_artifacts.py generate <id> --description <request> --label <semantic-label>
python skills/dynamic-html/scripts/html_artifacts.py remove <id> --yes
```

Pass `--root <Spore working directory>` before the command when the current directory is elsewhere. `generate` uses `DESKTOP_API_PORT` or `--port` and returns the existing artifact without regeneration unless `--force` is set.

## Document constraints

- Produce a complete document beginning with `<!doctype html>`.
- Keep CSS, JavaScript, and data inline. Do not use external resources, frames, imports, fetch, XHR, WebSocket, EventSource, or beacon APIs.
- Make layouts responsive from 360px through desktop and prevent overflow or overlap.
- Use semantic HTML, labels, keyboard controls, visible focus, and clear interaction states.
- Do not imitate login, payment, system, permission, or security dialogs and never request secrets.
- Treat `.spore/html/index.json` as managed data. Do not edit it manually.

## Runtime interaction protocol

The host monitors every trusted click, input, change, and submit operation inside a persisted iframe without blocking normal local HTML behavior. The first interaction opens a five-second collection window. It sends the complete chronological batch to the frontend AutoAgent, including event type, clicked text or word, element semantics, DOM path, nearby structure, control state, and viewport context. New interactions collected while a batch is processing form the next batch; updates to one artifact are serialized.

The frontend AutoAgent receives compact snippets for the interacted elements, nearby ancestors, a document outline, and limited inline CSS/JavaScript context. It does not receive or return the complete document for runtime interactions. For a mutation, its first non-empty streamed output must be `interrupt`, followed by the strict mutation JSON; `decision: "no_change"` must not emit `interrupt`. The mutation schema does not own Agent termination. The existing Spore protocol layer independently recognizes `@SPORE:STOP_REASON=...` and decides when the Frontend Agent multi-turn operation has ended. The host freezes the iframe as soon as `interrupt` appears, then waits for that protocol-level terminal decision before applying and validating the pending mutation.

The host allows only `append`, `prepend`, `before`, `after`, `replace_inner`, `replace_outer`, `set_attributes`, and `remove`. It resolves every reference against the current persisted DOM, applies the mutations structurally, validates the synthesized complete document for schema and blocked capabilities, and atomically persists only a valid changed result. The iframe is unfrozen only after the validated persisted content has been loaded. Invalid references, malformed JSON/fragments, oversized changes, and unsafe network code are rejected and sent back to the frontend AutoAgent for correction while the freeze remains active; terminal failures safely unfreeze without loading invalid HTML.

Add optional strong hints when a control intentionally points to content that does not exist yet:

```html
<button data-spore-target="packet-timeline"
        data-spore-request="Build the detailed packet timeline with protocol filters">
  Open timeline
</button>
```

Use `href="spore:packet-timeline"` as an equivalent navigation form. Give generated targets the corresponding `id` or `data-spore-view` so the host can restore focus after a hot reload.

Keep normal toggles, filters, tabs, and existing details in inline JavaScript. Do not depend on the Agent for basic responsiveness; the hook is an adaptive layer for inferred explanations, missing pages, deeper structures, and other new expression.
