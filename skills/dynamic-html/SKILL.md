---
name: dynamic-html
description: Create, render, persist, inspect, update, validate, and remove interactive HTML artifacts in Spore. Use when a response is better expressed as an interactive report, hierarchy, data explorer, dashboard, diagram, or one-off tool; when working with existing `.spore/html` assets; or when the user asks for HTML rendering or a reusable visual component.
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
8. Mark missing drill-down content with `data-spore-target` and `data-spore-request`. The render host watches these interactions and invokes the frontend AutoAgent only when the target is absent.

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

## Dynamic interaction protocol

Use a stable target ID on a trigger when clicking it may require content that is not in the current document:

```html
<button data-spore-target="packet-timeline"
        data-spore-request="Build the detailed packet timeline with protocol filters">
  Open timeline
</button>
```

If an element with `id="packet-timeline"` or `data-spore-view="packet-timeline"` already exists, the host reveals it locally. Otherwise, the host shows a generation state, asks the frontend AutoAgent to update the complete document, persists it, reloads the iframe, and reveals the new target. `href="spore:packet-timeline"` is an equivalent navigation form.

Keep normal toggles, filters, tabs, and existing details in inline JavaScript. Use the dynamic protocol only for a genuinely absent page, expansion branch, or drill-down.
