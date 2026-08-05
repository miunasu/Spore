// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { htmlApi, type HtmlInteractResult } from '../../services/api';
import {
  HtmlPreview,
  buildSandboxedHtml,
  extractStandaloneHtml,
  getHtmlArtifactId,
  isHtmlFile,
} from './HtmlPreview';
import {
  buildSemanticIntentEpisode,
  dynamicWindowDelay,
  shouldIgnoreLocallySatisfiedSignal,
  sha256Text,
  type HtmlInteractionEvent,
  type SemanticIntentEpisode,
} from './htmlIntent';

const initial = '<!doctype html><html data-spore-artifact-id="demo"><body><button>Run</button></body></html>';

function interactionEvent(
  timestamp: number,
  text: string,
  overrides: Partial<HtmlInteractionEvent> = {},
): HtmlInteractionEvent {
  return {
    timestamp_ms: timestamp,
    event_type: 'click',
    tag: 'button',
    element_id: '',
    role: '',
    text,
    clicked_word: text,
    aria_label: '',
    title: '',
    href: '',
    spore_target: '',
    spore_request: '',
    dom_path: `body > button:nth-of-type(1)`,
    ancestors: ['body'],
    scroll_y: 0,
    viewport: { width: 800, height: 600 },
    ...overrides,
  };
}

function bridgeMetadata(frame: HTMLIFrameElement) {
  const source = frame.getAttribute('srcdoc') ?? '';
  const document = new DOMParser().parseFromString(source, 'text/html');
  const bridgeSource = document.querySelector('script[data-spore-host-bridge]')?.textContent ?? '';
  const capabilityLiteral = /\)\(("[^"]+")\);\s*$/.exec(bridgeSource)?.[1];
  return {
    bridgeCapability: capabilityLiteral ? JSON.parse(capabilityLiteral) as string : '',
    documentToken: document.documentElement.dataset.sporeDocumentToken ?? '',
    documentGenerationId: document.documentElement.dataset.sporeDocumentGenerationId ?? '',
    restoreAttemptId: document.documentElement.dataset.sporeRestoreAttemptId ?? '',
  };
}

function sendInteraction(frame: HTMLIFrameElement, event: HtmlInteractionEvent) {
  const metadata = bridgeMetadata(frame);
  window.dispatchEvent(new MessageEvent('message', {
    source: frame.contentWindow,
    data: { source: 'spore-html', type: 'interaction', artifactId: 'demo', bridgeCapability: metadata.bridgeCapability, event },
  }));
}

function sendReady(frame: HTMLIFrameElement, overrides: Record<string, unknown> = {}) {
  const metadata = bridgeMetadata(frame);
  window.dispatchEvent(new MessageEvent('message', {
    source: frame.contentWindow,
    data: {
      source: 'spore-html', type: 'interaction_ready', artifactId: 'demo',
      ...metadata,
      bridgeInstalled: true,
      coreInteractionsReady: true,
      ready: true,
      restored: true,
      restoreRequested: true,
      initializationPending: false,
      documentReadyState: 'complete',
      restoreReport: { requested: true, parsed: true, success: true, attempted: {}, applied: {}, failures: [] },
      ...overrides,
    },
  }));
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    await Promise.resolve();
    await Promise.resolve();
  });
}

afterEach(() => {
  cleanup();
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('HTML preview', () => {

  it('detects explicit HTML documents, fences, and file names', () => {
    expect(extractStandaloneHtml('<!doctype html><html><body>ok</body></html>')).toContain('<html>');
    expect(extractStandaloneHtml('```html\n<div>ok</div>\n```')).toBe('<div>ok</div>');
    expect(extractStandaloneHtml('Before <div>not standalone</div>')).toBeNull();
    expect(isHtmlFile('report.HTML')).toBe(true);
    expect(isHtmlFile('report.md')).toBe(false);
  });

  it('injects the complete behavior bridge, restrictive CSP, runtime state, and ready token', () => {
    const html = buildSandboxedHtml(`
      <html><head>
        <base href="https://example.com/">
        <meta http-equiv="refresh" content="0;url=https://example.com">
        <script src="https://example.com/app.js"></script>
        <link rel="stylesheet" href="https://example.com/app.css">
      </head><body><iframe src="https://example.com"></iframe><a href="https://example.com">leave</a><script>window.ready = true</script><script>location.href = 'https://example.com'</script></body></html>
    `, undefined, 'demo', undefined, { scroll_x: 0, scroll_y: 90 }, 'document-1',
    'bridge-capability-test-0000000000000000', 'generation-1', 'restore-1');

    expect(html).toContain("connect-src 'none'");
    expect(html).not.toContain('<base');
    expect(html).not.toContain('src="https://example.com/app.js"');
    expect(html).not.toContain('<iframe');
    expect(html).not.toContain('href="https://example.com"');
    expect(html).not.toContain("location.href = 'https://example.com'");
    expect(html).toContain('<script>window.ready = true</script>');
    expect(html).toContain('data-spore-host-bridge');
    expect(html).toMatch(/addEventListener\(["']dblclick["']/);
    expect(html).toMatch(/addEventListener\(["']selectionchange["']/);
    expect(html).toMatch(/addEventListener\(["']copy["']/);
    expect(html).toMatch(/addEventListener\(["']keydown["']/);
    expect(html).toMatch(/addEventListener\(["']pointerdown["']/);
    expect(html).toMatch(/type:\s*["']interaction_ready["']/);
    expect(html).toContain('id="spore-runtime-state"');
    expect(html).toContain('data-spore-document-token="document-1"');
    expect(html).toContain('data-spore-document-generation-id="generation-1"');
    expect(html).toContain('data-spore-restore-attempt-id="restore-1"');
    expect(html).not.toContain('data-spore-bridge-capability');
    expect(html.indexOf('data-spore-host-bridge')).toBeLessThan(html.indexOf('window.ready = true'));
    expect(html).toContain('document.body.inert = hostFrozen');
  });

  it('removes the capability-bearing bridge script before an artifact script can inspect it', () => {
    const capability = 'bridge-secret-capability-0000000000000001';
    const html = buildSandboxedHtml(`
      <html><body>
        <script>
          window.__stolenBridgeCapability =
            document.documentElement.dataset.sporeBridgeCapability ||
            document.querySelector('[data-spore-host-bridge]')?.textContent || '';
          parent.postMessage({
            source: 'spore-html', type: 'interaction_ready', artifactId: 'demo',
            bridgeCapability: window.__stolenBridgeCapability, ready: true,
          }, '*');
        </script>
      </body></html>
    `, undefined, 'demo', undefined, undefined, 'document-malicious', capability, 'generation-malicious', 'restore-malicious');
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    const scripts = Array.from(parsed.querySelectorAll('script'));
    const bridge = scripts[0];
    const artifactScript = scripts[1];

    expect(bridge.getAttribute('data-spore-host-bridge')).toBe('');
    expect(bridge.textContent).toContain(capability);
    expect(bridge.textContent).toContain('bridgeScript?.remove()');
    expect(artifactScript.textContent).toContain('__stolenBridgeCapability');
    expect(parsed.documentElement.dataset.sporeBridgeCapability).toBeUndefined();

    bridge.remove();
    expect(parsed.documentElement.outerHTML).not.toContain(capability);
    expect(parsed.querySelector('[data-spore-host-bridge]')).toBeNull();
  });

  // The iframe sandbox is a security boundary, so the injected policy and the removal of
  // active external surfaces are asserted directly rather than inferred from render behavior.
  it('injects a restrictive CSP and removes active external surfaces', () => {
    const html = buildSandboxedHtml(`
      <html><head>
        <base href="https://example.com/">
        <meta http-equiv="refresh" content="0;url=https://example.com">
        <meta http-equiv="Content-Security-Policy" content="default-src *">
        <script src="https://example.com/app.js"></script>
        <link rel="stylesheet" href="https://example.com/app.css">
      </head><body>
        <iframe src="https://example.com"></iframe>
        <a href="https://example.com">leave</a>
        <a href="#local">stay</a>
        <form action="https://example.com/collect"><button>send</button></form>
        <div onclick="fetch('https://example.com')">tap</div>
        <script>window.ready = true</script>
        <script>location.href = 'https://example.com'</script>
      </body></html>
    `);

    expect(html).toContain("default-src 'none'");
    expect(html).toContain("connect-src 'none'");
    expect(html).toContain("base-uri 'none'");
    expect(html).toContain("form-action 'none'");
    expect(html).not.toContain('<base');
    expect(html).not.toContain('http-equiv="refresh"');
    expect(html).not.toContain('default-src *');
    expect(html).not.toContain('src="https://example.com/app.js"');
    expect(html).not.toContain('href="https://example.com/app.css"');
    expect(html).not.toContain('<iframe');
    expect(html).not.toContain('href="https://example.com"');
    expect(html).not.toContain('action="https://example.com/collect"');
    expect(html).not.toContain("location.href = 'https://example.com'");
    // Inert inline script and in-document navigation are the page's own expression and stay.
    expect(html).toContain('<script>window.ready = true</script>');
    expect(html).toContain('href="#local"');
    // Checked on the parsed element rather than the raw string, because the injected bridge
    // script legitimately contains the word "onclick" and would match a substring assertion.
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    expect(parsed.querySelector('div')?.hasAttribute('onclick')).toBe(false);
    expect(parsed.querySelector('form')?.hasAttribute('action')).toBe(false);
  });

  it('renders content only inside a sandboxed iframe and never sends capability in freeze messages', () => {
    render(<HtmlPreview content="<html><body><h1>Report</h1></body></html>" title="Report" />);
    const frame = screen.getByTitle('Report') as HTMLIFrameElement;
    const postMessage = vi.spyOn(frame.contentWindow!, 'postMessage');
    fireEvent.load(frame);

    expect(frame).toHaveAttribute('sandbox', 'allow-scripts');
    expect(frame).toHaveAttribute('referrerpolicy', 'no-referrer');
    expect(frame.getAttribute('srcdoc')).toContain('<h1>Report</h1>');
    expect(screen.queryByRole('heading', { name: 'Report' })).not.toBeInTheDocument();
    expect(postMessage).toHaveBeenCalledWith({
      source: 'spore-host', type: 'freeze', frozen: false,
    }, '*');
    expect(postMessage.mock.calls.some(([message]) =>
      Object.prototype.hasOwnProperty.call(message, 'bridgeCapability'))).toBe(false);
  });

  it('rejects forged iframe capabilities before collecting any user intent', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    });
    render(<HtmlPreview content={initial} title="Capability isolation" />);
    const frame = screen.getByTitle('Capability isolation') as HTMLIFrameElement;
    const observed = interactionEvent(100, 'PointerToRawData', { spore_request: 'Explain this field' });

    window.dispatchEvent(new MessageEvent('message', {
      source: frame.contentWindow,
      data: {
        source: 'spore-html', type: 'interaction', artifactId: 'demo',
        bridgeCapability: 'forged-bridge-capability', event: observed,
      },
    }));
    await advance(1000);
    expect(interact).not.toHaveBeenCalled();

    act(() => sendInteraction(frame, observed));
    await advance(80);
    expect(interact).toHaveBeenCalledTimes(1);
  });

  it('forms a semantic episode using a dynamic settling window instead of five-second batching', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({ artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, updated_at: 0 });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({ artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1 });
    render(<HtmlPreview content={initial} title="Dynamic report" />);
    const frame = screen.getByTitle('Dynamic report') as HTMLIFrameElement;

    act(() => {
      sendInteraction(frame, interactionEvent(100, 'PointerToRawData', { event_type: 'selection', selection_text: 'PointerToRawData', semantic_ref: 'IMAGE_SECTION_HEADER.PointerToRawData' }));
      sendInteraction(frame, interactionEvent(220, 'PointerToRawData', { event_type: 'dblclick', semantic_ref: 'IMAGE_SECTION_HEADER.PointerToRawData' }));
    });
    expect(getHtmlArtifactId(initial)).toBe('demo');
    expect(interact).not.toHaveBeenCalled();
    await advance(149);
    expect(interact).not.toHaveBeenCalled();
    await advance(1);

    expect(interact).toHaveBeenCalledTimes(1);
    const [artifactId, events, identity, episode] = interact.mock.calls[0];
    expect(artifactId).toBe('demo');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ event_type: 'dblclick', intent_epoch: 1, semantic_ref: 'IMAGE_SECTION_HEADER.PointerToRawData' });
    expect(String(events[0].spore_request)).toContain('explain_semantic_object');
    expect(identity!).toMatchObject({ intent_epoch: 1, base_html_revision: 1, state_revision: 1 });
    expect(identity!.agent_request_id).toMatch(/^request-/);
    expect(identity!.operation_id).toMatch(/^operation-/);
    expect(identity!.base_sha256).toBeTruthy();
    expect(episode).toMatchObject({ confidence: 'high', semantic_focus_ref: 'IMAGE_SECTION_HEADER.PointerToRawData' });
  });

  it('does not escalate a weak operation that the page already satisfied locally', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    const interact = vi.spyOn(htmlApi, 'interact');
    render(<HtmlPreview content={initial} title="Local outcome" />);
    const frame = screen.getByTitle('Local outcome') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'Open', {
      local_outcome: { observed: true, changed: true, satisfied: true, reveal_succeeded: true },
    })));
    await advance(3000);
    expect(interact).not.toHaveBeenCalled();
    expect(screen.queryByTestId('html-interaction-status')).not.toBeInTheDocument();
  });

  it('waits for confirmed pre-barrier cancellation and then starts only the latest episode', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    let resolveCancel: ((state: Awaited<ReturnType<typeof htmlApi.interactionCancel>>) => void) | undefined;
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockImplementation(
      () => new Promise((resolve) => { resolveCancel = resolve; }),
    );
    const interact = vi.spyOn(htmlApi, 'interact')
      .mockImplementationOnce(() => new Promise(() => undefined))
      .mockResolvedValueOnce({ artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1 });
    render(<HtmlPreview content={initial} title="Latest wins" />);
    const frame = screen.getByTitle('Latest wins') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'First', { spore_request: 'Explain first' })));
    await advance(80);
    act(() => sendInteraction(frame, interactionEvent(200, 'Second', { spore_request: 'Explain second' })));
    await advance(80);
    act(() => sendInteraction(frame, interactionEvent(300, 'Third', { spore_request: 'Explain third' })));
    await advance(80);

    expect(cancel).toHaveBeenCalledTimes(1);
    expect(interact).toHaveBeenCalledTimes(1);
    const firstIdentity = interact.mock.calls[0][2]!;
    await act(async () => {
      resolveCancel?.({
        artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2,
        operation_id: firstIdentity.operation_id, agent_request_id: firstIdentity.agent_request_id,
        intent_epoch: 2, updated_at: 0,
      });
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });
    await advance(0);

    expect(interact).toHaveBeenCalledTimes(2);
    expect(interact.mock.calls.map((call) => call[2]?.intent_epoch)).toEqual([1, 4]);
    expect(interact.mock.calls[1][1][0]).toMatchObject({ text: 'Third', intent_epoch: 4 });
  });

  it('retains old operation ownership during cancel and freezes on its committed barrier', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    let barrierCommitted = false;
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async () => {
      const identity = interact.mock.calls[0]?.[2];
      if (!barrierCommitted || !identity) {
        return { artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      }
      return {
        artifact_id: 'demo', phase: 'barrier_committed', frozen: false, revision: 2, state_revision: 2,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: identity.intent_epoch, updated_at: 0,
      };
    });
    let resolveCancel: ((state: Awaited<ReturnType<typeof htmlApi.interactionCancel>>) => void) | undefined;
    vi.spyOn(htmlApi, 'interactionCancel').mockImplementation(
      () => new Promise((resolve) => { resolveCancel = resolve; }),
    );
    render(<HtmlPreview content={initial} title="Cancel barrier ownership" />);
    const frame = screen.getByTitle('Cancel barrier ownership') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Old', { spore_request: 'Explain old' })));
    await advance(80);
    act(() => sendInteraction(frame, interactionEvent(200, 'New', { spore_request: 'Explain new' })));
    await advance(80);
    expect(interact).toHaveBeenCalledTimes(1);

    barrierCommitted = true;
    await advance(220);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    const identity = interact.mock.calls[0][2]!;
    await act(async () => {
      resolveCancel?.({
        artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 3, state_revision: 3,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: 2, updated_at: 0,
      });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
    expect(interact).toHaveBeenCalledTimes(1);
  });

  it('keeps a single weak click local instead of sending it to the Agent', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    const interact = vi.spyOn(htmlApi, 'interact');
    render(<HtmlPreview content={initial} title="Weak focus" />);
    const frame = screen.getByTitle('Weak focus') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'Field', {
      local_outcome: { observed: true, changed: false, satisfied: false },
    })));
    await advance(3000);
    expect(interact).not.toHaveBeenCalled();
  });

  it('holds ambiguous selection locally until the user explicitly confirms explain', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({ artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, updated_at: 0 });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({ artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1 });
    render(<HtmlPreview content={initial} title="Selection intent" />);
    const frame = screen.getByTitle('Selection intent') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'PointerToRawData', {
      event_type: 'selection', selection_text: 'PointerToRawData', semantic_ref: 'PE.PointerToRawData',
    })));
    await advance(450);
    expect(interact).not.toHaveBeenCalled();
    expect(screen.getByTestId('html-intent-candidate')).toBeInTheDocument();

    const candidateToolbar = screen.getByTestId('html-intent-candidate');
    // Toolbar order is build, explain, [compare], dismiss. Build leads, so explain is index 1.
    fireEvent.click(within(candidateToolbar).getAllByRole('button')[1]);
    await advance(1);
    expect(interact).toHaveBeenCalledTimes(1);
    expect(interact.mock.calls[0][2]).toMatchObject({ intent_epoch: 2 });
    expect(String(interact.mock.calls[0][1][0].spore_request)).toContain('Explain PointerToRawData');
  });

  it('cancels an implicit selection explanation when the user copies it', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    const interact = vi.spyOn(htmlApi, 'interact');
    render(<HtmlPreview content={initial} title="Copy intent" />);
    const frame = screen.getByTitle('Copy intent') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'PointerToRawData', {
      event_type: 'selection', selection_text: 'PointerToRawData', semantic_ref: 'PE.PointerToRawData',
    })));
    await advance(450);
    expect(screen.getByTestId('html-intent-candidate')).toBeInTheDocument();
    act(() => sendInteraction(frame, interactionEvent(200, 'PointerToRawData', {
      event_type: 'copy', selection_text: 'PointerToRawData', semantic_ref: 'PE.PointerToRawData',
    })));
    expect(screen.queryByTestId('html-intent-candidate')).not.toBeInTheDocument();
    await advance(3000);
    expect(interact).not.toHaveBeenCalled();
  });

  it('copy supersedes the active pre-barrier request', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    render(<HtmlPreview content={initial} title="Copy supersede" />);
    const frame = screen.getByTitle('Copy supersede') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'PointerToRawData', {
      spore_request: 'Explain this field', semantic_ref: 'PE.PointerToRawData',
    })));
    await advance(80);
    expect(htmlApi.interact).toHaveBeenCalledTimes(1);
    const identity = vi.mocked(htmlApi.interact).mock.calls[0][2]!;

    act(() => sendInteraction(frame, interactionEvent(200, 'PointerToRawData', {
      event_type: 'copy', selection_text: 'PointerToRawData', semantic_ref: 'PE.PointerToRawData',
    })));

    expect(cancel).toHaveBeenCalledWith('demo', {
      operation_id: identity.operation_id,
      agent_request_id: identity.agent_request_id,
      intent_epoch: 2,
      reason: 'user_copied_selection',
    });
    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();
  });

  it('selection_clear supersedes the active pre-barrier request', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    render(<HtmlPreview content={initial} title="Selection clear supersede" />);
    const frame = screen.getByTitle('Selection clear supersede') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'PointerToRawData', {
      spore_request: 'Explain this field', semantic_ref: 'PE.PointerToRawData',
    })));
    await advance(80);
    const identity = vi.mocked(htmlApi.interact).mock.calls[0][2]!;

    act(() => sendInteraction(frame, interactionEvent(200, 'PointerToRawData', {
      event_type: 'selection_clear', semantic_ref: 'PE.PointerToRawData',
    })));

    expect(cancel).toHaveBeenCalledWith('demo', expect.objectContaining({
      operation_id: identity.operation_id,
      agent_request_id: identity.agent_request_id,
      intent_epoch: 2,
      reason: 'user_cleared_selection',
    }));
    await advance(3000);
    expect(htmlApi.interact).toHaveBeenCalledTimes(1);
  });

  it('a weak unrelated focus shift cancels the old active pre-barrier request', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    render(<HtmlPreview content={initial} title="Weak focus shift" />);
    const frame = screen.getByTitle('Weak focus shift') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Old field', {
      spore_request: 'Explain old field', semantic_ref: 'PE.OldField', dom_path: 'body > main > span:nth-of-type(1)',
    })));
    await advance(80);
    const identity = vi.mocked(htmlApi.interact).mock.calls[0][2]!;

    act(() => sendInteraction(frame, interactionEvent(200, 'New field', {
      semantic_ref: 'PE.NewField', dom_path: 'body > aside > span:nth-of-type(1)',
      local_outcome: { observed: true, changed: false, satisfied: false },
    })));

    expect(cancel).toHaveBeenCalledWith('demo', expect.objectContaining({
      operation_id: identity.operation_id,
      intent_epoch: 2,
      reason: 'user_focus_changed',
    }));
    await advance(3000);
    expect(htmlApi.interact).toHaveBeenCalledTimes(1);
  });

  it('remembers a weak focus and combines it with a later related strong signal', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    });
    render(<HtmlPreview content={initial} title="Focus memory" />);
    const frame = screen.getByTitle('Focus memory') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'PointerToRawData', {
      semantic_ref: 'PE.PointerToRawData',
      local_outcome: { observed: true, changed: false, satisfied: false },
    })));
    await advance(760);
    expect(interact).not.toHaveBeenCalled();

    act(() => sendInteraction(frame, interactionEvent(900, 'PointerToRawData', {
      event_type: 'touch_long_press', semantic_ref: 'PE.PointerToRawData',
      local_outcome: { observed: true, changed: false, satisfied: false },
    })));
    await advance(1000);

    expect(interact).toHaveBeenCalledTimes(1);
    const episode = interact.mock.calls[0][3] as SemanticIntentEpisode;
    expect(episode.evidence.map((item) => item.event_type)).toEqual(['click', 'touch_long_press']);
    expect(episode.semantic_focus_ref).toBe('PE.PointerToRawData');
    expect(episode.confidence).toBe('high');
  });

  it('accepts interrupt freeze only for the current non-superseded request', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState')
      .mockResolvedValueOnce({ artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, updated_at: 0 })
      .mockResolvedValue({ artifact_id: 'demo', phase: 'frozen', frozen: true, revision: 2, updated_at: 0 });
    let finishFirst: ((value: HtmlInteractResult) => void) | undefined;
    vi.spyOn(htmlApi, 'interact')
      .mockImplementationOnce(() => new Promise((resolve) => { finishFirst = resolve; }))
      .mockResolvedValueOnce({ artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1 });
    render(<HtmlPreview content={initial} title="Stale interrupt" />);
    const frame = screen.getByTitle('Stale interrupt') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Old', { spore_request: 'Old intent' })));
    await advance(80);
    act(() => sendInteraction(frame, interactionEvent(200, 'Current', { spore_request: 'Current intent' })));
    await advance(80);
    await advance(250);
    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();

    await act(async () => {
      finishFirst?.({ artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1 });
      await Promise.resolve();
      await Promise.resolve();
    });
  });

  it('keeps a committed interrupt barrier frozen across request failure until backend recovery is terminal', async () => {
    vi.useFakeTimers();
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    let rejectInteraction: ((reason?: unknown) => void) | undefined;
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementationOnce(
      () => new Promise((_resolve, reject) => { rejectInteraction = reject; }),
    );
    let terminal = false;
    let stateCalls = 0;
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async () => {
      stateCalls += 1;
      const identity = interact.mock.calls[0]?.[2];
      if (!identity || stateCalls === 1) {
        return { artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      }
      return {
        artifact_id: 'demo', phase: terminal ? 'completed' : 'frozen', frozen: !terminal,
        revision: terminal ? 3 : 2, state_revision: terminal ? 3 : 2,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: identity.intent_epoch, updated_at: 0,
      };
    });
    vi.spyOn(htmlApi, 'interactionRecover').mockRejectedValue(new Error('recovery unavailable'));
    render(<HtmlPreview content={initial} title="Barrier recovery" />);
    const frame = screen.getByTitle('Barrier recovery') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Modify the result area' })));
    await advance(80);
    await advance(220);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await act(async () => {
      rejectInteraction?.(new Error('stream disconnected after interrupt'));
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    terminal = true;
    await advance(220);
    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();
  });

  it('unfreezes only after a matching, complete, successfully restored ready message', async () => {
    vi.useFakeTimers();
    const updated = '<!doctype html><html data-spore-artifact-id="demo"><body><main id="result">Validated</main></body></html>';
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    let finishInteraction: ((value: HtmlInteractResult) => void) | undefined;
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementationOnce(
      () => new Promise((resolve) => { finishInteraction = resolve; }),
    );
    let stateCalls = 0;
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async (requestedArtifactId) => {
      if (requestedArtifactId === 'other') {
        return { artifact_id: 'other', phase: 'idle', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      }
      stateCalls += 1;
      const identity = interact.mock.calls[0]?.[2];
      if (!identity || stateCalls === 1) return { artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      return {
        artifact_id: 'demo', phase: 'frozen', frozen: true, revision: 2, state_revision: 2,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: identity.intent_epoch, updated_at: 0,
      };
    });
    vi.spyOn(htmlApi, 'interactionHeartbeat').mockResolvedValue({ artifact_id: 'demo', phase: 'frozen', frozen: true, revision: 2, state_revision: 2, updated_at: 0 });
    const ready = vi.spyOn(htmlApi, 'interactionReady').mockImplementation(async (_artifactId, payload) => ({
      artifact_id: 'demo', phase: payload.ready ? 'interaction_ready' : 'frozen', frozen: !payload.ready,
      revision: payload.ready ? 5 : 4, state_revision: payload.ready ? 5 : 4,
      operation_id: payload.operation_id, agent_request_id: payload.agent_request_id, updated_at: 0,
    }));
    const view = render(<HtmlPreview content={initial} title="Ready barrier" />);
    const frame = screen.getByTitle('Ready barrier') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', {
      spore_request: 'Add result',
      runtime_state: {
        scroll_x: 0,
        scroll_y: 120,
        active: { element_id: 'run' },
        controls: [{ element_id: 'query', value: 'PE header' }],
        details: [{ element_id: 'section', open: true }],
      },
    })));
    await advance(80);
    await advance(220);
    expect(interact).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
    const identity = interact.mock.calls[0][2]!;

    await act(async () => {
      finishInteraction?.({
        artifact: {}, content: updated, generated: true, decision: 'updated', event_count: 1,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        html_sha256: 'updated-sha', state_revision: 3, requires_interaction_ready_ack: true,
        document_generation_id: 'generation-ready-1', restore_attempt_id: 'restore-ready-1',
        bridge_capability: 'bridge-ready-capability-0000000000000001',
      });
      await Promise.resolve();
    });
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
    expect(frame).toHaveAttribute('aria-busy', 'true');
    expect(frame.getAttribute('srcdoc')).toContain('id="result"');
    expect(frame.getAttribute('srcdoc')).toContain('id="spore-runtime-state"');
    const token = /data-spore-document-token="([^"]+)"/.exec(frame.getAttribute('srcdoc') ?? '')?.[1];
    expect(token).toBeTruthy();

    view.rerender(<HtmlPreview
      content={initial.replace('Run', 'EXTERNAL WHILE AWAITING READY')}
      artifactId="other"
      title="Ready barrier"
    />);
    await advance(0);
    expect(frame.getAttribute('srcdoc')).toContain('id="result"');
    expect(frame.getAttribute('srcdoc')).toContain('data-spore-artifact-id="demo"');
    expect(frame.getAttribute('srcdoc')).not.toContain('EXTERNAL WHILE AWAITING READY');
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await act(async () => {
      sendReady(frame, { documentToken: 'wrong-token' });
      await Promise.resolve();
    });
    expect(ready).not.toHaveBeenCalled();
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await act(async () => {
      sendReady(frame, { documentGenerationId: 'wrong-generation' });
      sendReady(frame, { restoreAttemptId: 'wrong-restore-attempt' });
      sendReady(frame, { bridgeCapability: 'forged-bridge-capability' });
      sendReady(frame, { bridgeCapability: undefined });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(ready).not.toHaveBeenCalled();
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    act(() => sendInteraction(frame, interactionEvent(300, 'Blocked while frozen', {
      spore_request: 'This must not start another request',
    })));
    await advance(80);
    expect(interact).toHaveBeenCalledTimes(1);

    await act(async () => {
      sendReady(frame);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(ready).toHaveBeenCalledTimes(1);
    expect(ready).toHaveBeenLastCalledWith('demo', expect.objectContaining({
      operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
      html_sha256: 'updated-sha', state_revision: 3,
      document_generation_id: 'generation-ready-1', restore_attempt_id: 'restore-ready-1',
      bridge_capability: 'bridge-ready-capability-0000000000000001', ready: true,
    }));
    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();
    expect(frame).toHaveAttribute('aria-busy', 'false');
    expect(frame).toHaveAttribute('tabindex', '0');
  });

  it('keeps the page frozen when iframe runtime-state restoration fails', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    let finishInteraction: ((value: HtmlInteractResult) => void) | undefined;
    vi.spyOn(htmlApi, 'interact').mockImplementationOnce(
      () => new Promise((resolve) => { finishInteraction = resolve; }),
    );
    const ready = vi.spyOn(htmlApi, 'interactionReady').mockImplementation(async (_artifactId, payload) => ({
      artifact_id: 'demo', phase: payload.ready ? 'interaction_ready' : 'failed_after_barrier',
      frozen: !payload.ready, revision: 3, state_revision: 3,
      document_load_result: payload.ready ? 'ready' : 'failed',
      operation_id: payload.operation_id, agent_request_id: payload.agent_request_id, updated_at: 0,
    }));
    const view = render(<HtmlPreview content={initial} title="Restore failure" />);
    const frame = screen.getByTitle('Restore failure') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', {
      spore_request: 'Update result',
      runtime_state: { scroll_x: 0, scroll_y: 80, active: { element_id: 'run' } },
    })));
    await advance(80);
    const identity = vi.mocked(htmlApi.interact).mock.calls[0][2]!;
    await act(async () => {
      finishInteraction?.({
        artifact: {}, content: initial.replace('Run', 'Updated'), generated: true,
        decision: 'updated', event_count: 1, operation_id: identity.operation_id,
        agent_request_id: identity.agent_request_id, html_sha256: 'restore-sha', state_revision: 2,
        requires_interaction_ready_ack: true, document_generation_id: 'generation-restore-1',
        restore_attempt_id: 'restore-attempt-restore-1',
        bridge_capability: 'bridge-restore-capability-0000000000001',
      });
      await Promise.resolve();
      await Promise.resolve();
    });
    const token = /data-spore-document-token="([^"]+)"/.exec(frame.getAttribute('srcdoc') ?? '')?.[1];
    expect(token).toBeTruthy();
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await act(async () => {
      sendReady(frame, { restored: false, restoreReport: { requested: true, parsed: true, success: false, attempted: {}, applied: {}, failures: [{ category: 'active', index: 0, reason: 'ref_not_found' }] } });
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    });

    await advance(1);
    expect(ready).toHaveBeenCalledWith('demo', expect.objectContaining({ ready: false }));
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
    expect(frame).toHaveAttribute('aria-busy', 'true');

    view.rerender(<HtmlPreview
      content={initial.replace('Run', 'EXTERNAL AFTER TERMINAL FAILURE')}
      artifactId="other"
      title="Restore failure"
    />);
    await advance(0);
    expect(frame.getAttribute('srcdoc')).toContain('Updated');
    expect(frame.getAttribute('srcdoc')).toContain('data-spore-artifact-id="demo"');
    expect(frame.getAttribute('srcdoc')).not.toContain('EXTERNAL AFTER TERMINAL FAILURE');
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await act(async () => {
      sendReady(frame, { ready: true, restored: true });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(ready).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
  });
  it('atomically clears a pre-barrier transaction on external content change and ignores its stale result', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    let resolveInteraction: ((result: HtmlInteractResult) => void) | undefined;
    vi.spyOn(htmlApi, 'interact').mockImplementation(
      () => new Promise((resolve) => { resolveInteraction = resolve; }),
    );
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    const view = render(<HtmlPreview content={initial} title="Content transaction reset" />);
    const frame = screen.getByTitle('Content transaction reset') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Explain run' })));
    await advance(80);
    const external = initial.replace('Run', 'External version');
    view.rerender(<HtmlPreview content={external} title="Content transaction reset" />);
    await advance(0);

    expect(cancel).toHaveBeenCalledWith('demo', expect.objectContaining({ reason: 'external_content_changed' }));
    expect(screen.queryByTestId('html-interaction-status')).not.toBeInTheDocument();
    expect(frame.getAttribute('srcdoc')).toContain('External version');

    await act(async () => {
      resolveInteraction?.({
        artifact: {}, content: initial.replace('Run', 'STALE AGENT RESULT'), generated: true,
        decision: 'updated', event_count: 1,
      });
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(frame.getAttribute('srcdoc')).not.toContain('STALE AGENT RESULT');
  });

  it('does not let external content overwrite the page while a barrier is frozen', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    let barrierCommitted = false;
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel');
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async () => {
      const identity = interact.mock.calls[0]?.[2];
      if (!barrierCommitted || !identity) {
        return { artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      }
      return {
        artifact_id: 'demo', phase: 'barrier_committed', frozen: true, revision: 2, state_revision: 2,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: identity.intent_epoch, updated_at: 0,
      };
    });
    const view = render(<HtmlPreview content={initial} title="Frozen content guard" />);
    const frame = screen.getByTitle('Frozen content guard') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Modify page' })));
    await advance(80);
    barrierCommitted = true;
    await advance(220);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    view.rerender(<HtmlPreview
      content={initial.replace('Run', 'EXTERNAL OVERWRITE')}
      artifactId="other"
      title="Frozen content guard"
    />);
    await advance(0);
    expect(frame.getAttribute('srcdoc')).toContain('Run');
    expect(frame.getAttribute('srcdoc')).toContain('data-spore-artifact-id="demo"');
    expect(frame.getAttribute('srcdoc')).not.toContain('EXTERNAL OVERWRITE');
    expect(cancel).not.toHaveBeenCalled();
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
  });

  it('atomically clears intent ownership when the artifact identity changes', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'cancelled', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    const view = render(<HtmlPreview content={initial} title="Artifact reset" />);
    const frame = screen.getByTitle('Artifact reset') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Explain run' })));
    await advance(80);

    view.rerender(<HtmlPreview content={initial} artifactId="other" title="Artifact reset" />);
    await advance(0);
    expect(cancel).toHaveBeenCalledWith('demo', expect.objectContaining({ reason: 'artifact_changed' }));
    expect(screen.queryByTestId('html-interaction-status')).not.toBeInTheDocument();
    expect(frame.getAttribute('srcdoc')).toContain('data-spore-artifact-id="other"');
  });

  it('stops heartbeat scheduling after a terminal failure', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    let phase: 'analyzing' | 'barrier_committed' | 'failed_after_barrier' = 'analyzing';
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async () => {
      const identity = interact.mock.calls[0]?.[2];
      if (!identity || phase === 'analyzing') {
        return { artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0 };
      }
      const failed = phase === 'failed_after_barrier';
      return {
        artifact_id: 'demo', phase, frozen: true, revision: failed ? 3 : 2, state_revision: failed ? 3 : 2,
        operation_id: identity.operation_id, agent_request_id: identity.agent_request_id,
        intent_epoch: identity.intent_epoch, document_load_result: failed ? 'failed' : undefined, updated_at: 0,
      };
    });
    const heartbeat = vi.spyOn(htmlApi, 'interactionHeartbeat').mockResolvedValue({
      artifact_id: 'demo', phase: 'barrier_committed', frozen: true, revision: 2, state_revision: 2, updated_at: 0,
    });
    render(<HtmlPreview content={initial} title="Terminal heartbeat" />);
    const frame = screen.getByTitle('Terminal heartbeat') as HTMLIFrameElement;
    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Modify page' })));
    await advance(80);
    phase = 'barrier_committed';
    await advance(220);
    await advance(20_000);
    expect(heartbeat.mock.calls.length).toBeGreaterThanOrEqual(2);

    phase = 'failed_after_barrier';
    await advance(220);
    const terminalCount = heartbeat.mock.calls.length;
    await advance(30_000);
    expect(heartbeat).toHaveBeenCalledTimes(terminalCount);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
  });
});

describe('HTML interaction API contract', () => {
  it('sends the operation identity, base SHA, and semantic snapshot using backend field names', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
    const identity = {
      intent_epoch: 7, agent_request_id: 'request-7', operation_id: 'operation-7',
      base_html_revision: 3, base_sha256: 'sha-7', state_revision: 11,
    };
    const snapshot = { episode_id: 'episode-7', candidate_intents: ['explain_semantic_object'] };
    await htmlApi.interact('demo', [{ event_type: 'dblclick' }], identity, snapshot);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      events: [{ event_type: 'dblclick' }],
      intent_epoch: 7,
      agent_request_id: 'request-7',
      operation_id: 'operation-7',
      base_html_revision: 3,
      base_html_sha256: 'sha-7',
      state_revision: 11,
      episode_id: 'episode-7',
      intent_snapshot: {
        ...snapshot,
        intent_epoch: 7,
        request_identity: {
          ...identity,
          episode_id: 'episode-7',
        },
      },
    });
  });

  it('restores a backend-owned frozen barrier after remount and waits for lease recovery', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState')
      .mockResolvedValueOnce({
        artifact_id: 'demo', phase: 'failed_after_barrier', frozen: true, revision: 5, state_revision: 5,
        operation_id: 'operation-orphan', agent_request_id: 'request-orphan', document_load_result: 'failed', updated_at: 0,
      })
      .mockResolvedValueOnce({
        artifact_id: 'demo', phase: 'failed_after_barrier', frozen: false, revision: 6, state_revision: 6,
        operation_id: 'operation-orphan', agent_request_id: 'request-orphan', operation_outcome: 'orphan_recovered', updated_at: 0,
      });

    render(<HtmlPreview content={initial} title="Remounted barrier" />);
    await advance(0);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();

    await advance(1000);
    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();
  });

  it('cancels a related pre-barrier request when a medium-confidence local candidate replaces it', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockResolvedValue({
      artifact_id: 'demo', phase: 'superseded', frozen: false, revision: 2, state_revision: 2, updated_at: 0,
    });
    render(<HtmlPreview content={initial} title="Candidate replaces active" />);
    const frame = screen.getByTitle('Candidate replaces active') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Field', {
      semantic_ref: 'PE.Field', spore_request: 'Explain the field',
    })));
    await advance(100);
    expect(htmlApi.interact).toHaveBeenCalledTimes(1);

    act(() => sendInteraction(frame, interactionEvent(300, 'Field', {
      event_type: 'selection', selection_text: 'Field', semantic_ref: 'PE.Field',
    })));
    await advance(500);

    expect(screen.getByTestId('html-intent-candidate')).toBeInTheDocument();
    expect(cancel).toHaveBeenCalledWith('demo', expect.objectContaining({
      intent_epoch: 2, reason: 'new_intent_requires_local_disambiguation',
    }));
  });

  it('advances epoch and cancels an unconfirmed pre-barrier operation when dismissing', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    vi.spyOn(htmlApi, 'interact').mockImplementation(() => new Promise(() => undefined));
    const cancelResolvers: Array<(state: Awaited<ReturnType<typeof htmlApi.interactionCancel>>) => void> = [];
    const cancel = vi.spyOn(htmlApi, 'interactionCancel').mockImplementation(
      () => new Promise((resolve) => { cancelResolvers.push(resolve); }),
    );
    render(<HtmlPreview content={initial} title="Dismiss active candidate" />);
    const frame = screen.getByTitle('Dismiss active candidate') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Field', {
      semantic_ref: 'PE.Field', spore_request: 'Explain the field',
    })));
    await advance(80);
    act(() => sendInteraction(frame, interactionEvent(300, 'Field', {
      event_type: 'selection', selection_text: 'Field', semantic_ref: 'PE.Field',
    })));
    await advance(500);
    const toolbar = screen.getByTestId('html-intent-candidate');
    const buttons = within(toolbar).getAllByRole('button');
    fireEvent.click(buttons[buttons.length - 1]);

    expect(cancel).toHaveBeenCalledTimes(2);
    expect(cancel.mock.calls[0][1]).toMatchObject({ intent_epoch: 2, reason: 'new_intent_requires_local_disambiguation' });
    expect(cancel.mock.calls[1][1]).toMatchObject({ intent_epoch: 3, reason: 'user_dismissed_intent_candidate' });
    expect(screen.queryByTestId('html-intent-candidate')).not.toBeInTheDocument();
    expect(htmlApi.interact).toHaveBeenCalledTimes(1);
  });

  it('dismisses a local candidate together with its focus memory', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, state_revision: 1, updated_at: 0,
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    });
    render(<HtmlPreview content={initial} title="Dismiss focus" />);
    const frame = screen.getByTitle('Dismiss focus') as HTMLIFrameElement;

    act(() => sendInteraction(frame, interactionEvent(100, 'Field', {
      event_type: 'selection', selection_text: 'Field', semantic_ref: 'PE.Field',
    })));
    await advance(500);
    const toolbar = screen.getByTestId('html-intent-candidate');
    const buttons = within(toolbar).getAllByRole('button');
    fireEvent.click(buttons[buttons.length - 1]);
    expect(screen.queryByTestId('html-intent-candidate')).not.toBeInTheDocument();

    act(() => sendInteraction(frame, interactionEvent(600, 'Field', {
      event_type: 'touch_long_press', semantic_ref: 'PE.Field',
    })));
    await advance(1000);

    const episode = interact.mock.calls[0][3] as SemanticIntentEpisode;
    expect(episode.evidence.map((item) => item.event_type)).toEqual(['touch_long_press']);
  });

  it('sends interactionCancel to the cancellation endpoint with the exact identity payload', async () => {
    const response = {
      artifact_id: 'demo/field', phase: 'cancelled', frozen: false,
      revision: 8, state_revision: 8, updated_at: 0,
    };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const payload = {
      operation_id: 'operation-8', agent_request_id: 'request-8',
      intent_epoch: 9, reason: 'user_focus_changed',
    };

    await htmlApi.interactionCancel('demo/field', payload);

    expect(String(fetchMock.mock.calls[0][0])).toContain('/api/html/demo%2Ffield/interaction-cancel');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual(payload);
  });
});

describe('semantic intent episode policy', () => {
  it('collapses click noise into a double-click explanation episode', () => {
    const episode = buildSemanticIntentEpisode([
      interactionEvent(100, 'PointerToRawData'),
      interactionEvent(160, 'PointerToRawData'),
      interactionEvent(220, 'PointerToRawData', { event_type: 'dblclick', semantic_ref: 'PE.PointerToRawData' }),
    ], 4);
    expect(episode).not.toBeNull();
    expect(episode?.evidence).toHaveLength(1);
    expect(episode?.evidence[0].event_type).toBe('dblclick');
    expect(episode?.candidate_intents).toContain('explain_semantic_object');
    expect(episode?.intent_epoch).toBe(4);
  });

  it('creates compare intent only for semantically comparable strong focuses', () => {
    const context = {
      object_type: 'field', domain: 'PE/COFF', container_ref: 'section-table',
    };
    const comparable = buildSemanticIntentEpisode([
      interactionEvent(100, 'VirtualSize', {
        event_type: 'dblclick', semantic_ref: 'PE.VirtualSize', semantic_context: { ...context, object_name: 'VirtualSize' },
      }),
      interactionEvent(300, 'SizeOfRawData', {
        event_type: 'dblclick', semantic_ref: 'PE.SizeOfRawData', semantic_context: { ...context, object_name: 'SizeOfRawData' },
      }),
    ], 1);
    const merelyAdjacent = buildSemanticIntentEpisode([
      interactionEvent(100, 'VirtualSize', {
        event_type: 'dblclick', semantic_ref: 'PE.VirtualSize', dom_path: 'body > main > span:nth-of-type(1)',
      }),
      interactionEvent(300, 'SizeOfRawData', {
        event_type: 'dblclick', semantic_ref: 'PE.SizeOfRawData', dom_path: 'body > main > span:nth-of-type(2)',
      }),
    ], 2);

    expect(comparable?.candidate_intents).toContain('compare_semantic_objects');
    expect(merelyAdjacent?.candidate_intents).not.toContain('compare_semantic_objects');
  });

  it('does not treat local DOM change as semantic satisfaction', () => {
    const changedOnly = interactionEvent(100, 'Reveal field', {
      local_outcome: { observed: true, changed: true, satisfied: false, reveal_succeeded: true },
    });
    const satisfied = interactionEvent(200, 'Reveal field', {
      local_outcome: { observed: true, changed: true, satisfied: true, reveal_succeeded: true },
    });

    expect(shouldIgnoreLocallySatisfiedSignal(changedOnly)).toBe(false);
    expect(buildSemanticIntentEpisode([changedOnly], 3)?.local_outcome).toBe('not_satisfied');
    expect(shouldIgnoreLocallySatisfiedSignal(satisfied)).toBe(true);
    expect(buildSemanticIntentEpisode([satisfied], 4)).toBeNull();
  });

  it('produces a real SHA-256 digest when WebCrypto is unavailable', async () => {
    vi.stubGlobal('crypto', {});
    await expect(sha256Text('abc')).resolves.toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('uses signal-specific dynamic windows', () => {
    expect(dynamicWindowDelay(interactionEvent(1, 'Copy', { event_type: 'copy' }), 1)).toBe(100);
    expect(dynamicWindowDelay(interactionEvent(1, 'Input', { event_type: 'input' }), 1)).toBe(700);
    expect(dynamicWindowDelay(interactionEvent(1, 'Explicit', { spore_request: 'Explain' }), 1)).toBe(80);
    expect(dynamicWindowDelay(
      interactionEvent(220, 'PointerToRawData', { event_type: 'dblclick' }),
      2,
      { recentCadenceMs: 120 },
    )).toBe(150);
  });
});
describe('HTML interaction epoch baseline and dispatch freeze', () => {
  it('lifts the local epoch baseline from the epoch the backend already admitted', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'idle', frozen: false, revision: 1, state_revision: 1,
      coordinator_latest_epoch: 12, updated_at: 0,
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    });
    render(<HtmlPreview content={initial} title="Epoch baseline" />);
    const frame = screen.getByTitle('Epoch baseline') as HTMLIFrameElement;
    await advance(0);

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Modify the result area' })));
    await advance(80);
    await advance(300);

    // A preview that keeps counting from its own zero emits an epoch the backend already
    // treats as stale, and then every later intent is dropped without a trace.
    expect(interact).toHaveBeenCalledTimes(1);
    expect(interact.mock.calls[0][2].intent_epoch).toBeGreaterThan(12);
  });

  it('realigns an intent epoch the backend would reject before dispatching it', async () => {
    vi.useFakeTimers();
    vi.spyOn(htmlApi, 'load').mockRejectedValue(new Error('not persisted'));
    let stateCalls = 0;
    vi.spyOn(htmlApi, 'interactionState').mockImplementation(async () => {
      stateCalls += 1;
      return {
        artifact_id: 'demo', phase: 'idle', frozen: false, revision: stateCalls, state_revision: stateCalls,
        // The admitted epoch only becomes observable on the baseline read taken inside dispatch.
        coordinator_latest_epoch: stateCalls === 1 ? undefined : 40, updated_at: 0,
      };
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValue({
      artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
    });
    render(<HtmlPreview content={initial} title="Epoch realign" />);
    const frame = screen.getByTitle('Epoch realign') as HTMLIFrameElement;
    await advance(0);

    act(() => sendInteraction(frame, interactionEvent(100, 'Run', { spore_request: 'Modify the result area' })));
    await advance(80);
    await advance(300);

    expect(interact).toHaveBeenCalledTimes(1);
    expect(interact.mock.calls[0][2].intent_epoch).toBe(41);
  });
});