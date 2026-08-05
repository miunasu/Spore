// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildDynamicBridge, DYNAMIC_BRIDGE } from './htmlBridge';

type ReadyReport = {
  type: string;
  bridgeCapability: string;
  ready: boolean;
  restored: boolean;
  restoreRequested: boolean;
  restoreReport: {
    parsed: boolean;
    success: boolean;
    attempted: Record<string, number>;
    applied: Record<string, number>;
    failures: Array<{ kind: string; reason: string }>;
  };
};

async function runBridge(
  runtimeState: unknown,
  body: string,
  bridgeCapability = 'bridge-test-capability-0000000000000001',
): Promise<ReadyReport> {
  vi.useFakeTimers();
  document.documentElement.dataset.sporeArtifactId = 'artifact-a';
  document.documentElement.dataset.sporeDocumentToken = 'document-a';
  document.documentElement.dataset.sporeReady = 'true';
  document.body.innerHTML = `${body}<script id="spore-runtime-state" type="application/json">${JSON.stringify(runtimeState)}</script>`;
  Object.defineProperty(window, 'requestAnimationFrame', {
    configurable: true,
    value: (callback: FrameRequestCallback) => window.setTimeout(() => callback(Date.now()), 0),
  });
  Object.defineProperty(window, 'scrollTo', { configurable: true, value: vi.fn() });
  const reports: ReadyReport[] = [];
  vi.spyOn(window, 'postMessage').mockImplementation((message: unknown) => {
    if ((message as ReadyReport)?.type === 'interaction_ready') reports.push(message as ReadyReport);
  });

  window.eval(buildDynamicBridge(bridgeCapability));
  await vi.advanceTimersByTimeAsync(3_100);
  const report = reports[reports.length - 1];
  if (!report) throw new Error('bridge did not emit a readiness report');
  return report;
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.innerHTML = '';
  delete document.documentElement.dataset.sporeArtifactId;
  delete document.documentElement.dataset.sporeDocumentToken;
  delete document.documentElement.dataset.sporeReady;
  delete document.documentElement.dataset.sporeFrozen;
});

describe('HTML sandbox bridge privacy and restore policy', () => {
  it('keeps the capability closure-only, trusts freeze only from parent, and signs bridge reports', async () => {
    const capability = 'bridge-test-capability-closure-000000000001';
    const reportPromise = runBridge(undefined, '<button id="run">Run</button>', capability);

    expect(document.documentElement.hasAttribute('data-spore-bridge-capability')).toBe(false);
    window.dispatchEvent(new MessageEvent('message', {
      source: null,
      data: { source: 'spore-host', type: 'freeze', frozen: true },
    }));
    expect(document.documentElement.dataset.sporeFrozen).toBeUndefined();

    window.dispatchEvent(new MessageEvent('message', {
      source: window,
      data: { source: 'spore-host', type: 'freeze', frozen: true },
    }));
    expect(document.documentElement.dataset.sporeFrozen).toBe('true');

    const report = await reportPromise;
    expect(report.bridgeCapability).toBe(capability);
    expect(buildDynamicBridge(capability)).toContain('bridgeScript?.remove()');
    expect(buildDynamicBridge(capability)).not.toContain('event.data?.bridgeCapability');
  });

  it('emits a strict failed restore report when a required ref cannot be restored', async () => {
    const report = await runBridge({
      scroll_x: 0,
      scroll_y: 0,
      controls: [{ element_id: 'missing', checked: true }],
    }, '<input id="present" type="checkbox">');

    expect(report.restoreRequested).toBe(true);
    expect(report.restored).toBe(false);
    expect(report.ready).toBe(false);
    expect(report.restoreReport.parsed).toBe(true);
    expect(report.restoreReport.success).toBe(false);
    expect(report.restoreReport.attempted.controls).toBe(1);
    expect(report.restoreReport.applied.controls).toBe(0);
    expect(report.restoreReport.failures).toContainEqual(expect.objectContaining({
      kind: 'controls',
      reason: 'ref_not_found',
    }));
  });

  it('restores only explicitly observable values and strips URL query and fragment', async () => {
    const report = await runBridge({
      scroll_x: 0,
      scroll_y: 0,
      controls: [{ element_id: 'url', value: 'https://example.test/path?token=secret#private' }],
    }, '<input id="url" type="url" data-spore-observe-value>');

    expect((document.getElementById('url') as HTMLInputElement).value).toBe('https://example.test/path');
    expect(report.restored).toBe(true);
    expect(report.restoreReport.success).toBe(true);
    expect(report.restoreReport.applied.controls).toBe(1);
  });

  it('keeps control value collection opt-in and privacy-sanitizes emitted hrefs', () => {
    expect(DYNAMIC_BRIDGE).toMatch(/hasAttribute\([\"']data-spore-observe-value[\"']\)/);
    expect(DYNAMIC_BRIDGE).toMatch(/value:\s*observedControlValue\(node\)/);
    expect(DYNAMIC_BRIDGE).not.toMatch(/sensitive\(node\)\s*\?\s*undefined\s*:\s*clean\(node\.value/);
    expect(DYNAMIC_BRIDGE).toMatch(/href\s*=\s*privacySafeUrl\(rawHref,\s*500\)/);
  });
});

