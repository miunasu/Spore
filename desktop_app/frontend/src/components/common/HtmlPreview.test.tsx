// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { htmlApi } from '../../services/api';
import {
  HtmlPreview,
  buildSandboxedHtml,
  extractStandaloneHtml,
  getHtmlArtifactId,
  isHtmlFile,
} from './HtmlPreview';

describe('HTML preview', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('detects explicit HTML documents, fences, and file names', () => {
    expect(extractStandaloneHtml('<!doctype html><html><body>ok</body></html>')).toContain('<html>');
    expect(extractStandaloneHtml('```html\n<div>ok</div>\n```')).toBe('<div>ok</div>');
    expect(extractStandaloneHtml('Before <div>not standalone</div>')).toBeNull();
    expect(isHtmlFile('report.HTML')).toBe(true);
    expect(isHtmlFile('report.md')).toBe(false);
  });

  it('injects a restrictive CSP and removes active external surfaces', () => {
    const html = buildSandboxedHtml(`
      <html><head>
        <base href="https://example.com/">
        <meta http-equiv="refresh" content="0;url=https://example.com">
        <script src="https://example.com/app.js"></script>
        <link rel="stylesheet" href="https://example.com/app.css">
      </head><body><iframe src="https://example.com"></iframe><a href="https://example.com">leave</a><script>window.ready = true</script><script>location.href = 'https://example.com'</script></body></html>
    `);

    expect(html).toContain("connect-src 'none'");
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain('<base');
    expect(html).not.toContain('http-equiv="refresh"');
    expect(html).not.toContain('src="https://example.com/app.js"');
    expect(html).not.toContain('<iframe');
    expect(html).not.toContain('href="https://example.com"');
    expect(html).not.toContain("location.href = 'https://example.com'");
    expect(html).toContain('<script>window.ready = true</script>');
    expect(html).toContain('data-spore-host-bridge');
    expect(html).toContain(":nth-of-type(");
    expect(html).toContain("parts.unshift('body')");
    expect(html).toContain("document.addEventListener('input'");
    expect(html).toContain("document.addEventListener('change'");
    expect(html).toContain("document.addEventListener('submit'");
    expect(html).toContain('document.body.inert = hostFrozen');
  });

  it('renders content only inside a sandboxed iframe', () => {
    render(<HtmlPreview content="<html><body><h1>Report</h1></body></html>" title="Report" />);
    const frame = screen.getByTitle('Report');
    expect(frame).toHaveAttribute('sandbox', 'allow-scripts');
    expect(frame).toHaveAttribute('referrerpolicy', 'no-referrer');
    expect(frame.getAttribute('srcdoc')).toContain('<h1>Report</h1>');
    expect(screen.queryByRole('heading', { name: 'Report' })).not.toBeInTheDocument();
  });

  it('batches trusted iframe interactions for five seconds before requesting the Agent', async () => {
    vi.useFakeTimers();
    const initial = '<!doctype html><html data-spore-artifact-id="demo"><body><button data-spore-target="details">Open</button></body></html>';
    const updated = '<!doctype html><html data-spore-artifact-id="demo"><body><section id="details">Ready</section></body></html>';
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not running'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, updated_at: 0,
    });
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValueOnce({
      artifact: {}, content: updated, generated: true, decision: 'updated', event_count: 2, iterations: 1,
    });
    render(<HtmlPreview content={initial} title="Dynamic report" />);
    const frame = screen.getByTitle('Dynamic report') as HTMLIFrameElement;

    expect(getHtmlArtifactId(initial)).toBe('demo');
    const sendClick = (timestamp: number, text: string, word: string) => {
      window.dispatchEvent(new MessageEvent('message', {
        source: frame.contentWindow,
        data: {
          source: 'spore-html', type: 'click', artifactId: 'demo',
          event: {
            timestamp_ms: timestamp, tag: 'button', element_id: '', role: '', text,
            clicked_word: word, aria_label: '', title: '', href: '', spore_target: 'details',
            spore_request: 'Build details', dom_path: 'main > button', ancestors: ['main'],
            scroll_y: 20, viewport: { width: 800, height: 600 },
          },
        },
      }));
    };
    act(() => {
      sendClick(100, 'Open', 'Open');
      sendClick(850, 'Details', 'Details');
    });

    expect(interact).not.toHaveBeenCalled();
    expect(screen.getByTestId('html-interaction-status')).toHaveAttribute('data-collecting-count', '2');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });

    expect(interact).toHaveBeenCalledTimes(1);
    const events = interact.mock.calls[0][1];
    expect(events).toHaveLength(2);
    expect(events.map((event) => event.elapsed_ms)).toEqual([0, 750]);
    expect(events.map((event) => event.clicked_word)).toEqual(['Open', 'Details']);
    expect(frame.getAttribute('srcdoc')).toContain('id="details"');
  });

  it('freezes the iframe after interrupt state and unfreezes only after validated content returns', async () => {
    vi.useFakeTimers();
    const initial = '<!doctype html><html data-spore-artifact-id="demo"><body><button>Run</button></body></html>';
    const updated = '<!doctype html><html data-spore-artifact-id="demo"><body><main id="result">Validated</main></body></html>';
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not running'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'frozen', frozen: true, revision: 2, updated_at: 0,
    });
    let finishInteraction: ((value: {
      artifact: Record<string, unknown>; content: string; generated: boolean;
      decision: 'updated'; event_count: number;
    }) => void) | undefined;
    const interact = vi.spyOn(htmlApi, 'interact').mockImplementationOnce(
      () => new Promise((resolve) => { finishInteraction = resolve; })
    );

    render(<HtmlPreview content={initial} title="Frozen report" />);
    const frame = screen.getByTitle('Frozen report') as HTMLIFrameElement;
    act(() => {
      window.dispatchEvent(new MessageEvent('message', {
        source: frame.contentWindow,
        data: {
          source: 'spore-html', type: 'interaction', artifactId: 'demo',
          event: {
            timestamp_ms: 100, event_type: 'click', tag: 'button', element_id: '',
            role: '', text: 'Run', clicked_word: 'Run', aria_label: '', title: '',
            href: '', spore_target: '', spore_request: '', dom_path: 'body > button:nth-of-type(1)',
            ancestors: ['body'], scroll_y: 0, viewport: { width: 800, height: 600 },
          },
        },
      }));
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
      await Promise.resolve();
    });

    expect(interact).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('html-interaction-freeze')).toBeInTheDocument();
    expect(frame).toHaveAttribute('aria-busy', 'true');
    expect(frame).toHaveAttribute('tabindex', '-1');

    await act(async () => {
      finishInteraction?.({
        artifact: {}, content: updated, generated: true, decision: 'updated', event_count: 1,
      });
      await Promise.resolve();
    });

    expect(screen.queryByTestId('html-interaction-freeze')).not.toBeInTheDocument();
    expect(frame).toHaveAttribute('aria-busy', 'false');
    expect(frame).toHaveAttribute('tabindex', '0');
    expect(frame.getAttribute('srcdoc')).toContain('id="result"');
  });

  it('queues a later interaction window while the previous Agent call is running', async () => {
    vi.useFakeTimers();
    const initial = '<!doctype html><html data-spore-artifact-id="demo"><body><button>Run</button></body></html>';
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not running'));
    vi.spyOn(htmlApi, 'interactionState').mockResolvedValue({
      artifact_id: 'demo', phase: 'analyzing', frozen: false, revision: 1, updated_at: 0,
    });
    let finishFirst: ((value: {
      artifact: Record<string, unknown>; content: string; generated: boolean;
      decision: 'no_change'; event_count: number;
    }) => void) | undefined;
    const interact = vi.spyOn(htmlApi, 'interact')
      .mockImplementationOnce(() => new Promise((resolve) => { finishFirst = resolve; }))
      .mockResolvedValueOnce({
        artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
      });
    render(<HtmlPreview content={initial} title="Queued report" />);
    const frame = screen.getByTitle('Queued report') as HTMLIFrameElement;
    const sendClick = (timestamp: number, text: string) => {
      window.dispatchEvent(new MessageEvent('message', {
        source: frame.contentWindow,
        data: {
          source: 'spore-html', type: 'click', artifactId: 'demo',
          event: {
            timestamp_ms: timestamp, tag: 'button', element_id: '', role: '', text,
            clicked_word: text, aria_label: '', title: '', href: '', spore_target: '',
            spore_request: '', dom_path: 'button', ancestors: ['body'], scroll_y: 0,
            viewport: { width: 800, height: 600 },
          },
        },
      }));
    };

    act(() => sendClick(100, 'First'));
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(interact).toHaveBeenCalledTimes(1);

    act(() => sendClick(2500, 'Second'));
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(interact).toHaveBeenCalledTimes(1);

    await act(async () => {
      finishFirst?.({
        artifact: {}, content: initial, generated: false, decision: 'no_change', event_count: 1,
      });
      await Promise.resolve();
    });
    expect(interact).toHaveBeenCalledTimes(2);
    expect(interact.mock.calls[1][1][0].text).toBe('Second');
  });
});
