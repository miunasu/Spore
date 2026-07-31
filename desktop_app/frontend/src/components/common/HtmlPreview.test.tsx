// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { htmlApi } from '../../services/api';
import {
  HtmlPreview,
  buildSandboxedHtml,
  extractStandaloneHtml,
  getHtmlArtifactId,
  isHtmlFile,
} from './HtmlPreview';

describe('HTML preview', () => {
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
  });

  it('renders content only inside a sandboxed iframe', () => {
    render(<HtmlPreview content="<html><body><h1>Report</h1></body></html>" title="Report" />);
    const frame = screen.getByTitle('Report');
    expect(frame).toHaveAttribute('sandbox', 'allow-scripts');
    expect(frame).toHaveAttribute('referrerpolicy', 'no-referrer');
    expect(frame.getAttribute('srcdoc')).toContain('<h1>Report</h1>');
    expect(screen.queryByRole('heading', { name: 'Report' })).not.toBeInTheDocument();
  });

  it('identifies persisted artifacts and requests a missing dynamic target', async () => {
    const initial = '<!doctype html><html data-spore-artifact-id="demo"><body><button data-spore-target="details">Open</button></body></html>';
    const updated = '<!doctype html><html data-spore-artifact-id="demo"><body><section id="details">Ready</section></body></html>';
    vi.spyOn(htmlApi, 'load').mockRejectedValueOnce(new Error('not running'));
    const interact = vi.spyOn(htmlApi, 'interact').mockResolvedValueOnce({
      artifact: {}, content: updated, generated: true, target: 'details', iterations: 1,
    });
    render(<HtmlPreview content={initial} title="Dynamic report" />);
    const frame = screen.getByTitle('Dynamic report') as HTMLIFrameElement;

    expect(getHtmlArtifactId(initial)).toBe('demo');
    await act(async () => {
      window.dispatchEvent(new MessageEvent('message', {
        source: frame.contentWindow,
        data: {
          source: 'spore-html', type: 'missing-target', artifactId: 'demo', target: 'details',
          request: 'Build details', action: 'click', triggerText: 'Open',
        },
      }));
    });

    await waitFor(() => expect(interact).toHaveBeenCalledWith('demo', {
      target: 'details', request: 'Build details', action: 'click', trigger_text: 'Open',
    }));
    await waitFor(() => expect(frame.getAttribute('srcdoc')).toContain('id="details"'));
    vi.restoreAllMocks();
  });
});
