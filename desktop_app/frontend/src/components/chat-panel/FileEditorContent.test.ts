import { describe, expect, it } from 'vitest';
import { MAX_HIGHLIGHT_CHARS } from '../common/SyntaxHighlighter';
import { getHtmlArtifactIdFromPath, shouldUseMarkdownFilePreview } from './FileEditorContent';
import { isHtmlFile } from '../common/HtmlPreview';

describe('file preview dispatch', () => {
  it('uses semantic preview only for Markdown documents', () => {
    expect(shouldUseMarkdownFilePreview('README.md', '# Title')).toBe(true);
    expect(shouldUseMarkdownFilePreview('guide.markdown', '# Title')).toBe(true);
    expect(shouldUseMarkdownFilePreview('component.mdx', '# Title')).toBe(false);
    expect(shouldUseMarkdownFilePreview('page.html', '# Title')).toBe(false);
    expect(shouldUseMarkdownFilePreview('script.js', '# Title')).toBe(false);
  });

  it('falls back to source preview for large Markdown files', () => {
    expect(shouldUseMarkdownFilePreview('README.md', 'x'.repeat(MAX_HIGHLIGHT_CHARS + 1))).toBe(false);
  });

  it('recognizes only HTML file extensions for sandbox preview', () => {
    expect(isHtmlFile('output/report.html')).toBe(true);
    expect(isHtmlFile('output/report.htm')).toBe(true);
    expect(isHtmlFile('output/report.html.txt')).toBe(false);
    expect(getHtmlArtifactIdFromPath('html/report.html')).toBe('report');
    expect(getHtmlArtifactIdFromPath('output/report.html')).toBeUndefined();
  });
});
