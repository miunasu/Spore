import { describe, expect, it } from 'vitest';
import { MAX_HIGHLIGHT_CHARS } from '../common/SyntaxHighlighter';
import { shouldUseMarkdownFilePreview } from './FileEditorContent';

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
});
