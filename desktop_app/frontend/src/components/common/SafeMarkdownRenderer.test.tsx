// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { SafeMarkdownRenderer } from './SafeMarkdownRenderer';

describe('SafeMarkdownRenderer', () => {
  it('renders file Markdown and highlighted code', () => {
    const { container } = render(
      <SafeMarkdownRenderer
        variant="file"
        content={'# Document\n\n| A | B |\n| --- | --- |\n| 1 | 2 |\n\n```xml\n<root value="1" />\n```'}
      />
    );
    expect(container.firstChild).toHaveClass('markdown-renderer--file');
    expect(screen.getByRole('heading', { name: 'Document' })).toBeInTheDocument();
    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(container.querySelector('code.language-xml .hljs-tag')).toBeInTheDocument();
  });

  it('never executes raw HTML or loads Markdown images', () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => undefined);
    const { container } = render(
      <SafeMarkdownRenderer content={'<script>alert(1)</script> ![remote](https://example.com/pixel.png)'} />
    );
    expect(container.querySelector('script')).not.toBeInTheDocument();
    expect(container.querySelector('img')).not.toBeInTheDocument();
    expect(container.textContent).toContain('<script>alert(1)</script>');
    expect(alertSpy).not.toHaveBeenCalled();
    alertSpy.mockRestore();
  });

  it('allows safe external links and blocks relative or dangerous links', () => {
    render(
      <SafeMarkdownRenderer content={'[safe](https://example.com) [relative](./guide.md) [bad](javascript:alert(1))'} />
    );
    expect(screen.getByRole('link', { name: 'safe' })).toHaveAttribute('rel', 'noopener noreferrer nofollow');
    expect(screen.queryByRole('link', { name: 'relative' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'bad' })).not.toBeInTheDocument();
  });
});
