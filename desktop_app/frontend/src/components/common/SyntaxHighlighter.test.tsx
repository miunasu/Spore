// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { buildHighlightModel, SyntaxHighlighter } from './SyntaxHighlighter';

describe('SyntaxHighlighter', () => {
  it('highlights XML and keeps markup as text', () => {
    const { container } = render(
      <SyntaxHighlighter content={'<root value="1"><script>alert(1)</script></root>'} fileName="page.xml" />
    );
    expect(container.querySelector('script')).not.toBeInTheDocument();
    expect(container.querySelector('.hljs-tag')).toBeInTheDocument();
    expect(container.textContent).toContain('<script>');
  });

  it('highlights JavaScript, TypeScript, JSX and TSX aliases', () => {
    expect(buildHighlightModel('const value = 1;', 'javascript').lines.flatMap((line) => line.tokens).some((token) => token.className?.includes('hljs-keyword'))).toBe(true);
    expect(buildHighlightModel('interface User { name: string }', 'typescript').lines.flatMap((line) => line.tokens).some((token) => token.className?.includes('hljs-keyword'))).toBe(true);
    expect(buildHighlightModel('const node = <main />;', 'jsx').lines.length).toBeGreaterThan(0);
    expect(buildHighlightModel('const node: JSX.Element = <main />;', 'tsx').lines.length).toBeGreaterThan(0);
  });

  it('renders line numbers and falls back for plain text', () => {
    const { container } = render(
      <SyntaxHighlighter content={'first\nsecond'} fileName="notes.txt" />
    );
    expect(container.querySelectorAll('.syntax-line-number')).toHaveLength(2);
    expect(container.querySelectorAll('.hljs-keyword')).toHaveLength(0);
  });
});
