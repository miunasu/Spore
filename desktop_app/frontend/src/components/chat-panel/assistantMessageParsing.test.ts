// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import {
  detectWholeCode,
  normalizeLanguageAlias,
  prepareAssistantMarkdown,
  safeLinkUrl,
  wrapCodeAsMarkdownFence,
} from './assistantMessageParsing';

describe('assistant message parsing', () => {
  it('detects complete JSON objects and arrays', () => {
    expect(detectWholeCode('{"name":"spore"}')?.language).toBe('json');
    expect(detectWholeCode('[1, 2, 3]')?.language).toBe('json');
    expect(detectWholeCode('42')).toBeNull();
  });

  it('detects complete XML and rejects incomplete or mixed XML', () => {
    expect(detectWholeCode('<?xml version="1.0"?><root><item id="1" /></root>')?.language).toBe('xml');
    expect(detectWholeCode('<root>\n  <item value="1" />\n</root>')?.language).toBe('xml');
    expect(detectWholeCode('<root>')).toBeNull();
    expect(detectWholeCode('<root></root> explanation')).toBeNull();
  });

  it('detects JavaScript, TypeScript, JSX and TSX with meaningful syntax', () => {
    expect(detectWholeCode('const add = (a, b) => a + b;')?.language).toBe('javascript');
    expect(detectWholeCode('interface User { name: string }')?.language).toBe('typescript');
    expect(detectWholeCode('const view = <main>Hello</main>;')?.language).toBe('jsx');
    expect(detectWholeCode('const view: JSX.Element = <main>Hello</main>;')?.language).toBe('tsx');
    expect(detectWholeCode('hello')).toBeNull();
    expect(detectWholeCode('1 + 2')).toBeNull();
  });

  it('does not reinterpret explicit Markdown', () => {
    expect(detectWholeCode('# Heading\n\n- item')).toBeNull();
    expect(detectWholeCode('```js\nconst value = 1;\n```')).toBeNull();
    expect(detectWholeCode('| a | b |\n| --- | --- |\n| 1 | 2 |')).toBeNull();
  });

  it('uses conservative detectors for other common languages', () => {
    expect(detectWholeCode('#!/usr/bin/env python\ndef main():\n    print("ok")')?.language).toBe('python');
    expect(detectWholeCode('#!/usr/bin/env bash\nfor item in "$@"; do\n  echo "$item"\ndone')?.language).toBe('bash');
    expect(detectWholeCode('SELECT id, name FROM users WHERE active = 1;')?.language).toBe('sql');
    expect(detectWholeCode('package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("ok") }')?.language).toBe('go');
    expect(detectWholeCode('标题: 这是普通文本')).toBeNull();
  });

  it('normalizes common language aliases', () => {
    expect(normalizeLanguageAlias('js')).toBe('javascript');
    expect(normalizeLanguageAlias('HTML')).toBe('xml');
    expect(normalizeLanguageAlias('c++')).toBe('cpp');
    expect(normalizeLanguageAlias('unknown')).toBeNull();
  });

  it('uses a fence longer than backtick runs in code', () => {
    const wrapped = wrapCodeAsMarkdownFence('const fence = "```";', 'javascript');
    expect(wrapped.startsWith('````javascript\n')).toBe(true);
    expect(wrapped.endsWith('\n````')).toBe(true);
  });

  it('only transforms complete bare code', () => {
    expect(prepareAssistantMarkdown('const ok = true;')).toContain('```javascript');
    expect(prepareAssistantMarkdown('普通的 **Markdown** 回复')).toBe('普通的 **Markdown** 回复');
  });

  it('allows only safe link protocols', () => {
    expect(safeLinkUrl('https://example.com')).toBe('https://example.com');
    expect(safeLinkUrl('mailto:test@example.com')).toBe('mailto:test@example.com');
    expect(safeLinkUrl('#section')).toBe('#section');
    expect(safeLinkUrl('javascript:alert(1)')).toBeNull();
    expect(safeLinkUrl('data:text/html,test')).toBeNull();
    expect(safeLinkUrl('file:///etc/passwd')).toBeNull();
    expect(safeLinkUrl('/relative')).toBeNull();
  });
});
