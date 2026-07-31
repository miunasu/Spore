import { describe, expect, it } from 'vitest';
import {
  getFileLanguage,
  isSemanticMarkdownFile,
  normalizeLanguageAlias,
} from './codeLanguages';

describe('code languages', () => {
  it('uses file extensions before content inference', () => {
    expect(getFileLanguage('page.html', '# Markdown').id).toBe('xml');
    expect(getFileLanguage('script.js', '<root />').id).toBe('javascript');
    expect(getFileLanguage('config.json', 'plain text').id).toBe('json');
  });

  it('classifies Markdown and MDX preview modes safely', () => {
    expect(getFileLanguage('README.md').previewKind).toBe('markdown');
    expect(isSemanticMarkdownFile('README.md')).toBe(true);
    expect(isSemanticMarkdownFile('guide.markdown')).toBe(true);
    expect(getFileLanguage('component.mdx').previewKind).toBe('source');
    expect(isSemanticMarkdownFile('component.mdx')).toBe(false);
    expect(isSemanticMarkdownFile('notes.txt')).toBe(false);
  });

  it('covers common source formats', () => {
    expect(getFileLanguage('component.tsx').id).toBe('tsx');
    expect(getFileLanguage('style.css').id).toBe('css');
    expect(getFileLanguage('query.sql').id).toBe('sql');
    expect(getFileLanguage('main.rs').id).toBe('rust');
    expect(getFileLanguage('settings.yaml').id).toBe('yaml');
  });

  it('normalizes fenced-code aliases', () => {
    expect(normalizeLanguageAlias('JS')).toBe('javascript');
    expect(normalizeLanguageAlias('html')).toBe('xml');
    expect(normalizeLanguageAlias('c++')).toBe('cpp');
    expect(normalizeLanguageAlias('unknown')).toBeNull();
  });
});
