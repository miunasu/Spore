import { useMemo, type Ref, type UIEventHandler } from 'react';
import { common, createLowlight } from 'lowlight';
import type { Element, Root, RootContent, Text } from 'hast';
import { t, localeTag } from '../../i18n';
import { getFileLanguage, type CodeLanguage, type FileLanguageInfo } from './codeLanguages';

export type SyntaxLanguageId = CodeLanguage;
export type SyntaxLanguageInfo = FileLanguageInfo;

type SyntaxHighlighterProps = {
  content: string;
  fileName: string;
  language?: CodeLanguage;
  viewerRef?: Ref<HTMLDivElement>;
  onScroll?: UIEventHandler<HTMLDivElement>;
  className?: string;
};

type Token = {
  text: string;
  className?: string;
};

type HighlightedLine = {
  tokens: Token[];
};

type HighlightModel = {
  lines: HighlightedLine[];
  notice?: string;
};

export const MAX_HIGHLIGHT_CHARS = 250_000;
export const MAX_RENDER_CHARS = 600_000;
export const MAX_RENDER_LINES = 8_000;

const lowlight = createLowlight(common);

export function getSyntaxLanguage(fileName: string, content = ''): SyntaxLanguageInfo {
  return getFileLanguage(fileName, content);
}

export function SyntaxHighlighter({
  content,
  fileName,
  language,
  viewerRef,
  onScroll,
  className = '',
}: SyntaxHighlighterProps) {
  const languageInfo = getSyntaxLanguage(fileName, content);
  const languageId = language ?? languageInfo.id;
  const model = useMemo(() => buildHighlightModel(content, languageId), [content, languageId]);

  return (
    <div
      ref={viewerRef}
      className={`syntax-viewer ${className}`}
      data-language={languageId}
      onScroll={onScroll}
    >
      {model.notice && <div className="syntax-notice">{model.notice}</div>}
      {model.lines.map((line, lineIndex) => (
        <div className="syntax-line" key={`${lineIndex}-${line.tokens.length}`}>
          <span className="syntax-line-number">{lineIndex + 1}</span>
          <code className="syntax-code">
            {line.tokens.map((token, tokenIndex) => (
              <span key={`${lineIndex}-${tokenIndex}`} className={token.className}>
                {token.text}
              </span>
            ))}
          </code>
        </div>
      ))}
    </div>
  );
}

export function buildHighlightModel(content: string, language: SyntaxLanguageId): HighlightModel {
  const truncatedContent = content.length > MAX_RENDER_CHARS
    ? content.slice(0, MAX_RENDER_CHARS)
    : content;
  const rawLines = truncatedContent.split('\n');
  const limitedLines = rawLines.length > MAX_RENDER_LINES
    ? rawLines.slice(0, MAX_RENDER_LINES)
    : rawLines;
  const limitedContent = limitedLines.join('\n');
  const previewContent = sanitizePreviewText(limitedContent);

  const notices: string[] = [];
  if (content.length > MAX_RENDER_CHARS) {
    notices.push(t('sidePanel.syntax.largeContent', { count: formatCount(MAX_RENDER_CHARS) }));
  }
  if (rawLines.length > MAX_RENDER_LINES) {
    notices.push(t('sidePanel.syntax.tooManyLines', { count: formatCount(MAX_RENDER_LINES) }));
  }
  if (previewContent !== limitedContent) {
    notices.push(t('sidePanel.syntax.controlCharsReplaced'));
  }

  if (previewContent.length > MAX_HIGHLIGHT_CHARS || language === 'plaintext') {
    if (previewContent.length > MAX_HIGHLIGHT_CHARS) {
      notices.push(t('sidePanel.syntax.highlightDisabled'));
    }
    return {
      lines: toPlainLines(previewContent),
      notice: notices.join(t('sidePanel.syntax.separator')),
    };
  }

  try {
    return {
      lines: highlightWithLowlight(previewContent, language),
      notice: notices.join(t('sidePanel.syntax.separator')),
    };
  } catch (error) {
    console.error('Syntax highlight failed:', error);
    return {
      lines: toPlainLines(previewContent),
      notice: t('sidePanel.syntax.highlightFailed'),
    };
  }
}

function highlightWithLowlight(content: string, language: CodeLanguage): HighlightedLine[] {
  if (language === 'plaintext') return toPlainLines(content);
  const highlightLanguage = language === 'jsx'
    ? 'javascript'
    : language === 'tsx'
      ? 'typescript'
      : language;
  const tree = lowlight.highlight(highlightLanguage, content);
  return lowlightTreeToLines(tree);
}

function lowlightTreeToLines(tree: Root): HighlightedLine[] {
  const lines: HighlightedLine[] = [{ tokens: [] }];
  appendNodesToLines(tree.children, lines, []);
  return lines;
}

function appendNodesToLines(
  nodes: RootContent[],
  lines: HighlightedLine[],
  inheritedClasses: string[]
) {
  for (const node of nodes) {
    if (node.type === 'text') {
      appendTextToLines(node, lines, inheritedClasses);
      continue;
    }
    if (node.type === 'element') {
      const classes = getElementClasses(node);
      appendNodesToLines(node.children, lines, [...inheritedClasses, ...classes]);
    }
  }
}

function appendTextToLines(node: Text, lines: HighlightedLine[], classes: string[]) {
  const parts = node.value.split('\n');
  for (let index = 0; index < parts.length; index++) {
    if (parts[index]) {
      lines[lines.length - 1].tokens.push({
        text: parts[index],
        className: classes.length > 0 ? classes.join(' ') : undefined,
      });
    }
    if (index < parts.length - 1) lines.push({ tokens: [] });
  }
}

function getElementClasses(node: Element) {
  const className = node.properties.className;
  if (Array.isArray(className)) return className.map(String);
  return [];
}

function toPlainLines(content: string): HighlightedLine[] {
  return content.split('\n').map((line) => ({ tokens: [{ text: line }] }));
}

function formatCount(value: number) {
  return value.toLocaleString(localeTag());
}

function sanitizePreviewText(content: string) {
  return Array.from(content, (character) => {
    const code = character.charCodeAt(0);
    const isDisallowedControl = code <= 8 || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127;
    return isDisallowedControl ? '�' : character;
  }).join('');
}
