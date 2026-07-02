import { useMemo } from 'react';

type TokenKind =
  | 'keyword'
  | 'string'
  | 'comment'
  | 'number'
  | 'function'
  | 'type'
  | 'operator'
  | 'punctuation'
  | 'property'
  | 'constant'
  | 'decorator'
  | 'link'
  | 'heading'
  | 'emphasis'
  | 'variable';

type Token = {
  text: string;
  kind?: TokenKind;
};

type HighlightedLine = {
  tokens: Token[];
};

export type SyntaxLanguageId =
  | 'markdown'
  | 'python'
  | 'c'
  | 'cpp'
  | 'javascript'
  | 'typescript'
  | 'json'
  | 'shell'
  | 'plain';

export type SyntaxLanguageInfo = {
  id: SyntaxLanguageId;
  label: string;
};

type SyntaxHighlighterProps = {
  content: string;
  fileName: string;
  className?: string;
};

type HighlightModel = {
  lines: HighlightedLine[];
  notice?: string;
};

const MAX_HIGHLIGHT_CHARS = 250_000;
const MAX_RENDER_CHARS = 600_000;
const MAX_RENDER_LINES = 8_000;
const MAX_TOKENIZED_LINE_CHARS = 4_000;

const PLAIN_LANGUAGE: SyntaxLanguageInfo = { id: 'plain', label: 'Plain text' };

const EXTENSION_LANGUAGE: Record<string, SyntaxLanguageInfo> = {
  md: { id: 'markdown', label: 'Markdown' },
  markdown: { id: 'markdown', label: 'Markdown' },
  mdx: { id: 'markdown', label: 'MDX' },
  py: { id: 'python', label: 'Python' },
  pyw: { id: 'python', label: 'Python' },
  c: { id: 'c', label: 'C' },
  h: { id: 'c', label: 'C/C++ Header' },
  cpp: { id: 'cpp', label: 'C++' },
  cc: { id: 'cpp', label: 'C++' },
  cxx: { id: 'cpp', label: 'C++' },
  hpp: { id: 'cpp', label: 'C++ Header' },
  hh: { id: 'cpp', label: 'C++ Header' },
  hxx: { id: 'cpp', label: 'C++ Header' },
  js: { id: 'javascript', label: 'JavaScript' },
  jsx: { id: 'javascript', label: 'JavaScript JSX' },
  mjs: { id: 'javascript', label: 'JavaScript' },
  cjs: { id: 'javascript', label: 'JavaScript' },
  ts: { id: 'typescript', label: 'TypeScript' },
  tsx: { id: 'typescript', label: 'TypeScript TSX' },
  json: { id: 'json', label: 'JSON' },
  jsonc: { id: 'javascript', label: 'JSONC' },
  sh: { id: 'shell', label: 'Shell' },
  bash: { id: 'shell', label: 'Bash' },
  zsh: { id: 'shell', label: 'Zsh' },
  ps1: { id: 'shell', label: 'PowerShell' },
};

const FILE_NAME_LANGUAGE: Record<string, SyntaxLanguageInfo> = {
  dockerfile: { id: 'shell', label: 'Dockerfile' },
  makefile: { id: 'shell', label: 'Makefile' },
  'package.json': { id: 'json', label: 'JSON' },
  tsconfig: { id: 'json', label: 'JSON' },
};

const C_KEYWORDS = new Set([
  'auto',
  'break',
  'case',
  'char',
  'const',
  'continue',
  'default',
  'do',
  'double',
  'else',
  'enum',
  'extern',
  'float',
  'for',
  'goto',
  'if',
  'inline',
  'int',
  'long',
  'register',
  'restrict',
  'return',
  'short',
  'signed',
  'sizeof',
  'static',
  'struct',
  'switch',
  'typedef',
  'union',
  'unsigned',
  'void',
  'volatile',
  'while',
  '_Bool',
  '_Complex',
  '_Imaginary',
]);

const CPP_KEYWORDS = new Set([
  ...C_KEYWORDS,
  'alignas',
  'alignof',
  'and',
  'and_eq',
  'asm',
  'bitand',
  'bitor',
  'bool',
  'catch',
  'class',
  'compl',
  'concept',
  'constexpr',
  'consteval',
  'constinit',
  'const_cast',
  'co_await',
  'co_return',
  'co_yield',
  'decltype',
  'delete',
  'dynamic_cast',
  'explicit',
  'export',
  'false',
  'friend',
  'mutable',
  'namespace',
  'new',
  'noexcept',
  'not',
  'not_eq',
  'nullptr',
  'operator',
  'or',
  'or_eq',
  'private',
  'protected',
  'public',
  'reinterpret_cast',
  'requires',
  'static_assert',
  'static_cast',
  'template',
  'this',
  'thread_local',
  'throw',
  'true',
  'try',
  'typename',
  'using',
  'virtual',
  'wchar_t',
  'xor',
  'xor_eq',
]);

const JS_KEYWORDS = new Set([
  'async',
  'await',
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'export',
  'extends',
  'finally',
  'for',
  'from',
  'function',
  'if',
  'import',
  'in',
  'instanceof',
  'let',
  'new',
  'of',
  'return',
  'static',
  'super',
  'switch',
  'this',
  'throw',
  'try',
  'typeof',
  'var',
  'void',
  'while',
  'with',
  'yield',
]);

const TS_KEYWORDS = new Set([
  ...JS_KEYWORDS,
  'abstract',
  'as',
  'declare',
  'enum',
  'implements',
  'interface',
  'keyof',
  'namespace',
  'never',
  'private',
  'protected',
  'public',
  'readonly',
  'satisfies',
  'type',
  'unknown',
]);

const PYTHON_KEYWORDS = new Set([
  'False',
  'None',
  'True',
  'and',
  'as',
  'assert',
  'async',
  'await',
  'break',
  'class',
  'continue',
  'def',
  'del',
  'elif',
  'else',
  'except',
  'finally',
  'for',
  'from',
  'global',
  'if',
  'import',
  'in',
  'is',
  'lambda',
  'nonlocal',
  'not',
  'or',
  'pass',
  'raise',
  'return',
  'try',
  'while',
  'with',
  'yield',
]);

const PYTHON_BUILTINS = new Set([
  'abs',
  'all',
  'any',
  'bool',
  'bytes',
  'dict',
  'enumerate',
  'filter',
  'float',
  'int',
  'len',
  'list',
  'map',
  'open',
  'print',
  'range',
  'set',
  'str',
  'sum',
  'tuple',
  'type',
  'zip',
]);

const SHELL_KEYWORDS = new Set([
  'case',
  'do',
  'done',
  'elif',
  'else',
  'esac',
  'fi',
  'for',
  'function',
  'if',
  'in',
  'select',
  'then',
  'until',
  'while',
]);

const CONSTANTS = new Set([
  'false',
  'False',
  'None',
  'NULL',
  'null',
  'nullptr',
  'true',
  'True',
  'undefined',
]);

const NUMBER_PATTERN = /^(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/;

export function getSyntaxLanguage(fileName: string, content = ''): SyntaxLanguageInfo {
  const name = fileName.split(/[\\/]/).pop()?.toLowerCase() ?? fileName.toLowerCase();
  const byName = FILE_NAME_LANGUAGE[name];
  if (byName) return byName;

  const extension = name.includes('.') ? name.split('.').pop() ?? '' : '';
  return EXTENSION_LANGUAGE[extension] ?? detectLanguageFromContent(content);
}

export function SyntaxHighlighter({ content, fileName, className = '' }: SyntaxHighlighterProps) {
  const language = getSyntaxLanguage(fileName, content);
  const model = useMemo(() => buildHighlightModel(content, language.id), [content, language.id]);

  return (
    <div className={`syntax-viewer ${className}`} data-language={language.id}>
      {model.notice && <div className="syntax-notice">{model.notice}</div>}
      {model.lines.map((line, lineIndex) => (
        <div className="syntax-line" key={`${lineIndex}-${line.tokens.length}`}>
          <span className="syntax-line-number">{lineIndex + 1}</span>
          <code className="syntax-code">
            {line.tokens.map((token, tokenIndex) => (
              <span
                key={`${lineIndex}-${tokenIndex}`}
                className={token.kind ? `syntax-token syntax-token--${token.kind}` : undefined}
              >
                {token.text}
              </span>
            ))}
          </code>
        </div>
      ))}
    </div>
  );
}

function detectLanguageFromContent(content: string): SyntaxLanguageInfo {
  const sample = content.slice(0, 20_000);
  const trimmed = sample.trimStart();

  if (/^[{[]/.test(trimmed)) {
    try {
      JSON.parse(trimmed);
      return { id: 'json', label: 'JSON' };
    } catch {
      if (/^\s*"[^"]+"\s*:/m.test(sample)) {
        return { id: 'json', label: 'JSON-like' };
      }
    }
  }

  if (/^(#{1,6}\s|[-*+]\s|\d+[.)]\s|>\s|```)/m.test(sample)) {
    return { id: 'markdown', label: 'Markdown' };
  }

  if (
    /^#!.*\bpython\b/.test(trimmed) ||
    /(^|\n)\s*(from\s+\w[\w.]*\s+import\s+|import\s+\w|def\s+\w+\s*\(|class\s+\w+)/.test(sample)
  ) {
    return { id: 'python', label: 'Python' };
  }

  if (/(^|\n)\s*#\s*include\s*[<"]|(^|\n)\s*(int|void|char|static)\s+\w+\s*\([^)]*\)\s*\{/.test(sample)) {
    return { id: 'c', label: 'C/C++' };
  }

  return PLAIN_LANGUAGE;
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
    notices.push(`文件内容较大，仅显示前 ${formatCount(MAX_RENDER_CHARS)} 个字符`);
  }
  if (rawLines.length > MAX_RENDER_LINES) {
    notices.push(`仅显示前 ${formatCount(MAX_RENDER_LINES)} 行`);
  }
  if (previewContent !== limitedContent) {
    notices.push('已替换不可见控制字符');
  }

  if (previewContent.length > MAX_HIGHLIGHT_CHARS || language === 'plain') {
    if (previewContent.length > MAX_HIGHLIGHT_CHARS) {
      notices.push('已关闭语法高亮以避免界面卡死');
    }
    return {
      lines: toPlainLines(previewContent),
      notice: notices.join('；'),
    };
  }

  try {
    return {
      lines: highlightContent(previewContent, language),
      notice: notices.join('；'),
    };
  } catch (error) {
    console.error('Syntax highlight failed:', error);
    return {
      lines: toPlainLines(previewContent),
      notice: '语法高亮失败，已切换为纯文本预览',
    };
  }
}

function toPlainLines(content: string): HighlightedLine[] {
  return content.split('\n').map((line) => ({ tokens: [{ text: line }] }));
}

function formatCount(value: number) {
  return value.toLocaleString('zh-CN');
}

function sanitizePreviewText(content: string) {
  return content.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '�');
}

function highlightContent(content: string, language: SyntaxLanguageId): HighlightedLine[] {
  switch (language) {
    case 'markdown':
      return highlightMarkdown(content);
    case 'python':
      return highlightPython(content);
    case 'c':
    case 'cpp':
    case 'javascript':
    case 'typescript':
    case 'json':
      return highlightCLike(content, language);
    case 'shell':
      return highlightShell(content);
    default:
      return toPlainLines(content);
  }
}

function pushToken(tokens: Token[], text: string, kind?: TokenKind) {
  if (!text) return;
  const previous = tokens[tokens.length - 1];
  if (previous && previous.kind === kind) {
    previous.text += text;
    return;
  }
  tokens.push({ text, kind });
}

function highlightMarkdown(content: string): HighlightedLine[] {
  let inFence = false;

  return content.split('\n').map((line) => {
    try {
      if (line.length > MAX_TOKENIZED_LINE_CHARS) {
        return { tokens: [{ text: line }] };
      }

      const tokens: Token[] = [];
      const trimmed = line.trimStart();
      const leadingLength = line.length - trimmed.length;
      const leading = line.slice(0, leadingLength);

      if (/^(```|~~~)/.test(trimmed)) {
        pushToken(tokens, leading);
        pushToken(tokens, trimmed, 'keyword');
        inFence = !inFence;
        return { tokens };
      }

      if (inFence) {
        pushToken(tokens, line, 'string');
        return { tokens };
      }

      const heading = /^(#{1,6})(\s+.*)?$/.exec(trimmed);
      if (heading) {
        pushToken(tokens, leading);
        pushToken(tokens, heading[1], 'keyword');
        pushToken(tokens, heading[2] ?? '', 'heading');
        return { tokens };
      }

      const quote = /^(>+)(\s?.*)$/.exec(trimmed);
      if (quote) {
        pushToken(tokens, leading);
        pushToken(tokens, quote[1], 'comment');
        pushToken(tokens, quote[2], 'comment');
        return { tokens };
      }

      const listItem = /^((?:[-+*]|\d+[.)])\s+)(.*)$/.exec(trimmed);
      if (listItem) {
        pushToken(tokens, leading);
        pushToken(tokens, listItem[1], 'punctuation');
        tokenizeMarkdownInline(listItem[2], tokens);
        return { tokens };
      }

      const tableSeparator = /^\|?(?:\s*:?-{3,}:?\s*\|)+\s*$/.exec(trimmed);
      if (tableSeparator) {
        pushToken(tokens, line, 'punctuation');
        return { tokens };
      }

      tokenizeMarkdownInline(line, tokens);
      return { tokens };
    } catch (error) {
      console.error('Markdown highlight line failed:', error);
      return { tokens: [{ text: line }] };
    }
  });
}

function tokenizeMarkdownInline(line: string, tokens: Token[]) {
  let index = 0;

  while (index < line.length) {
    const rest = line.slice(index);
    const code = /^`[^`]*`/.exec(rest);
    if (code) {
      pushToken(tokens, code[0], 'string');
      index += code[0].length;
      continue;
    }

    const strong = /^(\*\*[^*]+\*\*|__[^_]+__)/.exec(rest);
    if (strong) {
      pushToken(tokens, strong[0], 'emphasis');
      index += strong[0].length;
      continue;
    }

    const emphasis = /^(\*[^*\s][^*]*\*|_[^_\s][^_]*_)/.exec(rest);
    if (emphasis) {
      pushToken(tokens, emphasis[0], 'emphasis');
      index += emphasis[0].length;
      continue;
    }

    const link = /^!?\[[^\]]+\]\([^)]+\)/.exec(rest) ?? /^(?:https?:\/\/|www\.)\S+/.exec(rest);
    if (link) {
      pushToken(tokens, link[0], 'link');
      index += link[0].length;
      continue;
    }

    pushToken(tokens, line[index]);
    index++;
  }
}

function highlightCLike(content: string, language: SyntaxLanguageId): HighlightedLine[] {
  let inBlockComment = false;
  const keywords = getCLikeKeywords(language);
  const allowComments = language !== 'json';
  const allowBacktickStrings = language === 'javascript' || language === 'typescript';

  return content.split('\n').map((line) => {
    try {
      if (line.length > MAX_TOKENIZED_LINE_CHARS) {
        return { tokens: [{ text: line }] };
      }

      const tokens: Token[] = [];
      let index = 0;

      if (allowComments) {
        const firstNonSpace = line.search(/\S/);
        if (firstNonSpace >= 0 && line[firstNonSpace] === '#') {
          pushToken(tokens, line.slice(0, firstNonSpace));
          const directive = /^#\s*[A-Za-z_]\w*/.exec(line.slice(firstNonSpace));
          if (directive) {
            pushToken(tokens, directive[0], 'keyword');
            index = firstNonSpace + directive[0].length;
          }
        }
      }

      while (index < line.length) {
        if (inBlockComment) {
          const closeIndex = line.indexOf('*/', index);
          if (closeIndex === -1) {
            pushToken(tokens, line.slice(index), 'comment');
            index = line.length;
          } else {
            pushToken(tokens, line.slice(index, closeIndex + 2), 'comment');
            index = closeIndex + 2;
            inBlockComment = false;
          }
          continue;
        }

        if (allowComments && line.startsWith('/*', index)) {
          const closeIndex = line.indexOf('*/', index + 2);
          if (closeIndex === -1) {
            pushToken(tokens, line.slice(index), 'comment');
            inBlockComment = true;
            index = line.length;
          } else {
            pushToken(tokens, line.slice(index, closeIndex + 2), 'comment');
            index = closeIndex + 2;
          }
          continue;
        }

        if (allowComments && line.startsWith('//', index)) {
          pushToken(tokens, line.slice(index), 'comment');
          break;
        }

        const char = line[index];
        if (char === '"' || char === "'" || (allowBacktickStrings && char === '`')) {
          const end = readQuotedString(line, index, char);
          const kind = language === 'json' && peekNextNonWhitespace(line, end) === ':' ? 'property' : 'string';
          pushToken(tokens, line.slice(index, end), kind);
          index = end;
          continue;
        }

        if (/\s/.test(char)) {
          const nextIndex = readWhile(line, index, (value) => /\s/.test(value));
          pushToken(tokens, line.slice(index, nextIndex));
          index = nextIndex;
          continue;
        }

        const number = NUMBER_PATTERN.exec(line.slice(index));
        if (number) {
          pushToken(tokens, number[0], 'number');
          index += number[0].length;
          continue;
        }

        if (isIdentifierStart(char)) {
          const nextIndex = readWhile(line, index + 1, isIdentifierPart);
          const value = line.slice(index, nextIndex);
          pushToken(tokens, value, classifyCLikeIdentifier(value, language, keywords, line, nextIndex));
          index = nextIndex;
          continue;
        }

        if (/[{}()[\].,;:]/.test(char)) {
          pushToken(tokens, char, 'punctuation');
        } else {
          pushToken(tokens, char, 'operator');
        }
        index++;
      }

      return { tokens };
    } catch (error) {
      console.error('C-like highlight line failed:', error);
      return { tokens: [{ text: line }] };
    }
  });
}

function getCLikeKeywords(language: SyntaxLanguageId): Set<string> {
  switch (language) {
    case 'cpp':
      return CPP_KEYWORDS;
    case 'javascript':
      return JS_KEYWORDS;
    case 'typescript':
      return TS_KEYWORDS;
    case 'json':
      return CONSTANTS;
    default:
      return C_KEYWORDS;
  }
}

function classifyCLikeIdentifier(
  value: string,
  language: SyntaxLanguageId,
  keywords: Set<string>,
  line: string,
  nextIndex: number
): TokenKind | undefined {
  if (keywords.has(value)) return 'keyword';
  if (CONSTANTS.has(value)) return 'constant';
  if (language === 'json') return undefined;
  if (peekNextNonWhitespace(line, nextIndex) === '(') return 'function';
  if (/^[A-Z][A-Za-z0-9_]*$/.test(value)) return 'type';
  return undefined;
}

function highlightPython(content: string): HighlightedLine[] {
  let activeTripleQuote: string | null = null;

  return content.split('\n').map((line) => {
    try {
      if (line.length > MAX_TOKENIZED_LINE_CHARS) {
        return { tokens: [{ text: line }] };
      }

      const tokens: Token[] = [];
      let index = 0;
      let expectedDefinitionKind: TokenKind | null = null;
      const firstNonSpace = line.search(/\S/);

      while (index < line.length) {
        if (activeTripleQuote) {
          const closeIndex = line.indexOf(activeTripleQuote, index);
          if (closeIndex === -1) {
            pushToken(tokens, line.slice(index), 'string');
            index = line.length;
          } else {
            pushToken(tokens, line.slice(index, closeIndex + activeTripleQuote.length), 'string');
            index = closeIndex + activeTripleQuote.length;
            activeTripleQuote = null;
          }
          continue;
        }

        const stringStart = matchPythonStringStart(line, index);
        if (stringStart) {
          if (stringStart.quote.length === 3) {
            const contentStart = index + stringStart.rawStart.length;
            const closeIndex = line.indexOf(stringStart.quote, contentStart);
            if (closeIndex === -1) {
              pushToken(tokens, line.slice(index), 'string');
              activeTripleQuote = stringStart.quote;
              index = line.length;
            } else {
              pushToken(tokens, line.slice(index, closeIndex + stringStart.quote.length), 'string');
              index = closeIndex + stringStart.quote.length;
            }
          } else {
            const quoteIndex = index + stringStart.rawStart.length - 1;
            const end = readQuotedString(line, quoteIndex, stringStart.quote);
            pushToken(tokens, line.slice(index, end), 'string');
            index = end;
          }
          expectedDefinitionKind = null;
          continue;
        }

        const char = line[index];
        if (char === '#') {
          pushToken(tokens, line.slice(index), 'comment');
          break;
        }

        if (firstNonSpace === index && char === '@') {
          const decorator = /^@[A-Za-z_][\w.]*/.exec(line.slice(index));
          if (decorator) {
            pushToken(tokens, decorator[0], 'decorator');
            index += decorator[0].length;
            continue;
          }
        }

        if (/\s/.test(char)) {
          const nextIndex = readWhile(line, index, (value) => /\s/.test(value));
          pushToken(tokens, line.slice(index, nextIndex));
          index = nextIndex;
          continue;
        }

        const number = NUMBER_PATTERN.exec(line.slice(index));
        if (number) {
          pushToken(tokens, number[0], 'number');
          index += number[0].length;
          expectedDefinitionKind = null;
          continue;
        }

        if (isIdentifierStart(char)) {
          const nextIndex = readWhile(line, index + 1, isIdentifierPart);
          const value = line.slice(index, nextIndex);

          if (expectedDefinitionKind) {
            pushToken(tokens, value, expectedDefinitionKind);
            expectedDefinitionKind = null;
          } else if (PYTHON_KEYWORDS.has(value)) {
            pushToken(tokens, value, 'keyword');
            if (value === 'def') expectedDefinitionKind = 'function';
            if (value === 'class') expectedDefinitionKind = 'type';
          } else if (PYTHON_BUILTINS.has(value) || peekNextNonWhitespace(line, nextIndex) === '(') {
            pushToken(tokens, value, 'function');
          } else if (CONSTANTS.has(value)) {
            pushToken(tokens, value, 'constant');
          } else if (value === 'self' || value === 'cls') {
            pushToken(tokens, value, 'variable');
          } else {
            pushToken(tokens, value);
          }

          index = nextIndex;
          continue;
        }

        if (/[{}()[\].,;:]/.test(char)) {
          pushToken(tokens, char, 'punctuation');
        } else {
          pushToken(tokens, char, 'operator');
        }
        expectedDefinitionKind = null;
        index++;
      }

      return { tokens };
    } catch (error) {
      console.error('Python highlight line failed:', error);
      return { tokens: [{ text: line }] };
    }
  });
}

function matchPythonStringStart(line: string, index: number) {
  const match = /^(?:[rRuUbBfF]{1,3})?("""|'''|"|')/.exec(line.slice(index));
  if (!match) return null;
  return {
    quote: match[1],
    rawStart: match[0],
  };
}

function highlightShell(content: string): HighlightedLine[] {
  return content.split('\n').map((line) => {
    try {
      if (line.length > MAX_TOKENIZED_LINE_CHARS) {
        return { tokens: [{ text: line }] };
      }

      const tokens: Token[] = [];
      let index = 0;

      while (index < line.length) {
        const char = line[index];

        if (char === '#') {
          pushToken(tokens, line.slice(index), 'comment');
          break;
        }

        if (char === '"' || char === "'") {
          const end = readQuotedString(line, index, char);
          pushToken(tokens, line.slice(index, end), 'string');
          index = end;
          continue;
        }

        if (char === '$') {
          const variable = /^\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?/.exec(line.slice(index));
          if (variable) {
            pushToken(tokens, variable[0], 'variable');
            index += variable[0].length;
            continue;
          }
        }

        if (/\s/.test(char)) {
          const nextIndex = readWhile(line, index, (value) => /\s/.test(value));
          pushToken(tokens, line.slice(index, nextIndex));
          index = nextIndex;
          continue;
        }

        const number = NUMBER_PATTERN.exec(line.slice(index));
        if (number) {
          pushToken(tokens, number[0], 'number');
          index += number[0].length;
          continue;
        }

        if (isIdentifierStart(char)) {
          const nextIndex = readWhile(line, index + 1, isIdentifierPart);
          const value = line.slice(index, nextIndex);
          pushToken(tokens, value, SHELL_KEYWORDS.has(value) ? 'keyword' : undefined);
          index = nextIndex;
          continue;
        }

        if (/[{}()[\].,;:]/.test(char)) {
          pushToken(tokens, char, 'punctuation');
        } else {
          pushToken(tokens, char, 'operator');
        }
        index++;
      }

      return { tokens };
    } catch (error) {
      console.error('Shell highlight line failed:', error);
      return { tokens: [{ text: line }] };
    }
  });
}

function readQuotedString(line: string, startIndex: number, quote: string) {
  let index = startIndex + quote.length;
  let escaped = false;

  while (index < line.length) {
    const char = line[index];
    if (escaped) {
      escaped = false;
      index++;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      index++;
      continue;
    }
    if (line.startsWith(quote, index)) {
      return index + quote.length;
    }
    index++;
  }

  return line.length;
}

function readWhile(line: string, startIndex: number, predicate: (char: string) => boolean) {
  let index = startIndex;
  while (index < line.length && predicate(line[index])) {
    index++;
  }
  return index;
}

function peekNextNonWhitespace(line: string, startIndex: number) {
  const match = /^\s*(.)/.exec(line.slice(startIndex));
  return match?.[1] ?? '';
}

function isIdentifierStart(char: string) {
  return /[A-Za-z_$]/.test(char);
}

function isIdentifierPart(char: string) {
  return /[A-Za-z0-9_$]/.test(char);
}
