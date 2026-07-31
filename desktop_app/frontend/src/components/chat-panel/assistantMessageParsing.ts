import { parse, type ParserPlugin } from '@babel/parser';
import { normalizeLanguageAlias, type CodeLanguage } from '../common/codeLanguages';

export type SupportedCodeLanguage = CodeLanguage;

export type DetectedCode = {
  language: SupportedCodeLanguage;
  code: string;
};

const MARKDOWN_BLOCK_PATTERN = /^(?: {0,3}#{1,6}\s+| {0,3}(?:[-+*]|\d+[.)])\s+| {0,3}>\s+| {0,3}(?:```|~~~))/m;
const MARKDOWN_TABLE_PATTERN = /^\s*\|?.+\|.+\n\s*\|?\s*:?-{3,}/m;

export { normalizeLanguageAlias } from '../common/codeLanguages';

export function detectWholeCode(content: string): DetectedCode | null {
  const trimmed = content.trim();
  if (!trimmed || hasExplicitCodeFence(trimmed)) return null;

  const json = detectJson(trimmed);
  if (json) return json;

  const xml = detectXml(trimmed);
  if (xml) return xml;

  if (looksLikeMarkdown(trimmed)) return null;

  const script = detectJavaScriptFamily(trimmed);
  if (script) return script;

  const detectedLanguage = detectOtherLanguage(trimmed);
  return detectedLanguage ? { language: detectedLanguage, code: trimmed } : null;
}

export function wrapCodeAsMarkdownFence(code: string, language: SupportedCodeLanguage): string {
  const normalizedLanguage = normalizeLanguageAlias(language) ?? 'plaintext';
  const longestRun = Math.max(0, ...Array.from(code.matchAll(/`+/g), (match) => match[0].length));
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return `${fence}${normalizedLanguage}\n${code}\n${fence}`;
}

export function prepareAssistantMarkdown(content: string): string {
  const detected = detectWholeCode(content);
  return detected ? wrapCodeAsMarkdownFence(detected.code, detected.language) : content;
}

export { safeLinkUrl } from '../common/SafeMarkdownRenderer';

function hasExplicitCodeFence(content: string) {
  return /^(?: {0,3})(?:```|~~~)/m.test(content);
}

function looksLikeMarkdown(content: string) {
  return MARKDOWN_BLOCK_PATTERN.test(content) || MARKDOWN_TABLE_PATTERN.test(content);
}

function detectJson(content: string): DetectedCode | null {
  if (!/^[{[]/.test(content)) return null;
  try {
    const value: unknown = JSON.parse(content);
    if (value !== null && typeof value === 'object') {
      return { language: 'json', code: content };
    }
  } catch {
    // Invalid or mixed JSON is rendered as ordinary Markdown.
  }
  return null;
}

function detectXml(content: string): DetectedCode | null {
  if (!/^\s*(?:<\?xml\b|<!DOCTYPE\b|<[A-Za-z_][\w:.-]*(?:\s|>|\/))/i.test(content)) return null;

  const parser = new DOMParser();
  const document = parser.parseFromString(content, 'application/xml');
  if (document.querySelector('parsererror') || !document.documentElement) return null;

  const root = document.documentElement;
  const hasDeclaration = /^\s*(?:<\?xml\b|<!DOCTYPE\b)/i.test(content);
  const hasClosingTag = new RegExp(`<\\/${escapeRegExp(root.tagName)}\\s*>\\s*$`, 'i').test(content);
  const isSelfClosing = /\/\s*>\s*$/.test(content);
  const hasNestedElement = root.children.length > 0;
  const hasAttributes = root.attributes.length > 0;
  const isMultiline = content.includes('\n');

  if (!hasDeclaration && !hasClosingTag && !isSelfClosing) return null;
  if (!hasDeclaration && !hasNestedElement && !(hasAttributes && isMultiline) && !isSelfClosing) return null;
  return { language: 'xml', code: content };
}

function detectJavaScriptFamily(content: string): DetectedCode | null {
  if (!hasJavaScriptSignal(content)) return null;

  const candidates: Array<{ language: SupportedCodeLanguage; plugins: ParserPlugin[] }> = [];
  const hasJsxSignal = /<\/?[A-Za-z][\w.-]*(?:\s|>|\/)/.test(content);
  const hasTypeScriptSignal = /\b(?:interface|type|enum|namespace|implements|declare|readonly|keyof|satisfies)\b|:\s*[A-Z_a-z][\w<>{}\[\]|&,. ]*(?=[,)=;{])/m.test(content);

  if (hasJsxSignal && hasTypeScriptSignal) candidates.push({ language: 'tsx', plugins: ['typescript', 'jsx'] });
  if (hasTypeScriptSignal) candidates.push({ language: 'typescript', plugins: ['typescript'] });
  if (hasJsxSignal) candidates.push({ language: 'jsx', plugins: ['jsx'] });
  candidates.push({ language: 'javascript', plugins: [] });

  for (const candidate of candidates) {
    try {
      const ast = parse(content, {
        sourceType: 'unambiguous',
        errorRecovery: false,
        plugins: candidate.plugins,
      });
      if (hasMeaningfulScriptNode(ast.program.body)) {
        return { language: candidate.language, code: content };
      }
    } catch {
      // Try the next language family candidate.
    }
  }
  return null;
}

function hasJavaScriptSignal(content: string) {
  const signals = [
    /(?:^|\n)\s*(?:const|let|var)\s+[A-Za-z_$]/,
    /(?:^|\n)\s*(?:async\s+)?function\s+[A-Za-z_$]/,
    /(?:^|\n)\s*class\s+[A-Za-z_$]/,
    /(?:^|\n)\s*(?:import|export)\b/,
    /=>/,
    /(?:^|\n)\s*(?:if|for|while|switch|try)\s*\(/,
    /\b(?:interface|type|enum|namespace|declare)\s+[A-Za-z_$]/,
    /<\/?[A-Za-z][\w.-]*(?:\s|>|\/)/,
  ];
  return signals.some((pattern) => pattern.test(content));
}

function hasMeaningfulScriptNode(body: Array<{ type: string; expression?: { type?: string } }>) {
  const meaningfulStatements = new Set([
    'VariableDeclaration',
    'FunctionDeclaration',
    'ClassDeclaration',
    'ImportDeclaration',
    'ExportNamedDeclaration',
    'ExportDefaultDeclaration',
    'ExportAllDeclaration',
    'IfStatement',
    'ForStatement',
    'ForInStatement',
    'ForOfStatement',
    'WhileStatement',
    'DoWhileStatement',
    'SwitchStatement',
    'TryStatement',
    'TSInterfaceDeclaration',
    'TSTypeAliasDeclaration',
    'TSEnumDeclaration',
    'TSModuleDeclaration',
  ]);
  const meaningfulExpressions = new Set([
    'AssignmentExpression',
    'CallExpression',
    'ArrowFunctionExpression',
    'JSXElement',
    'JSXFragment',
  ]);

  return body.some((node) =>
    meaningfulStatements.has(node.type) ||
    (node.type === 'ExpressionStatement' && meaningfulExpressions.has(node.expression?.type ?? ''))
  );
}

function detectOtherLanguage(content: string): SupportedCodeLanguage | null {
  if (/^#!.*\b(?:bash|sh|zsh)\b/.test(content) || (/\b(?:then|fi|done|esac)\b/.test(content) && /(?:^|\n)\s*(?:if|for|while|case)\b/.test(content))) {
    return 'bash';
  }
  if (/^#!.*\bpython\b/.test(content) || (/(?:^|\n)\s*(?:async\s+def|def|class)\s+\w+/.test(content) && /:\s*(?:\n|$)/.test(content))) {
    return 'python';
  }
  if (/^[^{}\n]+\{[\s\S]*\b[-\w]+\s*:\s*[^;{}]+;[\s\S]*\}\s*$/.test(content)) return 'css';
  if (/^\s*(?:SELECT\b[\s\S]+\bFROM\b|INSERT\s+INTO\b|UPDATE\b[\s\S]+\bSET\b|CREATE\s+(?:TABLE|VIEW)\b)/i.test(content)) return 'sql';
  if (/^(?:use\s+[\w:]+;|fn\s+\w+\s*\(|impl(?:<[^>]+>)?\s+\w+|struct\s+\w+)[\s\S]*(?:\blet\s+(?:mut\s+)?\w+|\bfn\s+\w+)/m.test(content)) return 'rust';
  if (/^\s*package\s+\w+/m.test(content) && /(?:^|\n)\s*(?:import\s+\(?|func\s+\w+\s*\()/.test(content)) return 'go';
  if (/^\s*(?:package\s+[\w.]+;\s*)?(?:public\s+)?(?:class|interface|enum)\s+\w+/m.test(content) && /\b(?:public|private|protected|static|void)\b/.test(content)) return 'java';
  if (/^\s*(?:using\s+[\w.]+;|namespace\s+\w+)/m.test(content) && /\b(?:class|record|interface)\s+\w+/.test(content)) return 'csharp';
  if (/^\s*#\s*include\s*[<"]/m.test(content) && /\b(?:int|void|auto|class|struct)\s+\w+/.test(content)) {
    return /\b(?:std::|namespace|template|constexpr|cout)\b/.test(content) ? 'cpp' : 'c';
  }
  if (/^---\s*$/m.test(content) && /(?:^|\n)\s*(?:[-]\s+\S+|[\w.-]+:\s*\S+)/m.test(content)) return 'yaml';
  return null;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
