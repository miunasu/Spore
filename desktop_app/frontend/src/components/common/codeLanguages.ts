export type CodeLanguage =
  | 'bash'
  | 'c'
  | 'cpp'
  | 'csharp'
  | 'css'
  | 'go'
  | 'java'
  | 'javascript'
  | 'jsx'
  | 'json'
  | 'markdown'
  | 'plaintext'
  | 'python'
  | 'rust'
  | 'sql'
  | 'tsx'
  | 'typescript'
  | 'xml'
  | 'yaml';

export type FilePreviewKind = 'markdown' | 'source';

export type FileLanguageInfo = {
  id: CodeLanguage;
  label: string;
  previewKind: FilePreviewKind;
};

const PLAIN_LANGUAGE: FileLanguageInfo = {
  id: 'plaintext',
  label: 'Plain text',
  previewKind: 'source',
};

const LANGUAGE_LABELS: Record<CodeLanguage, string> = {
  bash: 'Shell',
  c: 'C',
  cpp: 'C++',
  csharp: 'C#',
  css: 'CSS',
  go: 'Go',
  java: 'Java',
  javascript: 'JavaScript',
  jsx: 'JavaScript JSX',
  json: 'JSON',
  markdown: 'Markdown',
  plaintext: 'Plain text',
  python: 'Python',
  rust: 'Rust',
  sql: 'SQL',
  tsx: 'TypeScript TSX',
  typescript: 'TypeScript',
  xml: 'XML/HTML',
  yaml: 'YAML',
};

const LANGUAGE_ALIASES: Record<string, CodeLanguage> = {
  bash: 'bash',
  c: 'c',
  'c++': 'cpp',
  cc: 'cpp',
  cpp: 'cpp',
  cxx: 'cpp',
  cs: 'csharp',
  csharp: 'csharp',
  css: 'css',
  go: 'go',
  golang: 'go',
  htm: 'xml',
  html: 'xml',
  java: 'java',
  javascript: 'javascript',
  js: 'javascript',
  cjs: 'javascript',
  mjs: 'javascript',
  jsx: 'jsx',
  json: 'json',
  jsonc: 'json',
  markdown: 'markdown',
  md: 'markdown',
  plaintext: 'plaintext',
  text: 'plaintext',
  txt: 'plaintext',
  py: 'python',
  python: 'python',
  rs: 'rust',
  rust: 'rust',
  sh: 'bash',
  shell: 'bash',
  zsh: 'bash',
  sql: 'sql',
  svg: 'xml',
  ts: 'typescript',
  typescript: 'typescript',
  tsx: 'tsx',
  xml: 'xml',
  xhtml: 'xml',
  yaml: 'yaml',
  yml: 'yaml',
};

const EXTENSION_LANGUAGES: Record<string, CodeLanguage> = {
  bash: 'bash',
  c: 'c',
  cc: 'cpp',
  cjs: 'javascript',
  cpp: 'cpp',
  cs: 'csharp',
  css: 'css',
  cts: 'typescript',
  cxx: 'cpp',
  go: 'go',
  h: 'c',
  hh: 'cpp',
  hpp: 'cpp',
  htm: 'xml',
  html: 'xml',
  hxx: 'cpp',
  java: 'java',
  js: 'javascript',
  json: 'json',
  jsonc: 'json',
  jsx: 'jsx',
  markdown: 'markdown',
  md: 'markdown',
  mdx: 'markdown',
  mjs: 'javascript',
  mts: 'typescript',
  ps1: 'bash',
  py: 'python',
  pyw: 'python',
  rs: 'rust',
  sh: 'bash',
  sql: 'sql',
  svg: 'xml',
  ts: 'typescript',
  tsx: 'tsx',
  txt: 'plaintext',
  xhtml: 'xml',
  xml: 'xml',
  yaml: 'yaml',
  yml: 'yaml',
  zsh: 'bash',
};

const FILE_NAME_LANGUAGES: Record<string, CodeLanguage> = {
  dockerfile: 'bash',
  makefile: 'bash',
  'package.json': 'json',
  tsconfig: 'json',
};

export function normalizeLanguageAlias(language: string): CodeLanguage | null {
  return LANGUAGE_ALIASES[language.trim().toLowerCase()] ?? null;
}

export function getFileLanguage(fileName: string, content = ''): FileLanguageInfo {
  const name = fileName.split(/[\\/]/).pop()?.toLowerCase() ?? fileName.toLowerCase();
  const byName = FILE_NAME_LANGUAGES[name];
  if (byName) return toFileLanguageInfo(byName, name === 'dockerfile' ? 'Dockerfile' : undefined);

  const extension = name.includes('.') ? name.split('.').pop() ?? '' : '';
  const byExtension = EXTENSION_LANGUAGES[extension];
  if (byExtension) {
    const label = extension === 'mdx' ? 'MDX source' : undefined;
    return toFileLanguageInfo(byExtension, label, extension === 'mdx' ? 'source' : undefined);
  }

  const detected = detectSourceLanguage(content);
  return detected ? toFileLanguageInfo(detected) : PLAIN_LANGUAGE;
}

export function isSemanticMarkdownFile(fileName: string) {
  const extension = fileName.split(/[\\/]/).pop()?.toLowerCase().split('.').pop() ?? '';
  return extension === 'md' || extension === 'markdown';
}

function toFileLanguageInfo(
  id: CodeLanguage,
  label = LANGUAGE_LABELS[id],
  previewKind: FilePreviewKind = id === 'markdown' ? 'markdown' : 'source'
): FileLanguageInfo {
  return { id, label, previewKind };
}

function detectSourceLanguage(content: string): CodeLanguage | null {
  const sample = content.slice(0, 20_000);
  const trimmed = sample.trimStart();
  if (!trimmed) return null;

  if (/^[{[]/.test(trimmed)) {
    try {
      JSON.parse(trimmed);
      return 'json';
    } catch {
      if (/^\s*"[^"]+"\s*:/m.test(sample)) return 'json';
    }
  }
  if (/^\s*(?:<\?xml\b|<!DOCTYPE\b|<[A-Za-z_][\w:.-]*(?:\s|>|\/))/i.test(trimmed)) return 'xml';
  if (/^#!.*\bpython\b/.test(trimmed) || /(?:^|\n)\s*(?:from\s+\w[\w.]*\s+import|import\s+\w|def\s+\w+\s*\(|class\s+\w+)/.test(sample)) return 'python';
  if (/^#!.*\b(?:bash|sh|zsh)\b/.test(trimmed)) return 'bash';
  if (/(?:^|\n)\s*(?:const|let|var|function|class|import|export)\b|=>/.test(sample)) return 'javascript';
  if (/(?:^|\n)\s*#\s*include\s*[<"]|(?:^|\n)\s*(?:int|void|char|static)\s+\w+\s*\([^)]*\)\s*\{/.test(sample)) return 'c';
  return null;
}
