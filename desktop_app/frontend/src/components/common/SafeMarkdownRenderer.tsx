import { type ComponentPropsWithoutRef, type Ref, type UIEventHandler } from 'react';
import ReactMarkdown from 'react-markdown';
import rehypeHighlight from 'rehype-highlight';
import remarkBreaks from 'remark-breaks';
import remarkGfm from 'remark-gfm';
import { normalizeLanguageAlias } from './codeLanguages';

type MarkdownVariant = 'chat' | 'mini' | 'file';

type SafeMarkdownRendererProps = {
  content: string;
  variant?: MarkdownVariant;
  containerRef?: Ref<HTMLDivElement>;
  onScroll?: UIEventHandler<HTMLDivElement>;
};

type MarkdownNode = {
  type: string;
  value?: string;
  children?: MarkdownNode[];
};

export function SafeMarkdownRenderer({
  content,
  variant = 'chat',
  containerRef,
  onScroll,
}: SafeMarkdownRendererProps) {
  return (
    <div
      ref={containerRef}
      className={`markdown-renderer markdown-renderer--${variant}`}
      onScroll={onScroll}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkBreaks, literalizeRawHtml]}
        rehypePlugins={[[rehypeHighlight, {
          detect: false,
          ignoreMissing: true,
          plainText: ['markdown', 'plaintext'],
          aliases: {
            javascript: ['js', 'jsx'],
            typescript: ['ts', 'tsx'],
            xml: ['html', 'svg'],
          },
        }]]}
        skipHtml
        urlTransform={transformUrl}
        components={{
          a: SafeLink,
          img: BlockedImage,
          code: SafeCode,
          table: ResponsiveTable,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}

export function safeLinkUrl(url: string): string | null {
  const value = url.trim();
  if (!value) return null;
  if (value.startsWith('#')) return value;

  try {
    const parsed = new URL(value);
    return ['https:', 'http:', 'mailto:'].includes(parsed.protocol) ? value : null;
  } catch {
    return null;
  }
}

export function literalizeRawHtml() {
  return (tree: MarkdownNode) => {
    visitMarkdownNodes(tree);
  };
}

function visitMarkdownNodes(node: MarkdownNode) {
  if (!node.children) return;
  node.children = node.children.map((child) => {
    if (child.type === 'html') return { type: 'text', value: child.value ?? '' };
    visitMarkdownNodes(child);
    return child;
  });
}

function transformUrl(url: string, key: string) {
  if (key === 'src') return '';
  return safeLinkUrl(url) ?? '';
}

function SafeLink({ href, children, ...props }: ComponentPropsWithoutRef<'a'>) {
  const safeHref = href ? safeLinkUrl(href) : null;
  if (!safeHref) return <span className="markdown-renderer__blocked-link">{children}</span>;

  const isExternal = /^https?:/i.test(safeHref);
  return (
    <a
      {...props}
      href={safeHref}
      target={isExternal ? '_blank' : undefined}
      rel={isExternal ? 'noopener noreferrer nofollow' : undefined}
      referrerPolicy={isExternal ? 'no-referrer' : undefined}
    >
      {children}
    </a>
  );
}

function BlockedImage({ alt }: ComponentPropsWithoutRef<'img'>) {
  return (
    <span className="markdown-renderer__blocked-image" role="img" aria-label={alt || 'image'}>
      [{alt || 'image'}]
    </span>
  );
}

function SafeCode({ className, children, ...props }: ComponentPropsWithoutRef<'code'>) {
  const languageMatch = /(?:^|\s)language-([^\s]+)/.exec(className ?? '');
  const language = languageMatch ? normalizeLanguageAlias(languageMatch[1]) : null;
  const baseClassName = (className ?? '')
    .split(/\s+/)
    .filter((name) => name && !name.startsWith('language-'))
    .join(' ');
  const normalizedClassName = language
    ? `${baseClassName} language-${language}`.trim()
    : baseClassName || undefined;

  return <code {...props} className={normalizedClassName}>{children}</code>;
}

function ResponsiveTable({ children, ...props }: ComponentPropsWithoutRef<'table'>) {
  return (
    <div className="markdown-renderer__table-wrap">
      <table {...props}>{children}</table>
    </div>
  );
}
