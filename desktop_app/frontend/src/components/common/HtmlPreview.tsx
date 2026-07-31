import { useEffect, useMemo, useRef, useState } from 'react';
import { htmlApi } from '../../services/api';
import { useT } from '../../i18n';

const HTML_FILE_PATTERN = /\.html?$/i;
const HTML_DOCUMENT_PATTERN = /^\s*(?:<!doctype\s+html\b|<html\b)/i;
const HTML_FENCE_PATTERN = /^\s*```html\s*\r?\n([\s\S]*?)\r?\n```\s*$/i;
const UNSAFE_SCRIPT_PATTERN = /\b(?:fetch\s*\(|XMLHttpRequest\b|WebSocket\s*\(|EventSource\s*\(|navigator\.sendBeacon\s*\(|window\.open\s*\(|(?:window\.)?location\s*(?:=|\.|\[))/i;

const SANDBOX_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  "img-src data: blob:",
  "font-src data:",
  "connect-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "navigate-to 'none'",
].join('; ');

type HtmlPreviewProps = {
  content: string;
  title: string;
  variant?: 'message' | 'file';
  artifactId?: string;
  onContentChange?: (content: string) => void;
};

type DynamicRequest = {
  source: 'spore-html';
  type: 'missing-target';
  artifactId: string;
  target: string;
  request: string;
  action: string;
  triggerText: string;
};

const DYNAMIC_BRIDGE = `(() => {
  const findTarget = (target) => {
    const byId = document.getElementById(target);
    if (byId) return byId;
    return Array.from(document.querySelectorAll('[data-spore-view]'))
      .find((node) => node.getAttribute('data-spore-view') === target) || null;
  };
  const reveal = (target) => {
    const node = findTarget(target);
    if (!node) return false;
    node.hidden = false;
    node.removeAttribute('hidden');
    if (node instanceof HTMLDetailsElement) node.open = true;
    node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return true;
  };
  document.addEventListener('click', (event) => {
    const origin = event.target instanceof Element ? event.target : null;
    const trigger = origin?.closest('[data-spore-target], a[href^="spore:"]');
    if (!trigger) return;
    const href = trigger.getAttribute('href') || '';
    const target = trigger.getAttribute('data-spore-target') ||
      (href.startsWith('spore:') ? decodeURIComponent(href.slice(6)) : '');
    if (!target) return;
    event.preventDefault();
    if (reveal(target)) return;
    const artifactId = document.documentElement.dataset.sporeArtifactId || '';
    if (!artifactId) return;
    parent.postMessage({
      source: 'spore-html',
      type: 'missing-target',
      artifactId,
      target,
      request: trigger.getAttribute('data-spore-request') || '',
      action: trigger.getAttribute('data-spore-action') || 'click',
      triggerText: (trigger.textContent || '').trim().slice(0, 300),
    }, '*');
  });
  const resume = document.documentElement.dataset.sporeResumeTarget;
  if (resume) requestAnimationFrame(() => reveal(resume));
})();`;

export function isHtmlFile(fileName: string): boolean {
  return HTML_FILE_PATTERN.test(fileName.trim());
}

export function extractStandaloneHtml(content: string): string | null {
  const fenced = HTML_FENCE_PATTERN.exec(content);
  if (fenced) return fenced[1].trim();

  const trimmed = content.trim();
  if (!HTML_DOCUMENT_PATTERN.test(trimmed)) return null;
  return trimmed;
}

export function getHtmlArtifactId(content: string): string | null {
  const document = new DOMParser().parseFromString(content, 'text/html');
  return document.documentElement.getAttribute('data-spore-artifact-id');
}

export function buildSandboxedHtml(content: string, resumeTarget?: string, artifactId?: string): string {
  const parser = new DOMParser();
  const document = parser.parseFromString(content, 'text/html');

  document.querySelectorAll('base, iframe, frame, object, embed, portal').forEach((node) => node.remove());
  document.querySelectorAll('meta[http-equiv]').forEach((node) => {
    const directive = node.getAttribute('http-equiv')?.toLowerCase();
    if (directive === 'refresh' || directive === 'content-security-policy') node.remove();
  });
  document.querySelectorAll('script[src], link[href]').forEach((node) => node.remove());
  document.querySelectorAll('script:not([src])').forEach((node) => {
    if (UNSAFE_SCRIPT_PATTERN.test(node.textContent ?? '')) node.remove();
  });
  document.querySelectorAll('a[href]').forEach((node) => {
    const href = node.getAttribute('href')?.trim() ?? '';
    if (!href.startsWith('#') && !href.startsWith('spore:')) node.removeAttribute('href');
  });
  document.querySelectorAll('*').forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      if (attribute.name.toLowerCase().startsWith('on') && UNSAFE_SCRIPT_PATTERN.test(attribute.value)) {
        node.removeAttribute(attribute.name);
      }
    }
  });
  document.querySelectorAll('form[action]').forEach((node) => node.removeAttribute('action'));

  const policy = document.createElement('meta');
  policy.setAttribute('http-equiv', 'Content-Security-Policy');
  policy.setAttribute('content', SANDBOX_CSP);
  document.head.prepend(policy);

  if (artifactId) document.documentElement.dataset.sporeArtifactId = artifactId;
  if (resumeTarget) document.documentElement.dataset.sporeResumeTarget = resumeTarget;
  const bridge = document.createElement('script');
  bridge.setAttribute('data-spore-host-bridge', '');
  bridge.textContent = DYNAMIC_BRIDGE;
  document.body.append(bridge);

  return `<!doctype html>\n${document.documentElement.outerHTML}`;
}

export function HtmlPreview({ content, title, variant = 'message', artifactId: artifactIdProp, onContentChange }: HtmlPreviewProps) {
  const t = useT();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const pendingRef = useRef(false);
  const [liveContent, setLiveContent] = useState(content);
  const [resumeTarget, setResumeTarget] = useState<string>();
  const [pendingTarget, setPendingTarget] = useState<string>();
  const [failedTarget, setFailedTarget] = useState<string>();
  const artifactId = useMemo(
    () => artifactIdProp ?? getHtmlArtifactId(liveContent),
    [artifactIdProp, liveContent]
  );
  const srcDoc = useMemo(
    () => buildSandboxedHtml(liveContent, resumeTarget, artifactId ?? undefined),
    [artifactId, liveContent, resumeTarget]
  );
  const sizeClass = variant === 'file'
    ? 'h-full w-full'
    : 'h-[min(520px,60vh)] w-[min(900px,70vw)] max-w-full';

  useEffect(() => {
    setLiveContent(content);
  }, [content]);

  useEffect(() => {
    if (!artifactId) return;
    let cancelled = false;
    htmlApi.load(artifactId).then((result) => {
      if (!cancelled && result.content !== liveContent) {
        setLiveContent(result.content);
        onContentChange?.(result.content);
      }
    }).catch(() => {
      // Inline message HTML may carry an ID before it has been persisted.
    });
    return () => { cancelled = true; };
  }, [artifactId]);

  useEffect(() => {
    const handleMessage = async (event: MessageEvent<DynamicRequest>) => {
      if (event.source !== frameRef.current?.contentWindow) return;
      const message = event.data;
      if (
        !message || message.source !== 'spore-html' || message.type !== 'missing-target' ||
        !artifactId || message.artifactId !== artifactId || pendingRef.current
      ) return;

      pendingRef.current = true;
      setPendingTarget(message.target);
      setFailedTarget(undefined);
      try {
        const result = await htmlApi.interact(artifactId, {
          target: message.target,
          request: message.request,
          action: message.action,
          trigger_text: message.triggerText,
        });
        setResumeTarget(message.target);
        setLiveContent(result.content);
        onContentChange?.(result.content);
      } catch (error) {
        console.error('Dynamic HTML target generation failed:', error);
        setFailedTarget(message.target);
      } finally {
        pendingRef.current = false;
        setPendingTarget(undefined);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [artifactId, onContentChange]);

  return (
    <div className={`${sizeClass} relative max-w-full`}>
      <iframe
        ref={frameRef}
        className="block h-full w-full rounded-md border border-spore-border/40 bg-white"
        sandbox="allow-scripts"
        referrerPolicy="no-referrer"
        srcDoc={srcDoc}
        title={title}
      />
      {pendingTarget && (
        <div className="absolute inset-x-3 bottom-3 rounded border border-spore-border/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-text shadow-lg">
          <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-spore-highlight" />
          {t('chatPanel.htmlPreview.generatingTarget', { target: pendingTarget })}
        </div>
      )}
      {failedTarget && !pendingTarget && (
        <div className="absolute inset-x-3 bottom-3 rounded border border-spore-error/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-error shadow-lg">
          {t('chatPanel.htmlPreview.generationFailed', { target: failedTarget })}
        </div>
      )}
    </div>
  );
}
