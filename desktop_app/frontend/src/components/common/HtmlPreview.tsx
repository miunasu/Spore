import { useEffect, useMemo, useRef, useState } from 'react';
import { htmlApi } from '../../services/api';
import { wsService } from '../../services/websocket';
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

export type HtmlInteractionEvent = {
  timestamp_ms: number;
  event_type?: 'click' | 'input' | 'change' | 'submit';
  tag: string;
  element_id: string;
  role: string;
  text: string;
  clicked_word: string;
  aria_label: string;
  title: string;
  href: string;
  spore_target: string;
  spore_request: string;
  dom_path: string;
  ancestors: string[];
  control?: { type: string; value: string; checked: boolean };
  scroll_y: number;
  viewport: { width: number; height: number };
};

type DynamicRequest = {
  source: 'spore-html';
  type: 'click' | 'interaction';
  artifactId: string;
  event: HtmlInteractionEvent;
};

const DYNAMIC_BRIDGE = `(() => {
  const clean = (value, limit = 500) => String(value || '').replace(/\\s+/g, ' ').trim().slice(0, limit);
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
  const clickedWord = (event) => {
    let node = null;
    let offset = 0;
    if (document.caretPositionFromPoint) {
      const position = document.caretPositionFromPoint(event.clientX, event.clientY);
      node = position?.offsetNode || null;
      offset = position?.offset || 0;
    } else if (document.caretRangeFromPoint) {
      const range = document.caretRangeFromPoint(event.clientX, event.clientY);
      node = range?.startContainer || null;
      offset = range?.startOffset || 0;
    }
    if (!node || node.nodeType !== Node.TEXT_NODE) return '';
    const value = node.textContent || '';
    let start = Math.min(offset, value.length);
    let end = start;
    const word = /[\\p{L}\\p{N}_'-]/u;
    while (start > 0 && word.test(value[start - 1])) start -= 1;
    while (end < value.length && word.test(value[end])) end += 1;
    return clean(value.slice(start, end), 160);
  };
  const domPath = (node) => {
    const parts = [];
    let current = node;
    while (current && current !== document.body && parts.length < 20) {
      const tag = current.tagName.toLowerCase();
      let position = 1;
      let sibling = current.previousElementSibling;
      while (sibling) {
        if (sibling.tagName === current.tagName) position += 1;
        sibling = sibling.previousElementSibling;
      }
      parts.unshift(tag + ':nth-of-type(' + position + ')');
      current = current.parentElement;
    }
    if (current !== document.body) return '';
    parts.unshift('body');
    return clean(parts.join(' > '), 500);
  };
  const describe = (node) => clean([
    node.tagName.toLowerCase(),
    node.id ? '#' + node.id : '',
    node.getAttribute('role') || '',
    node.getAttribute('aria-label') || '',
    node.textContent || '',
  ].filter(Boolean).join(' '), 300);
  let hostFrozen = false;
  window.addEventListener('message', (event) => {
    if (event.source !== parent || event.data?.source !== 'spore-host' || event.data?.type !== 'freeze') return;
    hostFrozen = Boolean(event.data.frozen);
    document.documentElement.dataset.sporeFrozen = hostFrozen ? 'true' : 'false';
    if ('inert' in document.body) document.body.inert = hostFrozen;
    if (hostFrozen && document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  const controlState = (subject) => subject instanceof HTMLInputElement || subject instanceof HTMLSelectElement || subject instanceof HTMLTextAreaElement
    ? {
        type: clean(subject.getAttribute('type') || subject.tagName.toLowerCase(), 40),
        value: subject instanceof HTMLInputElement && subject.type === 'password' ? '' : clean(subject.value, 500),
        checked: subject instanceof HTMLInputElement ? subject.checked : false,
      }
    : undefined;
  const postInteraction = (eventType, subject, word = '') => {
    if (hostFrozen) return;
    const artifactId = document.documentElement.dataset.sporeArtifactId || '';
    if (!artifactId || !(subject instanceof Element)) return;
    const href = subject.getAttribute('href') || '';
    const target = subject.getAttribute('data-spore-target') ||
      (href.startsWith('spore:') ? decodeURIComponent(href.slice(6)) : '');
    setTimeout(() => {
      parent.postMessage({
        source: 'spore-html',
        type: 'interaction',
        artifactId,
        event: {
          timestamp_ms: Math.round(performance.now()),
          event_type: eventType,
          tag: subject.tagName.toLowerCase(),
          element_id: clean(subject.id, 120),
          role: clean(subject.getAttribute('role'), 80),
          text: clean(subject.textContent, 500),
          clicked_word: word,
          aria_label: clean(subject.getAttribute('aria-label'), 300),
          title: clean(subject.getAttribute('title'), 300),
          href: clean(href, 500),
          spore_target: clean(target, 120),
          spore_request: clean(subject.getAttribute('data-spore-request'), 1000),
          dom_path: domPath(subject),
          ancestors: Array.from(function* () {
            let node = subject.parentElement;
            for (let i = 0; node && i < 4; i += 1, node = node.parentElement) yield describe(node);
          }()),
          control: controlState(subject),
          scroll_y: Math.max(0, Math.round(window.scrollY)),
          viewport: { width: window.innerWidth, height: window.innerHeight },
        },
      }, '*');
    }, 0);
  };
  document.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const origin = event.target instanceof Element ? event.target : null;
    if (!origin) return;
    let subject = origin.closest('button, a, summary, input, select, textarea, label, [role], [data-spore-target]') || origin;
    if (subject instanceof HTMLLabelElement && subject.control) subject = subject.control;
    const href = subject.getAttribute('href') || '';
    const target = subject.getAttribute('data-spore-target') ||
      (href.startsWith('spore:') ? decodeURIComponent(href.slice(6)) : '');
    if (href.startsWith('spore:')) event.preventDefault();
    if (target) reveal(target);
    postInteraction('click', subject, clickedWord(event));
  }, true);
  document.addEventListener('change', (event) => {
    if (!event.isTrusted) return;
    const subject = event.target instanceof Element
      ? event.target.closest('input, select, textarea, [role]')
      : null;
    if (subject) postInteraction('change', subject);
  }, true);
  const inputTimers = new WeakMap();
  document.addEventListener('input', (event) => {
    if (!event.isTrusted) return;
    const subject = event.target instanceof Element
      ? event.target.closest('input, textarea, select')
      : null;
    if (!subject) return;
    const previous = inputTimers.get(subject);
    if (previous) clearTimeout(previous);
    inputTimers.set(subject, setTimeout(() => {
      inputTimers.delete(subject);
      postInteraction('input', subject);
    }, 350));
  }, true);
  document.addEventListener('submit', (event) => {
    if (!event.isTrusted) return;
    const subject = event.target instanceof HTMLFormElement ? event.target : null;
    if (subject) postInteraction('submit', subject);
  }, true);
  const resume = document.documentElement.dataset.sporeResumeTarget;
  if (resume) requestAnimationFrame(() => reveal(resume));
  const resumeScroll = Number(document.documentElement.dataset.sporeResumeScroll || 0);
  if (resumeScroll > 0) requestAnimationFrame(() => window.scrollTo(0, resumeScroll));
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

export function buildSandboxedHtml(
  content: string,
  resumeTarget?: string,
  artifactId?: string,
  resumeScroll?: number
): string {
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
  if (resumeScroll) document.documentElement.dataset.sporeResumeScroll = String(resumeScroll);
  const bridge = document.createElement('script');
  bridge.setAttribute('data-spore-host-bridge', '');
  bridge.textContent = DYNAMIC_BRIDGE;
  document.body.append(bridge);

  return `<!doctype html>\n${document.documentElement.outerHTML}`;
}

export function HtmlPreview({ content, title, variant = 'message', artifactId: artifactIdProp, onContentChange }: HtmlPreviewProps) {
  const t = useT();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const liveContentRef = useRef(content);
  const interactionBufferRef = useRef<HtmlInteractionEvent[]>([]);
  const batchQueueRef = useRef<HtmlInteractionEvent[][]>([]);
  const collectionTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const interactionStatePollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const processingRef = useRef(false);
  const interactionStateRevisionRef = useRef(0);
  const processNextRef = useRef<() => void>(() => undefined);
  const mountedRef = useRef(true);
  const [liveContent, setLiveContent] = useState(content);
  const [resumeTarget, setResumeTarget] = useState<string>();
  const [resumeScroll, setResumeScroll] = useState<number>();
  const [collectingCount, setCollectingCount] = useState(0);
  const [processingCount, setProcessingCount] = useState(0);
  const [interactionFrozen, setInteractionFrozen] = useState(false);
  const [interactionFailed, setInteractionFailed] = useState(false);
  const artifactId = useMemo(
    () => artifactIdProp ?? getHtmlArtifactId(liveContent),
    [artifactIdProp, liveContent]
  );
  const srcDoc = useMemo(
    () => buildSandboxedHtml(liveContent, resumeTarget, artifactId ?? undefined, resumeScroll),
    [artifactId, liveContent, resumeScroll, resumeTarget]
  );
  const sizeClass = variant === 'file'
    ? 'h-full w-full'
    : 'h-[min(520px,60vh)] w-[min(900px,70vw)] max-w-full';

  useEffect(() => {
    liveContentRef.current = content;
    setLiveContent(content);
  }, [content]);

  useEffect(() => {
    liveContentRef.current = liveContent;
  }, [liveContent]);

  useEffect(() => {
    frameRef.current?.contentWindow?.postMessage({
      source: 'spore-host',
      type: 'freeze',
      frozen: interactionFrozen,
    }, '*');
    if (interactionFrozen) frameRef.current?.blur();
  }, [interactionFrozen, srcDoc]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (collectionTimerRef.current) clearTimeout(collectionTimerRef.current);
      if (interactionStatePollTimerRef.current) clearInterval(interactionStatePollTimerRef.current);
    };
  }, []);

  useEffect(() => {
    if (!artifactId) return;
    let cancelled = false;
    htmlApi.load(artifactId).then((result) => {
      if (!cancelled && result.content !== liveContent) {
        liveContentRef.current = result.content;
        setLiveContent(result.content);
        onContentChange?.(result.content);
      }
    }).catch(() => {
      // Inline message HTML may carry an ID before it has been persisted.
    });
    return () => { cancelled = true; };
  }, [artifactId]);

  useEffect(() => {
    if (!artifactId) return;
    const applyCompletedArtifact = async () => {
      try {
        const result = await htmlApi.load(artifactId);
        if (result.content !== liveContentRef.current) {
          liveContentRef.current = result.content;
          setLiveContent(result.content);
          onContentChange?.(result.content);
        }
      } catch {
        // The active interaction request remains the authoritative fallback.
      } finally {
        if (!processingRef.current && mountedRef.current) setInteractionFrozen(false);
      }
    };
    const unsubscribe = wsService.subscribeSingle((event) => {
      if (event.type !== 'html_interaction_state' || event.data.artifact_id !== artifactId) return;
      if (event.data.revision < interactionStateRevisionRef.current) return;
      interactionStateRevisionRef.current = event.data.revision;
      if (event.data.frozen) {
        setInteractionFrozen(true);
      } else if (event.data.phase === 'completed') {
        if (!processingRef.current) void applyCompletedArtifact();
      } else if (event.data.phase === 'failed' || event.data.phase === 'idle') {
        setInteractionFrozen(false);
      }
    });
    return unsubscribe;
  }, [artifactId, onContentChange]);

  const processNextBatch = async () => {
    if (processingRef.current || !artifactId) return;
    const batch = batchQueueRef.current.shift();
    if (!batch?.length) return;

    processingRef.current = true;
    if (mountedRef.current) {
      setProcessingCount(batch.length);
      setInteractionFailed(false);
    }
    const startedAt = batch[0].timestamp_ms;
    const events = batch.map((item) => ({
      ...item,
      elapsed_ms: Math.max(0, item.timestamp_ms - startedAt),
    }));
    const pollInteractionState = async () => {
      try {
        const state = await htmlApi.interactionState(artifactId);
        if (state.revision < interactionStateRevisionRef.current) return;
        interactionStateRevisionRef.current = state.revision;
        if (state.frozen && mountedRef.current) setInteractionFrozen(true);
      } catch {
        // WebSocket is the primary signal; polling is only a disconnect fallback.
      }
    };
    void pollInteractionState();
    if (interactionStatePollTimerRef.current) clearInterval(interactionStatePollTimerRef.current);
    interactionStatePollTimerRef.current = setInterval(() => { void pollInteractionState(); }, 200);
    try {
      const result = await htmlApi.interact(artifactId, events);
      if (mountedRef.current && result.generated && result.content !== liveContentRef.current) {
        const lastClick = events[events.length - 1];
        setResumeTarget(lastClick.spore_target || lastClick.element_id || undefined);
        setResumeScroll(lastClick.scroll_y || undefined);
        liveContentRef.current = result.content;
        setLiveContent(result.content);
        onContentChange?.(result.content);
      }
    } catch (error) {
      console.error('Dynamic HTML interaction analysis failed:', error);
      if (mountedRef.current) setInteractionFailed(true);
    } finally {
      if (interactionStatePollTimerRef.current) {
        clearInterval(interactionStatePollTimerRef.current);
        interactionStatePollTimerRef.current = null;
      }
      processingRef.current = false;
      if (mountedRef.current) {
        setProcessingCount(0);
        // Backend only resolves the request after the Spore protocol ends the Agent operation, structural application,
        // full-document validation, and persistence have all completed.
        setInteractionFrozen(false);
      }
      processNextRef.current();
    }
  };
  processNextRef.current = () => { void processNextBatch(); };

  const flushInteractionBuffer = () => {
    collectionTimerRef.current = null;
    const batch = interactionBufferRef.current.splice(0);
    if (mountedRef.current) setCollectingCount(0);
    if (!batch.length) return;
    batchQueueRef.current.push(batch);
    processNextRef.current();
  };

  useEffect(() => {
    const handleMessage = (event: MessageEvent<DynamicRequest>) => {
      if (event.source !== frameRef.current?.contentWindow) return;
      const message = event.data;
      if (
        !message || message.source !== 'spore-html' || !['click', 'interaction'].includes(message.type) ||
        !artifactId || message.artifactId !== artifactId || !message.event
      ) return;

      interactionBufferRef.current.push(message.event);
      setCollectingCount(interactionBufferRef.current.length);
      setInteractionFailed(false);
      if (!collectionTimerRef.current) {
        collectionTimerRef.current = setTimeout(flushInteractionBuffer, 5000);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [artifactId]);

  return (
    <div className={`${sizeClass} relative max-w-full`}>
      <iframe
        ref={frameRef}
        className={`block h-full w-full rounded-md border border-spore-border/40 bg-white ${interactionFrozen ? 'pointer-events-none select-none' : ''}`}
        sandbox="allow-scripts"
        referrerPolicy="no-referrer"
        srcDoc={srcDoc}
        title={title}
        tabIndex={interactionFrozen ? -1 : 0}
        aria-busy={interactionFrozen}
        onLoad={() => frameRef.current?.contentWindow?.postMessage({
          source: 'spore-host', type: 'freeze', frozen: interactionFrozen,
        }, '*')}
      />
      {interactionFrozen && (
        <div
          data-testid="html-interaction-freeze"
          className="absolute inset-0 z-20 flex cursor-wait items-center justify-center rounded-md bg-spore-bg/70 backdrop-blur-[1px]"
          role="status"
          aria-live="assertive"
        >
          <div className="rounded border border-spore-highlight/50 bg-spore-card px-4 py-3 text-sm text-spore-text shadow-lg">
            <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-spore-highlight" />
            {t('chatPanel.htmlPreview.pageFrozen')}
          </div>
        </div>
      )}
      {(collectingCount > 0 || processingCount > 0) && !interactionFrozen && (
        <div
          data-testid="html-interaction-status"
          data-collecting-count={collectingCount}
          data-processing-count={processingCount}
          className="pointer-events-none absolute inset-x-3 bottom-3 rounded border border-spore-border/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-text shadow-lg"
        >
          <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-spore-highlight" />
          {processingCount > 0
            ? t('chatPanel.htmlPreview.interpretingClicks', { count: processingCount })
            : t('chatPanel.htmlPreview.collectingClicks', { count: collectingCount })}
          {processingCount > 0 && collectingCount > 0 && (
            <span className="ml-2 text-spore-muted">
              {t('chatPanel.htmlPreview.queuedClicks', { count: collectingCount })}
            </span>
          )}
        </div>
      )}
      {interactionFailed && collectingCount === 0 && processingCount === 0 && (
        <div className="pointer-events-none absolute inset-x-3 bottom-3 rounded border border-spore-error/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-error shadow-lg">
          {t('chatPanel.htmlPreview.interactionFailed')}
        </div>
      )}
    </div>
  );
}
