import { useEffect, useMemo, useRef, useState } from 'react';
import { htmlApi, type HtmlInteractionState, type HtmlInteractResult } from '../../services/api';
import { wsService } from '../../services/websocket';
import { useT } from '../../i18n';
import { buildDynamicBridge } from './htmlBridge';
import {
  MAX_INTENT_WINDOW_MS,
  buildSemanticIntentEpisode,
  createInteractionId,
  dynamicWindowDelay,
  eventFocusRef,
  eventsLikelyRelated,
  interactionLocallyResolved,
  isStrongIntentSignal,
  episodeToAgentEvent,
  sha256Text,
  shouldIgnoreLocallySatisfiedSignal,
  type HtmlInteractionEvent,
  type HtmlInteractionRequestIdentity,
  type HtmlRuntimeState,
  type SemanticIntentEpisode,
} from './htmlIntent';

export type { HtmlInteractionEvent } from './htmlIntent';

const HTML_FILE_PATTERN = /\.html?$/i;
const HTML_DOCUMENT_PATTERN = /^\s*(?:<!doctype\s+html\b|<html\b)/i;
const HTML_FENCE_PATTERN = /^\s*```html\s*\r?\n([\s\S]*?)\r?\n```\s*$/i;
const UNSAFE_SCRIPT_PATTERN = /\b(?:fetch\s*\(|XMLHttpRequest\b|WebSocket\s*\(|EventSource\s*\(|navigator\.sendBeacon\s*\(|window\.open\s*\(|(?:window\.)?location\s*(?:=|\.|\[))/i;
const READY_TIMEOUT_MS = 10_000;
// The backend freezes the page at dispatch so the Agent reasons about a stable DOM.
// That freeze is not a committed barrier: it is still supersedable by a newer intent.
const PRE_BARRIER_FROZEN_PHASES = ['analyzing'];
const SANDBOX_CSP = [
  "default-src 'none'", "script-src 'unsafe-inline'", "style-src 'unsafe-inline'",
  'img-src data: blob:', 'font-src data:', "connect-src 'none'", "media-src 'none'",
  "object-src 'none'", "frame-src 'none'", "worker-src 'none'", "base-uri 'none'",
  "form-action 'none'", "navigate-to 'none'",
].join('; ');

type HtmlPreviewProps = {
  content: string;
  title: string;
  variant?: 'message' | 'file';
  artifactId?: string;
  onContentChange?: (content: string) => void;
  /** When false, user interactions are observed but never forwarded to the Frontend Agent. */
  frontendAgentEnabled?: boolean;
};

type DynamicRequest = {
  source: 'spore-html';
  type: 'click' | 'interaction' | 'interaction_ready';
  artifactId: string;
  event?: HtmlInteractionEvent;
  documentToken?: string;
  ready?: boolean;
  restored?: boolean;
  restoreRequested?: boolean;
  initializationPending?: boolean;
  documentReadyState?: string;
  interactiveCount?: number;
  bridgeCapability?: string;
  documentGenerationId?: string;
  restoreAttemptId?: string;
  bridgeInstalled?: boolean;
  coreInteractionsReady?: boolean;
  restoreReport?: Record<string, unknown>;
};

type ActiveRequest = {
  artifactId: string;
  identity: HtmlInteractionRequestIdentity;
  episode: SemanticIntentEpisode;
  superseded: boolean;
  barrierCommitted: boolean;
  awaitingReady: boolean;
  terminalFailure: boolean;
  cancelPending: boolean;
  cancelEpoch?: number;
  /** User explicitly confirmed this intent (Build/Explain/Compare); do not supersede until complete. */
  userConfirmed?: boolean;
};

export function isHtmlFile(fileName: string): boolean {
  return HTML_FILE_PATTERN.test(fileName.trim());
}

export function extractStandaloneHtml(content: string): string | null {
  const fenced = HTML_FENCE_PATTERN.exec(content);
  if (fenced) return fenced[1].trim();
  const trimmed = content.trim();
  return HTML_DOCUMENT_PATTERN.test(trimmed) ? trimmed : null;
}

export function getHtmlArtifactId(content: string): string | null {
  const document = new DOMParser().parseFromString(content, 'text/html');
  return document.documentElement.getAttribute('data-spore-artifact-id');
}

export function buildSandboxedHtml(
  content: string,
  resumeTarget?: string,
  artifactId?: string,
  resumeScroll?: number,
  runtimeState?: HtmlRuntimeState,
  documentToken?: string,
  bridgeCapability = 'spore-local-bridge-capability-unbound',
  documentGenerationId = 'spore-local-document-generation',
  restoreAttemptId = 'spore-local-restore-attempt',
): string {
  const document = new DOMParser().parseFromString(content, 'text/html');
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
      if (attribute.name.toLowerCase().startsWith('on') && UNSAFE_SCRIPT_PATTERN.test(attribute.value)) node.removeAttribute(attribute.name);
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
  if (documentToken) document.documentElement.dataset.sporeDocumentToken = documentToken;
  document.documentElement.dataset.sporeDocumentGenerationId = documentGenerationId;
  document.documentElement.dataset.sporeRestoreAttemptId = restoreAttemptId;
  if (runtimeState) {
    const state = document.createElement('script');
    state.id = 'spore-runtime-state';
    state.type = 'application/json';
    state.textContent = JSON.stringify(runtimeState).replace(/</g, '\\u003c');
    document.body.append(state);
  }
  const bridge = document.createElement('script');
  bridge.setAttribute('data-spore-host-bridge', '');
  bridge.textContent = buildDynamicBridge(bridgeCapability);
  policy.after(bridge);
  return `<!doctype html>\n${document.documentElement.outerHTML}`;
}

function preservesFrozenTransactionOwner(active: ActiveRequest | null | undefined): boolean {
  return Boolean(active && (active.barrierCommitted || active.awaitingReady || active.terminalFailure));
}

function stateMatchesRequest(state: HtmlInteractionState, active: ActiveRequest): boolean {
  const revision = state.state_revision ?? state.revision;
  const transactional = state.frozen || !['idle', 'collecting', 'intent_ready'].includes(state.phase);
  if (transactional && !state.operation_id) return false;
  if (state.operation_id && state.operation_id !== active.identity.operation_id) return false;
  if (state.agent_request_id && state.agent_request_id !== active.identity.agent_request_id) return false;
  if (state.intent_epoch != null && state.intent_epoch !== active.identity.intent_epoch &&
      (!active.cancelPending || state.intent_epoch !== active.cancelEpoch)) return false;
  return revision > active.identity.state_revision;
}

export function HtmlPreview({ content, title, variant = 'message', artifactId: artifactIdProp, onContentChange, frontendAgentEnabled = true }: HtmlPreviewProps) {
  const t = useT();
  const frameRef = useRef<HTMLIFrameElement>(null);
  const liveContentRef = useRef(content);
  const htmlRevisionRef = useRef(1);
  const draftEventsRef = useRef<HtmlInteractionEvent[]>([]);
  const focusMemoryRef = useRef<HtmlInteractionEvent | null>(null);
  const settleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const maxWindowTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const statePollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const readyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const confirmHeartbeatTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const confirmTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const recoveryInFlightRef = useRef(false);
  const activeRequestRef = useRef<ActiveRequest | null>(null);
  const latestPendingRef = useRef<SemanticIntentEpisode | null>(null);
  const intentEpochRef = useRef(0);
  const interactionStateRevisionRef = useRef(0);
  const pendingReadyRef = useRef<{
    documentToken: string;
    operationId: string;
    agentRequestId: string;
    htmlSha256: string;
    stateRevision: number;
    expectedRestore: boolean;
    bridgeCapability: string;
    documentGenerationId: string;
    restoreAttemptId: string;
    submitted: boolean;
  } | null>(null);
  const interactionFrozenRef = useRef(false);
  /** Mirror of agentImproving for use inside handleMessage (avoids stale closure). */
  const agentImprovingRef = useRef(false);
  /**
   * True after the first acceptInteractionState call for the current artifactId.
   * Blocks iframe interaction events from triggering intent collection during the
   * brief window between component (re)mount and when the backend state is loaded —
   * prevents spurious intent collection when switching back to a conversation where
   * the frontend agent was already working.
   */
  const stateInitializedRef = useRef(false);
  /** Mirror of frontendAgentEnabled prop for use inside handleMessage (avoids stale closure). */
  const frontendAgentEnabledRef = useRef(frontendAgentEnabled);
  const resetIntentTransactionRef = useRef<(reason: string, cancelArtifactId?: string | null) => boolean>(() => false);
  const lastDblClickRef = useRef<{ timestamp: number; focusRef: string; domPath: string } | null>(null);
  /** Set to true before startEpisode when the user explicitly confirmed Build/Explain/Compare. */
  const nextEpisodeUserConfirmedRef = useRef(false);
  const mountedRef = useRef(true);
  const finalizeDraftRef = useRef<() => void>(() => undefined);
  const startEpisodeRef = useRef<(episode: SemanticIntentEpisode) => void>(() => undefined);
  const finishActiveRef = useRef<(active: ActiveRequest) => void>(() => undefined);
  const acceptInteractionStateRef = useRef<(state: HtmlInteractionState) => void>(() => undefined);
  const onContentChangeRef = useRef(onContentChange);
  const [liveContent, setLiveContent] = useState(content);
  const [resumeTarget, setResumeTarget] = useState<string>();
  const [resumeScroll, setResumeScroll] = useState<number>();
  const [runtimeState, setRuntimeState] = useState<HtmlRuntimeState>();
  const [documentToken, setDocumentToken] = useState(() => createInteractionId('document'));
  const [bridgeCapability, setBridgeCapability] = useState(() => createInteractionId('bridge-capability'));
  const [documentGenerationId, setDocumentGenerationId] = useState(() => createInteractionId('document-generation'));
  const [restoreAttemptId, setRestoreAttemptId] = useState(() => createInteractionId('restore-attempt'));
  const [collectingCount, setCollectingCount] = useState(0);
  const [processingCount, setProcessingCount] = useState(0);
  const [interactionFrozen, setInteractionFrozen] = useState(false);
  const [interactionFailed, setInteractionFailed] = useState(false);
  const [intentCandidate, setIntentCandidate] = useState<SemanticIntentEpisode | null>(null);
  const [agentConfirmation, setAgentConfirmation] = useState<{
    reason: string;
    operationId: string;
    agentRequestId: string;
    timedOut?: boolean;
  } | null>(null);
  const [agentImproving, setAgentImproving] = useState(false);
  // Round-1 ASSESS question: shown before any mutation is generated.
  const [agentAssessQuestion, setAgentAssessQuestion] = useState<{
    question: string;
    operationId: string;
    agentRequestId: string;
  } | null>(null);
  const requestedArtifactId = useMemo(() => artifactIdProp ?? getHtmlArtifactId(liveContent), [artifactIdProp, liveContent]);
  const protectedOwner = activeRequestRef.current;
  const artifactId = protectedOwner && preservesFrozenTransactionOwner(protectedOwner) ? protectedOwner.artifactId : requestedArtifactId;
  const artifactIdRef = useRef(artifactId);
  const previousArtifactIdRef = useRef(artifactId);
  const srcDoc = useMemo(
    () => buildSandboxedHtml(
      liveContent, resumeTarget, artifactId ?? undefined, resumeScroll, runtimeState, documentToken,
      bridgeCapability, documentGenerationId, restoreAttemptId,
    ),
    [artifactId, bridgeCapability, documentGenerationId, documentToken, liveContent, restoreAttemptId, resumeScroll, resumeTarget, runtimeState],
  );
  const sizeClass = variant === 'file' ? 'h-full w-full' : 'h-[min(520px,60vh)] w-[min(900px,70vw)] max-w-full';

  useEffect(() => { onContentChangeRef.current = onContentChange; }, [onContentChange]);
  useEffect(() => {
    if (content === liveContentRef.current) return;
    const active = activeRequestRef.current;
    if (interactionFrozenRef.current || preservesFrozenTransactionOwner(active)) return;
    const nextArtifactId = artifactIdProp ?? getHtmlArtifactId(content);
    resetIntentTransactionRef.current('external_content_changed', artifactIdRef.current);
    previousArtifactIdRef.current = nextArtifactId;
    liveContentRef.current = content;
    htmlRevisionRef.current += 1;
    setRuntimeState(undefined);
    setResumeTarget(undefined);
    setResumeScroll(undefined);
    setDocumentToken(createInteractionId('document'));
    setBridgeCapability(createInteractionId('bridge-capability'));
    setDocumentGenerationId(createInteractionId('document-generation'));
    setRestoreAttemptId(createInteractionId('restore-attempt'));
    setLiveContent(content);
  }, [artifactIdProp, content]);
  useEffect(() => { liveContentRef.current = liveContent; }, [liveContent]);
  useEffect(() => {
    frameRef.current?.contentWindow?.postMessage({
      source: 'spore-host', type: 'freeze', frozen: interactionFrozen,
    }, '*');
    if (interactionFrozen) frameRef.current?.blur();
  }, [interactionFrozen, srcDoc]);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (settleTimerRef.current) clearTimeout(settleTimerRef.current);
      if (maxWindowTimerRef.current) clearTimeout(maxWindowTimerRef.current);
      if (statePollTimerRef.current) clearInterval(statePollTimerRef.current);
      if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
      if (heartbeatTimerRef.current) clearInterval(heartbeatTimerRef.current);
      if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
      if (confirmTimeoutRef.current) clearTimeout(confirmTimeoutRef.current);
    };
  }, []);
  useEffect(() => {
    const previousArtifactId = previousArtifactIdRef.current;
    if (previousArtifactId !== artifactId) {
      resetIntentTransactionRef.current('artifact_changed', previousArtifactId);
      interactionStateRevisionRef.current = 0;
      previousArtifactIdRef.current = artifactId;
    }
    artifactIdRef.current = artifactId;
    if (!artifactId) {
      // No artifact — nothing to load, allow interaction immediately.
      stateInitializedRef.current = true;
      return;
    }
    // Block intent collection until the backend interaction state is confirmed.
    stateInitializedRef.current = false;
    let cancelled = false;
    htmlApi.load(artifactId).then((result) => {
      const active = activeRequestRef.current;
      if (cancelled || result.content === liveContentRef.current || interactionFrozenRef.current || preservesFrozenTransactionOwner(active)) return;
      resetIntentTransactionRef.current('loaded_content_changed', artifactId);
      liveContentRef.current = result.content;
      htmlRevisionRef.current += 1;
      setRuntimeState(undefined);
      setResumeTarget(undefined);
      setResumeScroll(undefined);
      setDocumentToken(createInteractionId('document'));
      setBridgeCapability(createInteractionId('bridge-capability'));
      setDocumentGenerationId(createInteractionId('document-generation'));
      setRestoreAttemptId(createInteractionId('restore-attempt'));
      setLiveContent(result.content);
      onContentChangeRef.current?.(result.content);
    }).catch(() => { /* Inline HTML may not have been persisted yet. */ });
    htmlApi.interactionState(artifactId).then((state) => {
      if (!cancelled) acceptInteractionStateRef.current(state);
    }).catch(() => {
      // State fetch failed — unblock interaction so the user isn't permanently locked out.
      if (!cancelled) stateInitializedRef.current = true;
    });
    return () => { cancelled = true; };
  }, [artifactId]);

  const clearPoll = () => {
    if (statePollTimerRef.current) clearInterval(statePollTimerRef.current);
    statePollTimerRef.current = null;
  };
  const clearHeartbeat = () => {
    if (heartbeatTimerRef.current) clearInterval(heartbeatTimerRef.current);
    heartbeatTimerRef.current = null;
  };
  const setFrozen = (frozen: boolean) => {
    interactionFrozenRef.current = frozen;
    if (mountedRef.current) setInteractionFrozen(frozen);
  };
  // Keep agentImprovingRef in sync so handleMessage (inside useEffect) always reads the latest value.
  agentImprovingRef.current = agentImproving;
  // Keep frontendAgentEnabledRef in sync so handleMessage always reads the latest prop value.
  frontendAgentEnabledRef.current = frontendAgentEnabled;
  const recoverIfExpired = async (state: HtmlInteractionState): Promise<boolean> => {
    if (!artifactId || recoveryInFlightRef.current || !state.frozen) return false;
    const operationId = state.operation_id;
    const agentRequestId = state.agent_request_id;
    const stateRevision = state.state_revision ?? state.revision;
    const leaseExpiresAt = Number(state.lease_expires_at ?? Number.POSITIVE_INFINITY);
    if (!operationId || !agentRequestId || !Number.isFinite(leaseExpiresAt) || leaseExpiresAt > Date.now() / 1000) return false;
    recoveryInFlightRef.current = true;
    try {
      const recovered = await htmlApi.interactionRecover(artifactId, {
        operation_id: operationId,
        agent_request_id: agentRequestId,
        expected_state_revision: stateRevision,
      });
      acceptInteractionStateRef.current(recovered.state);
      return recovered.recovered;
    } catch {
      return false;
    } finally {
      recoveryInFlightRef.current = false;
    }
  };
  const clearDraftIntent = () => {
    if (settleTimerRef.current) clearTimeout(settleTimerRef.current);
    if (maxWindowTimerRef.current) clearTimeout(maxWindowTimerRef.current);
    settleTimerRef.current = null;
    maxWindowTimerRef.current = null;
    draftEventsRef.current = [];
    focusMemoryRef.current = null;
    latestPendingRef.current = null;
    setCollectingCount(0);
    setIntentCandidate(null);
  };
  const resetIntentTransaction = (reason: string, cancelArtifactId: string | null | undefined = artifactIdRef.current): boolean => {
    const active = activeRequestRef.current;
    if (preservesFrozenTransactionOwner(active)) {
      setFrozen(true);
      return false;
    }
    const resetEpoch = ++intentEpochRef.current;
    clearDraftIntent();
    clearPoll();
    clearHeartbeat();
    if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
    readyTimeoutRef.current = null;
    pendingReadyRef.current = null;
    if (active && !active.barrierCommitted && !active.awaitingReady && cancelArtifactId) {
      void htmlApi.interactionCancel(cancelArtifactId, {
        operation_id: active.identity.operation_id,
        agent_request_id: active.identity.agent_request_id,
        intent_epoch: resetEpoch,
        reason,
      }).catch(() => undefined);
    }
    if (active) active.superseded = true;
    activeRequestRef.current = null;
    setProcessingCount(0);
    setInteractionFailed(false);
    setFrozen(false);
    return true;
  };
  resetIntentTransactionRef.current = resetIntentTransaction;

  const finishActive = (active: ActiveRequest) => {
    if (activeRequestRef.current !== active || active.awaitingReady) return;
    clearPoll();
    clearHeartbeat();
    activeRequestRef.current = null;
    if (mountedRef.current) setProcessingCount(0);
    const pending = latestPendingRef.current;
    latestPendingRef.current = null;
    if (pending) queueMicrotask(() => startEpisodeRef.current(pending));
  };
  finishActiveRef.current = finishActive;

  const supersedeActiveBeforeBarrier = (reason: string, suppliedEpoch?: number) => {
    const active = activeRequestRef.current;
    if (!active || active.barrierCommitted || active.awaitingReady || !artifactId) return false;
    const supersedingEpoch = suppliedEpoch ?? (intentEpochRef.current + 1);
    intentEpochRef.current = Math.max(intentEpochRef.current, supersedingEpoch);
    active.cancelPending = true;
    active.cancelEpoch = supersedingEpoch;
    const cancelArtifactId = artifactId;
    void htmlApi.interactionCancel(cancelArtifactId, {
      operation_id: active.identity.operation_id,
      agent_request_id: active.identity.agent_request_id,
      intent_epoch: supersedingEpoch,
      reason,
    }).then((state) => {
      if (activeRequestRef.current !== active || !active.cancelPending || active.cancelEpoch !== supersedingEpoch) return;
      acceptInteractionStateRef.current({
        ...state,
        operation_id: state.operation_id ?? active.identity.operation_id,
        agent_request_id: state.agent_request_id ?? active.identity.agent_request_id,
        intent_epoch: state.intent_epoch ?? supersedingEpoch,
      });
    }).catch(() => { /* Polling retains ownership until cancellation or a barrier is observed. */ });
    return true;
  };

  const markDocumentReadyRequired = (
    active: ActiveRequest,
    nextContent: string,
    restoreState: HtmlRuntimeState | undefined,
    htmlSha256: string,
    stateRevision: number,
    nextDocumentGenerationId: string,
    nextRestoreAttemptId: string,
    nextBridgeCapability: string,
  ) => {
    const token = createInteractionId('document');
    clearHeartbeat();
    active.awaitingReady = true;
    pendingReadyRef.current = {
      documentToken: token, operationId: active.identity.operation_id,
      agentRequestId: active.identity.agent_request_id, htmlSha256, stateRevision, expectedRestore: Boolean(restoreState),
      bridgeCapability: nextBridgeCapability,
      documentGenerationId: nextDocumentGenerationId,
      restoreAttemptId: nextRestoreAttemptId,
      submitted: false,
    };
    setFrozen(true);
    setResumeTarget(active.episode.presentation_target_ref || undefined);
    setResumeScroll(restoreState?.scroll_y ?? active.episode.representative_event.scroll_y);
    setRuntimeState(restoreState);
    liveContentRef.current = nextContent;
    htmlRevisionRef.current += 1;
    setDocumentToken(token);
    setBridgeCapability(nextBridgeCapability);
    setDocumentGenerationId(nextDocumentGenerationId);
    setRestoreAttemptId(nextRestoreAttemptId);
    setLiveContent(nextContent);
    onContentChangeRef.current?.(nextContent);
    if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
    readyTimeoutRef.current = setTimeout(() => {
      const waiting = pendingReadyRef.current;
      if (!waiting || waiting.documentToken !== token) return;
      const reportFailure = async () => {
        try {
          const state = await htmlApi.interactionReady(artifactId!, {
            operation_id: waiting.operationId, agent_request_id: waiting.agentRequestId,
            html_sha256: waiting.htmlSha256, state_revision: waiting.stateRevision,
            document_generation_id: waiting.documentGenerationId,
            restore_attempt_id: waiting.restoreAttemptId,
            bridge_capability: waiting.bridgeCapability,
            readiness_report: {
              ready: false,
              reason: 'timeout',
              document_token: waiting.documentToken,
              document_generation_id: waiting.documentGenerationId,
              restore_attempt_id: waiting.restoreAttemptId,
            },
            ready: false,
            error: 'iframe interaction readiness timed out',
          });
          acceptInteractionState(state);
        } catch {
          try {
            const state = await htmlApi.interactionState(artifactId!);
            acceptInteractionState(state);
            await recoverIfExpired(state);
          } catch { /* Keep frozen until strict lease recovery becomes eligible. */ }
        }
      };
      if (mountedRef.current) setInteractionFailed(true);
      void reportFailure();
    }, READY_TIMEOUT_MS);
  };

  // The backend rejects any intent whose epoch is not strictly greater than the epoch it
  // has already admitted. A reattached or restarted preview starts from 0, so every
  // observed epoch must lift the local baseline or the artifact stops responding.
  const liftIntentEpochBaseline = (state: {
    intent_epoch?: number;
    active_intent_epoch?: number;
    latest_pending_intent_epoch?: number;
    coordinator_latest_epoch?: number | null;
  }): number => {
    const observed = Math.max(
      state.coordinator_latest_epoch ?? 0,
      state.active_intent_epoch ?? 0,
      state.latest_pending_intent_epoch ?? 0,
      state.intent_epoch ?? 0,
    );
    if (observed > intentEpochRef.current) intentEpochRef.current = observed;
    // The observed value is returned, not the local baseline, so callers only realign when
    // the backend has genuinely already admitted an epoch at or above their own.
    return observed;
  };

  const acceptInteractionState = (state: HtmlInteractionState) => {
    const revision = state.state_revision ?? state.revision;
    if (revision < interactionStateRevisionRef.current) return;
    liftIntentEpochBaseline(state);
    const active = activeRequestRef.current;
    if (!active) {
      interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, revision);
      // Unblock intent collection — backend state has been confirmed for this artifact.
      stateInitializedRef.current = true;
      if (state.frozen) {
        if (mountedRef.current) {
          // An ownerless frozen state still freezes the page; only lease recovery releases it.
          setFrozen(true);
          setInteractionFailed(state.phase === 'failed_after_barrier' || state.document_load_result === 'failed');
        }
        if (!statePollTimerRef.current && artifactId) {
          statePollTimerRef.current = setInterval(() => {
            void htmlApi.interactionState(artifactId).then((nextState) => {
              acceptInteractionStateRef.current(nextState);
              void recoverIfExpired(nextState);
            }).catch(() => undefined);
          }, 1000);
        }
      } else {
        // Restore agentImproving indicator if the backend reports the agent is still
        // executing mutations (implementing phase). This recovers the visual state lost
        // when the component unmounted during a conversation switch.
        const isImprovingPhase = state.phase === 'implementing';
        if (mountedRef.current) {
          setFrozen(false);
          setAgentImproving(isImprovingPhase);
          agentImprovingRef.current = isImprovingPhase;
        }
        if (isImprovingPhase) {
          // Keep polling until the implementing phase completes.
          if (!statePollTimerRef.current && artifactId) {
            statePollTimerRef.current = setInterval(() => {
              void htmlApi.interactionState(artifactId).then((nextState) => {
                acceptInteractionStateRef.current(nextState);
                void recoverIfExpired(nextState);
              }).catch(() => undefined);
            }, 1000);
          }
        } else {
          clearPoll();
          clearHeartbeat();
        }
      }
      return;
    }
    if (active.superseded || !stateMatchesRequest(state, active)) return;
    interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, revision);
    active.identity.state_revision = Math.max(active.identity.state_revision, revision);
    const terminalFailure = ['failed', 'failed_before_barrier', 'failed_after_barrier'].includes(state.phase) || state.document_load_result === 'failed';
    const preBarrierFreeze = PRE_BARRIER_FROZEN_PHASES.includes(state.phase);
    const frozenState = state.frozen;
    if (preBarrierFreeze && frozenState) {
      // Freeze the page without claiming a barrier, so a newer intent can still supersede.
      if (mountedRef.current) setFrozen(true);
      return;
    }
    if (frozenState) {
      active.barrierCommitted = true;
      const waiting = pendingReadyRef.current;
      if (waiting && state.operation_id === waiting.operationId && state.phase === 'reloading') {
        waiting.stateRevision = Math.max(waiting.stateRevision, revision);
      }
      active.terminalFailure = terminalFailure;
      setFrozen(true);
      if (active.terminalFailure) {
        clearHeartbeat();
        if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
        readyTimeoutRef.current = null;
        pendingReadyRef.current = null;
        active.awaitingReady = false;
        if (mountedRef.current) setInteractionFailed(true);
      }
      return;
    }
    // pending_confirmation: barrier is held but page must be interactive while user decides.
    if (state.phase === 'pending_confirmation') {
      if (mountedRef.current) setFrozen(false);
      return;
    }
    // awaiting_user_decision / implementing: pre-mutation assess round, no freeze.
    if (state.phase === 'awaiting_user_decision' || state.phase === 'implementing') {
      if (mountedRef.current) setFrozen(false);
      return;
    }
    // discarded: user declined the assess question — treat as terminal.
    if (state.phase === 'discarded') {
      if (mountedRef.current) {
        setAgentAssessQuestion(null);
        setFrozen(false);
      }
    }
    const terminal = ['completed', 'interaction_ready', 'failed', 'failed_before_barrier', 'failed_after_barrier', 'cancelled', 'superseded', 'discarded', 'idle'].includes(state.phase);
    if (!terminal) return;
    if (active.barrierCommitted && active.cancelPending && ['cancelled', 'superseded', 'failed_before_barrier'].includes(state.phase)) return;
    active.terminalFailure = terminalFailure;
    if (active.terminalFailure) clearHeartbeat();
    if (active.awaitingReady) {
      if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
      readyTimeoutRef.current = null;
      pendingReadyRef.current = null;
      active.awaitingReady = false;
    }
    active.cancelPending = false;
    if (mountedRef.current) {
      setFrozen(false);
      if (state.phase !== 'interaction_ready' && state.phase !== 'idle' && state.phase !== 'cancelled' && state.phase !== 'superseded') setInteractionFailed(true);
    }
    finishActiveRef.current(active);
  };
  acceptInteractionStateRef.current = acceptInteractionState;
  useEffect(() => {
    if (!artifactId) return;
    return wsService.subscribeSingle((event) => {
      if (event.type !== 'html_interaction_state' || event.data.artifact_id !== artifactId) return;
      acceptInteractionState(event.data);
    });
  }, [artifactId]);

  const startEpisode = async (episode: SemanticIntentEpisode) => {
    if (!artifactId) return;
    const isUserConfirmed = nextEpisodeUserConfirmedRef.current;
    nextEpisodeUserConfirmedRef.current = false;
    const previousActive = activeRequestRef.current;
    if (previousActive) {
      if (previousActive.barrierCommitted || previousActive.awaitingReady || previousActive.cancelPending ||
          previousActive.userConfirmed) {
        // Lock: user confirmed this operation — queue the new intent instead of superseding.
        const pendingEpoch = Math.max(intentEpochRef.current, episode.intent_epoch);
        intentEpochRef.current = pendingEpoch;
        latestPendingRef.current = { ...episode, intent_epoch: pendingEpoch };
        setCollectingCount(episode.evidence.length);
        return;
      }
      const cancelEpoch = Math.max(intentEpochRef.current, episode.intent_epoch);
      const requestEpoch = cancelEpoch + 1;
      intentEpochRef.current = requestEpoch;
      latestPendingRef.current = { ...episode, intent_epoch: requestEpoch };
      setCollectingCount(episode.evidence.length);
      supersedeActiveBeforeBarrier('newer_intent_episode', cancelEpoch);
      return;
    }
    let effectiveEpisode = episode;
    if (episode.intent_epoch < intentEpochRef.current) {
      const requestEpoch = intentEpochRef.current + 1;
      intentEpochRef.current = requestEpoch;
      effectiveEpisode = { ...episode, intent_epoch: requestEpoch };
    }
    const identity: HtmlInteractionRequestIdentity = {
      intent_epoch: effectiveEpisode.intent_epoch,
      agent_request_id: createInteractionId('request'),
      operation_id: createInteractionId('operation'),
      base_html_revision: htmlRevisionRef.current,
      base_sha256: '',
      state_revision: interactionStateRevisionRef.current,
    };
    const active: ActiveRequest = {
      artifactId, identity, episode: effectiveEpisode, superseded: false, barrierCommitted: false,
      awaitingReady: false, terminalFailure: false, cancelPending: false,
      userConfirmed: isUserConfirmed,
    };
    activeRequestRef.current = active;
    setProcessingCount(episode.evidence.length);
    setCollectingCount(0);
    setInteractionFailed(false);
    try {
      try {
        const baseline = await htmlApi.interactionState(artifactId);
        if (activeRequestRef.current !== active) return;
        interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, baseline.state_revision ?? baseline.revision);
        identity.state_revision = interactionStateRevisionRef.current;
        identity.base_html_revision = baseline.html_revision ?? identity.base_html_revision;
        identity.base_sha256 = baseline.html_sha256 ?? '';
        const admitted = liftIntentEpochBaseline(baseline);
        if (admitted >= identity.intent_epoch) {
          const realigned = admitted + 1;
          intentEpochRef.current = realigned;
          identity.intent_epoch = realigned;
          effectiveEpisode = { ...effectiveEpisode, intent_epoch: realigned };
          active.episode = effectiveEpisode;
        }
      } catch { /* WebSocket state remains the fallback. */ }
      if (!identity.base_sha256) identity.base_sha256 = await sha256Text(liveContentRef.current);
      if (activeRequestRef.current !== active) return;
      const poll = async () => {
        try {
          const state = await htmlApi.interactionState(artifactId);
          acceptInteractionState(state);
          await recoverIfExpired(state);
        } catch { /* WebSocket is primary. */ }
      };
      clearPoll();
      statePollTimerRef.current = setInterval(() => { void poll(); }, 200);
      const result: HtmlInteractResult = await htmlApi.interact(
        artifactId,
        [episodeToAgentEvent(effectiveEpisode, identity)],
        identity,
        effectiveEpisode,
      );
      if (activeRequestRef.current !== active || active.superseded) return;
      if (result.coordinator_latest_epoch != null) {
        intentEpochRef.current = Math.max(intentEpochRef.current, result.coordinator_latest_epoch);
      }
      if (result.decision === 'pending_confirmation') {
        // Agent has proposed mutations; await user acceptance before persisting.
        // Do not freeze — the page stays interactive.
        if (mountedRef.current) {
          setAgentConfirmation({
            reason: result.reason ?? result.intent ?? '',
            operationId: result.operation_id ?? active.identity.operation_id,
            agentRequestId: result.agent_request_id ?? active.identity.agent_request_id,
          });
          setProcessingCount(0);
        }
        // Start heartbeat to keep the backend lease alive.
        if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
        const confirmOpId = result.operation_id ?? active.identity.operation_id;
        const confirmReqId = result.agent_request_id ?? active.identity.agent_request_id;
        confirmHeartbeatTimerRef.current = setInterval(() => {
          if (!artifactId) return;
          void htmlApi.interactionHeartbeat(artifactId, confirmOpId, confirmReqId).catch(() => undefined);
        }, 10_000);
        // 120 s timeout: if user does not respond, mark as timed out.
        if (confirmTimeoutRef.current) clearTimeout(confirmTimeoutRef.current);
        confirmTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) setAgentConfirmation((prev) => prev ? { ...prev, timedOut: true } : prev);
          if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
          confirmHeartbeatTimerRef.current = null;
        }, 120_000);
        return;
      }

      // Round-1 ASSESS: agent asked the user a question, waiting for decision.
      if (result.decision === 'awaiting_user_decision') {
        if (mountedRef.current) {
          setAgentAssessQuestion({
            question: result.question ?? '',
            operationId: result.operation_id ?? active.identity.operation_id,
            agentRequestId: result.agent_request_id ?? active.identity.agent_request_id,
          });
          setProcessingCount(0);
        }
        return;
      }
      if (result.decision === 'superseded' && !result.generated) {
        // A stale-epoch rejection publishes no state transition. The baseline is realigned
        // above so the next intent is admitted, and the user sees the same visible
        // affordance as any other intent that was not applied instead of nothing at all.
        if (mountedRef.current) {
          setFrozen(false);
          setInteractionFailed(true);
        }
        return;
      }
      if (result.operation_id) active.identity.operation_id = result.operation_id;
      if (result.agent_request_id) active.identity.agent_request_id = result.agent_request_id;
      if (result.state_revision != null) {
        active.identity.state_revision = Math.max(active.identity.state_revision, result.state_revision);
        interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, result.state_revision);
      }
      if (result.generated && result.content !== liveContentRef.current) {
        const committedSha = result.html_sha256 ?? await sha256Text(result.content);
        const committedStateRevision = Math.max(active.identity.state_revision, interactionStateRevisionRef.current);
        if (!result.document_generation_id || !result.restore_attempt_id || !result.bridge_capability) {
          throw new Error('Committed HTML mutation is missing document readiness identity');
        }
        markDocumentReadyRequired(
          active, result.content, undefined, committedSha, committedStateRevision,
          result.document_generation_id, result.restore_attempt_id, result.bridge_capability,
        );
      } else if (!active.barrierCommitted && mountedRef.current) {
        setFrozen(false);
      } else if (active.barrierCommitted) {
        // A committed barrier can only be released by a matching terminal backend state.
        try { acceptInteractionState(await htmlApi.interactionState(artifactId)); } catch { /* Polling/lease recovery remains active. */ }
      }
    } catch (error) {
      console.error('Dynamic HTML semantic interaction analysis failed:', error);
      if (!active.superseded && mountedRef.current) {
        setInteractionFailed(true);
        setFrozen(active.barrierCommitted);
      }
      if (!active.superseded && active.barrierCommitted) {
        try {
          const state = await htmlApi.interactionState(artifactId);
          acceptInteractionState(state);
          await recoverIfExpired(state);
        } catch { /* Keep frozen until strict lease recovery becomes eligible. */ }
      }
    } finally {
      if (activeRequestRef.current === active && !active.awaitingReady && !active.barrierCommitted && !active.cancelPending) finishActiveRef.current(active);
    }
  };
  startEpisodeRef.current = (episode) => { void startEpisode(episode); };

  const finalizeDraft = () => {
    if (settleTimerRef.current) clearTimeout(settleTimerRef.current);
    if (maxWindowTimerRef.current) clearTimeout(maxWindowTimerRef.current);
    settleTimerRef.current = null;
    maxWindowTimerRef.current = null;
    // While the agent is implementing a mutation (Round 2 through commit), discard
    // any collected draft so no new episode is dispatched until the cycle completes.
    if (agentImproving) {
      draftEventsRef.current = [];
      setCollectingCount(0);
      return;
    }
    // Frontend Agent is disabled — drop the draft without dispatching.
    if (!frontendAgentEnabled) {
      draftEventsRef.current = [];
      setCollectingCount(0);
      return;
    }
    const events = draftEventsRef.current.splice(0);
    if (!events.length) return;
    intentEpochRef.current += 1;
    const episode = buildSemanticIntentEpisode(events, intentEpochRef.current);
    setCollectingCount(0);
    if (!episode) return;
    // Gating follows whether the page answered the user, not gesture strength. A dead operable
    // control dispatches even at low confidence; a change that did not clearly satisfy the user
    // goes to local disambiguation instead of being dropped without a trace.
    const copiedWithoutExplicitRequest = episode.evidence.some((item) => item.event_type === 'copy') &&
      !episode.representative_event.spore_request;
    if (copiedWithoutExplicitRequest || episode.disposition === 'discard') {
      setIntentCandidate(null);
      return;
    }
    if (episode.disposition === 'disambiguate') {
      supersedeActiveBeforeBarrier('new_intent_requires_local_disambiguation', episode.intent_epoch);
      setIntentCandidate(episode);
      return;
    }
    setIntentCandidate(null);
    startEpisodeRef.current(episode);
  };
  finalizeDraftRef.current = finalizeDraft;

  useEffect(() => {
    const handleMessage = (event: MessageEvent<DynamicRequest>) => {
      if (event.source !== frameRef.current?.contentWindow) return;
      const message = event.data;
      if (!message || message.source !== 'spore-html' || !artifactId || message.artifactId !== artifactId) return;
      if (message.bridgeCapability !== bridgeCapability) return;
      if (message.type === 'interaction_ready') {
        const waiting = pendingReadyRef.current;
        const active = activeRequestRef.current;
        if (!waiting || waiting.submitted || !active || active.terminalFailure || message.documentToken !== waiting.documentToken || active.identity.operation_id !== waiting.operationId) return;
        if (message.documentGenerationId !== waiting.documentGenerationId || message.restoreAttemptId !== waiting.restoreAttemptId) return;
        waiting.submitted = true;
        if (readyTimeoutRef.current) clearTimeout(readyTimeoutRef.current);
        readyTimeoutRef.current = null;
        const readinessAccepted = message.ready === true && message.bridgeInstalled === true &&
          message.coreInteractionsReady === true && !message.initializationPending &&
          (!waiting.expectedRestore || (message.restoreRequested === true && message.restored === true));
        const readinessReport = {
          ready: readinessAccepted,
          bridge_installed: message.bridgeInstalled === true,
          core_interactions_ready: message.coreInteractionsReady === true,
          document_token: message.documentToken,
          document_generation_id: message.documentGenerationId,
          restore_attempt_id: message.restoreAttemptId,
          restored: message.restored === true,
          restore_requested: message.restoreRequested === true,
          restore_report: message.restoreReport ?? null,
          initialization_pending: message.initializationPending === true,
          document_ready_state: message.documentReadyState ?? 'unknown',
          interactive_count: message.interactiveCount ?? 0,
        };
        void htmlApi.interactionReady(artifactId, {
          operation_id: waiting.operationId, agent_request_id: waiting.agentRequestId,
          html_sha256: waiting.htmlSha256, state_revision: waiting.stateRevision,
          document_generation_id: waiting.documentGenerationId,
          restore_attempt_id: waiting.restoreAttemptId,
          bridge_capability: waiting.bridgeCapability,
          readiness_report: readinessReport,
          ready: readinessAccepted,
          error: readinessAccepted ? undefined : `iframe readiness rejected: state=${message.documentReadyState ?? 'unknown'}, restored=${Boolean(message.restored)}, initializing=${Boolean(message.initializationPending)}`,
        }).then((state) => {
          if (pendingReadyRef.current !== waiting || activeRequestRef.current !== active) return;
          acceptInteractionState(state);
        }).catch(async () => {
          if (pendingReadyRef.current !== waiting || activeRequestRef.current !== active) return;
          if (mountedRef.current) setInteractionFailed(true);
          try {
            const state = await htmlApi.interactionState(artifactId);
            acceptInteractionState(state);
            await recoverIfExpired(state);
          } catch { /* Keep frozen until strict lease recovery becomes eligible. */ }
        });
        return;
      }
      const hasActiveRequest = activeRequestRef.current !== null;
      // stateInitializedRef guards the window between (re)mount and first backend state
      // confirmation — without it, iframe events arrive while agentImproving/interactionFrozen
      // are still false and spuriously open the intent-collection dialog.
      if (!stateInitializedRef.current || !['click', 'interaction'].includes(message.type) || !message.event || interactionFrozen ||
          hasActiveRequest || agentImprovingRef.current || !frontendAgentEnabledRef.current) return;
      const observed = message.event;
      // Record dblclick so we can suppress its ghost click events that arrive late
      // (bridge sends dblclick with delay=40ms but click with delay=400ms, so clicks
      // from the same double-click sequence arrive ~360ms after the dblclick).
      if ((observed.event_type ?? 'click') === 'dblclick') {
        lastDblClickRef.current = {
          timestamp: observed.timestamp_ms,
          focusRef: eventFocusRef(observed),
          domPath: observed.dom_path ?? '',
        };
      }
      // Suppress ghost clicks from a preceding double-click sequence.
      if ((observed.event_type ?? 'click') === 'click') {
        const last = lastDblClickRef.current;
        if (last !== null && Math.abs(observed.timestamp_ms - last.timestamp) <= 600) {
          const sameFocus = eventFocusRef(observed) === last.focusRef ||
            (Boolean(observed.dom_path) && observed.dom_path === last.domPath);
          if (sameFocus) return;
        }
      }
      const active = activeRequestRef.current;
      const focusShifted = Boolean(active && !active.barrierCommitted &&
        eventFocusRef(active.episode.representative_event) !== eventFocusRef(observed) &&
        !eventsLikelyRelated(active.episode.representative_event, observed));
      if (focusShifted) supersedeActiveBeforeBarrier('user_focus_changed');
      if (['copy', 'selection_clear'].includes(observed.event_type ?? '') && !observed.spore_request) {
        supersedeActiveBeforeBarrier(observed.event_type === 'copy' ? 'user_copied_selection' : 'user_cleared_selection');
        if (settleTimerRef.current) clearTimeout(settleTimerRef.current);
        if (maxWindowTimerRef.current) clearTimeout(maxWindowTimerRef.current);
        settleTimerRef.current = null;
        maxWindowTimerRef.current = null;
        draftEventsRef.current = [];
        focusMemoryRef.current = null;
        setCollectingCount(0);
        setIntentCandidate(null);
        return;
      }
      const remembered = focusMemoryRef.current;
      focusMemoryRef.current = observed;
      if (shouldIgnoreLocallySatisfiedSignal(observed)) return;
      if (!draftEventsRef.current.length && remembered && !isStrongIntentSignal(remembered) &&
          !interactionLocallyResolved(remembered) && isStrongIntentSignal(observed) &&
          observed.timestamp_ms - remembered.timestamp_ms <= 10_000 && eventsLikelyRelated(remembered, observed)) {
        draftEventsRef.current.push(remembered);
      }
      const previous = draftEventsRef.current[draftEventsRef.current.length - 1];
      if (previous && !eventsLikelyRelated(previous, observed)) finalizeDraftRef.current();
      draftEventsRef.current.push(observed);
      setCollectingCount(draftEventsRef.current.length);
      setIntentCandidate(null);
      setInteractionFailed(false);
      if (settleTimerRef.current) clearTimeout(settleTimerRef.current);
      const cadence = previous ? Math.max(0, observed.timestamp_ms - previous.timestamp_ms) : undefined;
      const activePreBarrier = Boolean(activeRequestRef.current && !activeRequestRef.current.barrierCommitted);
      settleTimerRef.current = setTimeout(
        () => finalizeDraftRef.current(),
        dynamicWindowDelay(observed, draftEventsRef.current.length, {
          activePreBarrier,
          pageChangedLocally: Boolean(observed.local_outcome?.changed && !interactionLocallyResolved(observed)),
          recentCadenceMs: cadence,
        }),
      );
      if (!maxWindowTimerRef.current) {
        const maximumLifetime = activePreBarrier ? 1600 : observed.event_type === 'input' ? 3200 : MAX_INTENT_WINDOW_MS;
        maxWindowTimerRef.current = setTimeout(() => finalizeDraftRef.current(), maximumLifetime);
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [artifactId, bridgeCapability, interactionFrozen]);

  const dismissIntentCandidate = () => {
    const dismissEpoch = ++intentEpochRef.current;
    latestPendingRef.current = null;
    supersedeActiveBeforeBarrier('user_dismissed_intent_candidate', dismissEpoch);
    clearDraftIntent();
  };

  const clearConfirmation = () => {
    if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
    if (confirmTimeoutRef.current) clearTimeout(confirmTimeoutRef.current);
    confirmHeartbeatTimerRef.current = null;
    confirmTimeoutRef.current = null;
    if (mountedRef.current) {
      setAgentConfirmation(null);
      setAgentImproving(false);
    }
  };

  const dismissAssessQuestion = () => {
    const assess = agentAssessQuestion;
    if (mountedRef.current) setAgentAssessQuestion(null);
    if (artifactId && assess) {
      void htmlApi.interactionResume(artifactId, {
        operation_id: assess.operationId,
        agent_request_id: assess.agentRequestId,
        user_agreed: false,
      }).catch(() => undefined);
    }
    const active = activeRequestRef.current;
    if (active) {
      active.superseded = true;
      active.barrierCommitted = false;
      finishActiveRef.current(active);
    }
    if (mountedRef.current) {
      setFrozen(false);
      setInteractionFailed(false);
    }
  };

  const acceptAssessQuestion = async () => {
    const assess = agentAssessQuestion;
    if (!assess || !artifactId) return;
    if (mountedRef.current) {
      setAgentAssessQuestion(null);
      setAgentImproving(true);   // ← 立即标记，守卫生效
      setProcessingCount(1);
    }
    agentImprovingRef.current = true; // ← 同步写 ref，handleMessage 守卫即刻生效
    try {
      const result = await htmlApi.interactionResume(artifactId, {
        operation_id: assess.operationId,
        agent_request_id: assess.agentRequestId,
        user_agreed: true,
      });
      const active = activeRequestRef.current;
      if (result.state_revision != null) {
        if (active) active.identity.state_revision = Math.max(active.identity.state_revision, result.state_revision);
        interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, result.state_revision);
      }
      if (result.decision === 'pending_confirmation') {
        const confirmOpId = result.operation_id ?? assess.operationId;
        const confirmReqId = result.agent_request_id ?? assess.agentRequestId;
        if (mountedRef.current) {
          setAgentConfirmation({
            reason: result.reason ?? result.intent ?? '',
            operationId: confirmOpId,
            agentRequestId: confirmReqId,
          });
          setProcessingCount(0);
          setAgentImproving(false);
        }
        agentImprovingRef.current = false;
        if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
        confirmHeartbeatTimerRef.current = setInterval(() => {
          if (!artifactId) return;
          void htmlApi.interactionHeartbeat(artifactId, confirmOpId, confirmReqId).catch(() => undefined);
        }, 10_000);
        if (confirmTimeoutRef.current) clearTimeout(confirmTimeoutRef.current);
        confirmTimeoutRef.current = setTimeout(() => {
          if (mountedRef.current) setAgentConfirmation((prev) => prev ? { ...prev, timedOut: true } : prev);
          if (confirmHeartbeatTimerRef.current) clearInterval(confirmHeartbeatTimerRef.current);
          confirmHeartbeatTimerRef.current = null;
        }, 120_000);
      } else {
        // no_change / aborted / superseded — operation done, clear improving state.
        clearConfirmation();
        if (mountedRef.current) setProcessingCount(0);
        if (active) finishActiveRef.current(active);
        if (mountedRef.current) setFrozen(false);
      }
    } catch (error) {
      console.error('Assess accept failed:', error);
      if (mountedRef.current) {
        setProcessingCount(0);
        setInteractionFailed(true);
      }
      const active = activeRequestRef.current;
      if (active) finishActiveRef.current(active);
    }
  };

  const dismissAgentConfirmation = () => {
    const confirmation = agentConfirmation;
    clearConfirmation();
    // Release the operation on the backend (barrier was committed — use supersede).
    const active = activeRequestRef.current;
    if (active) {
      active.superseded = true;
      active.barrierCommitted = false;  // Allow finishActive to proceed.
      finishActiveRef.current(active);
    }
    if (artifactId && confirmation) {
      const cancelEpoch = ++intentEpochRef.current;
      void htmlApi.interactionCancel(artifactId, {
        operation_id: confirmation.operationId,
        agent_request_id: confirmation.agentRequestId,
        intent_epoch: cancelEpoch,
        reason: 'user_dismissed_agent_confirmation',
      }).catch(() => undefined);
    }
    setFrozen(false);
    setInteractionFailed(false);
  };

  const acceptAgentConfirmation = async () => {
    const confirmation = agentConfirmation;
    if (!confirmation || !artifactId || agentImproving) return;
    if (confirmTimeoutRef.current) clearTimeout(confirmTimeoutRef.current);
    confirmTimeoutRef.current = null;
    if (mountedRef.current) setAgentImproving(true);
    try {
      const result = await htmlApi.interactionConfirm(artifactId, {
        operation_id: confirmation.operationId,
        agent_request_id: confirmation.agentRequestId,
      });
      clearConfirmation();
      const active = activeRequestRef.current;
      // Update revision counters regardless of whether active was already cleared by a WebSocket race.
      if (result.state_revision != null) {
        if (active) active.identity.state_revision = Math.max(active.identity.state_revision, result.state_revision);
        interactionStateRevisionRef.current = Math.max(interactionStateRevisionRef.current, result.state_revision);
      }
      if (result.generated && result.content && result.content !== liveContentRef.current) {
        if (result.requires_interaction_ready_ack && result.document_generation_id && result.restore_attempt_id && result.bridge_capability) {
          // Full bridge readiness handshake path — needs an active operation for the ready ACK.
          if (!active) return;
          const committedSha = result.html_sha256 ?? await sha256Text(result.content);
          const committedStateRevision = Math.max(active.identity.state_revision, interactionStateRevisionRef.current);
          markDocumentReadyRequired(
            active, result.content, undefined, committedSha, committedStateRevision,
            result.document_generation_id, result.restore_attempt_id, result.bridge_capability,
          );
        } else {
          // Simple path: apply the committed content even if the WebSocket completed-state event
          // already cleared activeRequestRef before this HTTP response arrived.
          liveContentRef.current = result.content;
          htmlRevisionRef.current += 1;
          setDocumentToken(createInteractionId('document'));
          setBridgeCapability(createInteractionId('bridge-capability'));
          setDocumentGenerationId(createInteractionId('document-generation'));
          setRestoreAttemptId(createInteractionId('restore-attempt'));
          setLiveContent(result.content);
          onContentChangeRef.current?.(result.content);
          setFrozen(false);
          if (active) finishActiveRef.current(active);
        }
      } else {
        setFrozen(false);
        if (active) finishActiveRef.current(active);
      }
    } catch (error) {
      console.error('Agent confirmation failed:', error);
      clearConfirmation();
      if (mountedRef.current) setInteractionFailed(true);
      const active = activeRequestRef.current;
      if (active) {
        try {
          const state = await htmlApi.interactionState(artifactId);
          acceptInteractionStateRef.current(state);
          await recoverIfExpired(state);
        } catch { /* Keep state until lease recovery. */ }
      }
    }
  };

  // `build` is page-expression work the Agent completes from artifact data, so it needs no
  // grounded knowledge packet. `explain`/`compare` assert domain facts and do.
  const CONFIRMED_INTENT_REQUESTS: Record<'build' | 'explain' | 'compare', (label: string) => string> = {
    build: (label) => `Build the interface affordance this control promises for ${label}, using the page's own data and the presentation target.`,
    compare: (label) => `Compare the selected semantic objects, including ${label}, using a stable page explanation area.`,
    explain: (label) => `Explain ${label} in its current semantic context and include the current value when available.`,
  };
  const CONFIRMED_INTENT_CANDIDATES: Record<'build' | 'explain' | 'compare', string> = {
    build: 'build_missing_control_affordance',
    compare: 'compare_semantic_objects',
    explain: 'explain_semantic_object',
  };

  const confirmIntentCandidate = (intent: 'build' | 'explain' | 'compare') => {
    const candidate = intentCandidate;
    if (!candidate) return;
    const label = candidate.focus.label || candidate.semantic_focus_ref;
    const confirmed: SemanticIntentEpisode = {
      ...candidate,
      intent_epoch: ++intentEpochRef.current,
      confidence: 'high',
      disposition: 'dispatch',
      candidate_intents: [CONFIRMED_INTENT_CANDIDATES[intent]],
      representative_event: {
        ...candidate.representative_event,
        spore_request: CONFIRMED_INTENT_REQUESTS[intent](label),
      },
    };
    setIntentCandidate(null);
    nextEpisodeUserConfirmedRef.current = true;
    startEpisodeRef.current(confirmed);
  };

  useEffect(() => {
    if (!interactionFrozen || !artifactId || activeRequestRef.current?.terminalFailure) {
      clearHeartbeat();
      return;
    }
    const heartbeat = () => {
      const active = activeRequestRef.current;
      // Every frozen phase holds a lease, including the pre-barrier analyzing freeze.
      // Skipping renewal there would let the lease expire mid-analysis and orphan it.
      if (!active || active.awaitingReady || active.terminalFailure) return;
      void htmlApi.interactionHeartbeat(
        artifactId, active.identity.operation_id, active.identity.agent_request_id,
      ).catch(() => undefined);
    };
    heartbeat();
    heartbeatTimerRef.current = setInterval(heartbeat, 10_000);
    return clearHeartbeat;
  }, [artifactId, interactionFrozen]);

  // 底栏弹窗 3 秒自动消失：后出现的弹窗会替换前面的，同时旧弹窗因 state 清零而 unmount。
  // intentCandidate 渲染在最后（DOM 层叠最高），确保它始终覆盖 agent 弹窗。
  const BOTTOM_POPUP_DISMISS_MS = 6_000;
  useEffect(() => {
    if (!intentCandidate) return;
    const timer = setTimeout(() => dismissIntentCandidate(), BOTTOM_POPUP_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [intentCandidate]);
  useEffect(() => {
    if (!agentAssessQuestion) return;
    const timer = setTimeout(() => dismissAssessQuestion(), BOTTOM_POPUP_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [agentAssessQuestion]);

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
          className="pointer-events-none absolute inset-x-3 top-3 rounded border border-spore-border/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-text shadow-lg"
        >
          <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-spore-highlight" />
          {processingCount > 0
            ? t('chatPanel.htmlPreview.interpretingClicks', { count: processingCount })
            : t('chatPanel.htmlPreview.collectingClicks', { count: collectingCount })}
          {processingCount > 0 && collectingCount > 0 && (
            <span className="ml-2 text-spore-muted">{t('chatPanel.htmlPreview.queuedClicks', { count: collectingCount })}</span>
          )}
        </div>
      )}
      {interactionFailed && collectingCount === 0 && processingCount === 0 && !agentConfirmation && !agentImproving && (
        <div className="pointer-events-none absolute inset-x-3 bottom-3 rounded border border-spore-error/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-error shadow-lg">
          {t('chatPanel.htmlPreview.interactionFailed')}
        </div>
      )}
      {agentImproving && !interactionFrozen && (
        <div
          data-testid="html-agent-improving"
          className="pointer-events-none absolute inset-x-3 bottom-3 rounded border border-spore-highlight/50 bg-spore-card/95 px-3 py-2 text-xs text-spore-text shadow-lg"
        >
          <span className="mr-2 inline-block h-2 w-2 animate-spin rounded-full border border-spore-highlight border-t-transparent" />
          {t('chatPanel.htmlPreview.agentImproving')}
        </div>
      )}
      {agentConfirmation && !agentImproving && (
        <div
          data-testid="html-agent-confirmation"
          className="absolute inset-x-3 bottom-3 z-10 flex flex-col gap-2 rounded-md border border-spore-highlight/60 bg-spore-card px-3 py-3 text-xs text-spore-text shadow-lg"
          role="dialog"
          aria-label={t('chatPanel.htmlPreview.agentConfirmTitle')}
        >
          <div className="flex items-start gap-2">
            <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-spore-highlight" />
            <p className="min-w-0 flex-1 leading-snug">
              <span className="mr-1 font-medium">{t('chatPanel.htmlPreview.agentConfirmTitle')}:</span>
              {agentConfirmation.reason}
            </p>
          </div>
          {agentConfirmation.timedOut ? (
            <p className="text-spore-error">{t('chatPanel.htmlPreview.agentConfirmTimeout')}</p>
          ) : null}
          <div className="flex justify-end gap-2">
            {!agentConfirmation.timedOut && (
              <button
                type="button"
                className="rounded border border-spore-highlight/60 bg-spore-highlight/10 px-3 py-1 font-medium hover:bg-spore-highlight/20"
                onClick={() => { void acceptAgentConfirmation(); }}
              >
                {t('chatPanel.htmlPreview.agentConfirmAccept')}
              </button>
            )}
            <button
              type="button"
              className="rounded border border-spore-border px-3 py-1 hover:bg-spore-hover"
              onClick={dismissAgentConfirmation}
            >
              {t('chatPanel.htmlPreview.agentConfirmDismiss')}
            </button>
          </div>
        </div>
      )}
      {agentAssessQuestion && !agentImproving && !agentConfirmation && (
        <div
          data-testid="html-agent-assess-question"
          className="absolute inset-x-3 bottom-3 z-10 flex flex-col gap-2 rounded-md border border-spore-border bg-spore-card px-3 py-3 text-xs text-spore-text shadow-lg"
          role="dialog"
          aria-label={t('chatPanel.htmlPreview.agentAssessTitle')}
        >
          <div className="flex items-start gap-2">
            <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full bg-spore-muted" />
            <p className="min-w-0 flex-1 leading-snug">
              <span className="mr-1 font-medium">{t('chatPanel.htmlPreview.agentAssessTitle')}:</span>
              {agentAssessQuestion.question}
            </p>
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className="rounded border border-spore-highlight/60 bg-spore-highlight/10 px-3 py-1 font-medium hover:bg-spore-highlight/20"
              onClick={() => { void acceptAssessQuestion(); }}
            >
              {t('chatPanel.htmlPreview.agentAssessAccept')}
            </button>
            <button
              type="button"
              className="rounded border border-spore-border px-3 py-1 hover:bg-spore-hover"
              onClick={dismissAssessQuestion}
            >
              {t('chatPanel.htmlPreview.agentAssessDismiss')}
            </button>
          </div>
        </div>
      )}
      {/* intentCandidate 渲染在最后：DOM 层叠最高，确保后出现的用户操作意图弹窗覆盖 agent 弹窗 */}
      {intentCandidate && !interactionFrozen && (
        <div
          data-testid="html-intent-candidate"
          className="absolute inset-x-3 bottom-3 z-10 flex flex-wrap items-center gap-2 rounded-md border border-spore-border bg-spore-card px-3 py-2 text-xs text-spore-text shadow-lg"
          role="toolbar"
          aria-label={t('chatPanel.htmlPreview.intentCandidate')}
        >
          <span className="min-w-0 flex-1 truncate" title={intentCandidate.focus.label}>
            {t('chatPanel.htmlPreview.intentCandidate')}: {intentCandidate.focus.label}
          </span>
          <button type="button" className="rounded border border-spore-border px-2 py-1 hover:bg-spore-hover" onClick={() => confirmIntentCandidate('build')}>
            {t('chatPanel.htmlPreview.build')}
          </button>
          <button type="button" className="rounded border border-spore-border px-2 py-1 hover:bg-spore-hover" onClick={() => confirmIntentCandidate('explain')}>
            {t('chatPanel.htmlPreview.explain')}
          </button>
          {intentCandidate.candidate_intents.includes('compare_semantic_objects') && (
            <button type="button" className="rounded border border-spore-border px-2 py-1 hover:bg-spore-hover" onClick={() => confirmIntentCandidate('compare')}>
              {t('chatPanel.htmlPreview.compare')}
            </button>
          )}
          <button type="button" className="rounded px-2 py-1 text-spore-muted hover:bg-spore-hover" onClick={dismissIntentCandidate}>
            {t('chatPanel.htmlPreview.dismiss')}
          </button>
        </div>
      )}
    </div>
  );
}
