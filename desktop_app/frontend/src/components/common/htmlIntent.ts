export type HtmlInteractionEventType =
  | 'click'
  | 'dblclick'
  | 'selection'
  | 'selection_clear'
  | 'copy'
  | 'input'
  | 'change'
  | 'submit'
  | 'keyboard_activate'
  | 'keyboard_navigate'
  | 'touch_long_press';

export type HtmlRuntimeElementRef = {
  element_id?: string;
  dom_path?: string;
  spore_view?: string;
};

export type HtmlRuntimeState = {
  scroll_x: number;
  scroll_y: number;
  active?: HtmlRuntimeElementRef;
  selection?: {
    text: string;
    start_path: string;
    start_offset: number;
    end_path: string;
    end_offset: number;
  };
  controls?: Array<HtmlRuntimeElementRef & { value?: string; value_observed?: boolean; redacted?: boolean; checked?: boolean; selected_index?: number }>;
  details?: Array<HtmlRuntimeElementRef & { open: boolean }>;
  toggles?: Array<HtmlRuntimeElementRef & { hidden?: boolean; aria_expanded?: string; aria_selected?: string }>;
};

export type HtmlLocalOutcome = {
  observed: boolean;
  changed: boolean;
  satisfied: boolean;
  reveal_succeeded?: boolean;
  target_visible?: boolean;
  /** Whether the revealed target actually carries content rather than an empty slot. */
  target_has_content?: boolean;
  /** A declared target became visible while still empty: an unmet need, not a fulfilled one. */
  placeholder_revealed?: boolean;
  before_signature?: string;
  after_signature?: string;
};

export type HtmlSemanticContext = {
  /** The artifact author marked this element as an inspectable semantic object. */
  annotated?: boolean;
  object_name?: string;
  object_type?: string;
  domain?: string;
  semantic_path?: string;
  container_ref?: string;
  current_value?: string;
  instance_data?: string;
  related_refs?: string[];
  explanation_present?: boolean;
  inspector_ref?: string;
  presentation_ref?: string;
  mutation_ref?: string;
};

export type HtmlInteractionEvent = {
  timestamp_ms: number;
  artifact_id?: string;
  event_type?: HtmlInteractionEventType;
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
  semantic_ref?: string;
  presentation_ref?: string;
  mutation_ref?: string;
  semantic_context?: HtmlSemanticContext;
  selection_text?: string;
  key?: string;
  pointer_type?: string;
  control?: { type: string; value?: string; checked: boolean; redacted?: boolean; value_observed?: boolean };
  /** The bridge judged this element operable by the user (control, role, tabindex, pointer cursor). */
  operable?: boolean;
  local_outcome?: HtmlLocalOutcome;
  runtime_state?: HtmlRuntimeState;
  scroll_y: number;
  viewport: { width: number; height: number };
};

export type SemanticIntentEpisode = {
  episode_id: string;
  intent_epoch: number;
  started_at_ms: number;
  ended_at_ms: number;
  semantic_focus_ref: string;
  presentation_target_ref: string;
  mutation_target_ref: string;
  focus: {
    label: string;
    context: string[];
    selected_text?: string;
    object_type?: string;
    domain?: string;
    semantic_path?: string;
    current_value?: string;
    instance_data?: string;
    explanation_present?: boolean;
    inspector_ref?: string;
    related_refs?: string[];
  };
  focuses: Array<{
    ref: string;
    label: string;
    object_type?: string;
    domain?: string;
    semantic_path?: string;
    current_value?: string;
    instance_data?: string;
    explanation_present?: boolean;
    inspector_ref?: string;
    presentation_ref?: string;
    mutation_ref?: string;
    container_ref?: string;
    related_refs?: string[];
  }>;
  evidence: Array<{
    event_type: HtmlInteractionEventType;
    elapsed_ms: number;
    focus_ref: string;
    word?: string;
    selection?: string;
    key?: string;
    operable?: boolean;
    local_outcome?: HtmlLocalOutcome;
    semantic_context?: HtmlSemanticContext;
  }>;
  candidate_intents: string[];
  confidence: 'low' | 'medium' | 'high';
  local_outcome: 'satisfied' | 'not_satisfied' | 'unknown';
  /** What the host should do with this episode. See `IntentDisposition`. */
  disposition: IntentDisposition;
  representative_event: HtmlInteractionEvent;
  runtime_state?: HtmlRuntimeState;
};

/**
 * What the host should do with an episode.
 *
 * Gating is decided by whether the page answered the user, not by how hard the user clicked.
 * Confidence measures gesture strength and is only a tiebreaker here.
 */
export type IntentDisposition = 'discard' | 'disambiguate' | 'dispatch';

/**
 * Decide what the host does with this episode by asking whether the page already answered the
 * user, not by how hard they clicked. A click on an operable control that changed nothing is a
 * dead control -- the strongest available evidence of an unmet need -- and dispatches even at
 * low confidence. A click that changed something but did not clearly satisfy the user is
 * ambiguous and goes to local disambiguation rather than being silently discarded or blindly
 * dispatched. Confidence only breaks residual ties.
 */
export function computeIntentDisposition(
  events: HtmlInteractionEvent[],
  candidateIntents: string[],
  confidence: SemanticIntentEpisode['confidence'],
): IntentDisposition {
  const representative = events[events.length - 1];
  if (representative?.spore_request) return 'dispatch';
  if (candidateIntents.includes('complete_requested_action')) return 'dispatch';
  if (candidateIntents.includes('copy_content_without_page_change')) return 'discard';
  const outcomes = events.map((event) => event.local_outcome).filter(Boolean) as HtmlLocalOutcome[];
  const allSatisfied = outcomes.length > 0 &&
    outcomes.every((outcome) => outcome.satisfied && !outcome.placeholder_revealed);
  if (allSatisfied) return 'discard';
  const deadOperableControl = events.some((event) =>
    event.operable && event.local_outcome?.observed && !event.local_outcome.changed && !event.local_outcome.satisfied);
  const placeholderRevealed = outcomes.some((outcome) => outcome.placeholder_revealed);
  if (deadOperableControl || placeholderRevealed) return 'dispatch';
  if (candidateIntents.includes('explain_repeatedly_unresponsive_object')) return 'dispatch';
  // All remaining cases surface the local toolbar rather than auto-dispatching. dblclick,
  // selection, and confidence-based signals are too ambiguous to mutate the page without
  // explicit user confirmation — only structural cues above warrant auto-dispatch.
  return confidence === 'low' ? 'discard' : 'disambiguate';
}

export type HtmlInteractionRequestIdentity = {
  intent_epoch: number;
  agent_request_id: string;
  operation_id: string;
  base_html_revision: number;
  base_sha256: string;
  state_revision: number;
};

const STRONG_TYPES = new Set<HtmlInteractionEventType>([
  'dblclick', 'selection', 'copy', 'submit', 'keyboard_activate', 'touch_long_press',
]);

const uid = (prefix: string): string => {
  const uuid = globalThis.crypto?.randomUUID?.();
  return `${prefix}-${uuid ?? `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`}`;
};

export const createInteractionId = uid;

export function eventFocusRef(event: HtmlInteractionEvent): string {
  return event.semantic_ref || event.spore_target || event.element_id || event.dom_path ||
    event.clicked_word || event.selection_text || event.aria_label || event.text.slice(0, 120) || event.tag;
}

const CROSS_WINDOW_WEAK_CLICK_TTL_MS = 10_000;
const MAX_WEAK_CLICK_MEMORY = 64;
const weakClickMemory = new Map<string, HtmlInteractionEvent>();

/**
 * A locally satisfied outcome only counts when real content answered the interaction.
 * Revealing an empty placeholder leaves the user's need unmet and must still reach the Agent.
 */
export function interactionLocallyResolved(event: HtmlInteractionEvent): boolean {
  const outcome = event.local_outcome;
  if (!outcome?.satisfied) return false;
  return !outcome.placeholder_revealed;
}

function isWeakUnansweredClick(event: HtmlInteractionEvent): boolean {
  return (event.event_type ?? 'click') === 'click' && !event.spore_request && !interactionLocallyResolved(event);
}

function weakClickKey(event: HtmlInteractionEvent): string {
  return `${event.artifact_id || 'unscoped'}\u0000${eventFocusRef(event)}`;
}

function priorWeakClick(event: HtmlInteractionEvent): HtmlInteractionEvent | undefined {
  if (!isWeakUnansweredClick(event)) return undefined;
  const prior = weakClickMemory.get(weakClickKey(event));
  if (!prior) return undefined;
  const elapsed = event.timestamp_ms - prior.timestamp_ms;
  return elapsed > 0 && elapsed <= CROSS_WINDOW_WEAK_CLICK_TTL_MS ? prior : undefined;
}

function rememberWeakClick(event: HtmlInteractionEvent): void {
  if (!isWeakUnansweredClick(event)) return;
  const key = weakClickKey(event);
  weakClickMemory.delete(key);
  weakClickMemory.set(key, event);
  while (weakClickMemory.size > MAX_WEAK_CLICK_MEMORY) {
    const oldest = weakClickMemory.keys().next().value;
    if (oldest === undefined) break;
    weakClickMemory.delete(oldest);
  }
}

function clearRememberedWeakClicks(events: HtmlInteractionEvent[]): void {
  for (const event of events) weakClickMemory.delete(weakClickKey(event));
}

export function clearSemanticIntentFocusMemory(): void {
  weakClickMemory.clear();
}

export function isStrongIntentSignal(event: HtmlInteractionEvent): boolean {
  return Boolean(event.spore_request) || STRONG_TYPES.has(event.event_type ?? 'click');
}

function comparableSemanticFocus(left: HtmlInteractionEvent, right: HtmlInteractionEvent): boolean {
  const leftContext = left.semantic_context;
  const rightContext = right.semantic_context;
  if (!leftContext || !rightContext) return false;
  const sameDomain = Boolean(leftContext.domain && leftContext.domain === rightContext.domain);
  const sameContainer = Boolean(leftContext.container_ref && leftContext.container_ref === rightContext.container_ref);
  const compatibleType = Boolean(leftContext.object_type && leftContext.object_type === rightContext.object_type);
  return sameContainer && (sameDomain || compatibleType);
}

export function eventsLikelyRelated(left: HtmlInteractionEvent, right: HtmlInteractionEvent): boolean {
  const leftRef = eventFocusRef(left);
  const rightRef = eventFocusRef(right);
  if (leftRef && leftRef === rightRef) return true;
  const leftContext = left.semantic_context;
  const rightContext = right.semantic_context;
  if (leftContext?.semantic_path && leftContext.semantic_path === rightContext?.semantic_path) return true;
  if (left.spore_target && left.spore_target === right.spore_target) return true;
  const elapsed = Math.abs(right.timestamp_ms - left.timestamp_ms);
  if (elapsed <= 1600 && isStrongIntentSignal(left) && isStrongIntentSignal(right) && comparableSemanticFocus(left, right)) return true;
  const parentPath = (value: string) => value.split(' > ').slice(0, -1).join(' > ');
  const sameParent = Boolean(left.dom_path && right.dom_path && parentPath(left.dom_path) === parentPath(right.dom_path));
  const sameObject = Boolean(leftContext?.object_name && leftContext.object_name === rightContext?.object_name);
  return elapsed <= 500 && sameParent && sameObject;
}

export function shouldIgnoreLocallySatisfiedSignal(event: HtmlInteractionEvent): boolean {
  if (!interactionLocallyResolved(event)) return false;
  if (event.spore_request) return false;
  return !['dblclick', 'selection', 'copy', 'touch_long_press'].includes(event.event_type ?? 'click');
}

export type DynamicWindowContext = {
  activePreBarrier?: boolean;
  pageChangedLocally?: boolean;
  recentCadenceMs?: number;
  htmlRevisionChanged?: boolean;
};

/** A settling delay, not a collection cadence. Every meaningful signal and runtime condition can change it. */
export function dynamicWindowDelay(
  event: HtmlInteractionEvent,
  evidenceCount: number,
  context: DynamicWindowContext = {},
): number {
  if (event.spore_request || event.event_type === 'submit') return 80;
  let delay: number;
  switch (event.event_type) {
    case 'selection_clear': return 0;
    case 'copy': return 100;
    case 'keyboard_activate': delay = 120; break;
    case 'dblclick': delay = 180; break;
    case 'touch_long_press': delay = 220; break;
    case 'change': delay = 320; break;
    case 'selection': delay = 450; break;
    case 'keyboard_navigate': delay = 520; break;
    case 'input': delay = 700; break;
    case 'click':
    default:
      delay = evidenceCount > 1 ? 520 : 760;
  }
  if (context.pageChangedLocally) delay += 180;
  if (context.activePreBarrier) delay = Math.max(80, Math.round(delay * 0.65));
  if (context.htmlRevisionChanged) delay = 80;
  if (context.recentCadenceMs && context.recentCadenceMs > 0) {
    delay = Math.max(80, Math.min(1200, Math.round((delay + context.recentCadenceMs) / 2)));
  }
  return delay;
}

export const MAX_INTENT_WINDOW_MS = 2400;

function compactEvidence(events: HtmlInteractionEvent[]): HtmlInteractionEvent[] {
  const output: HtmlInteractionEvent[] = [];
  for (const event of events) {
    const type = event.event_type ?? 'click';
    if (type === 'dblclick') {
      // Remove preceding clicks on the same element (browser fires click before dblclick).
      for (let i = output.length - 1; i >= 0; i -= 1) {
        const prior = output[i];
        if ((prior.event_type ?? 'click') !== 'click') break;
        const sameFocus = eventFocusRef(prior) === eventFocusRef(event) ||
          (Boolean(prior.dom_path) && prior.dom_path === event.dom_path) ||
          (Boolean(prior.element_id) && prior.element_id === event.element_id);
        if (event.timestamp_ms - prior.timestamp_ms > 600 || !sameFocus) break;
        output.splice(i, 1);
      }
    }
    if (type === 'click') {
      // The bridge sends dblclick with delay=40ms but click with delay=400ms, so the
      // dblclick message arrives at the host first, followed by its constituent clicks.
      // These late-arriving clicks must be suppressed so they don't override the dblclick
      // episode with a dead-control dispatch or a low-confidence discard.
      const absorbedByDblclick = output.some((prior) => {
        if (prior.event_type !== 'dblclick') return false;
        const sameFocus = eventFocusRef(prior) === eventFocusRef(event) ||
          (Boolean(prior.dom_path) && prior.dom_path === event.dom_path) ||
          (Boolean(prior.element_id) && prior.element_id === event.element_id);
        return sameFocus && Math.abs(event.timestamp_ms - prior.timestamp_ms) <= 600;
      });
      if (absorbedByDblclick) continue;
    }
    const previous = output[output.length - 1];
    if (
      previous && previous.event_type === event.event_type &&
      eventFocusRef(previous) === eventFocusRef(event) &&
      ['input', 'selection', 'keyboard_navigate'].includes(type)
    ) {
      output[output.length - 1] = event;
    } else {
      output.push(event);
    }
  }
  return output.slice(-12);
}

function mergeCrossWindowWeakClickEvidence(events: HtmlInteractionEvent[]): HtmlInteractionEvent[] {
  if (!events.length) return events;
  const remembered = events.map(priorWeakClick).filter(Boolean) as HtmlInteractionEvent[];
  if (!remembered.length) return events;
  return compactEvidence([...remembered, ...events].sort((left, right) => left.timestamp_ms - right.timestamp_ms));
}

function chooseRepresentative(events: HtmlInteractionEvent[]): HtmlInteractionEvent {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    if (isStrongIntentSignal(events[index])) return events[index];
  }
  return events[events.length - 1];
}

function inferCandidates(events: HtmlInteractionEvent[]): string[] {
  const types = new Set(events.map((event) => event.event_type ?? 'click'));
  const focusRefs = new Set(events.map(eventFocusRef).filter(Boolean));
  const strongEvents = events.filter(isStrongIntentSignal);
  const comparablePair = strongEvents.some((left, index) => strongEvents.slice(index + 1).some((right) =>
    eventFocusRef(left) !== eventFocusRef(right) && comparableSemanticFocus(left, right)));
  const candidates: string[] = [];
  const explicit = events.some((event) => Boolean(event.spore_request));
  const copied = types.has('copy');
  const repeatedUnanswered = events.length >= 2 && focusRefs.size === 1 && events.every((event) =>
    (event.event_type ?? 'click') === 'click' && !interactionLocallyResolved(event));
  // A declared-but-empty region that just became visible is an explicit request to materialize it.
  const placeholderRevealed = events.some((event) => event.local_outcome?.placeholder_revealed);
  // An annotated semantic object with no explanation yet is a request to expand it in place.
  const unexplainedAnnotatedObject = events.some((event) => {
    const semantic = event.semantic_context;
    if (!semantic || semantic.explanation_present) return false;
    return Boolean(semantic.annotated || semantic.domain || semantic.object_type || semantic.semantic_path);
  });
  // An operable control that changed nothing promises an affordance the page never built.
  // This is page-expression work the Agent can complete from artifact data alone.
  const deadOperableControl = events.some((event) =>
    event.operable && event.local_outcome?.observed && !event.local_outcome.changed && !event.local_outcome.satisfied);
  if (explicit) candidates.push('fulfill_explicit_page_request');
  if (placeholderRevealed) candidates.push('materialize_declared_empty_region');
  if (!copied && deadOperableControl) candidates.push('build_missing_control_affordance');
  if (!copied && unexplainedAnnotatedObject) candidates.push('expand_semantic_object_details');
  if (!copied && comparablePair) candidates.push('compare_semantic_objects');
  if (!copied && (types.has('dblclick') || types.has('touch_long_press'))) candidates.push('explain_semantic_object');
  if (!copied && types.has('selection')) candidates.push('explain_selected_content');
  if (copied) candidates.push('copy_content_without_page_change');
  if (types.has('submit')) candidates.push('complete_requested_action');
  if (types.has('input') || types.has('change')) candidates.push('respond_to_control_change');
  if (types.has('keyboard_activate')) candidates.push('activate_focused_semantic_object');
  if (repeatedUnanswered) candidates.push('explain_repeatedly_unresponsive_object');
  if (!candidates.length) candidates.push('inspect_or_navigate_semantic_object');
  return [...new Set(candidates)].slice(0, 4);
}

export function buildSemanticIntentEpisode(
  rawEvents: HtmlInteractionEvent[],
  intentEpoch: number,
): SemanticIntentEpisode | null {
  const currentEvents = compactEvidence(rawEvents.filter((event) => !shouldIgnoreLocallySatisfiedSignal(event)));
  if (!currentEvents.length) return null;
  const events = mergeCrossWindowWeakClickEvidence(currentEvents);
  const representative = chooseRepresentative(events);
  const focusRef = eventFocusRef(representative);
  const outcomes = events.map((event) => event.local_outcome).filter(Boolean) as HtmlLocalOutcome[];
  const locallySatisfied = outcomes.length > 0 &&
    outcomes.every((outcome) => outcome.satisfied && !outcome.placeholder_revealed);
  const candidateIntents = inferCandidates(events);
  const focusRefs = new Set(events.map(eventFocusRef).filter(Boolean));
  const copied = events.some((event) => event.event_type === 'copy');
  const repeatedUnanswered = events.length >= 2 && focusRefs.size === 1 && events.every((event) =>
    (event.event_type ?? 'click') === 'click' && !interactionLocallyResolved(event));
  const placeholderRevealed = events.some((event) => event.local_outcome?.placeholder_revealed);
  const confidence: SemanticIntentEpisode['confidence'] = events.some((event) => Boolean(event.spore_request)) ||
    events.some((event) => ['dblclick', 'submit', 'touch_long_press'].includes(event.event_type ?? 'click')) ||
    repeatedUnanswered || placeholderRevealed
    ? 'high'
    : !copied && events.some((event) => event.event_type === 'selection' || event.event_type === 'keyboard_activate')
      ? 'medium'
      : 'low';
  if (repeatedUnanswered) clearRememberedWeakClicks(events);
  else currentEvents.forEach(rememberWeakClick);
  const startedAt = events[0].timestamp_ms;
  const context = representative.ancestors.slice(0, 3);
  const focuses = Array.from(new Map(events.map((event) => {
    const ref = eventFocusRef(event);
    const semantic = event.semantic_context;
    return [ref, {
      ref,
      label: semantic?.object_name || event.clicked_word || event.selection_text || event.aria_label || event.text.slice(0, 200) || event.tag,
      object_type: semantic?.object_type,
      domain: semantic?.domain,
      semantic_path: semantic?.semantic_path,
      current_value: semantic?.current_value,
      instance_data: semantic?.instance_data,
      explanation_present: semantic?.explanation_present,
      inspector_ref: semantic?.inspector_ref,
      presentation_ref: event.presentation_ref || semantic?.presentation_ref,
      mutation_ref: event.mutation_ref || semantic?.mutation_ref,
      container_ref: semantic?.container_ref,
      related_refs: semantic?.related_refs,
    }] as const;
  })).values()).slice(-4);
  return {
    episode_id: uid('episode'),
    intent_epoch: intentEpoch,
    started_at_ms: startedAt,
    ended_at_ms: events[events.length - 1].timestamp_ms,
    semantic_focus_ref: focusRef,
    presentation_target_ref: representative.presentation_ref || representative.semantic_context?.presentation_ref || representative.semantic_context?.inspector_ref || representative.spore_target || representative.semantic_context?.container_ref || '',
    mutation_target_ref: representative.mutation_ref || representative.semantic_context?.mutation_ref || '',
    focus: {
      label: representative.semantic_context?.object_name || representative.clicked_word || representative.selection_text || representative.aria_label ||
        representative.title || representative.text.slice(0, 200) || representative.tag,
      context,
      selected_text: representative.selection_text || undefined,
      object_type: representative.semantic_context?.object_type,
      domain: representative.semantic_context?.domain,
      semantic_path: representative.semantic_context?.semantic_path,
      current_value: representative.semantic_context?.current_value,
      instance_data: representative.semantic_context?.instance_data,
      explanation_present: representative.semantic_context?.explanation_present,
      inspector_ref: representative.semantic_context?.inspector_ref,
      related_refs: representative.semantic_context?.related_refs,
    },
    focuses,
    evidence: events.map((event) => ({
      event_type: event.event_type ?? 'click',
      elapsed_ms: Math.max(0, event.timestamp_ms - startedAt),
      focus_ref: eventFocusRef(event),
      word: event.clicked_word || undefined,
      selection: event.selection_text || undefined,
      key: event.key || undefined,
      operable: event.operable,
      local_outcome: event.local_outcome,
      semantic_context: event.semantic_context,
    })),
    candidate_intents: candidateIntents,
    confidence,
    local_outcome: locallySatisfied ? 'satisfied' : outcomes.length ? 'not_satisfied' : 'unknown',
    disposition: computeIntentDisposition(events, candidateIntents, confidence),
    representative_event: representative,
    runtime_state: [...events].reverse().find((event) => event.runtime_state)?.runtime_state,
  };
}

export function episodeToAgentEvent(
  episode: SemanticIntentEpisode,
  identity: HtmlInteractionRequestIdentity,
): HtmlInteractionEvent & Record<string, unknown> {
  const representative = episode.representative_event;
  const summary = {
    semantic_focus: episode.focus,
    candidate_intents: episode.candidate_intents,
    confidence: episode.confidence,
    local_outcome: episode.local_outcome,
    disposition: episode.disposition,
    evidence: episode.evidence,
    focuses: episode.focuses,
    semantic_focus_ref: episode.semantic_focus_ref,
    presentation_target_ref: episode.presentation_target_ref,
    mutation_target_ref: episode.mutation_target_ref,
  };
  return {
    ...representative,
    timestamp_ms: episode.ended_at_ms,
    spore_request: representative.spore_request || `Semantic intent episode: ${JSON.stringify(summary)}`,
    semantic_ref: episode.semantic_focus_ref,
    intent_episode: summary,
    episode_id: episode.episode_id,
    intent_epoch: identity.intent_epoch,
    agent_request_id: identity.agent_request_id,
    operation_id: identity.operation_id,
    base_html_revision: identity.base_html_revision,
    base_sha256: identity.base_sha256,
    state_revision: identity.state_revision,
  };
}

export async function sha256Text(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  // WebCrypto is normally available in the desktop WebView. Keep a standards-
  // compatible SHA-256 fallback so transaction identities never degrade to a
  // non-cryptographic or non-64-character digest in restricted runtimes.
  const constants = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const message = Array.from(bytes);
  const bitLengthLow = (bytes.length << 3) >>> 0;
  const bitLengthHigh = Math.floor(bytes.length / 0x20000000) >>> 0;
  message.push(0x80);
  while (message.length % 64 !== 56) message.push(0);
  for (let shift = 24; shift >= 0; shift -= 8) message.push((bitLengthHigh >>> shift) & 0xff);
  for (let shift = 24; shift >= 0; shift -= 8) message.push((bitLengthLow >>> shift) & 0xff);

  const hash = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const words = new Uint32Array(64);
  const rotateRight = (word: number, bits: number) => (word >>> bits) | (word << (32 - bits));
  for (let offset = 0; offset < message.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      const cursor = offset + index * 4;
      words[index] = (
        (message[cursor] << 24) | (message[cursor + 1] << 16) |
        (message[cursor + 2] << 8) | message[cursor + 3]
      ) >>> 0;
    }
    for (let index = 16; index < 64; index += 1) {
      const left = words[index - 15];
      const right = words[index - 2];
      const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
      const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
      words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = hash;
    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (h + sum1 + choice + constants[index] + words[index]) >>> 0;
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (sum0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    hash[0] = (hash[0] + a) >>> 0; hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0; hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0; hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0; hash[7] = (hash[7] + h) >>> 0;
  }
  return Array.from(hash, (word) => word.toString(16).padStart(8, '0')).join('');
}

