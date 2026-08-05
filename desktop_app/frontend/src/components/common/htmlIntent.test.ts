import { afterEach, describe, expect, it } from 'vitest';
import {
  buildSemanticIntentEpisode,
  clearSemanticIntentFocusMemory,
  computeIntentDisposition,
  interactionLocallyResolved,
  shouldIgnoreLocallySatisfiedSignal,
  type HtmlInteractionEvent,
} from './htmlIntent';

function event(timestamp: number, overrides: Partial<HtmlInteractionEvent> = {}): HtmlInteractionEvent {
  return {
    timestamp_ms: timestamp,
    artifact_id: 'artifact-a',
    event_type: 'click',
    tag: 'span',
    element_id: 'field',
    role: '',
    text: 'PointerToRawData',
    clicked_word: 'PointerToRawData',
    aria_label: '',
    title: '',
    href: '',
    spore_target: '',
    spore_request: '',
    dom_path: 'body > span:nth-of-type(1)',
    ancestors: ['body'],
    semantic_ref: 'PE.PointerToRawData',
    local_outcome: { observed: true, changed: false, satisfied: false },
    scroll_y: 0,
    viewport: { width: 800, height: 600 },
    ...overrides,
  };
}

afterEach(() => clearSemanticIntentFocusMemory());

describe('HTML semantic intent isolation policy', () => {
  it('does not upgrade semantic or presentation refs into mutation authority', () => {
    const episode = buildSemanticIntentEpisode([event(100, {
      event_type: 'dblclick',
      semantic_context: {
        object_name: 'PointerToRawData',
        container_ref: 'section-table',
        inspector_ref: 'field-inspector',
      },
    })], 1);

    expect(episode?.semantic_focus_ref).toBe('PE.PointerToRawData');
    expect(episode?.presentation_target_ref).toBe('field-inspector');
    expect(episode?.mutation_target_ref).toBe('');

    const explicitlyAuthorized = buildSemanticIntentEpisode([event(200, {
      event_type: 'dblclick',
      mutation_ref: 'field-explanation-slot',
    })], 2);
    expect(explicitlyAuthorized?.mutation_target_ref).toBe('field-explanation-slot');
  });

  it('carries repeated unanswered weak clicks across settling windows', () => {
    const first = buildSemanticIntentEpisode([event(1_000)], 1);
    const second = buildSemanticIntentEpisode([event(6_000)], 2);

    expect(first?.confidence).toBe('low');
    expect(second?.confidence).toBe('high');
    expect(second?.evidence).toHaveLength(2);
    expect(second?.candidate_intents).toContain('explain_repeatedly_unresponsive_object');
  });

  it('keeps only the latest stateful evidence for the same semantic focus', () => {
    const episode = buildSemanticIntentEpisode([
      event(100, { event_type: 'input', text: 'P', clicked_word: 'P' }),
      event(200, { event_type: 'input', text: 'PE', clicked_word: 'PE' }),
      event(300, { event_type: 'input', text: 'PE32', clicked_word: 'PE32' }),
    ], 3);

    expect(episode?.evidence).toHaveLength(1);
    expect(episode?.evidence[0]).toMatchObject({ elapsed_ms: 0, word: 'PE32' });
    expect(episode?.representative_event).toMatchObject({ timestamp_ms: 300, text: 'PE32' });
  });

  it('treats a revealed empty placeholder as an unmet intent, not a satisfied one', () => {
    const placeholder = event(100, {
      local_outcome: {
        observed: true, changed: true, satisfied: true,
        reveal_succeeded: true, target_visible: true,
        target_has_content: false, placeholder_revealed: true,
      },
    });

    expect(interactionLocallyResolved(placeholder)).toBe(false);
    expect(shouldIgnoreLocallySatisfiedSignal(placeholder)).toBe(false);
    const episode = buildSemanticIntentEpisode([placeholder], 1);
    expect(episode).not.toBeNull();
    expect(episode?.local_outcome).toBe('not_satisfied');
    expect(episode?.confidence).toBe('high');
    expect(episode?.candidate_intents).toContain('materialize_declared_empty_region');
  });

  it('still discards a click that real content answered locally', () => {
    const answered = event(100, {
      local_outcome: {
        observed: true, changed: true, satisfied: true,
        reveal_succeeded: true, target_visible: true, target_has_content: true,
      },
    });

    expect(interactionLocallyResolved(answered)).toBe(true);
    expect(shouldIgnoreLocallySatisfiedSignal(answered)).toBe(true);
    expect(buildSemanticIntentEpisode([answered], 1)).toBeNull();
  });

  it('reads an annotated object without an explanation as a request to expand details', () => {
    const episode = buildSemanticIntentEpisode([event(100, {
      semantic_context: {
        annotated: true,
        object_name: 'PointerToRawData',
        object_type: 'field',
        domain: 'PE/COFF',
        explanation_present: false,
      },
    })], 1);

    expect(episode?.candidate_intents).toContain('expand_semantic_object_details');
  });

  it('does not ask to expand an object that already carries an explanation', () => {
    const episode = buildSemanticIntentEpisode([event(100, {
      semantic_context: {
        annotated: true,
        object_name: 'PointerToRawData',
        object_type: 'field',
        explanation_present: true,
      },
    })], 1);

    expect(episode?.candidate_intents).not.toContain('expand_semantic_object_details');
  });

  it('does not combine weak-click memory across artifacts', () => {
    buildSemanticIntentEpisode([event(1_000)], 1);
    const otherArtifact = buildSemanticIntentEpisode([event(2_000, { artifact_id: 'artifact-b' })], 2);

    expect(otherArtifact?.confidence).toBe('low');
    expect(otherArtifact?.evidence).toHaveLength(1);
  });
});

// Gating asks whether the page answered the user, not how hard the user clicked. These cases
// pin that ordering down: local outcome decides first, and gesture strength only breaks ties
// the outcome cannot settle.
describe('intent disposition', () => {
  it('dispatches a dead operable control even at the weakest confidence', () => {
    const deadControl = event(100, {
      operable: true,
      local_outcome: { observed: true, changed: false, satisfied: false },
    });

    expect(computeIntentDisposition([deadControl], ['build_missing_control_affordance'], 'low'))
      .toBe('dispatch');
  });

  it('discards an interaction the page fully answered even at the strongest confidence', () => {
    const answered = event(100, {
      event_type: 'dblclick',
      operable: true,
      local_outcome: { observed: true, changed: true, satisfied: true, target_has_content: true },
    });

    expect(computeIntentDisposition([answered], ['explain_semantic_object'], 'high')).toBe('discard');
  });

  it('dispatches a revealed placeholder because the need is declared but unmet', () => {
    const emptyReveal = event(100, {
      operable: true,
      local_outcome: {
        observed: true, changed: true, satisfied: true,
        placeholder_revealed: true, target_has_content: false,
      },
    });

    expect(computeIntentDisposition([emptyReveal], ['materialize_declared_empty_region'], 'low'))
      .toBe('dispatch');
  });

  it('sends a change that did not satisfy the user to local disambiguation below high confidence', () => {
    const partial = event(100, {
      event_type: 'selection',
      local_outcome: { observed: true, changed: true, satisfied: false },
    });

    expect(computeIntentDisposition([partial], ['explain_selected_content'], 'medium'))
      .toBe('disambiguate');
    expect(computeIntentDisposition([partial], ['explain_selected_content'], 'high')).toBe('dispatch');
  });

  it('falls back to gesture strength when no local outcome was measured', () => {
    const unmeasured = event(100, { local_outcome: undefined });

    expect(computeIntentDisposition([unmeasured], ['explain_semantic_object'], 'high')).toBe('dispatch');
    expect(computeIntentDisposition([unmeasured], ['explain_semantic_object'], 'medium')).toBe('disambiguate');
    expect(computeIntentDisposition([unmeasured], ['inspect_or_navigate_semantic_object'], 'low')).toBe('discard');
  });

  it('always honours an explicit page request and never escalates a bare copy', () => {
    const explicit = event(100, { spore_request: 'Explain this field' });
    const copied = event(200, {
      event_type: 'copy',
      local_outcome: { observed: true, changed: false, satisfied: false },
    });

    expect(computeIntentDisposition([explicit], ['fulfill_explicit_page_request'], 'low')).toBe('dispatch');
    expect(computeIntentDisposition([copied], ['copy_content_without_page_change'], 'high')).toBe('discard');
  });
});
