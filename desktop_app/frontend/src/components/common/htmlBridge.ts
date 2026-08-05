// The function is serialized into the sandboxed iframe. Keep it dependency-free.
// @ts-nocheck
function dynamicBridge(bridgeCapability) {
  const bridgeScript = document.currentScript;
  bridgeScript?.remove();
  const postToHost = (payload) => parent.postMessage({ ...payload, bridgeCapability }, '*');
  const clean = (value, limit = 500) => String(value || '').replace(/\s+/g, ' ').trim().slice(0, limit);
  const escapeAttributeValue = (value) => globalThis.CSS?.escape ? globalThis.CSS.escape(value) : String(value || '').replace(/[\\"']/g, '\\$&');
  const privacySafeUrl = (value, limit = 500) => {
    const raw = clean(value, Math.max(limit, 2000));
    if (!raw) return '';
    const query = raw.indexOf('?');
    const fragment = raw.indexOf('#');
    const boundary = [query, fragment].filter((index) => index >= 0).sort((left, right) => left - right)[0];
    return clean(boundary === undefined ? raw : raw.slice(0, boundary), limit);
  };
  const findTarget = (target) => document.getElementById(target) || Array.from(document.querySelectorAll('[data-spore-view]')).find((node) => node.getAttribute('data-spore-view') === target) || null;
  const reveal = (target) => {
    const node = findTarget(target);
    if (!node) return false;
    node.hidden = false;
    node.removeAttribute('hidden');
    if (node instanceof HTMLDetailsElement) node.open = true;
    node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return true;
  };
  // A placeholder that merely became visible is not a fulfilled interaction. Content is only
  // genuinely present when it carries real markup or more than a token of text.
  const MEANINGFUL_CONTENT_CHARS = 24;
  const substantive = (node) => {
    if (!(node instanceof Element)) return false;
    if (node.querySelector('img, svg, canvas, table, li, dd, p, input, select, textarea, button, video, audio')) return true;
    return clean(node.textContent, 4000).length >= MEANINGFUL_CONTENT_CHARS;
  };
  // A control the user can plausibly operate. A click that changes nothing on an operable
  // control is a dead control: the strongest available evidence of an unmet need. Clicks on
  // inert text must stay weak, so this distinction decides whether `changed: false` can
  // reach the Agent at all. Handlers are often bound to an ancestor, so walk a few levels.
  const INTERACTIVE_SELECTOR = 'button, a[href], summary, input, select, textarea, label,' +
    '[role="button"], [role="tab"], [role="treeitem"], [role="menuitem"], [role="option"],' +
    '[role="link"], [role="checkbox"], [role="radio"], [role="switch"],' +
    '[tabindex], [aria-expanded], [aria-controls], [onclick], [data-spore-target]';
  const operable = (node) => {
    let current = node instanceof Element ? node : null;
    for (let depth = 0; current && depth < 3; depth += 1, current = current.parentElement) {
      if (current.matches(INTERACTIVE_SELECTOR)) return true;
      try {
        if (getComputedStyle(current).cursor === 'pointer') return true;
      } catch { /* Detached or cross-document nodes simply do not qualify. */ }
    }
    return false;
  };
  const domPath = (node) => {
    const parts = [];
    let current = node instanceof Element ? node : node?.parentElement;
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
    const word = /[\p{L}\p{N}_'-]/u;
    while (start > 0 && word.test(value[start - 1])) start -= 1;
    while (end < value.length && word.test(value[end])) end += 1;
    return clean(value.slice(start, end), 160);
  };
  const describe = (node) => clean([node.tagName.toLowerCase(), node.id ? '#' + node.id : '', node.getAttribute('role') || '', node.getAttribute('aria-label') || '', node.textContent || ''].filter(Boolean).join(' '), 300);
  const elementRef = (node) => node instanceof Element ? { element_id: clean(node.id, 120), dom_path: domPath(node), spore_view: clean(node.getAttribute('data-spore-view'), 120) } : undefined;
  const resolveRef = (ref) => {
    if (!ref) return null;
    if (ref.element_id && document.getElementById(ref.element_id)) return document.getElementById(ref.element_id);
    if (ref.spore_view) {
      const node = Array.from(document.querySelectorAll('[data-spore-view]')).find((item) => item.getAttribute('data-spore-view') === ref.spore_view);
      if (node) return node;
    }
    if (ref.dom_path) try { return document.querySelector(ref.dom_path); } catch { return null; }
    return null;
  };
  const sensitive = (node) => node instanceof HTMLInputElement && (['password', 'email', 'tel', 'hidden'].includes(node.type) || /password|passwd|secret|token|api.?key|cc-|cvc|cvv|one-time-code/i.test((node.autocomplete || '') + ' ' + (node.name || '') + ' ' + (node.id || '')));
  const observesValue = (node) => node instanceof Element && node.hasAttribute('data-spore-observe-value') && !sensitive(node);
  const observedControlValue = (node) => {
    if (!observesValue(node)) return undefined;
    const value = node instanceof HTMLInputElement && node.type === 'url' ? privacySafeUrl(node.value, 500) : clean(node.value, 500);
    return value || '';
  };
  const controlState = (node) => node instanceof HTMLInputElement || node instanceof HTMLSelectElement || node instanceof HTMLTextAreaElement ? {
    type: clean(node.getAttribute('type') || node.tagName.toLowerCase(), 40),
    value: observedControlValue(node),
    checked: node instanceof HTMLInputElement ? node.checked : false,
    redacted: sensitive(node),
    value_observed: observesValue(node),
  } : undefined;
  const selectionState = () => {
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed || !selection.rangeCount) return undefined;
    const range = selection.getRangeAt(0);
    const text = clean(selection.toString(), 500);
    if (!text) return undefined;
    return { text, start_path: domPath(range.startContainer), start_offset: range.startOffset, end_path: domPath(range.endContainer), end_offset: range.endOffset };
  };
  const runtimeState = () => ({
    scroll_x: Math.max(0, Math.round(window.scrollX)), scroll_y: Math.max(0, Math.round(window.scrollY)),
    active: elementRef(document.activeElement), selection: selectionState(),
    controls: Array.from(document.querySelectorAll('input, select, textarea')).slice(0, 80).map((node) => ({ ...elementRef(node), value: observedControlValue(node), value_observed: observesValue(node), redacted: sensitive(node), checked: node instanceof HTMLInputElement ? node.checked : undefined, selected_index: node instanceof HTMLSelectElement ? node.selectedIndex : undefined })),
    details: Array.from(document.querySelectorAll('details')).slice(0, 50).map((node) => ({ ...elementRef(node), open: node.open })),
    toggles: Array.from(document.querySelectorAll('[data-spore-view], [aria-expanded], [aria-selected], [hidden]')).slice(0, 80).map((node) => ({ ...elementRef(node), hidden: node.hidden, aria_expanded: node.getAttribute('aria-expanded') || undefined, aria_selected: node.getAttribute('aria-selected') || undefined })),
  });
  // Bounding the body text before measuring made this saturate on long documents, so a page
  // that grew a whole subtree still looked unchanged. Measure the raw length instead, and add
  // the element count so structural growth is visible even when text length is stable.
  const documentScale = () => {
    const text = document.body?.textContent;
    return (typeof text === 'string' ? text.length : 0) + ':' + (document.body?.getElementsByTagName('*').length ?? 0);
  };
  const signature = (subject, target) => clean(JSON.stringify({
    body_scale: documentScale(),
    subject: subject instanceof Element ? { text: clean(subject.textContent, 300), hidden: subject.hidden, expanded: subject.getAttribute('aria-expanded'), selected: subject.getAttribute('aria-selected'), control: controlState(subject) } : null,
    target: target instanceof Element ? { text: clean(target.textContent, 500), hidden: target.hidden, expanded: target.getAttribute('aria-expanded'), open: target instanceof HTMLDetailsElement ? target.open : undefined } : null,
  }), 1200);
  let hostFrozen = false;
  window.addEventListener('message', (event) => {
    if (event.source !== parent || event.data?.source !== 'spore-host' || event.data?.type !== 'freeze') return;
    hostFrozen = Boolean(event.data.frozen);
    document.documentElement.dataset.sporeFrozen = hostFrozen ? 'true' : 'false';
    if ('inert' in document.body) document.body.inert = hostFrozen;
    if (hostFrozen && document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  const subjectFor = (origin) => {
    let subject = origin.closest('button, a, summary, input, select, textarea, label, [role], [data-spore-target], [data-spore-semantic-ref]') || origin;
    if (subject instanceof HTMLLabelElement && subject.control) subject = subject.control;
    return subject;
  };
  const semanticContext = (subject) => {
    if (!(subject instanceof Element)) return undefined;
    const row = subject.closest('tr');
    const table = subject.closest('table');
    const section = subject.closest('section, article, details, main');
    const cells = row ? Array.from(row.querySelectorAll('th, td')) : [];
    const cell = subject.closest('th, td');
    const cellIndex = cell ? cells.indexOf(cell) : -1;
    const headers = table ? Array.from(table.querySelectorAll('thead th')).map((node) => clean(node.textContent, 120)) : [];
    const headingPath = [];
    let scope = subject.parentElement;
    while (scope && scope !== document.body && headingPath.length < 4) {
      const heading = scope.querySelector(':scope > h1, :scope > h2, :scope > h3, :scope > h4, :scope > h5, :scope > h6, :scope > summary, :scope > caption');
      if (heading) headingPath.unshift(clean(heading.textContent, 160));
      scope = scope.parentElement;
    }
    const explicitRef = clean(subject.getAttribute('data-spore-semantic-ref') || subject.getAttribute('data-field') || subject.getAttribute('data-key'), 240);
    const objectName = clean(subject.getAttribute('data-spore-object-name') || subject.getAttribute('data-field') || subject.getAttribute('data-key') || subject.getAttribute('aria-label') || subject.textContent, 240);
    const objectType = clean(subject.getAttribute('data-spore-object-type') || (subject.matches('code, kbd, samp, var') ? 'code_symbol' : row ? (cellIndex <= 0 ? 'field' : 'field_value') : subject.getAttribute('role') || subject.tagName.toLowerCase()), 80);
    const domain = clean(subject.getAttribute('data-spore-domain') || table?.getAttribute('data-spore-domain') || section?.getAttribute('data-spore-domain'), 120);
    const semanticPath = clean(subject.getAttribute('data-spore-path') || [...headingPath, table?.querySelector('caption')?.textContent || '', objectName].filter(Boolean).join(' ? '), 500);
    const currentValue = clean(subject.getAttribute('data-spore-value') || (row && cellIndex >= 0 ? cells[Math.min(cells.length - 1, cellIndex + (cellIndex === 0 ? 1 : 0))]?.textContent : ''), 300);
    const instanceData = clean(subject.getAttribute('data-spore-instance') || (cellIndex >= 0 && headers[cellIndex] ? headers[cellIndex] + ': ' + (cell?.textContent || '') : ''), 500);
    const inspector = subject.getAttribute('data-spore-inspector') || table?.getAttribute('data-spore-inspector') || section?.getAttribute('data-spore-inspector') || '';
    const describedBy = subject.getAttribute('aria-describedby') || '';
    const explanationNode = (explicitRef ? document.querySelector('[data-spore-explanation-for="' + escapeAttributeValue(explicitRef) + '"]') : null) || (describedBy ? document.getElementById(describedBy) : null);
    // A declared but empty explanation slot is an unmet need, not an existing explanation.
    const explanationPresent = substantive(explanationNode);
    const annotated = Boolean(subject.getAttribute('data-spore-semantic-ref') || subject.getAttribute('data-spore-object-type') || subject.getAttribute('data-spore-domain') || subject.getAttribute('data-spore-path') || subject.getAttribute('data-field') || subject.getAttribute('data-key'));
    return {
      annotated,
      object_name: objectName,
      object_type: objectType,
      domain,
      semantic_path: semanticPath,
      container_ref: clean(table?.id || table?.getAttribute('data-spore-semantic-ref') || section?.id || section?.getAttribute('data-spore-semantic-ref') || domPath(table || section), 240),
      current_value: currentValue,
      instance_data: instanceData,
      related_refs: cells.slice(0, 6).map((node) => clean(node.getAttribute('data-spore-semantic-ref') || node.getAttribute('data-field') || node.textContent, 120)).filter(Boolean),
      explanation_present: explanationPresent,
      inspector_ref: clean(inspector, 120),
      presentation_ref: clean(subject.getAttribute('data-spore-presentation-ref') || inspector, 120),
      mutation_ref: clean(subject.getAttribute('data-spore-mutation-ref'), 120),
    };
  };
  const post = (eventType, subject, options = {}) => {
    if (hostFrozen || !(subject instanceof Element)) return;
    const artifactId = document.documentElement.dataset.sporeArtifactId || '';
    if (!artifactId) return;
    const rawHref = subject.getAttribute('href') || '';
    const href = privacySafeUrl(rawHref, 500);
    const targetName = subject.getAttribute('data-spore-target') || (rawHref.startsWith('spore:') ? decodeURIComponent(privacySafeUrl(rawHref.slice(6), 120)) : '');
    const before = options.before || signature(subject, findTarget(targetName));
    const beforeSemantic = semanticContext(subject);
    setTimeout(() => {
      if (hostFrozen) return;
      const targetNode = findTarget(targetName);
      const after = signature(subject, targetNode);
      const afterSemantic = semanticContext(subject);
      const changed = before !== after;
      const targetVisible = targetNode instanceof Element ? !targetNode.hidden && targetNode.getAttribute('aria-hidden') !== 'true' : false;
      const explanationAppeared = !beforeSemantic?.explanation_present && Boolean(afterSemantic?.explanation_present);
      const targetHasContent = substantive(targetNode);
      // Revealing a declared target only satisfies the click when real content sits behind it.
      const placeholderRevealed = Boolean(targetName) && targetVisible && !targetHasContent;
      const satisfied = explanationAppeared ||
        Boolean(targetHasContent && (options.revealed || (targetName && targetVisible && changed)));
      postToHost({ source: 'spore-html', type: 'interaction', artifactId, event: {
        timestamp_ms: Date.now(), artifact_id: artifactId, event_type: eventType, tag: subject.tagName.toLowerCase(), element_id: clean(subject.id, 120),
        role: clean(subject.getAttribute('role'), 80), text: clean(subject.textContent, 500), clicked_word: clean(options.word, 160),
        selection_text: clean(options.selection, 500), key: clean(options.key, 40), pointer_type: clean(options.pointerType, 30),
        aria_label: clean(subject.getAttribute('aria-label'), 300), title: clean(subject.getAttribute('title'), 300), href: clean(href, 500),
        spore_target: clean(targetName, 120), spore_request: clean(subject.getAttribute('data-spore-request'), 1000),
        semantic_ref: clean(subject.getAttribute('data-spore-semantic-ref') || subject.getAttribute('data-field') || subject.getAttribute('data-key'), 240),
        presentation_ref: clean(subject.getAttribute('data-spore-presentation-ref'), 120), mutation_ref: clean(subject.getAttribute('data-spore-mutation-ref'), 120), semantic_context: afterSemantic,
        dom_path: domPath(subject), ancestors: Array.from(function* () { let node = subject.parentElement; for (let i = 0; node && i < 4; i += 1, node = node.parentElement) yield describe(node); }()),
        control: controlState(subject), local_outcome: { observed: true, changed, satisfied, reveal_succeeded: Boolean(options.revealed), target_visible: targetVisible, target_has_content: targetHasContent, placeholder_revealed: placeholderRevealed, before_signature: before, after_signature: after },
        // operable lets the intent layer distinguish a dead interactive control (no change on
        // an operable element) from a click on inert text (no change, no control, discard).
        operable: operable(subject),
        runtime_state: runtimeState(), scroll_y: Math.max(0, Math.round(window.scrollY)), viewport: { width: window.innerWidth, height: window.innerHeight },
      } });
    //400 ms gives async JS (setTimeout0, microtask chains, CSS transitions) time to settle
    // before we measure `changed`. dblclick/change/submit/copy all pass their own delay.
    }, Number.isFinite(options.delay) ? options.delay : 400);
  };
  document.addEventListener('click', (event) => {
    if (!event.isTrusted || !(event.target instanceof Element)) return;
    const subject = subjectFor(event.target);
    const rawHref = subject.getAttribute('href') || '';
    const targetName = subject.getAttribute('data-spore-target') || (rawHref.startsWith('spore:') ? decodeURIComponent(privacySafeUrl(rawHref.slice(6), 120)) : '');
    const before = signature(subject, findTarget(targetName));
    if (rawHref.startsWith('spore:')) event.preventDefault();
    post('click', subject, { word: clickedWord(event), before, revealed: targetName ? reveal(targetName) : false });
  }, true);
  document.addEventListener('dblclick', (event) => { if (event.isTrusted && event.target instanceof Element) post('dblclick', subjectFor(event.target), { word: clickedWord(event), delay: 40 }); }, true);
  document.addEventListener('change', (event) => { const subject = event.target instanceof Element ? event.target.closest('input, select, textarea, [role]') : null; if (event.isTrusted && subject) post('change', subject, { delay: 30 }); }, true);
  const inputTimers = new WeakMap();
  document.addEventListener('input', (event) => {
    const subject = event.target instanceof Element ? event.target.closest('input, textarea, select') : null;
    if (!event.isTrusted || !subject) return;
    const prior = inputTimers.get(subject); if (prior) clearTimeout(prior);
    inputTimers.set(subject, setTimeout(() => { inputTimers.delete(subject); post('input', subject, { delay: 0 }); }, 350));
  }, true);
  document.addEventListener('submit', (event) => { if (event.isTrusted && event.target instanceof HTMLFormElement) post('submit', event.target, { delay: 30 }); }, true);
  let selectionTimer = null;
  let selectionSubject = null;
  document.addEventListener('selectionchange', (event) => {
    if (!event.isTrusted || hostFrozen) return;
    if (selectionTimer) clearTimeout(selectionTimer);
    selectionTimer = setTimeout(() => {
      const selection = window.getSelection();
      const origin = selection?.anchorNode?.nodeType === Node.TEXT_NODE ? selection.anchorNode.parentElement : selection?.anchorNode;
      if (selection && !selection.isCollapsed && clean(selection.toString(), 500) && origin instanceof Element) {
        selectionSubject = subjectFor(origin);
        post('selection', selectionSubject, { selection: selection.toString(), delay: 0 });
      } else if (selectionSubject instanceof Element) {
        post('selection_clear', selectionSubject, { delay: 0 });
        selectionSubject = null;
      }
    }, 180);
  }, true);
  document.addEventListener('copy', (event) => {
    if (!event.isTrusted) return;
    const selection = window.getSelection();
    const origin = selection?.anchorNode?.nodeType === Node.TEXT_NODE ? selection.anchorNode.parentElement : selection?.anchorNode;
    const subject = origin instanceof Element ? subjectFor(origin) : document.activeElement;
    if (subject instanceof Element) post('copy', subject, { selection: selection?.toString() || '', delay: 0 });
  }, true);
  document.addEventListener('keydown', (event) => {
    if (!event.isTrusted || event.isComposing || !(event.target instanceof Element) || event.target.matches('input, textarea, select, [contenteditable="true"]')) return;
    if (event.key === 'Enter' || event.key === ' ') post('keyboard_activate', subjectFor(event.target), { key: event.key, delay: 30 });
    else if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) post('keyboard_navigate', subjectFor(event.target), { key: event.key, delay: 80 });
  }, true);
  const touches = new Map();
  document.addEventListener('pointerdown', (event) => {
    if (!event.isTrusted || event.pointerType !== 'touch' || !(event.target instanceof Element)) return;
    const record = { x: event.clientX, y: event.clientY, subject: subjectFor(event.target), timer: null };
    record.timer = setTimeout(() => { touches.delete(event.pointerId); post('touch_long_press', record.subject, { pointerType: 'touch', word: clickedWord(event), delay: 0 }); }, 550);
    touches.set(event.pointerId, record);
  }, true);
  document.addEventListener('pointermove', (event) => { const record = touches.get(event.pointerId); if (record && Math.hypot(event.clientX - record.x, event.clientY - record.y) >= 12) { clearTimeout(record.timer); touches.delete(event.pointerId); } }, true);
  const cancelTouch = (event) => { const record = touches.get(event.pointerId); if (record) clearTimeout(record.timer); touches.delete(event.pointerId); };
  document.addEventListener('pointerup', cancelTouch, true);
  document.addEventListener('pointercancel', cancelTouch, true);
  const restore = () => {
    const payload = document.getElementById('spore-runtime-state');
    const report = {
      requested: Boolean(payload?.textContent), parsed: false, success: false,
      attempted: { controls: 0, details: 0, toggles: 0, active: 0, selection: 0, scroll: 0 },
      applied: { controls: 0, details: 0, toggles: 0, active: 0, selection: 0, scroll: 0 },
      failures: [],
    };
    const fail = (kind, index, reason, item) => {
      if (report.failures.length < 20) report.failures.push({ kind, index, reason, ref: elementRef(resolveRef(item)) || { element_id: clean(item?.element_id, 120), dom_path: clean(item?.dom_path, 500), spore_view: clean(item?.spore_view, 120) } });
    };
    if (!report.requested) return report;
    let state;
    try { state = JSON.parse(payload.textContent); report.parsed = Boolean(state && typeof state === 'object' && !Array.isArray(state)); }
    catch { fail('payload', 0, 'invalid_json'); return report; }
    if (!report.parsed) { fail('payload', 0, 'invalid_state'); return report; }
    const restoreItems = (kind, items, expectedType, apply) => {
      if (!Array.isArray(items)) { if (items !== undefined) fail(kind, 0, 'invalid_collection'); return; }
      items.forEach((item, index) => {
        report.attempted[kind] += 1;
        const node = resolveRef(item);
        if (!(node instanceof expectedType)) { fail(kind, index, node ? 'type_mismatch' : 'ref_not_found', item); return; }
        try {
          if (!apply(node, item)) { fail(kind, index, 'verification_failed', item); return; }
          report.applied[kind] += 1;
        } catch { fail(kind, index, 'apply_failed', item); }
      });
    };
    restoreItems('controls', state.controls, Element, (node, item) => {
      if (!(node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement || node instanceof HTMLSelectElement)) return false;
      if (typeof item.value === 'string') {
        if (!observesValue(node)) return false;
        node.value = node instanceof HTMLInputElement && node.type === 'url' ? privacySafeUrl(item.value, 500) : clean(item.value, 500);
        if (node.value !== (node instanceof HTMLInputElement && node.type === 'url' ? privacySafeUrl(item.value, 500) : clean(item.value, 500))) return false;
      }
      if (node instanceof HTMLInputElement && typeof item.checked === 'boolean') { node.checked = item.checked; if (node.checked !== item.checked) return false; }
      if (node instanceof HTMLSelectElement && Number.isInteger(item.selected_index)) { node.selectedIndex = item.selected_index; if (node.selectedIndex !== item.selected_index) return false; }
      return true;
    });
    restoreItems('details', state.details, HTMLDetailsElement, (node, item) => { node.open = Boolean(item.open); return node.open === Boolean(item.open); });
    restoreItems('toggles', state.toggles, Element, (node, item) => {
      if (typeof item.hidden === 'boolean') node.hidden = item.hidden;
      if (typeof item.aria_expanded === 'string') node.setAttribute('aria-expanded', item.aria_expanded);
      if (typeof item.aria_selected === 'string') node.setAttribute('aria-selected', item.aria_selected);
      return (typeof item.hidden !== 'boolean' || node.hidden === item.hidden) &&
        (typeof item.aria_expanded !== 'string' || node.getAttribute('aria-expanded') === item.aria_expanded) &&
        (typeof item.aria_selected !== 'string' || node.getAttribute('aria-selected') === item.aria_selected);
    });
    if (state.active) {
      report.attempted.active = 1;
      const active = resolveRef(state.active);
      if (active instanceof HTMLElement) {
        try { active.focus({ preventScroll: true }); if (document.activeElement === active) report.applied.active = 1; else fail('active', 0, 'verification_failed', state.active); }
        catch { fail('active', 0, 'apply_failed', state.active); }
      } else fail('active', 0, active ? 'type_mismatch' : 'ref_not_found', state.active);
    }
    const firstTextNode = (element) => {
      if (!(element instanceof Element)) return null;
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      return walker.nextNode();
    };
    const selected = state.selection;
    if (selected) {
      report.attempted.selection = 1;
      try {
        const start = firstTextNode(document.querySelector(selected.start_path));
        const end = firstTextNode(document.querySelector(selected.end_path));
        const selection = window.getSelection();
        if (!start || !end || !selection) fail('selection', 0, 'ref_not_found', selected);
        else {
          const range = document.createRange();
          range.setStart(start, Math.min(Math.max(0, Number(selected.start_offset) || 0), start.textContent?.length || 0));
          range.setEnd(end, Math.min(Math.max(0, Number(selected.end_offset) || 0), end.textContent?.length || 0));
          selection.removeAllRanges(); selection.addRange(range);
          if (selection.rangeCount && selection.getRangeAt(0).startContainer === start && selection.getRangeAt(0).endContainer === end) report.applied.selection = 1;
          else fail('selection', 0, 'verification_failed', selected);
        }
      } catch { fail('selection', 0, 'apply_failed', selected); }
    }
    report.attempted.scroll = 1;
    try { window.scrollTo(Number(state.scroll_x || 0), Number(state.scroll_y || 0)); report.applied.scroll = 1; }
    catch { fail('scroll', 0, 'apply_failed'); }
    report.success = report.parsed && report.failures.length === 0;
    return report;
  };
  const start = () => {
    const resume = document.documentElement.dataset.sporeResumeTarget;
    if (resume) requestAnimationFrame(() => reveal(resume));
    const restoreReport = restore();
    const restoreRequested = restoreReport.requested;
    const restored = restoreRequested && restoreReport.success;
    const resumeScroll = Number(document.documentElement.dataset.sporeResumeScroll || 0);
    if (!restored && resumeScroll > 0) requestAnimationFrame(() => window.scrollTo(0, resumeScroll));
    const readinessStartedAt = Date.now();
    const announceReadiness = () => {
      const initializationPending = Boolean(document.querySelector('[data-spore-initializing="true"]')) || document.documentElement.dataset.sporeReady === 'false';
      const documentSettled = document.readyState === 'interactive' || document.readyState === 'complete';
      const restorationReady = !restoreRequested || restored;
      const ready = documentSettled && !initializationPending && restorationReady && document.body?.isConnected;
      const report = {
        source: 'spore-html', type: 'interaction_ready', artifactId: document.documentElement.dataset.sporeArtifactId || '',
        documentToken: document.documentElement.dataset.sporeDocumentToken || '',
        documentGenerationId: document.documentElement.dataset.sporeDocumentGenerationId || '',
        restoreAttemptId: document.documentElement.dataset.sporeRestoreAttemptId || '',
        bridgeInstalled: true, coreInteractionsReady: true, ready: Boolean(ready), restored,
        restoreRequested, restoreReport, initializationPending, documentReadyState: document.readyState,
        interactiveCount: document.querySelectorAll('button, a[href], input, select, textarea, summary, [tabindex], [role="button"]').length,
      };
      if (ready || Date.now() - readinessStartedAt >= 3000) postToHost(report);
      else setTimeout(announceReadiness, 50);
    };
    requestAnimationFrame(() => requestAnimationFrame(announceReadiness));
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
}

export const buildDynamicBridge = (bridgeCapability: string): string =>
  `(${dynamicBridge.toString()})(${JSON.stringify(bridgeCapability)});`;

// Retained for focused bridge tests and callers that do not need a transaction-bound capability.
export const DYNAMIC_BRIDGE = buildDynamicBridge('spore-test-bridge-capability-0000000000000000');
