/**
 * VIGIL Blueprint: Autonomous Dynamic Bidirectional Rehydration Engine
 * 
 * Tracks session-scoped surrogate-to-real entity mappings and transparently
 * re-hydrates streaming cloud AI responses (ChatGPT, Claude, Gemini, etc.)
 * directly inside the browser DOM in real time.
 * The cloud provider only ever sees synthetic surrogates; the user sees their real data.
 */
(function (root) {
  'use strict';

  // Session-scoped substitution tree: surrogate -> real
  const sessionSubstitutions = new Map();
  let streamingObserver = null;
  let isMutatingInternally = false;
  const processedNodes = new WeakSet();
  const MAX_SUBSTITUTIONS = 500;
  const SUBSTITUTION_TTL_MS = 60 * 60 * 1000; // 60 minutes TTL

  function getCurrentOrigin() {
    try {
      if (typeof window !== 'undefined' && window.location && window.location.origin) {
        return window.location.origin;
      }
    } catch (_) {}
    return null;
  }

  /**
   * Registers a surrogate-to-real mapping for the current browsing session
   */
  function recordSubstitution(surrogate, original, category = 'GENERAL', origin = null) {
    if (!surrogate || !original || typeof surrogate !== 'string' || typeof original !== 'string' || surrogate === original) return false;
    if (sessionSubstitutions.size >= MAX_SUBSTITUTIONS) {
      const oldest = sessionSubstitutions.keys().next().value;
      sessionSubstitutions.delete(oldest);
    }
    const boundOrigin = origin !== null ? origin : getCurrentOrigin();
    sessionSubstitutions.set(surrogate, { original, category, origin: boundOrigin, timestamp: Date.now() });
    return true;
  }

  /**
   * Bulk registers mappings from a substitution tree
   */
  function recordSubstitutionTree(reverseTree, origin = null) {
    if (!reverseTree || typeof reverseTree !== 'object') return 0;
    let count = 0;
    for (const [surrogate, original] of Object.entries(reverseTree)) {
      if (recordSubstitution(surrogate, original, 'GENERAL', origin)) count++;
    }
    return count;
  }

  /**
   * Returns current active surrogate count
   */
  function getSubstitutionCount() {
    return sessionSubstitutions.size;
  }

  /**
   * Clears all session substitutions
   */
  function clearSubstitutions() {
    sessionSubstitutions.clear();
  }

  /**
   * Pure text rehydration: replaces all known surrogates with original values
   */
  function rehydrateText(text, targetOrigin = null) {
    if (!text || typeof text !== 'string' || sessionSubstitutions.size === 0) return text || '';
    const now = Date.now();
    const effectiveOrigin = targetOrigin !== null ? targetOrigin : getCurrentOrigin();
    let result = text;
    // Sort surrogates longest first to prevent partial collision
    const keys = Array.from(sessionSubstitutions.keys()).sort((a, b) => b.length - a.length);

    keys.forEach((surrogate) => {
      const entry = sessionSubstitutions.get(surrogate);
      if (!entry || !entry.original) return;
      if (now - entry.timestamp > SUBSTITUTION_TTL_MS) {
        sessionSubstitutions.delete(surrogate);
        return;
      }
      if (entry.origin && effectiveOrigin && entry.origin !== effectiveOrigin) {
        return; // Isolate cross-origin substitutions
      }
      const escaped = surrogate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      result = result.replace(new RegExp(escaped, 'g'), entry.original);
    });

    return result;
  }

  /**
   * Checks if a DOM element is safe to rehydrate (never inputs or editable areas)
   */
  function isSafeToRehydrate(node) {
    if (!node || !node.parentElement) return false;
    let curr = node.parentElement;
    while (curr && curr.nodeType === Node.ELEMENT_NODE) {
      if (curr.isContentEditable || curr.contentEditable === 'true' || curr.contentEditable === true) return false;
      const tag = (curr.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return false;
      if (curr.getAttribute && curr.getAttribute('role') === 'textbox') return false;
      if (curr.hasAttribute && (curr.hasAttribute('contenteditable') || curr.hasAttribute('data-vigil'))) return false;
      if (curr.closest && (curr.closest('input, textarea, select, [contenteditable], [role="textbox"], [data-vigil]'))) return false;
      curr = curr.parentElement;
    }
    return true;
  }

  /**
   * In-place safe rehydration of a single DOM text node
   */
  function rehydrateTextNode(node) {
    if (!node || node.nodeType !== Node.TEXT_NODE || processedNodes.has(node)) return false;
    if (!isSafeToRehydrate(node)) return false;

    const val = node.nodeValue;
    if (!val || val.length < 3) return false;

    const rehydrated = rehydrateText(val);
    if (rehydrated !== val) {
      isMutatingInternally = true;
      try {
        node.nodeValue = rehydrated;
        processedNodes.add(node);
      } finally {
        isMutatingInternally = false;
      }
      return true;
    }
    return false;
  }

  /**
   * Crawls a subtree and rehydrates all eligible text nodes
   */
  function rehydrateSubtree(rootEl) {
    if (!rootEl || !rootEl.nodeType || sessionSubstitutions.size === 0) return 0;
    if (typeof document === 'undefined') return 0;

    let modifiedCount = 0;
    const walker = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        return isSafeToRehydrate(n) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });

    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((n) => {
      if (rehydrateTextNode(n)) modifiedCount++;
    });

    return modifiedCount;
  }

  /**
   * Starts a performant MutationObserver to rehydrate streaming tokens as they arrive
   */
  function startStreamingObserver(targetContainer = null) {
    if (typeof document === 'undefined' || typeof MutationObserver === 'undefined') return false;
    stopStreamingObserver();

    const target = targetContainer || document.body;
    if (!target) return false;

    streamingObserver = new MutationObserver((mutations) => {
      if (isMutatingInternally || sessionSubstitutions.size === 0) return;

      for (let i = 0; i < mutations.length; i++) {
        const m = mutations[i];
        if (m.type === 'characterData') {
          rehydrateTextNode(m.target);
        } else if (m.type === 'childList') {
          for (let j = 0; j < m.addedNodes.length; j++) {
            const added = m.addedNodes[j];
            if (added.nodeType === Node.TEXT_NODE) {
              rehydrateTextNode(added);
            } else if (added.nodeType === Node.ELEMENT_NODE) {
              rehydrateSubtree(added);
            }
          }
        }
      }
    });

    streamingObserver.observe(target, {
      childList: true,
      subtree: true,
      characterData: true
    });

    return true;
  }

  /**
   * Stops the streaming MutationObserver
   */
  function stopStreamingObserver() {
    if (streamingObserver) {
      streamingObserver.disconnect();
      streamingObserver = null;
    }
  }

  const VIGIL_REHYDRATION = {
    recordSubstitution,
    recordSubstitutionTree,
    getSubstitutionCount,
    clearSubstitutions,
    rehydrateText,
    rehydrateTextNode,
    rehydrateSubtree,
    startStreamingObserver,
    stopStreamingObserver
  };

  root.VIGIL_REHYDRATION = VIGIL_REHYDRATION;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_REHYDRATION;
})(typeof self !== 'undefined' ? self : globalThis);
