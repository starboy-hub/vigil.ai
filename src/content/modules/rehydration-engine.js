/**
 * VIGIL Security Policy: Autonomous Dynamic Bidirectional Rehydration Engine
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

  let pendingBatchNodes = new Set();
  let rafScheduled = false;

  function scheduleBatchFlush() {
    if (rafScheduled) return;
    rafScheduled = true;
    const scheduler = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (fn) => setTimeout(fn, 16);
    scheduler(flushPendingBatch);
  }

  function flushPendingBatch() {
    rafScheduled = false;
    if (isMutatingInternally || pendingBatchNodes.size === 0) return;
    const nodes = Array.from(pendingBatchNodes);
    pendingBatchNodes.clear();
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!n || !n.parentElement) continue;
      if (n.nodeType === Node.TEXT_NODE) {
        rehydrateTextNode(n);
      } else if (n.nodeType === Node.ELEMENT_NODE) {
        rehydrateSubtree(n);
      }
    }
  }

  function getThreadRegistry() {
    if (typeof root !== 'undefined' && root.VIGIL_THREAD_REGISTRY) return root.VIGIL_THREAD_REGISTRY;
    if (typeof globalThis !== 'undefined' && globalThis.VIGIL_THREAD_REGISTRY) return globalThis.VIGIL_THREAD_REGISTRY;
    try {
      if (typeof require === 'function') return require('./thread-registry');
    } catch (_) {}
    return null;
  }

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
    let isAssistant = false;

    while (curr && curr.nodeType === 1 /* Node.ELEMENT_NODE */) {
      // 1. Strictly forbid inputs, textareas, contenteditables, and extension UI
      if (curr.isContentEditable || curr.contentEditable === 'true' || curr.contentEditable === true) return false;
      const tag = (curr.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return false;
      if (curr.getAttribute && curr.getAttribute('role') === 'textbox') return false;
      if (curr.hasAttribute && (curr.hasAttribute('contenteditable') || curr.hasAttribute('data-vigil'))) return false;

      // 2. Strictly forbid user prompt containers in chat threads
      const role = curr.getAttribute && curr.getAttribute('data-message-author-role');
      if (role === 'user') return false;
      const testId = curr.getAttribute && curr.getAttribute('data-testid');
      if (testId && (testId.includes('user-message') || testId === 'user-turn')) return false;
      const className = (curr.className && typeof curr.className === 'string') ? curr.className.toLowerCase() : '';
      if (className.includes('bubble user') || className.includes('user-bubble') || className.includes('chat-bubble-user') || className.includes('user-message') || className.includes('items-end')) {
        return false;
      }

      // 3. Detect assistant response containers
      if (role === 'assistant' || role === 'model') isAssistant = true;
      if (curr.hasAttribute && curr.hasAttribute('data-message-model-slug')) isAssistant = true;
      if (className.includes('font-claude-message') || className.includes('chat-message-assistant') || className.includes('assistant-container') || className.includes('ai-response')) {
        isAssistant = true;
      }
      if (curr.id === 'ai-stream-response') isAssistant = true;

      curr = curr.parentElement;
    }

    // On known AI platforms (ChatGPT, Claude, Gemini, etc.), strictly require assistant response container
    if (typeof window !== 'undefined' && window.location) {
      const host = (window.location.hostname || '').toLowerCase();
      if (/chatgpt\.com|openai\.com|claude\.ai|gemini\.google\.com|copilot\.microsoft\.com|perplexity\.ai/i.test(host)) {
        return isAssistant;
      }
    }

    // On test fixtures or generic pages
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
          pendingBatchNodes.add(m.target);
        } else if (m.type === 'childList') {
          for (let j = 0; j < m.addedNodes.length; j++) {
            pendingBatchNodes.add(m.addedNodes[j]);
          }
        }
      }
      scheduleBatchFlush();
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
    stopStreamingObserver,
    flushPendingBatch
  };

  root.VIGIL_REHYDRATION = VIGIL_REHYDRATION;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_REHYDRATION;
})(typeof self !== 'undefined' ? self : globalThis);
