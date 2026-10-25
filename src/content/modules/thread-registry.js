/**
 * VIGIL AI — Conversational Thread State Registry (ThreadRegistry)
 *
 * Implements thread-scoped dialogue state tracking for Conversational AI
 * (ChatGPT, Claude, Gemini, Copilot, DeepSeek).
 *
 * Capabilities:
 * - DOM-Anchored Session Tree (WeakMap binding to conversation containers)
 * - SPA URL Reconciliation (seamless aliasing from ephemeral ID to /c/[uuid])
 * - Bijective Entity Lexicon Store with sliding TTL (60 min) & LRU cap (500 items)
 * - Multi-turn Quasi-Identifier accumulation across dialogue turns
 * - Sticky Consent ("Always mask in this thread")
 *
 * 100% Local / Zero-Cloud / Fail-Closed.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_THREAD_REGISTRY = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Private DOM WeakMap: Element -> Ephemeral Thread ID
  const domNodeToThreadId = new WeakMap();

  // Thread Map: threadId -> ThreadData
  // ThreadData: {
  //   id: string,
  //   canonicalId: string|null,
  //   entities: Map<canonicalKey, SurrogateEntry>,
  //   quasiIdentifiers: Array<QIEntry>,
  //   stickyConsent: boolean,
  //   createdAt: number,
  //   lastActive: number
  // }
  const threadStore = new Map();

  const MAX_ENTITIES_PER_THREAD = 500;
  const THREAD_TTL_MS = 60 * 60 * 1000; // 60 minutes
  const MAX_TRACKED_THREADS = 100;

  /**
   * Generates a cryptographically strong or pseudo-random ephemeral UUID.
   */
  function generateSessionId() {
    try {
      if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return 'vigil_session_' + crypto.randomUUID();
      }
    } catch (_) {}
    return 'vigil_session_' + Math.random().toString(36).slice(2, 11) + '_' + Date.now().toString(36);
  }

  /**
   * Inspects current window location to extract canonical chat thread IDs.
   */
  function detectCanonicalUrlThreadId() {
    try {
      if (typeof window === 'undefined' || !window.location) return null;
      const path = window.location.pathname || '';
      
      // ChatGPT: /c/[uuid] or /g/[g-code]/c/[uuid]
      const chatGptMatch = path.match(/\/c\/([a-zA-Z0-9_-]+)/);
      if (chatGptMatch) return 'chatgpt_' + chatGptMatch[1];

      // Claude: /chat/[uuid]
      const claudeMatch = path.match(/\/chat\/([a-zA-Z0-9_-]+)/);
      if (claudeMatch) return 'claude_' + claudeMatch[1];

      // Gemini: /app/[uuid]
      const geminiMatch = path.match(/\/app\/([a-zA-Z0-9_-]+)/);
      if (geminiMatch) return 'gemini_' + geminiMatch[1];

      // Perplexity: /search/[uuid]
      const perplexityMatch = path.match(/\/search\/([a-zA-Z0-9_-]+)/);
      if (perplexityMatch) return 'perplexity_' + perplexityMatch[1];
    } catch (_) {}
    return null;
  }

  /**
   * Locates the nearest conversation host root in the DOM.
   */
  function findConversationHost(element) {
    if (!element || typeof element.closest !== 'function') {
      if (typeof document !== 'undefined' && document.body) return document.body;
      return null;
    }
    const host = element.closest('main, [role="main"], [data-testid="conversation-turn"], .chat-container, article, body');
    return host || (typeof document !== 'undefined' ? document.body : null);
  }

  /**
   * Retrieves or initializes a ThreadData object.
   */
  function getOrCreateThread(threadId) {
    cleanupStaleThreads();
    let thread = threadStore.get(threadId);
    if (!thread) {
      if (threadStore.size >= MAX_TRACKED_THREADS) {
        // Evict oldest thread
        const oldestId = threadStore.keys().next().value;
        threadStore.delete(oldestId);
      }
      thread = {
        id: threadId,
        canonicalId: null,
        entities: new Map(),
        quasiIdentifiers: [],
        stickyConsent: false,
        createdAt: Date.now(),
        lastActive: Date.now()
      };
      threadStore.set(threadId, thread);
    } else {
      thread.lastActive = Date.now();
    }
    return thread;
  }

  /**
   * Resolves the active thread ID for a given interaction element.
   * Priority: Canonical URL ID -> Bound DOM WeakMap -> Fresh Ephemeral UUID.
   */
  function resolveThreadId(element = null) {
    const canonical = detectCanonicalUrlThreadId();
    const host = findConversationHost(element);

    if (canonical) {
      const thread = getOrCreateThread(canonical);
      thread.canonicalId = canonical;
      if (host) domNodeToThreadId.set(host, canonical);
      return canonical;
    }

    if (host && domNodeToThreadId.has(host)) {
      const existingId = domNodeToThreadId.get(host);
      getOrCreateThread(existingId); // Touch lastActive
      return existingId;
    }

    const ephemeralId = generateSessionId();
    if (host) domNodeToThreadId.set(host, ephemeralId);
    getOrCreateThread(ephemeralId);
    return ephemeralId;
  }

  /**
   * Reconciles an ephemeral thread ID with a canonical server ID (SPA navigation).
   * Migrates all entities and quasi-identifiers to the canonical ID.
   */
  function aliasThread(oldThreadId, newThreadId) {
    if (!oldThreadId || !newThreadId || oldThreadId === newThreadId) return;
    const oldThread = threadStore.get(oldThreadId);
    if (!oldThread) return;

    const newThread = getOrCreateThread(newThreadId);
    newThread.canonicalId = newThreadId;
    newThread.stickyConsent = newThread.stickyConsent || oldThread.stickyConsent;

    // Merge entities
    for (const [key, val] of oldThread.entities.entries()) {
      if (!newThread.entities.has(key)) {
        newThread.entities.set(key, val);
      }
    }

    // Merge quasi-identifiers
    oldThread.quasiIdentifiers.forEach(qi => {
      if (!newThread.quasiIdentifiers.some(x => x.raw === qi.raw)) {
        newThread.quasiIdentifiers.push(qi);
      }
    });

    threadStore.delete(oldThreadId);
  }

  /**
   * Normalizes an entity key for consistent dictionary lookup.
   */
  function normalizeKey(entityText) {
    if (!entityText || typeof entityText !== 'string') return '';
    return entityText.trim().toLowerCase();
  }

  /**
   * Registers a surrogate mapping within a thread.
   */
  function recordThreadEntity(threadId, originalText, surrogateData) {
    if (!threadId || !originalText || !surrogateData) return false;
    const thread = getOrCreateThread(threadId);
    const key = normalizeKey(originalText);

    if (thread.entities.size >= MAX_ENTITIES_PER_THREAD) {
      const oldestKey = thread.entities.keys().next().value;
      thread.entities.delete(oldestKey);
    }

    thread.entities.set(key, {
      original: originalText,
      surrogate: surrogateData.surrogate,
      category: surrogateData.category || 'PII',
      subEntities: surrogateData.subEntities || [],
      timestamp: Date.now()
    });

    thread.lastActive = Date.now();
    return true;
  }

  /**
   * Retrieves registered surrogate data for an entity in a thread.
   */
  function getThreadEntity(threadId, originalText) {
    if (!threadId || !originalText) return null;
    const thread = threadStore.get(threadId);
    if (!thread) return null;
    const key = normalizeKey(originalText);
    const entry = thread.entities.get(key);
    if (entry) {
      thread.lastActive = Date.now();
      return entry;
    }
    return null;
  }

  /**
   * Checks if an entity is already registered in a thread.
   */
  function hasThreadEntity(threadId, originalText) {
    if (!threadId || !originalText) return false;
    const thread = threadStore.get(threadId);
    if (!thread) return false;
    return thread.entities.has(normalizeKey(originalText));
  }

  /**
   * Returns a complete map of all surrogate -> original substitutions for rehydration.
   */
  function getAllThreadSubstitutions(threadId) {
    const substitutions = {};
    if (!threadId) return substitutions;
    const thread = threadStore.get(threadId);
    if (!thread) return substitutions;

    thread.entities.forEach(entry => {
      if (entry.surrogate && entry.original) {
        substitutions[entry.surrogate] = entry.original;
      }
      if (Array.isArray(entry.subEntities)) {
        entry.subEntities.forEach(sub => {
          if (sub.surrogate && sub.original) {
            substitutions[sub.surrogate] = sub.original;
          }
        });
      }
    });

    return substitutions;
  }

  /**
   * Records a quasi-identifier for longitudinal k-anonymity tracking.
   */
  function recordThreadQuasiIdentifier(threadId, qi) {
    if (!threadId || !qi || !qi.raw) return;
    const thread = getOrCreateThread(threadId);
    const exists = thread.quasiIdentifiers.some(x => x.raw === qi.raw && x.category === qi.category);
    if (!exists) {
      thread.quasiIdentifiers.push({ ...qi, timestamp: Date.now() });
      thread.lastActive = Date.now();
    }
  }

  /**
   * Retrieves all accumulated quasi-identifiers for the thread.
   */
  function getThreadQuasiIdentifiers(threadId) {
    if (!threadId) return [];
    const thread = threadStore.get(threadId);
    return thread ? [...thread.quasiIdentifiers] : [];
  }

  /**
   * Sticky consent management ("Always mask in this chat").
   */
  function setStickyConsent(threadId, enabled = true) {
    if (!threadId) return;
    const thread = getOrCreateThread(threadId);
    thread.stickyConsent = Boolean(enabled);
  }

  function isStickyConsentActive(threadId) {
    if (!threadId) return false;
    const thread = threadStore.get(threadId);
    return Boolean(thread && thread.stickyConsent);
  }

  /**
   * Removes stale threads older than TTL.
   */
  function cleanupStaleThreads(maxAgeMs = THREAD_TTL_MS) {
    const now = Date.now();
    for (const [id, thread] of threadStore.entries()) {
      if (now - thread.lastActive > maxAgeMs) {
        threadStore.delete(id);
      }
    }
  }

  /**
   * Clears a thread explicitly.
   */
  function clearThread(threadId) {
    if (threadId) threadStore.delete(threadId);
  }

  /**
   * Reset all threads (for testing).
   */
  function resetAll() {
    threadStore.clear();
  }

  return {
    resolveThreadId,
    aliasThread,
    recordThreadEntity,
    getThreadEntity,
    hasThreadEntity,
    getAllThreadSubstitutions,
    recordThreadQuasiIdentifier,
    getThreadQuasiIdentifiers,
    setStickyConsent,
    isStickyConsentActive,
    cleanupStaleThreads,
    clearThread,
    resetAll,
    _getStoreSize: () => threadStore.size
  };
});
