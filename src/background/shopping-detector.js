/**
 * VIGIL Blueprint #10: Multi-Provider Jailbreak Shopping Detection
 *
 * Problem: Attackers test identical jailbreak or prompt-injection payloads across
 * multiple AI providers within minutes to discover the weakest guardrails.
 *
 * Solution: Computes a privacy-preserving SHA-256 hash of outbound prompts,
 * tracks distinct AI provider targets in ephemeral storage (chrome.storage.session),
 * and flags an alert if the same prompt pattern is blasted across 3+ distinct
 * providers within a 5-minute sliding window. Zero cleartext prompt text is stored.
 */
(function (root) {
  'use strict';

  const SHOPPING_STORAGE_KEY = 'vigil_shopping_records';
  const DEFAULT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
  const DEFAULT_THRESHOLD = 3; // 3 or more distinct AI providers
  const MIN_PROMPT_LENGTH = 25; // Skip short greetings / casual questions

  // Known AI provider rules
  const PROVIDER_RULES = [
    { provider: 'openai', match: /(?:^|\.)(?:chatgpt\.com|openai\.com)$/i },
    { provider: 'anthropic', match: /(?:^|\.)(?:claude\.ai|anthropic\.com)$/i },
    { provider: 'google', match: /(?:^|\.)(?:gemini\.google\.com|bard\.google\.com|aistudio\.google\.com)$/i },
    { provider: 'microsoft', match: /(?:^|\.)(?:copilot\.microsoft\.com|bing\.com)$/i },
    { provider: 'perplexity', match: /(?:^|\.)(?:perplexity\.ai)$/i },
    { provider: 'mistral', match: /(?:^|\.)(?:chat\.mistral\.ai|mistral\.ai)$/i },
    { provider: 'xai', match: /(?:^|\.)(?:grok\.com|x\.com)$/i },
    { provider: 'poe', match: /(?:^|\.)(?:poe\.com)$/i },
    { provider: 'deepseek', match: /(?:^|\.)(?:deepseek\.com|chat\.deepseek\.com)$/i },
    { provider: 'cohere', match: /(?:^|\.)(?:coral\.cohere\.com|cohere\.com)$/i }
  ];

  function canonicalizeProvider(hostname) {
    if (!hostname || typeof hostname !== 'string') return 'unknown';
    const cleanHost = hostname.trim().toLowerCase();
    for (const rule of PROVIDER_RULES) {
      if (rule.match.test(cleanHost)) return rule.provider;
    }
    // Fallback: extract root domain or sanitized hostname
    const parts = cleanHost.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return cleanHost || 'unknown';
  }

  /**
   * Normalizes prompt text for fingerprinting:
   * - Strips zero-width steganographic characters (\u200B, \u200C, \u200D, \uFEFF, \u2060)
   * - Lowercase
   * - Strips non-alphanumeric punctuation (retaining letters, numbers, and spaces)
   * - Collapses consecutive whitespace
   * - Trims
   */
  function normalizePrompt(text) {
    if (!text || typeof text !== 'string') return '';
    return text
      .replace(/[\u200B-\u200D\uFEFF\u2060]/g, '')
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s]/gu, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function getSubtle(cryptoApi) {
    if (cryptoApi && cryptoApi.subtle) return cryptoApi.subtle;
    if (typeof crypto !== 'undefined' && crypto.subtle) return crypto.subtle;
    try {
      const nodeCrypto = require('crypto');
      if (nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle) return nodeCrypto.webcrypto.subtle;
    } catch (e) {}
    return null;
  }

  const TextEncoderCls = typeof TextEncoder !== 'undefined' ? TextEncoder : (typeof require !== 'undefined' ? require('util').TextEncoder : null);

  /**
   * Generates SHA-256 fingerprint of normalized text.
   */
  async function hashPrompt(normalizedText, cryptoApi) {
    const subtle = getSubtle(cryptoApi);
    if (subtle && TextEncoderCls) {
      const encoder = new TextEncoderCls();
      const data = encoder.encode(normalizedText);
      const digestBuffer = await subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(digestBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // Deterministic fallback if subtle crypto is unavailable
    let h1 = 0xdeadbeef ^ normalizedText.length;
    let h2 = 0x41c6ce57 ^ normalizedText.length;
    for (let i = 0; i < normalizedText.length; i++) {
      const ch = normalizedText.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(16, '0');
  }

  function createShoppingDetector(storage, cryptoApi, options = {}) {
    const windowMs = options.windowMs || DEFAULT_WINDOW_MS;
    const threshold = options.threshold || DEFAULT_THRESHOLD;
    const minLength = options.minLength || MIN_PROMPT_LENGTH;

    async function getRecords() {
      if (!storage) return {};
      const res = await storage.get(SHOPPING_STORAGE_KEY);
      return (res && res[SHOPPING_STORAGE_KEY]) || {};
    }

    async function saveRecords(records) {
      if (!storage) return;
      await storage.set({ [SHOPPING_STORAGE_KEY]: records });
    }

    function prune(records, now = Date.now()) {
      const cutoff = now - windowMs;
      const pruned = {};
      for (const [hash, entry] of Object.entries(records)) {
        if (!entry || !entry.providers) continue;
        const validProviders = {};
        for (const [prov, ts] of Object.entries(entry.providers)) {
          if (ts >= cutoff) {
            validProviders[prov] = ts;
          }
        }
        const provKeys = Object.keys(validProviders);
        if (provKeys.length > 0) {
          pruned[hash] = {
            firstSeen: entry.firstSeen >= cutoff ? entry.firstSeen : Math.min(...Object.values(validProviders)),
            lastSeen: Math.max(...Object.values(validProviders)),
            providers: validProviders
          };
        }
      }
      return pruned;
    }

    // Read-modify-write serialization: two outbound prompts racing through
    // getRecords/saveRecords would drop one update and undercount providers.
    let opQueue = Promise.resolve();

    async function checkAndRecordPromptInner(promptText, hostname, timestamp = Date.now(), opts = {}) {
      if (!promptText || typeof promptText !== 'string') {
        return { tracked: false, shoppingDetected: false, reason: 'empty_prompt' };
      }

      const normalized = normalizePrompt(promptText);
      if (normalized.length < minLength) {
        return { tracked: false, shoppingDetected: false, reason: 'prompt_too_short' };
      }

      const provider = canonicalizeProvider(hostname);
      const hash = await hashPrompt(normalized, cryptoApi);

      const rawRecords = await getRecords();
      const records = prune(rawRecords, timestamp);

      const entry = records[hash] || {
        firstSeen: timestamp,
        lastSeen: timestamp,
        providers: {}
      };

      entry.providers[provider] = timestamp;
      entry.lastSeen = timestamp;
      records[hash] = entry;

      // opts.record === false → dry-run (forensics replay): evaluate the
      // cross-provider count without writing into live detection data.
      if (opts.record !== false) {
        await saveRecords(records);
      }

      const activeProviders = Object.keys(entry.providers);
      const count = activeProviders.length;
      const shoppingDetected = count >= threshold;

      return {
        tracked: true,
        shoppingDetected,
        provider,
        providers: activeProviders,
        count,
        hash,
        windowMs
      };
    }

    async function clear() {
      if (!storage) return;
      if (storage.remove) {
        await storage.remove(SHOPPING_STORAGE_KEY);
      } else {
        await storage.set({ [SHOPPING_STORAGE_KEY]: {} });
      }
    }

    function checkAndRecordPrompt(promptText, hostname, timestamp = Date.now(), opts = {}) {
      const run = opQueue.then(() => checkAndRecordPromptInner(promptText, hostname, timestamp, opts));
      opQueue = run.then(() => undefined, () => undefined);
      return run;
    }

    return {
      checkAndRecordPrompt,
      getRecords,
      clear,
      prune,
      canonicalizeProvider,
      normalizePrompt,
      hashPrompt
    };
  }

  const VIGIL_SHOPPING = {
    canonicalizeProvider,
    normalizePrompt,
    hashPrompt,
    createShoppingDetector,
    SHOPPING_STORAGE_KEY,
    DEFAULT_WINDOW_MS,
    DEFAULT_THRESHOLD,
    MIN_PROMPT_LENGTH
  };

  root.VIGIL_SHOPPING = VIGIL_SHOPPING;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_SHOPPING;
  }
})(typeof self !== 'undefined' ? self : globalThis);
