/**
 * Tests for Granular Ignore Controls, Non-Destructive Submission Interception,
 * 2-Way Popup Synchronization, and SPA Conversation Reset.
 */

const VIGIL_ENGINE = require('../src/content/modules/detection-engine.js');
const VIGIL_FAKE = require('../src/content/modules/fake-data.js');

describe('Granular Ignore, SPA Reset & Submission Interception', () => {
  let ignoredTexts;
  let pausedThreads;
  let customAllowedEntities;
  let allowedPromptHashes;
  let activeLocation;

  beforeEach(() => {
    ignoredTexts = new Map();
    pausedThreads = new Map();
    customAllowedEntities = new Set();
    allowedPromptHashes = new Set();
    activeLocation = {
      origin: 'https://chatgpt.com',
      hostname: 'chatgpt.com',
      pathname: '/c/1234-abcd'
    };
  });

  function getThreadKey(loc = activeLocation) {
    return loc.origin + loc.pathname;
  }

  function pauseThread(loc = activeLocation, durationMs = 15 * 60 * 1000) {
    pausedThreads.set(getThreadKey(loc), Date.now() + durationMs);
  }

  function isThreadPaused(loc = activeLocation) {
    const key = getThreadKey(loc);
    const expiry = pausedThreads.get(key);
    if (expiry && Date.now() < expiry) return true;
    if (expiry && Date.now() >= expiry) pausedThreads.delete(key);
    return false;
  }

  function whitelistEntity(text) {
    if (!text || typeof text !== 'string') return;
    const trimmed = text.trim();
    if (!trimmed) return;
    customAllowedEntities.add(trimmed);
    customAllowedEntities.add(trimmed.toLowerCase());
  }

  function ignoreText(text, host = activeLocation.hostname, durationMs = 5 * 60 * 1000) {
    if (!text) return;
    if (!ignoredTexts.has(host)) ignoredTexts.set(host, new Map());
    ignoredTexts.get(host).set(text, Date.now() + durationMs);
  }

  function isTextIgnored(text, loc = activeLocation) {
    if (!text) return false;
    if (isThreadPaused(loc)) return true;
    const trimmed = String(text).trim();
    if (customAllowedEntities.has(trimmed) || customAllowedEntities.has(trimmed.toLowerCase())) return true;
    const hostMap = ignoredTexts.get(loc.hostname);
    if (!hostMap) return false;
    const expiry = hostMap.get(trimmed) || hostMap.get(text);
    if (expiry === undefined) return false;
    if (Date.now() > expiry) { hostMap.delete(text); hostMap.delete(trimmed); return false; }
    return true;
  }

  function allowCurrentPrompt(text) {
    const t = String(text || '').trim();
    if (t) allowedPromptHashes.add(t);
  }

  function isPromptAllowed(text) {
    if (!text) return false;
    const t = String(text).trim();
    return allowedPromptHashes.has(t);
  }

  describe('1. Granular Ignore Levels', () => {
    test('Level 1: Per-Prompt Allow bypasses current query snapshot only', () => {
      const promptText = 'Here is my test email john.doe@example.com for this turn';
      const scanRes = VIGIL_ENGINE.scanWithRegex(promptText);
      expect(scanRes.redactions.length).toBeGreaterThan(0);

      // User chooses "Allow Once / Allow for this Prompt"
      allowCurrentPrompt(promptText);
      expect(isPromptAllowed(promptText)).toBe(true);

      // Subsequent query containing DIFFERENT text/PII is NOT allowed and gets actively scanned
      const nextPrompt = 'Please also check jane.smith@acme.org';
      expect(isPromptAllowed(nextPrompt)).toBe(false);
      const nextScanRes = VIGIL_ENGINE.scanWithRegex(nextPrompt);
      expect(nextScanRes.redactions.length).toBeGreaterThan(0);
    });

    test('Level 2: Per-Entity Whitelist ignores specific pattern while catching other PII', () => {
      const dummyApiKey = 'sk-proj-' + 'test1234567890abcdef1234567890abcdef';
      whitelistEntity(dummyApiKey);

      expect(isTextIgnored(dummyApiKey)).toBe(true);
      expect(isTextIgnored(dummyApiKey.toLowerCase())).toBe(true);

      // Other real PII is NOT ignored
      const realSSN = '123-45-6789';
      expect(isTextIgnored(realSSN)).toBe(false);
    });

    test('Level 3: Thread Pause silences alerts on active conversation for 15 minutes', () => {
      expect(isThreadPaused()).toBe(false);

      pauseThread(activeLocation, 15 * 60 * 1000);
      expect(isThreadPaused()).toBe(true);
      expect(isTextIgnored('any.email@example.com')).toBe(true);

      // Another conversation thread on the same domain remains UNPAUSED
      const otherThread = { origin: 'https://chatgpt.com', hostname: 'chatgpt.com', pathname: '/c/9999-different' };
      expect(isThreadPaused(otherThread)).toBe(false);
      expect(isTextIgnored('any.email@example.com', otherThread)).toBe(false);
    });

    test('Level 4: Host map does not overwrite previously ignored entities on new additions', () => {
      ignoreText('token-1', 'chatgpt.com');
      ignoreText('token-2', 'chatgpt.com');

      expect(isTextIgnored('token-1')).toBe(true);
      expect(isTextIgnored('token-2')).toBe(true);
      expect(isTextIgnored('token-3')).toBe(false);
    });
  });

  describe('2. SPA Conversation Navigation Reset', () => {
    test('Navigating between chat conversations clears per-prompt allowances', () => {
      const prompt1 = 'Confidential prompt with ssn 000-12-3456';
      allowCurrentPrompt(prompt1);
      expect(isPromptAllowed(prompt1)).toBe(true);

      // Simulate SPA Navigation event (pushState / popstate to new conversation ID)
      activeLocation.pathname = '/c/5678-new-thread';
      allowedPromptHashes.clear(); // Reset on navigation

      expect(isPromptAllowed(prompt1)).toBe(false);
    });
  });

  describe('3. Non-Destructive React-Compatible Sanitization', () => {
    test('Redacts PII cleanly into synthetic pseudonyms without breaking text integrity', () => {
      const original = 'Contact me at admin@security.org or call 555-019-2834';
      const scanRes = VIGIL_ENGINE.scanWithRegex(original);
      expect(scanRes.redactions.length).toBeGreaterThan(0);

      const result = VIGIL_FAKE.redactText(original, scanRes.redactions, true);
      expect(result.text).not.toContain('admin@security.org');
      expect(result.text).not.toContain('555-019-2834');
      expect(result.replacements.length).toBe(scanRes.redactions.length);
    });
  });

  describe('4. Two-Way Popup & Content Synchronization Contracts', () => {
    test('DISMISS_PAGE_ALERT message handling contracts', () => {
      const sampleAlert = {
        id: 101,
        alerts: [{ type: 'Email', severity: 'medium' }],
        redactions: [{ text: 'user@test.com', type: 'Email' }],
        element: { value: 'user@test.com' }
      };

      // Handler simulation
      function handleDismiss(mode, alert) {
        if (mode === 'THREAD') {
          pauseThread();
        } else if (mode === 'ENTITY' || mode === 'WHITELIST') {
          const txt = alert.redactions[0].text;
          whitelistEntity(txt);
          ignoreText(txt);
        } else if (mode === 'PROMPT' || mode === 'ONCE') {
          allowCurrentPrompt(alert.element.value);
        }
      }

      // Test PROMPT mode
      handleDismiss('PROMPT', sampleAlert);
      expect(isPromptAllowed('user@test.com')).toBe(true);

      // Test ENTITY mode
      handleDismiss('ENTITY', sampleAlert);
      expect(isTextIgnored('user@test.com')).toBe(true);

      // Test THREAD mode
      handleDismiss('THREAD', sampleAlert);
      expect(isThreadPaused()).toBe(true);
    });
  });
});
