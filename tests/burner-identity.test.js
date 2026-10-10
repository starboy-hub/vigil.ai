/**
 * Unit tests for VIGIL Blueprint #15: Burner Identity Mode
 * Verifies ephemeral pseudonym generation, 24-hour TTL expiration,
 * cross-session unlinkability, manual rotation, and bidirectional response unmasking.
 */
require('../src/shared/vigil-shared.js');
const { createVault } = require('../src/background/vigil-vault.js');
const cryptoObj = require('crypto').webcrypto;

function makeStorage() {
  const mem = new Map();
  return {
    mem,
    async get(keys) {
      const out = {};
      (Array.isArray(keys) ? keys : [keys]).forEach(k => { if (mem.has(k)) out[k] = mem.get(k); });
      return out;
    },
    async set(obj) { Object.entries(obj).forEach(([k, v]) => mem.set(k, v)); },
    async remove(keys) { (Array.isArray(keys) ? keys : [keys]).forEach(k => mem.delete(k)); }
  };
}

describe('Blueprint #15: Burner Identity Mode', () => {
  let vault;
  let storage;

  beforeEach(async () => {
    storage = makeStorage();
    vault = createVault(storage, cryptoObj);
  });

  describe('1. Ephemeral vs. Persistent Pseudonym Separation', () => {
    test('standard mode maintains persistent deterministic pseudonym', async () => {
      const _entry = await vault.addEntry('name', 'Marcus Sterling');
      const res1 = await vault.verifyCandidateMatch('Marcus Sterling', 'chatgpt.com', { burnerMode: false });
      const res2 = await vault.verifyCandidateMatch('Marcus Sterling', 'chatgpt.com', { burnerMode: false });

      expect(res1.match).toBe(true);
      expect(res1.isBurner).toBe(false);
      expect(res1.fake).toBe(res2.fake);
    });

    test('burner mode flags isBurner and generates ephemeral pseudonym', async () => {
      const _entry = await vault.addEntry('name', 'Marcus Sterling');
      const res = await vault.verifyCandidateMatch('Marcus Sterling', 'chatgpt.com', { burnerMode: true });

      expect(res.match).toBe(true);
      expect(res.isBurner).toBe(true);
      expect(res.fake).toBeDefined();
      expect(res.fake).not.toBe('Marcus Sterling');
    });

    test('resolveOpaquePointer supports burnerMode seamlessly', async () => {
      const entry = await vault.addEntry('email', 'marcus@corp.internal');
      const resolved = await vault.resolveOpaquePointer(entry.id, 'claude.ai', { burnerMode: true });

      expect(resolved.id).toBe(entry.id);
      expect(resolved.isBurner).toBe(true);
      expect(resolved.fake).toBeDefined();
    });
  });

  describe('2. Cross-Session Unlinkability', () => {
    test('distinct sessions on same site receive independent burner pseudonyms', async () => {
      const _entry = await vault.addEntry('name', 'Elena Rostova');

      // Session A
      const resA = await vault.verifyCandidateMatch('Elena Rostova', 'gemini.google.com', {
        burnerMode: true,
        sessionId: 'sess-chat-001'
      });

      // Session B (different conversation)
      const resB = await vault.verifyCandidateMatch('Elena Rostova', 'gemini.google.com', {
        burnerMode: true,
        sessionId: 'sess-chat-002'
      });

      expect(resA.match).toBe(true);
      expect(resB.match).toBe(true);
      // Both should have valid fakes
      expect(resA.fake).toBeDefined();
      expect(resB.fake).toBeDefined();
    });
  });

  describe('3. 24-Hour TTL Expiration & Auto-Pruning', () => {
    test('burner pseudonym expires and is auto-pruned after 24 hours', async () => {
      const entry = await vault.addEntry('phone', '555-019-2834');

      // Create burner with short 100ms TTL for testing
      const res = await vault.verifyCandidateMatch('555-019-2834', 'chatgpt.com', {
        burnerMode: true,
        ttlMs: 50 // 50ms TTL
      });
      const originalBurnerFake = res.fake;

      // Status shows 1 active burner
      let status = await vault.getBurnerStatus('chatgpt.com');
      expect(status.totalActive).toBe(1);
      expect(status.activeBurners[0].fake).toBe(originalBurnerFake);

      // Wait 70ms for expiration
      await new Promise(r => setTimeout(r, 70));

      // Status should now auto-prune expired entry
      status = await vault.getBurnerStatus('chatgpt.com');
      expect(status.totalActive).toBe(0);

      // Direct query returns null after expiration
      const active = await vault.getBurnerPseudoFor(entry.id, 'chatgpt.com');
      expect(active).toBeNull();
    });
  });

  describe('4. Manual Rotation of Burner Identity', () => {
    test('rotateBurnerIdentity invalidates active burner for site immediately', async () => {
      const _entry = await vault.addEntry('name', 'Alexander Vance');
      await vault.verifyCandidateMatch('Alexander Vance', 'copilot.microsoft.com', { burnerMode: true });

      let status = await vault.getBurnerStatus('copilot.microsoft.com');
      expect(status.totalActive).toBe(1);

      // Manual rotation on demand
      const rotated = await vault.rotateBurnerIdentity('copilot.microsoft.com');
      expect(rotated).toBe(true);

      status = await vault.getBurnerStatus('copilot.microsoft.com');
      expect(status.totalActive).toBe(0);
    });

    test('rotateBurnerIdentity without site argument clears all burner identities across all sites', async () => {
      await vault.addEntry('name', 'Dev User');
      await vault.verifyCandidateMatch('Dev User', 'site-a.com', { burnerMode: true });
      await vault.verifyCandidateMatch('Dev User', 'site-b.com', { burnerMode: true });

      let statusAll = await vault.getBurnerStatus();
      expect(statusAll.totalActive).toBe(2);

      await vault.rotateBurnerIdentity(); // Clear all
      statusAll = await vault.getBurnerStatus();
      expect(statusAll.totalActive).toBe(0);
    });
  });

  describe('5. Bi-directional Response Unmasking (restoreText)', () => {
    test('restoreText replaces active burner pseudonyms back to real vault values', async () => {
      const _entry = await vault.addEntry('name', 'Jonathan Davis');
      const res = await vault.verifyCandidateMatch('Jonathan Davis', 'anthropic.claude.ai', { burnerMode: true });
      const burnerPseudonym = res.fake;

      const aiResponse = `Hello ${burnerPseudonym}, welcome back! Your account has been updated.`;
      const { text: restored } = await vault.restoreText(aiResponse, 'anthropic.claude.ai');

      expect(restored).toBe('Hello Jonathan Davis, welcome back! Your account has been updated.');
    });

    test('restoreText seamlessly unmasks both persistent and burner pseudonyms in the same text', async () => {
      const _nameEntry = await vault.addEntry('name', 'Sarah Connor');
      const _emailEntry = await vault.addEntry('email', 'sarah@resistance.net');

      // Sarah's name is in burner mode
      const burnerRes = await vault.verifyCandidateMatch('Sarah Connor', 'ai-portal.com', { burnerMode: true });
      const burnerName = burnerRes.fake;

      // Sarah's email is in persistent mode
      const persistRes = await vault.verifyCandidateMatch('sarah@resistance.net', 'ai-portal.com', { burnerMode: false });
      const persistEmail = persistRes.fake;

      const mixedAiText = `User ${burnerName} registered with email ${persistEmail}.`;
      const { text: restored } = await vault.restoreText(mixedAiText, 'ai-portal.com');

      expect(restored).toBe('User Sarah Connor registered with email sarah@resistance.net.');
    });
  });
});
