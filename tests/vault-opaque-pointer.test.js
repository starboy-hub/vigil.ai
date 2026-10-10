/**
 * Tests for Blueprint #1 & #3: Opaque Pointer Pattern & Zero-Trust Vault Oracle
 * Verifies blind indexing, side-channel resistant verification, opaque pointer generation,
 * and zero cleartext leakage.
 */
require('../src/shared/vigil-shared.js');
const { createVault, normalizeVaultValue, constantTimeEqual, computeBlindHash } = require('../src/background/vigil-vault.js');
const { createOpaquePointer, redactText } = require('../src/content/modules/fake-data.js');

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

describe('Blueprint #1 & #3: Opaque Pointer Pattern & Crypto Oracle', () => {
  let vault;

  beforeEach(() => {
    vault = createVault(makeStorage(), cryptoObj);
  });

  describe('1. Normalization & Constant-Time Helpers', () => {
    test('normalizeVaultValue handles phones, emails, and names', () => {
      expect(normalizeVaultValue('phone', '+1 (555) 123-4567')).toBe('15551234567');
      expect(normalizeVaultValue('email', '  Alice.Smith@Domain.COM  ')).toBe('alice.smith@domain.com');
      expect(normalizeVaultValue('name', '  Alice    Smith  ')).toBe('alice smith');
    });

    test('constantTimeEqual correctly checks string equality without timing leaks', () => {
      expect(constantTimeEqual('secret123', 'secret123')).toBe(true);
      expect(constantTimeEqual('secret123', 'secret456')).toBe(false);
      expect(constantTimeEqual('short', 'longer-string')).toBe(false);
      expect(constantTimeEqual('', '')).toBe(true);
    });
  });

  describe('2. Blind Index Generation (Zero Cleartext Exposure)', () => {
    test('getBlindIndices returns salted SHA-256 hashes without cleartext secrets', async () => {
      await vault.addEntry('name', 'Alice Montgomery');
      await vault.addEntry('email', 'alice@confidential.org');
      await vault.addEntry('phone', '555-892-1049');

      const { salt, indices } = await vault.getBlindIndices('test-session-salt-123');
      expect(salt).toBe('test-session-salt-123');
      expect(indices).toHaveLength(3);

      indices.forEach(idx => {
        expect(idx.id).toBeDefined();
        expect(idx.kind).toBeDefined();
        expect(idx.blindHash).toMatch(/^[a-f0-9]{64}$/);
        // CRITICAL ZERO-TRUST REQUIREMENT: cleartext values must NOT be in the indices!
        expect(idx.value).toBeUndefined();
      });

      // Verification of deterministic blind hashing
      const expectedEmailHash = await computeBlindHash('test-session-salt-123', 'alice@confidential.org', cryptoObj.subtle);
      const emailIdx = indices.find(i => i.kind === 'email');
      expect(emailIdx.blindHash).toBe(expectedEmailHash);
    });
  });

  describe('3. Crypto Oracle Candidate Verification', () => {
    test('verifyCandidateMatch matches registered identity and returns opaque pointer', async () => {
      const entry = await vault.addEntry('email', 'secops@corp.internal');

      const matchResult = await vault.verifyCandidateMatch('  SECOPS@CORP.INTERNAL ', 'chatgpt.com');
      expect(matchResult.match).toBe(true);
      expect(matchResult.entryId).toBe(entry.id);
      expect(matchResult.kind).toBe('email');
      expect(matchResult.opaquePointer).toBe(`{{VAULT:${entry.id}}}`);
      expect(matchResult.fake).toBeDefined();

      // Ensure wrong candidate does not match
      const mismatch = await vault.verifyCandidateMatch('other@corp.internal', 'chatgpt.com');
      expect(mismatch.match).toBe(false);
    });

    test('verifyCandidateMatch normalizes phone number formatting', async () => {
      const entry = await vault.addEntry('phone', '(555) 789-1234');
      const matchResult = await vault.verifyCandidateMatch('555-789-1234', 'claude.ai');
      expect(matchResult.match).toBe(true);
      expect(matchResult.entryId).toBe(entry.id);
    });
  });

  describe('4. Opaque Pointer Resolution & Response Text Restoration', () => {
    test('resolveOpaquePointer returns site-scoped pseudonym and opaque token', async () => {
      const entry = await vault.addEntry('name', 'Robert Henderson');
      const resolved = await vault.resolveOpaquePointer(entry.id, 'gemini.google.com');

      expect(resolved.id).toBe(entry.id);
      expect(resolved.kind).toBe('name');
      expect(resolved.opaquePointer).toBe(`{{VAULT:${entry.id}}}`);
      expect(resolved.fake).toBeDefined();
      expect(resolved.fake).not.toBe('Robert Henderson');
    });

    test('restoreText replaces site pseudonyms back to real vault values', async () => {
      const entry = await vault.addEntry('name', 'Robert Henderson');
      const resolved = await vault.resolveOpaquePointer(entry.id, 'gemini.google.com');
      const pseudonym = resolved.fake;

      const aiResponse = `Hello ${pseudonym}, I have reviewed your request.`;
      const { text: restored } = await vault.restoreText(aiResponse, 'gemini.google.com');

      expect(restored).toBe('Hello Robert Henderson, I have reviewed your request.');
    });
  });

  describe('5. Client-Side Opaque Pointer Tokenization', () => {
    test('createOpaquePointer generates properly formatted tokens', () => {
      const token = createOpaquePointer('EMAIL', 'usr123');
      expect(token).toBe('{{PTR:EMAIL_usr123}}');
    });

    test('redactText injects opaque pointer when provided', () => {
      const text = 'Contact me at alice@secret.org immediately.';
      const redactions = [{
        text: 'alice@secret.org',
        type: 'Email',
        opaquePointer: '{{PTR:VAULT_usr999}}'
      }];

      const res = redactText(text, redactions, false);
      expect(res.text).toBe('Contact me at {{PTR:VAULT_usr999}} immediately.');
      expect(res.replacements).toHaveLength(1);
      expect(res.replacements[0].fake).toBe('{{PTR:VAULT_usr999}}');
    });
  });
});
