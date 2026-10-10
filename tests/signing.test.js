/**
 * Tests for VIGIL content signing (provenance) and the swarm threat store
 */
const VIGIL = require('../src/shared/vigil-shared.js');
const { createSigner } = require('../src/background/signing-engine.js');
const { createThreatStore } = require('../src/background/threat-store.js');
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

describe('VIGIL content signing', () => {
  test('sign -> format -> parse -> verify roundtrip', async () => {
    const signer = createSigner(makeStorage(), cryptoObj);
    const block = await signer.signText('Meet me at noon. — Sarah');
    const formatted = signer.formatSignedMessage('Meet me at noon. — Sarah', block);
    expect(formatted).toContain('-----BEGIN VIGIL SIGNED MESSAGE-----');

    const parsed = signer.parseSignedMessage(formatted);
    expect(parsed.text).toBe('Meet me at noon. — Sarah');

    const result = await signer.verifySignedMessage(formatted);
    expect(result.valid).toBe(true);
    expect(result.ts).toBeTruthy();
  });

  test('tampered content fails verification loudly', async () => {
    const signer = createSigner(makeStorage(), cryptoObj);
    const block = await signer.signText('I will pay you 100');
    const forged = signer.formatSignedMessage('I will pay you 999999', block);
    const result = await signer.verifySignedMessage(forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('does not match');
  });

  test('keys persist: a new signer from the same storage verifies old signatures', async () => {
    const storage = makeStorage();
    const signerA = createSigner(storage, cryptoObj);
    const formatted = signerA.formatSignedMessage('original text', await signerA.signText('original text'));

    const signerB = createSigner(storage, cryptoObj);
    expect((await signerB.verifySignedMessage(formatted)).valid).toBe(true);
  });

  test('malformed blocks fail safely', async () => {
    const signer = createSigner(makeStorage(), cryptoObj);
    expect((await signer.verifySignedMessage('no block here')).valid).toBe(false);
    expect((await signer.verifySignedMessage('-----BEGIN VIGIL SIGNED MESSAGE-----\nbad\n-----BEGIN VIGIL SIGNATURE-----\nnot json\n-----END VIGIL SIGNATURE-----')).valid).toBe(false);
  });
});

describe('VIGIL swarm threat store', () => {
  test('record -> known; export pack contains hashes only', async () => {
    const storage = makeStorage();
    const threats = createThreatStore(storage, VIGIL);
    await threats.record('abc123');
    expect(await threats.isKnown('abc123')).toBe(true);
    expect(await threats.isKnown('other')).toBe(false);

    const pack = await threats.exportPack();
    expect(pack.vigilThreatPack).toBe(true);
    expect(pack.signatures.some(s => s.value === 'abc123')).toBe(true);
    // Privacy by construction: no raw text in the pack
    expect(JSON.stringify(pack)).not.toContain('message text here');
  });

  test('import merges packs without duplicates', async () => {
    const storage = makeStorage();
    const threats = createThreatStore(storage, VIGIL);
    await threats.record('hash1');
    const pack = { vigilThreatPack: true, version: 1, signatures: [{ value: 'hash1' }, { value: 'hash2' }, { value: 'hash3' }] };
    const result = await threats.importPack(pack);
    expect(result.added).toBe(2);
    expect(await threats.isKnown('hash3')).toBe(true);
    expect((await threats.exportPack()).count).toBe(3);
  });

  test('invalid packs are rejected safely', async () => {
    const threats = createThreatStore(makeStorage(), VIGIL);
    expect((await threats.importPack({})).added).toBe(0);
    expect((await threats.importPack(null)).error).toBeTruthy();
  });

  test('normalizeForSignature defeats trivial variation', () => {
    const a = VIGIL.normalizeForSignature('URGENT!!!  Act   now — you have WON!!!');
    const b = VIGIL.normalizeForSignature('urgent act now you have won');
    expect(a).toBe(b);
  });
});
