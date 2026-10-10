/**
 * Tests for Blueprint #8: Invisible Steganographic Prompt Watermarking
 * Verifies zero-width Unicode encoding/decoding, invisible signature embedding,
 * extraction, cryptographic verification, and tamper detection.
 */
const {
  createSigner,
  bytesToZeroWidth,
  zeroWidthToBytes,
  cleanVisibleText,
  embedInvisibleWatermark,
  extractInvisibleWatermark
} = require('../src/background/signing-engine.js');

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

describe('Blueprint #8: Invisible Steganographic Prompt Watermarking', () => {
  let signer;

  beforeEach(() => {
    signer = createSigner(makeStorage(), cryptoObj);
  });

  describe('1. 2-Bit Zero-Width Encoding & Decoding Primitives', () => {
    test('bytesToZeroWidth and zeroWidthToBytes roundtrip byte arrays accurately', () => {
      const sampleBytes = new Uint8Array([0x41, 0x42, 0x43, 0xff, 0x00, 0x7e, 0xaa]);
      const zwString = bytesToZeroWidth(sampleBytes);

      // Verify that zwString only consists of zero-width characters and delimiter
      // Zero-width escapes are alternatives, not joined sequences (lint false positive)
      // eslint-disable-next-line no-misleading-character-class
      expect(zwString).toMatch(new RegExp('^[\\u2060\\u200B\\u200C\\u200D\\uFEFF]+$'));

      const recoveredBytes = zeroWidthToBytes(zwString);
      expect(Array.from(recoveredBytes)).toEqual(Array.from(sampleBytes));
    });

    test('cleanVisibleText cleanly removes all zero-width characters', () => {
      const text = 'Hello \u200B\u200C\u200D\uFEFF\u2060world!';
      expect(cleanVisibleText(text)).toBe('Hello world!');
    });
  });

  describe('2. Steganographic Watermark Embedding & Extraction', () => {
    test('embedInvisibleWatermark embeds payload invisibly without mutating visible text', () => {
      const originalText = 'Summarize quarterly financial results for Q3.';
      const mockBlock = { alg: 'ES256', ts: '2026-10-05T00:00:00Z', pub: 'pubkey123', sig: 'sig123' };

      const watermarked = embedInvisibleWatermark(originalText, mockBlock);
      expect(watermarked).not.toBe(originalText);
      expect(cleanVisibleText(watermarked)).toBe(originalText);

      const extracted = extractInvisibleWatermark(watermarked);
      expect(extracted).not.toBeNull();
      expect(extracted.watermark).toEqual(mockBlock);
      expect(extracted.visibleText).toBe(originalText);
    });

    test('extractInvisibleWatermark returns null for unwatermarked text', () => {
      expect(extractInvisibleWatermark('Plain text with no watermark')).toBeNull();
      expect(extractInvisibleWatermark('')).toBeNull();
      expect(extractInvisibleWatermark(null)).toBeNull();
    });
  });

  describe('3. Cryptographic Provenance: signInvisible & verifyInvisible', () => {
    test('full signInvisible -> verifyInvisible roundtrip succeeds', async () => {
      const prompt = 'Analyze the network topology and flag open ports.';
      const watermarkedPrompt = await signer.signInvisible(prompt);

      // Cleaned text equals the prompt
      expect(cleanVisibleText(watermarkedPrompt)).toBe(prompt);

      // Verification succeeds
      const result = await signer.verifyInvisible(watermarkedPrompt);
      expect(result.hasWatermark).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.text).toBe(prompt);
      expect(result.pub).toBeDefined();
      expect(result.ts).toBeDefined();
    });

    test('tampered visible text fails verification loudly', async () => {
      const prompt = 'Transfer $50 to account 12345.';
      const watermarkedPrompt = await signer.signInvisible(prompt);

      // Tamper with the visible content (e.g. change 50 to 5000)
      const tamperedPrompt = watermarkedPrompt.replace('50', '5000');

      const result = await signer.verifyInvisible(tamperedPrompt);
      expect(result.hasWatermark).toBe(true);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('signature does not match');
    });

    test('verifying text without watermark returns hasWatermark: false', async () => {
      const result = await signer.verifyInvisible('Just an ordinary user question without signature.');
      expect(result.hasWatermark).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('no invisible watermark found');
    });
  });

  describe('4. Backwards Compatibility with ASCII Blocks', () => {
    test('existing formatSignedMessage and verifySignedMessage continue to work', async () => {
      const text = 'Important legal memo text.';
      const block = await signer.signText(text);
      const formatted = signer.formatSignedMessage(text, block);

      expect(formatted).toContain('-----BEGIN VIGIL SIGNED MESSAGE-----');
      const res = await signer.verifySignedMessage(formatted);
      expect(res.valid).toBe(true);
      expect(res.text).toBe(text);
    });
  });

  describe('5. Publisher Trust (trusted vs self-attested provenance)', () => {
    test('own watermark is trusted; a foreign watermark is intact but NOT trusted', async () => {
      const ownText = 'Report text published by this device.';
      const ownWatermarked = await signer.signInvisible(ownText);
      const ownResult = await signer.verifyInvisible(ownWatermarked);
      expect(ownResult.valid).toBe(true);
      expect(ownResult.trusted).toBe(true);

      // A second device (own keypair in separate storage) signs the same text
      const foreignSigner = createSigner(makeStorage(), cryptoObj);
      const foreignWatermarked = await foreignSigner.signInvisible(ownText);
      const foreignResult = await signer.verifyInvisible(foreignWatermarked);
      expect(foreignResult.valid).toBe(true); // signature is cryptographically intact
      expect(foreignResult.trusted).toBe(false);
      expect(foreignResult.reason).toContain('self-attested');
    });
  });
});
