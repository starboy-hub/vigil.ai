/**
 * Property-based testing for VIGIL Cryptography and Vault logic
 * Tests invariant mathematical properties across randomized inputs.
 */
const crypto = require('crypto');
const { TextEncoder, TextDecoder } = require('util');
const VIGIL = require('../src/shared/vigil-shared.js');
const { MerkleTree } = require('../src/shared/zk-compliance.js');
const { normalizeVaultValue, computeBlindHash } = require('../src/background/vigil-vault.js');

const cryptoObj = crypto.webcrypto;
const subtle = cryptoObj.subtle;

describe('Blueprint 4: Cryptographic & Vault Property-Based Invariants', () => {
  describe('Hash Function Determinism & Range Invariants', () => {
    test('strHash is strictly deterministic for 1,000 randomized inputs', () => {
      for (let i = 0; i < 1000; i++) {
        const randomStr = crypto.randomBytes(32).toString('base64');
        const h1 = VIGIL.strHash(randomStr);
        const h2 = VIGIL.strHash(randomStr);
        expect(h1).toBe(h2);
        expect(typeof h1).toBe('number');
        expect(Number.isFinite(h1)).toBe(true);
        expect(h1).toBeGreaterThanOrEqual(0);
      }
    });

    test('strHash produces valid numeric hashes across multi-byte Unicode', () => {
      const scripts = ['🔐🛡️✨', '日本語のテスト', 'العربية', 'русский язык', '中文测试数据', ''];
      for (const sample of scripts) {
        const h = VIGIL.strHash(sample);
        expect(typeof h).toBe('number');
        expect(Number.isFinite(h)).toBe(true);
        expect(h).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe('AES-256-GCM AEAD Invariants (WebCrypto)', () => {
    test('decrypt(encrypt(m, k, iv)) === m invariant across 100 random payloads', async () => {
      const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

      for (let i = 0; i < 100; i++) {
        const payloadLength = Math.floor(Math.random() * 512) + 1;
        const plaintext = crypto.randomBytes(payloadLength).toString('utf-8');
        const iv = crypto.randomBytes(12);

        const encBuffer = new TextEncoder().encode(plaintext);
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, encBuffer);

        const decryptedBuffer = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        const recovered = new TextDecoder().decode(decryptedBuffer);

        expect(recovered).toBe(plaintext);
      }
    });

    test('bit-flip tamper detection invariant: any altered ciphertext bit causes decrypt failure', async () => {
      const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

      for (let i = 0; i < 50; i++) {
        const plaintext = 'Sensitive-Enterprise-Identity-Token-' + i;
        const iv = crypto.randomBytes(12);

        const ciphertext = await subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          new TextEncoder().encode(plaintext)
        );

        const tampered = new Uint8Array(ciphertext);
        // Flip a random bit in the ciphertext / authentication tag
        const flipByteIndex = Math.floor(Math.random() * tampered.length);
        tampered[flipByteIndex] ^= (1 << (i % 8));

        await expect(subtle.decrypt({ name: 'AES-GCM', iv }, key, tampered)).rejects.toThrow();
      }
    });
  });

  describe('Blind-Index Consistency & Collision Resistance Invariants', () => {
    test('normalization invariant: formatting variations map to identical blind hashes', async () => {
      const salt = crypto.randomBytes(16).toString('hex');

      const phoneSamples = [
        ['(555) 234-5678', '5552345678'],
        ['555-234-5678', '555.234.5678'],
        ['  (555) 234 5678  ', '555-234-5678']
      ];

      for (const [raw1, raw2] of phoneSamples) {
        const norm1 = normalizeVaultValue('phone', raw1);
        const norm2 = normalizeVaultValue('phone', raw2);
        const h1 = await computeBlindHash(salt, norm1, subtle);
        const h2 = await computeBlindHash(salt, norm2, subtle);
        expect(h1).toBe(h2);
      }

      const emailSamples = [
        ['USER@Example.COM', 'user@example.com'],
        ['  Alice.Smith@Domain.Org  ', 'alice.smith@domain.org']
      ];

      for (const [raw1, raw2] of emailSamples) {
        const norm1 = normalizeVaultValue('email', raw1);
        const norm2 = normalizeVaultValue('email', raw2);
        const h1 = await computeBlindHash(salt, norm1, subtle);
        const h2 = await computeBlindHash(salt, norm2, subtle);
        expect(h1).toBe(h2);
      }
    });

    test('collision resistance invariant: distinct values under same salt yield distinct blind hashes', async () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const seenHashes = new Set();

      for (let i = 0; i < 200; i++) {
        const val = 'user_' + i + '@domain.org';
        const norm = normalizeVaultValue('email', val);
        const h = await computeBlindHash(salt, norm, subtle);
        expect(seenHashes.has(h)).toBe(false);
        seenHashes.add(h);
      }
    });
  });

  describe('Merkle Attestation Invariants (zk-compliance)', () => {
    test('Merkle root is deterministic and tamper-sensitive', () => {
      const leaves = Array.from({ length: 16 }, (_, i) =>
        crypto.createHash('sha256').update('event_' + i).digest('hex')
      );

      const tree1 = new MerkleTree(leaves);
      const tree2 = new MerkleTree(leaves);
      expect(tree1.getRoot()).toBe(tree2.getRoot());

      // Mutating any single leaf changes the Merkle root
      const mutatedLeaves = [...leaves];
      mutatedLeaves[7] = crypto.createHash('sha256').update('tampered_event').digest('hex');
      const treeMutated = new MerkleTree(mutatedLeaves);
      expect(treeMutated.getRoot()).not.toBe(tree1.getRoot());
    });
  });
});
