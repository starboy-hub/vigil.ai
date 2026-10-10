/**
 * VIGIL perceptual image hashing (Blueprint #6 companion: synthetic media
 * provenance). The canonical 64-bit pHash implementation — the Rust daemon
 * (desktop/src/phash.rs) computes the identical algorithm; this JS fallback
 * keeps provenance checks working when the daemon is not connected.
 *
 * Input: 32x32 (or smaller) grayscale pixels as a byte array.
 */
(function (root) {
  'use strict';

  function downsampleTo32(gray, width, height) {
    if (!width || !height || !gray || gray.length < width * height) return null;
    const out = new Float64Array(32 * 32);
    for (let y = 0; y < 32; y++) {
      for (let x = 0; x < 32; x++) {
        out[y * 32 + x] = gray[Math.floor(y * height / 32) * width + Math.floor(x * width / 32)];
      }
    }
    return out;
  }

  function dct1d(input) {
    const n = input.length;
    const out = new Float64Array(n);
    for (let k = 0; k < n; k++) {
      let sum = 0;
      for (let i = 0; i < n; i++) {
        sum += input[i] * Math.cos((Math.PI * (2 * i + 1) * k) / (2 * n));
      }
      out[k] = sum;
    }
    return out;
  }

  /** 64-bit pHash as a 16-char hex string; null on invalid input. */
  function perceptualHash(gray, width, height) {
    const small = downsampleTo32(gray, width, height);
    if (!small) return null;

    const rows = [];
    for (let y = 0; y < 32; y++) rows.push(dct1d(Array.from(small.slice(y * 32, (y + 1) * 32))));
    const freq = new Float64Array(32 * 32);
    for (let x = 0; x < 32; x++) {
      const col = [];
      for (let y = 0; y < 32; y++) col.push(rows[y][x]);
      const colDct = dct1d(col);
      for (let y = 0; y < 32; y++) freq[y * 32 + x] = colDct[y];
    }

    const coeffs = [];
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        if (x === 0 && y === 0) continue;
        coeffs.push(freq[y * 32 + x]);
      }
    }
    const sorted = [...coeffs].sort((a, b) => a - b);
    const median = sorted[31];

    let hash = 0n;
    let bit = 0n;
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        if (x === 0 && y === 0) continue;
        if (freq[y * 32 + x] > median) hash |= (1n << bit);
        bit += 1n;
      }
    }
    return hash.toString(16).padStart(16, '0');
  }

  /** Hamming distance between two 16-char hex hashes. */
  function hammingHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== 16 || b.length !== 16) return 64;
    let dist = 0;
    for (let i = 0; i < 16; i++) {
      let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
      while (x) { dist += x & 1; x >>= 1; }
    }
    return dist;
  }

  const VIGIL_PHASH = { perceptualHash, hammingHex, downsampleTo32 };
  root.VIGIL_PHASH = VIGIL_PHASH;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_PHASH;
})(typeof self !== 'undefined' ? self : globalThis);
