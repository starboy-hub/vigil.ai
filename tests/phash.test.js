/**
 * Tests for the perceptual image hash (Blueprint #6 companion).
 * The JS fallback must match the Rust daemon's semantics: deterministic,
 * perceptually-stable, and distance-measurable.
 */
const VIGIL_PHASH = require('../src/shared/phash.js');
const { perceptualHash, hammingHex } = VIGIL_PHASH;

function gradient() {
  const px = [];
  for (let y = 0; y < 32; y++) {
    for (let x = 0; x < 32; x++) px.push((x * 8 + y * 4) % 256);
  }
  return px;
}

describe('Perceptual image hash (pHash)', () => {
  test('deterministic for identical input', () => {
    const px = gradient();
    expect(perceptualHash(px, 32, 32)).toBe(perceptualHash(px, 32, 32));
  });

  test('produces a 16-char hex hash', () => {
    expect(perceptualHash(gradient(), 32, 32)).toMatch(/^[0-9a-f]{16}$/);
  });

  test('slight brightness shift stays perceptually close', () => {
    const px = gradient();
    const shifted = px.map((v) => Math.min(255, v + 12));
    const d = hammingHex(perceptualHash(px, 32, 32), perceptualHash(shifted, 32, 32));
    expect(d).toBeLessThanOrEqual(12);
  });

  test('flat vs gradient images are far apart', () => {
    const flat = new Array(32 * 32).fill(128);
    const d = hammingHex(perceptualHash(flat, 32, 32), perceptualHash(gradient(), 32, 32));
    expect(d).toBeGreaterThanOrEqual(20);
  });

  test('hammingHex counts differing bits and rejects malformed input', () => {
    expect(hammingHex('0000000000000000', '0000000000000000')).toBe(0);
    expect(hammingHex('0000000000000000', 'ffffffffffffffff')).toBe(64);
    expect(hammingHex('zz', 'ff')).toBe(64);
  });

  test('rejects invalid pixel buffers', () => {
    expect(perceptualHash([], 0, 0)).toBeNull();
    expect(perceptualHash([1, 2, 3], 16, 16)).toBeNull();
  });
});
