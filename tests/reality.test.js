/**
 * Tests for the VIGIL Reality engine — image provenance byte forensics
 */
const { analyzeImageBytes } = require('../src/background/reality-engine.js');

const PNG_SIG = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const enc = s => Array.from(s).map(c => c.charCodeAt(0) & 0xFF);
const img = (...parts) => Uint8Array.from([...PNG_SIG, ...parts.flatMap(p => (typeof p === 'string' ? enc(p) : p))]);

describe('VIGIL Reality engine', () => {
  test('C2PA manifest + trainedAlgorithmicMedia -> ai-generated', () => {
    const r = analyzeImageBytes(img('....jumbox c2pa urn:uuid:c2pa DigitalSourceType trainedAlgorithmicMedia....'));
    expect(r.verdict).toBe('ai-generated');
    expect(r.signals.some(s => s.id === 'c2pa')).toBe(true);
    expect(r.signals.some(s => s.id === 'trained_media')).toBe(true);
  });

  test('Stable Diffusion parameter block -> ai-generated', () => {
    const r = analyzeImageBytes(img('parameters\nSteps: 30, Sampler: Euler a, CFG scale: 7, Size: 512x512'));
    expect(r.verdict).toBe('ai-generated');
    expect(r.signals.some(s => s.id === 'sd_params')).toBe(true);
  });

  test('generator signature is extracted by name', () => {
    const r = analyzeImageBytes(img('Software: Stable Diffusion XL 1.0'));
    expect(r.verdict).toBe('ai-generated');
    expect(r.generator).toBe('Stable Diffusion');
  });

  test('"Made with AI" IPTC label -> ai-generated', () => {
    const r = analyzeImageBytes(img('XMP: Made with AI digital_source_type'));
    expect(r.verdict).toBe('ai-generated');
  });

  test('clean photo bytes -> no-metadata, honest disclaimer', () => {
    const r = analyzeImageBytes(img([0xFF, 0xD8, 0xFF, 0xE0], 'JFIF a lovely landscape photo taken on holiday', [0xFF, 0xD9]));
    expect(r.verdict).toBe('no-metadata');
    expect(r.generator).toBeNull();
    expect(r.disclaimer).toContain('does NOT prove');
  });

  test('weak editor tag alone stays no-metadata (editing is not AI)', () => {
    const r = analyzeImageBytes(img('Adobe Photoshop 25.1 Windows'));
    expect(r.verdict).toBe('no-metadata');
    expect(r.signals.some(s => s.id === 'editor')).toBe(true);
  });

  test('empty/short input -> no-metadata without crash', () => {
    expect(analyzeImageBytes(new Uint8Array(0)).verdict).toBe('no-metadata');
    expect(analyzeImageBytes(null).verdict).toBe('no-metadata');
  });
});
