/**
 * VIGIL Reality Engine
 * Scans image bytes for provenance metadata that reveals AI generation:
 * C2PA/JUMBF content credentials, IPTC digital-source-type labels,
 * generator software signatures, and diffusion-model parameter blocks.
 *
 * Honest scope: metadata proves AI origin when present; its absence proves
 * nothing (metadata is often stripped). The verdict wording reflects that.
 * Pure module — used by the background worker, tested directly.
 */
(function (root) {
  'use strict';

  const MAX_SCAN_BYTES = 32 * 1024 * 1024;

  const GENERATORS = [
    'Stable Diffusion', 'Midjourney', 'DALL·E', 'DALL-E', 'DALL E 2', 'DALL E 3',
    'Adobe Firefly', 'Firefly', 'Google AI', 'Gemini', 'Imagen', 'Flux.1', 'FLUX.1',
    'NovelAI', 'Bing Image Creator', 'Grok Imagine', 'Ideogram', 'Leonardo AI'
  ];

  const SIGNALS = [
    { id: 'trained_media', label: 'Marked as algorithmically generated media', strong: true, re: /trainedalgorithmicmedia|compositewithtrainedalgorithmicmedia|digitalsourcetype[^a-z]{0,4}trainedalgorithmic/i },
    { id: 'c2pa', label: 'C2PA content credentials (provenance manifest)', strong: true, re: /c2pa|jumbox|urn:uuid:2c25a/i },
    { id: 'generator', label: 'AI generator signature', strong: true, re: /dall[\s·-]?e\b|stable diffusion|midjourney|adobe firefly|\bfirefly\b|google ai|gemini|\bimagen\b|flux\.1|novelai|bing image creator|ideogram|grok imagine|\bai generated\b|made with ai\b|ai-generated/i },
    { id: 'sd_params', label: 'Diffusion-model parameter block', strong: true, re: /parameters[\r\n][\s\S]{0,600}?steps:\s*\d+[\s\S]{0,160}?sampler:/i },
    { id: 'editor', label: 'Image-editor software tag (editing is not AI — informational)', strong: false, re: /\b(?:photoshop|lightroom|gimp) \d/i }
  ];

  function bytesToLatin1(bytes) {
    const len = Math.min(bytes.length, MAX_SCAN_BYTES);
    let s = '';
    const CHUNK = 65536;
    for (let i = 0; i < len; i += CHUNK) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, len)));
    }
    return s;
  }

  function findGenerator(text) {
    const lower = text.toLowerCase();
    for (const g of GENERATORS) {
      if (lower.indexOf(g.toLowerCase()) !== -1) return g;
    }
    return null;
  }

  /**
   * Analyze raw image bytes for AI-provenance metadata.
   * @param {Uint8Array} bytes
   * @returns {{verdict: 'ai-generated'|'no-metadata', generator: string|null,
   *            signals: Array<{id,label,detail}>, disclaimer: string}}
   */
  function analyzeImageBytes(bytes) {
    if (!bytes || bytes.length < 16) {
      return { verdict: 'no-metadata', generator: null, signals: [], disclaimer: DISCLAIMER };
    }
    const text = bytesToLatin1(bytes);
    const signals = [];
    let generator = null;
    let strong = false;
    for (const sig of SIGNALS) {
      const m = text.match(sig.re);
      if (!m) continue;
      if (sig.strong) strong = true;
      signals.push({ id: sig.id, label: sig.label, detail: m[0].slice(0, 80) });
      if (sig.id === 'generator' && !generator) generator = findGenerator(text);
    }
    return {
      verdict: strong ? 'ai-generated' : 'no-metadata',
      generator,
      signals,
      disclaimer: DISCLAIMER
    };
  }

  const DISCLAIMER = 'Metadata proves AI origin when present. Its absence does NOT prove an image is real — metadata is often stripped. Judge the content, not just the file.';

  const VIGIL_REALITY = { analyzeImageBytes, SIGNALS, DISCLAIMER };
  root.VIGIL_REALITY = VIGIL_REALITY;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_REALITY;
})(typeof self !== 'undefined' ? self : globalThis);
