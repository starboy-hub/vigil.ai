/**
 * VIGIL Multimodal Vision & Image Steganography Canary
 * Inspects images pasted or dragged into multimodal AI interfaces (GPT-4o, Claude 3.5, Gemini)
 * for visual prompt injections, hidden text layers, and adversarial perturbations.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(root);
  } else {
    root.VIGIL_VISION_CANARY = factory(root);
  }
}(typeof self !== 'undefined' ? self : this, function (_root) {
  'use strict';

  function analyzeImageDimensions(width, height) {
    const isExtremeAspectRatio = (width / height > 15) || (height / width > 15);
    const isMicroImage = width > 0 && height > 0 && (width < 32 || height < 32);
    return { isExtremeAspectRatio, isMicroImage };
  }

  function detectHiddenAlphaText(imageData) {
    if (!imageData || !imageData.data) return false;
    const data = imageData.data;
    let nonOpaquePixels = 0;
    let highAlphaVariance = 0;

    for (let i = 3; i < data.length; i += 16) {
      const alpha = data[i];
      if (alpha < 250 && alpha > 5) {
        nonOpaquePixels++;
      }
      if (alpha % 2 !== 0) {
        highAlphaVariance++;
      }
    }

    const totalSamples = data.length / 16;
    const alphaRatio = nonOpaquePixels / totalSamples;
    const stegoRatio = highAlphaVariance / totalSamples;

    return alphaRatio > 0.15 && stegoRatio > 0.4;
  }

  function calculateSpatialFrequencyEnergy(imageData) {
    if (!imageData || !imageData.data || imageData.width < 16 || imageData.height < 16) return { energy: 0, isAnomalous: false };
    const { data, width, height } = imageData;
    const w = Math.min(width, 128);
    const h = Math.min(height, 128);
    let laplacianSum = 0;
    let sampleCount = 0;

    // Compute discrete 2D spatial Laplacian variance on luminance
    for (let y = 1; y < h - 1; y += 2) {
      for (let x = 1; x < w - 1; x += 2) {
        const idx = (y * width + x) * 4;
        const lum = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2];
        
        const idxUp = ((y - 1) * width + x) * 4;
        const idxDown = ((y + 1) * width + x) * 4;
        const idxLeft = (y * width + (x - 1)) * 4;
        const idxRight = (y * width + (x + 1)) * 4;

        const lumUp = 0.299 * data[idxUp] + 0.587 * data[idxUp + 1] + 0.114 * data[idxUp + 2];
        const lumDown = 0.299 * data[idxDown] + 0.587 * data[idxDown + 1] + 0.114 * data[idxDown + 2];
        const lumLeft = 0.299 * data[idxLeft] + 0.587 * data[idxLeft + 1] + 0.114 * data[idxLeft + 2];
        const lumRight = 0.299 * data[idxRight] + 0.587 * data[idxRight + 1] + 0.114 * data[idxRight + 2];

        const laplacian = Math.abs(4 * lum - lumUp - lumDown - lumLeft - lumRight);
        laplacianSum += laplacian;
        sampleCount++;
      }
    }

    const meanLaplacian = sampleCount > 0 ? (laplacianSum / sampleCount) : 0;
    const isAnomalous = meanLaplacian > 95.0;
    return { energy: meanLaplacian, isAnomalous };
  }

  function getWasmSimdFftEngine() {
    if (typeof _root !== 'undefined' && (_root.VIGIL_WASM_SIMD_FFT || _root.VIGIL_WASM_SIMD_FFT)) {
      return _root.VIGIL_WASM_SIMD_FFT || _root.VIGIL_WASM_SIMD_FFT;
    }
    if (typeof require === 'function') {
      try {
        return require('./wasm-simd-fft');
      } catch (_e) {}
    }
    return null;
  }

  async function inspectCanvasElement(canvas) {
    if (!canvas) {
      return { hasVisualInjection: false, reason: 'Invalid canvas element' };
    }

    const { isExtremeAspectRatio, isMicroImage } = analyzeImageDimensions(canvas.width || 0, canvas.height || 0);
    if (isExtremeAspectRatio || isMicroImage) {
      return {
        hasVisualInjection: true,
        reason: 'Concealed micro-graphic layer / extreme aspect ratio (possible visual injection)'
      };
    }

    // Utilize WebAssembly SIMD FFT engine if available for 4K / high-resolution canvas frames
    const wasmFft = getWasmSimdFftEngine();
    if (wasmFft && typeof wasmFft.inspectCanvas === 'function') {
      try {
        const res = await wasmFft.inspectCanvas(canvas);
        if (res) return res;
      } catch (_e) {
        // Fallback to baseline inspection on error
      }
    }

    try {
      if (typeof canvas.getContext !== 'function') {
        return { hasVisualInjection: false, reason: 'No 2D context' };
      }
      const ctx = canvas.getContext('2d');
      if (!ctx) return { hasVisualInjection: false, reason: 'No 2D context' };

      const imageData = ctx.getImageData(0, 0, Math.min(canvas.width, 256), Math.min(canvas.height, 256));
      const hasStego = detectHiddenAlphaText(imageData);
      const freq = calculateSpatialFrequencyEnergy(imageData);
      const isHostile = hasStego || freq.isAnomalous;

      return {
        hasVisualInjection: isHostile,
        reason: hasStego ? 'Steganographic alpha-channel perturbation detected' : (freq.isAnomalous ? 'High-frequency adversarial noise perturbation detected' : 'Clean image layer')
      };
    } catch (err) {
      return { hasVisualInjection: false, reason: err.message };
    }
  }

  return {
    analyzeImageDimensions,
    detectHiddenAlphaText,
    calculateSpatialFrequencyEnergy,
    inspectCanvasElement,
    getWasmSimdFftEngine
  };
}));
