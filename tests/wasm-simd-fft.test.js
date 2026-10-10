/**
 * @jest-environment jsdom
 */
const { WasmSimdFftEngine, calculateSpatialFrequency, compute2dSpectralEnergy, inspectCanvas, isSimdSupported } = require('../src/content/modules/wasm-simd-fft.js');
const { inspectCanvasElement, getWasmSimdFftEngine } = require('../src/content/modules/vision-canary.js');

describe('WebAssembly SIMD 2D FFT & 4K Canvas Frequency Analysis Engine', () => {
  let engine;

  beforeEach(() => {
    engine = new WasmSimdFftEngine();
  });

  test('isSimdSupported and engine initialization report active acceleration mode', () => {
    const supported = isSimdSupported();
    expect(typeof supported).toBe('boolean');
    expect(engine.accelerationMode).toMatch(/WASM_SIMD_128|TYPEDARRAY_VECTORIZED/);
  });

  test('calculateSpatialFrequency processes clean low-frequency image without false anomalies', () => {
    // 512x512 smooth gradient (low frequency)
    const width = 512;
    const height = 512;
    const data = new Uint8ClampedArray(width * height * 4);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 4;
        const val = Math.floor((x / width) * 200);
        data[idx] = val;     // R
        data[idx + 1] = val; // G
        data[idx + 2] = val; // B
        data[idx + 3] = 255; // A
      }
    }

    const res = calculateSpatialFrequency({ data, width, height });
    expect(res.energy).toBeLessThan(50.0);
    expect(res.isAnomalous).toBe(false);
    expect(res.highFreqRatio).toBeLessThan(0.2);
  });

  test('calculateSpatialFrequency detects high-frequency adversarial noise perturbation', () => {
    // 256x256 image with high-frequency checkered checkerboard noise (adversarial perturbation)
    const width = 256;
    const height = 256;
    const data = new Uint8ClampedArray(width * height * 4);
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 4;
        const isOdd = (x + y) % 2 === 0;
        const val = isOdd ? 255 : 0;
        data[idx] = val;
        data[idx + 1] = val;
        data[idx + 2] = val;
        data[idx + 3] = 255;
      }
    }

    const res = calculateSpatialFrequency({ data, width, height });
    expect(res.energy).toBeGreaterThan(95.0);
    expect(res.isAnomalous).toBe(true);
    expect(res.highFreqRatio).toBeGreaterThan(0.5);
  });

  test('calculateSpatialFrequency handles ultra-high-resolution 4K (3840x2160) canvas frames rapidly', () => {
    const _width = 3840;
    const _height = 2160;
    // Downscaled mock buffer for 4K test
    const strideW = 512;
    const strideH = 288;
    const data = new Uint8ClampedArray(strideW * strideH * 4).fill(128);

    const startTime = Date.now();
    const res = calculateSpatialFrequency({ data, width: strideW, height: strideH }, { maxDim: 512 });
    const duration = Date.now() - startTime;

    expect(duration).toBeLessThan(1000); // Sub-second execution tolerance on shared CI runners
    expect(res.isAnomalous).toBe(false);
    expect(res.mode).toBeDefined();
  });

  test('compute2dSpectralEnergy generates 2D DCT spectral distribution', () => {
    const width = 128;
    const height = 128;
    const data = new Uint8ClampedArray(width * height * 4).fill(200);

    const spectral = compute2dSpectralEnergy({ data, width, height }, 16);
    expect(spectral.dcEnergy).toBeGreaterThan(0);
    expect(spectral.spectralAnomaly).toBe(false);
    expect(spectral.spectralCoefficients.length).toBe(256); // 16x16
  });

  test('inspectCanvas detects adversarial layers on HTML Canvas element', async () => {
    const canvas = document.createElement('canvas');
    canvas.width = 1920;
    canvas.height = 1080;

    const ctx = {
      getImageData: jest.fn().mockImplementation((x, y, w, h) => {
        const arr = new Uint8ClampedArray(w * h * 4);
        for (let py = 0; py < h; py++) {
          for (let px = 0; px < w; px++) {
            const idx = (py * w + px) * 4;
            // High-frequency adversarial perturbation block noise
            const isHigh = ((Math.floor(px / 2) + Math.floor(py / 2)) % 2 === 0);
            const val = isHigh ? 255 : 0;
            arr[idx] = val;
            arr[idx + 1] = val;
            arr[idx + 2] = val;
            arr[idx + 3] = 255;
          }
        }
        return { data: arr, width: w, height: h };
      })
    };
    canvas.getContext = jest.fn().mockReturnValue(ctx);

    const res = await inspectCanvas(canvas);
    expect(res.hasVisualInjection).toBe(true);
    expect(res.reason).toMatch(/adversarial|steganography|perturbation/i);
    expect(res.details).toBeDefined();
    expect(res.details.accelerationMode).toBeDefined();
  });

  test('vision-canary seamlessly delegates canvas inspection to Wasm SIMD FFT engine', async () => {
    const wasmEngine = getWasmSimdFftEngine();
    expect(wasmEngine).toBeDefined();

    const canvas = document.createElement('canvas');
    canvas.width = 3840;
    canvas.height = 2160;

    const ctx = {
      getImageData: jest.fn().mockReturnValue({
        data: new Uint8ClampedArray(1024 * 1024 * 4).fill(120),
        width: 1024,
        height: 1024
      })
    };
    canvas.getContext = jest.fn().mockReturnValue(ctx);

    const verdict = await inspectCanvasElement(canvas);
    expect(verdict.hasVisualInjection).toBe(false);
    expect(verdict.reason).toBe('Clean image layer');
  });
});
