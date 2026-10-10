/**
 * @jest-environment jsdom
 */

const { analyzeImageDimensions, detectHiddenAlphaText, inspectCanvasElement } = require('../src/content/modules/vision-canary.js');

describe('VIGIL Multimodal Vision Canary Engine', () => {
  test('analyzeImageDimensions flags micro-images and extreme aspect ratios', () => {
    expect(analyzeImageDimensions(10, 10).isMicroImage).toBe(true);
    expect(analyzeImageDimensions(1000, 10).isExtremeAspectRatio).toBe(true);
    expect(analyzeImageDimensions(800, 600).isMicroImage).toBe(false);
    expect(analyzeImageDimensions(800, 600).isExtremeAspectRatio).toBe(false);
  });

  test('detectHiddenAlphaText detects non-opaque pixel variance steganography', () => {
    // Standard opaque image
    const opaqueData = { data: new Uint8ClampedArray(256 * 4).fill(255) };
    expect(detectHiddenAlphaText(opaqueData)).toBe(false);

    // Steganographic image with alternating alpha noise
    const stegoArray = new Uint8ClampedArray(256 * 4).fill(255);
    for (let i = 3; i < stegoArray.length; i += 4) {
      stegoArray[i] = (i % 2 === 0) ? 200 : 201;
    }
    const stegoData = { data: stegoArray };
    expect(detectHiddenAlphaText(stegoData)).toBe(true);
  });

  test('inspectCanvasElement flags micro canvas layers safely', async () => {
    const canvas = document.createElement('canvas');
    canvas.width = 10;
    canvas.height = 10;

    const result = await inspectCanvasElement(canvas);
    expect(result.hasVisualInjection).toBe(true);
    expect(result.reason).toContain('Concealed micro-graphic layer');
  });

  test('inspectCanvasElement returns clean verdict for standard canvas', async () => {
    const canvas = document.createElement('canvas');
    canvas.width = 400;
    canvas.height = 300;

    const result = await inspectCanvasElement(canvas);
    expect(result.hasVisualInjection).toBe(false);
  });
});
