/**
 * VIGIL Detection Engine Fuzzing & ReDoS Safety Test Suite
 * Generates 1,000 randomized, malformed, and unicode-stuffed payloads
 * to verify that detection engines fail gracefully without unhandled exceptions
 * or catastrophic regex backtracking (ReDoS).
 */
const { performance } = require('perf_hooks');
const VIGIL_ENGINE = require('../src/content/modules/detection-engine');
const VIGIL_SECRETS = require('../src/content/modules/secret-engine');
const VIGIL_SENTINEL = require('../src/content/modules/sentinel-engine');
const VIGIL_INJECTION = require('../src/content/modules/injection-engine');

describe('VIGIL Detection Engine Fuzzing & ReDoS Safety', () => {

  function generateFuzzPayload(index) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:\'",.<>/?\\\n\t\r\u200B\u200C\u200D\uFEFF';
    const noiseLength = (index % 200) + 10;
    let noise = '';
    for (let i = 0; i < noiseLength; i++) {
      noise += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // Mix in malformed PII variations
    const malformedVariants = [
      '555- 12 3-4567',
      'john.doe[at]example.com',
      'AKIA' + 'A'.repeat(index % 30),
      'sk-live-' + '123'.repeat(index % 10),
      'https://' + 'a'.repeat(index % 50) + '.com',
      'Ignore ' + 'previous '.repeat(index % 15) + 'instructions'
    ];

    return noise + ' ' + malformedVariants[index % malformedVariants.length] + ' ' + noise;
  }

  test('executes 1,000 randomized fuzz passes without throwing exceptions or catastrophic backtracking', () => {
    // Warm up JIT
    VIGIL_ENGINE.scanWithRegex(VIGIL_ENGINE.cleanText(generateFuzzPayload(0)));

    const totalFuzzPasses = 1000;
    let maxExecutionMs = 0;

    for (let i = 0; i < totalFuzzPasses; i++) {
      const payload = generateFuzzPayload(i);
      const start = performance.now();

      expect(() => {
        const ct = VIGIL_ENGINE.cleanText(payload);
        VIGIL_ENGINE.scanWithRegex(ct);
        VIGIL_SECRETS.scanSecrets(ct);
        VIGIL_SENTINEL.analyzeMessage(ct);
        VIGIL_INJECTION.analyzeInjection(ct);
      }).not.toThrow();

      const duration = performance.now() - start;
      if (duration > maxExecutionMs) {
        maxExecutionMs = duration;
      }
    }

    // Assert that no single fuzz pass triggers ReDoS backtracking (>1500ms on CI runners)
    expect(maxExecutionMs).toBeLessThan(1500.0);
  });

  test('handles massive nested repetition without catastrophic backtracking', () => {
    const nestedReDoSInput = 'a'.repeat(5000) + '!' + '1'.repeat(5000);
    const start = performance.now();

    expect(() => {
      const ct = VIGIL_ENGINE.cleanText(nestedReDoSInput);
      VIGIL_ENGINE.scanWithRegex(ct);
      VIGIL_SECRETS.scanSecrets(ct);
    }).not.toThrow();

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(50.0);
  });
});
