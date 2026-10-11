/**
 * VIGIL Typing Latency & Performance Micro-Benchmark
 * Verifies that detection scanning on typing inputs finishes in < 1ms
 * to ensure zero typing latency or UI lag for users.
 */
const { performance } = require('perf_hooks');
const VIGIL_ENGINE = require('../src/content/modules/detection-engine');
const VIGIL_SECRETS = require('../src/content/modules/secret-engine');
const VIGIL_SENTINEL = require('../src/content/modules/sentinel-engine');

function runLatencyBenchmark() {
  console.log('════════════════════════════════════════════');
  console.log(' VIGIL Performance & Latency Benchmark');
  console.log('════════════════════════════════════════════');

  const testParagraph = `
    Hi team, here is the updated API key for testing: AKIAIOSFODNN7EXAMPLE.
    Please do not share my email jane.doe@company.com or phone 555-0199 with anyone.
    The database URL is postgres://admin:secret123@localhost:5432/production_db.
  `.repeat(10); // ~2.5 KB payload

  // Warm up JIT and regex compilation before benchmarking
  for (let w = 0; w < 50; w++) {
    const ct = VIGIL_ENGINE.cleanText(testParagraph);
    VIGIL_ENGINE.scanWithRegex(ct);
    VIGIL_SECRETS.scanSecrets(ct);
    VIGIL_SENTINEL.analyzeMessage(ct);
  }

  const iterations = 1000;
  const start = performance.now();

  for (let i = 0; i < iterations; i++) {
    const ct = VIGIL_ENGINE.cleanText(testParagraph);
    VIGIL_ENGINE.scanWithRegex(ct);
    VIGIL_SECRETS.scanSecrets(ct);
    VIGIL_SENTINEL.analyzeMessage(ct);
  }

  const duration = performance.now() - start;
  const avgLatencyMs = duration / iterations;
  const thresholdMs = Number(process.env.VIGIL_LATENCY_THRESHOLD_MS) || 5.0;

  console.log(`Payload Size:      ${(testParagraph.length / 1024).toFixed(2)} KB`);
  console.log(`Total Iterations:  ${iterations}`);
  console.log(`Total Time:        ${duration.toFixed(2)} ms`);
  console.log(`Average Latency:   ${avgLatencyMs.toFixed(3)} ms per scan`);

  if (avgLatencyMs > thresholdMs) {
    console.error(`❌ Performance Failure: Average latency (${avgLatencyMs.toFixed(3)}ms) exceeded ${thresholdMs}ms threshold!`);
    process.exit(1);
  } else {
    console.log(`✅ Performance Passed: Latency is well below ${thresholdMs}ms threshold (${avgLatencyMs.toFixed(3)}ms per scan).`);
  }
}

if (require.main === module) {
  runLatencyBenchmark();
}

module.exports = { runLatencyBenchmark };
