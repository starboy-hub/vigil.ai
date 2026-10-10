/**
 * tests/local-lora.test.js
 * Blueprint #16 — Asynchronous Local LoRA Fine-Tuning
 */

'use strict';

// Mock chrome.idle.queryState (returns 'idle' by default)
global.chrome = {
  idle: {
    queryState: jest.fn((threshold, cb) => cb('idle')),
    onStateChanged: { addListener: jest.fn() }
  },
  storage: { local: {} }
};

// Mock navigator.getBattery (charging by default)
global.navigator = {
  getBattery: jest.fn(() => Promise.resolve({ charging: true, level: 1.0 }))
};

const VIGIL_LORA = require('../src/background/local-lora');
const { LoRAAdapter, RANK, D_IN, N_CLASSES, ALPHA, SCALE } = VIGIL_LORA;

// Helper: produce a deterministic embedding of length D_IN
function makeEmbedding(seed = 1) {
  return Array.from({ length: D_IN }, (_, i) => Math.sin(seed * (i + 1) * 0.1));
}

// Helper: create a fresh adapter with its own storage
function makeAdapter() {
  const store = {};
  const storage = {
    get: (keys) => {
      const result = {};
      (Array.isArray(keys) ? keys : [keys]).forEach(k => { result[k] = store[k]; });
      return Promise.resolve(result);
    },
    set: (obj) => {
      Object.assign(store, obj);
      return Promise.resolve();
    }
  };
  return { adapter: new LoRAAdapter(), storage };
}

// ── Constants ──────────────────────────────────────────────────────────────
describe('Constants', () => {
  test('RANK is 4', () => expect(RANK).toBe(4));
  test('D_IN is 128', () => expect(D_IN).toBe(128));
  test('N_CLASSES is 3', () => expect(N_CLASSES).toBe(3));
  test('ALPHA is 1.0', () => expect(ALPHA).toBe(1.0));
  test('SCALE = ALPHA/RANK = 0.25', () => expect(SCALE).toBeCloseTo(0.25));
});

// ── Forward pass ──────────────────────────────────────────────────────────
describe('applyAdapter', () => {
  test('returns Float32Array of length N_CLASSES', () => {
    const { adapter } = makeAdapter();
    const base = [0.1, 0.5, 0.4];
    const emb  = makeEmbedding(1);
    const out  = adapter.applyAdapter(base, emb);
    expect(out).toBeInstanceOf(Float32Array);
    expect(out.length).toBe(N_CLASSES);
  });

  test('zero B matrix → adapted logits equal base logits', () => {
    const { adapter } = makeAdapter();
    // B starts at all-zeros → B·Ax = 0 → out = base
    const base = [0.2, 0.3, 0.5];
    const emb  = makeEmbedding(2);
    const out  = adapter.applyAdapter(base, emb);
    for (let i = 0; i < N_CLASSES; i++) {
      expect(out[i]).toBeCloseTo(base[i], 5);
    }
  });

  test('after training, adapted logits differ from base logits', () => {
    const { adapter } = makeAdapter();
    const emb  = makeEmbedding(3);
    // Record a sample and train once
    adapter.recordCorrection(emb, 2); // label = block
    adapter.trainEpoch();
    const base = [0.2, 0.3, 0.5];
    const out  = adapter.applyAdapter(base, emb);
    const anyDiff = Array.from(out).some((v, i) => Math.abs(v - base[i]) > 1e-8);
    expect(anyDiff).toBe(true);
  });

  test('handles short embedding by slicing to D_IN', () => {
    const { adapter } = makeAdapter();
    // Embedding shorter than D_IN should be padded with zeros by Float32Array
    const shortEmb = Array.from({ length: 64 }, (_, i) => 0.01 * i);
    const base = [0.1, 0.2, 0.7];
    const out  = adapter.applyAdapter(base, shortEmb);
    expect(out.length).toBe(N_CLASSES);
  });
});

// ── recordCorrection ──────────────────────────────────────────────────────
describe('recordCorrection', () => {
  test('returns true and buffers sample', () => {
    const { adapter } = makeAdapter();
    const ok = adapter.recordCorrection(makeEmbedding(1), 0);
    expect(ok).toBe(true);
    expect(adapter._samples.length).toBe(1);
  });

  test('returns false for invalid embedding', () => {
    const { adapter } = makeAdapter();
    expect(adapter.recordCorrection('not-array', 0)).toBe(false);
    expect(adapter.recordCorrection([], 0)).toBe(false);
    expect(adapter._samples.length).toBe(0);
  });

  test('ring-buffer caps at MAX_SAMPLES (512)', () => {
    const { adapter } = makeAdapter();
    for (let i = 0; i < 520; i++) {
      adapter.recordCorrection(makeEmbedding(i), i % 3);
    }
    expect(adapter._samples.length).toBe(512);
  });
});

// ── trainEpoch ────────────────────────────────────────────────────────────
describe('trainEpoch', () => {
  test('returns { loss: 0, steps: 0 } with no samples', () => {
    const { adapter } = makeAdapter();
    const result = adapter.trainEpoch();
    expect(result.loss).toBe(0);
    expect(result.steps).toBe(0);
  });

  test('returns positive loss when samples are present', () => {
    const { adapter } = makeAdapter();
    adapter.recordCorrection(makeEmbedding(1), 1);
    adapter.recordCorrection(makeEmbedding(2), 0);
    const { loss, steps } = adapter.trainEpoch();
    expect(loss).toBeGreaterThan(0);
    expect(steps).toBeGreaterThanOrEqual(1);
  });

  test('updates currentLoss and epochsTrained', () => {
    const { adapter } = makeAdapter();
    adapter.recordCorrection(makeEmbedding(5), 2);
    adapter.trainEpoch();
    expect(adapter.currentLoss).not.toBeNull();
    expect(adapter.epochsTrained).toBe(1);
  });

  test('loss decreases after multiple epochs (SGD convergence)', () => {
    const { adapter } = makeAdapter();
    // 32 samples all with label=2 (block)
    for (let i = 0; i < 32; i++) {
      adapter.recordCorrection(makeEmbedding(i), 2);
    }
    const first = adapter.trainEpoch().loss;
    let last = first;
    for (let e = 0; e < 20; e++) last = adapter.trainEpoch().loss;
    expect(last).toBeLessThan(first);
  });
});

// ── canTrain (gating) ─────────────────────────────────────────────────────
describe('canTrain', () => {
  test('returns true when idle and charging', async () => {
    chrome.idle.queryState.mockImplementationOnce((t, cb) => cb('idle'));
    global.navigator.getBattery = jest.fn(() => Promise.resolve({ charging: true, level: 0.5 }));
    const { adapter } = makeAdapter();
    await expect(adapter.canTrain()).resolves.toBe(true);
  });

  test('returns false when NOT idle', async () => {
    chrome.idle.queryState.mockImplementationOnce((t, cb) => cb('active'));
    const { adapter } = makeAdapter();
    await expect(adapter.canTrain()).resolves.toBe(false);
  });

  test('returns false when idle but battery not charging and below 80%', async () => {
    chrome.idle.queryState.mockImplementationOnce((t, cb) => cb('idle'));
    global.navigator.getBattery = jest.fn(() => Promise.resolve({ charging: false, level: 0.5 }));
    const { adapter } = makeAdapter();
    await expect(adapter.canTrain()).resolves.toBe(false);
  });

  test('returns true when idle and battery level >= 0.8 even if not charging', async () => {
    chrome.idle.queryState.mockImplementationOnce((t, cb) => cb('idle'));
    global.navigator.getBattery = jest.fn(() => Promise.resolve({ charging: false, level: 0.9 }));
    const { adapter } = makeAdapter();
    await expect(adapter.canTrain()).resolves.toBe(true);
  });
});

// ── saveAdapter / loadAdapter ─────────────────────────────────────────────
describe('Persistence', () => {
  test('saveAdapter persists weights to storage key', async () => {
    const { adapter, storage } = makeAdapter();
    adapter.recordCorrection(makeEmbedding(1), 0);
    adapter.trainEpoch();
    await adapter.saveAdapter(storage);

    const stored = await storage.get(['vigil_lora_adapter']);
    expect(stored['vigil_lora_adapter']).toBeDefined();
    expect(stored['vigil_lora_adapter'].A.length).toBe(RANK * D_IN);
    expect(stored['vigil_lora_adapter'].B.length).toBe(N_CLASSES * RANK);
  });

  test('loadAdapter restores weights from storage', async () => {
    const { adapter: a1, storage } = makeAdapter();
    a1.recordCorrection(makeEmbedding(7), 1);
    a1.trainEpoch();
    await a1.saveAdapter(storage);

    const a2 = new LoRAAdapter();
    const ok = await a2.loadAdapter(storage);
    expect(ok).toBe(true);
    // Weight arrays should match
    expect(Array.from(a2.A)).toEqual(Array.from(a1.A));
    expect(Array.from(a2.B)).toEqual(Array.from(a1.B));
    expect(a2._samples.length).toBe(a1._samples.length);
    expect(a2.currentLoss).toBeCloseTo(a1.currentLoss, 6);
  });

  test('loadAdapter returns false when storage is empty', async () => {
    const { adapter, storage } = makeAdapter();
    const ok = await adapter.loadAdapter(storage);
    expect(ok).toBe(false);
  });

  test('forward pass is identical after save/load roundtrip', async () => {
    const { adapter: a1, storage } = makeAdapter();
    a1.recordCorrection(makeEmbedding(3), 2);
    a1.trainEpoch();
    await a1.saveAdapter(storage);

    const a2 = new LoRAAdapter();
    await a2.loadAdapter(storage);

    const emb  = makeEmbedding(9);
    const base = [0.3, 0.3, 0.4];
    const out1 = a1.applyAdapter(base, emb);
    const out2 = a2.applyAdapter(base, emb);
    for (let i = 0; i < N_CLASSES; i++) {
      expect(out2[i]).toBeCloseTo(out1[i], 5);
    }
  });
});

// ── getStatus ─────────────────────────────────────────────────────────────
describe('getStatus', () => {
  test('returns correct shape with defaults', () => {
    const { adapter } = makeAdapter();
    const s = adapter.getStatus();
    expect(s.rank).toBe(RANK);
    expect(s.alpha).toBe(ALPHA);
    expect(s.scale).toBeCloseTo(SCALE);
    expect(s.sampleCount).toBe(0);
    expect(s.currentLoss).toBeNull();
    expect(s.epochsTrained).toBe(0);
    expect(s.lastTrainedAt).toBeNull();
  });

  test('reflects updates after training', () => {
    const { adapter } = makeAdapter();
    adapter.recordCorrection(makeEmbedding(1), 0);
    adapter.trainEpoch();
    const s = adapter.getStatus();
    expect(s.sampleCount).toBe(1);
    expect(s.epochsTrained).toBe(1);
    expect(s.currentLoss).toBeGreaterThan(0);
    expect(s.lastTrainedAt).not.toBeNull();
  });
});

// ── Module export ─────────────────────────────────────────────────────────
describe('Module exports', () => {
  test('exports loraAdapter singleton', () => {
    expect(VIGIL_LORA.loraAdapter).toBeInstanceOf(LoRAAdapter);
  });

  test('singleton and new instance are independent', () => {
    const fresh = new LoRAAdapter();
    fresh.recordCorrection(makeEmbedding(1), 0);
    expect(VIGIL_LORA.loraAdapter._samples.length).toBe(0);
  });
});
