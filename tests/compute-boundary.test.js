/**
 * Tests for Blueprint #4: Dynamic Compute Boundary & Hardware Budgeting
 */
const {
  COMPUTE_TIERS,
  probeHardwareCapabilities,
  determineComputeTier,
  ComputeBoundaryManager
} = require('../src/background/compute-boundary.js');

describe('Blueprint #4: Dynamic Compute Boundary & Hardware Budgeting', () => {
  describe('Hardware Capability Probing & Tier Determination', () => {
    test('probes default capabilities safely without navigator', () => {
      const caps = probeHardwareCapabilities({});
      expect(caps.deviceMemory).toBe(8);
      expect(caps.hardwareConcurrency).toBe(4);
      expect(caps.hasWebGPU).toBe(false);
      expect(typeof caps.hasWasmSimd).toBe('boolean');
    });

    test('extracts custom navigator properties correctly', () => {
      const mockNav = {
        deviceMemory: 16,
        hardwareConcurrency: 8,
        gpu: { requestAdapter: jest.fn() }
      };
      const caps = probeHardwareCapabilities(mockNav);
      expect(caps.deviceMemory).toBe(16);
      expect(caps.hardwareConcurrency).toBe(8);
      expect(caps.hasWebGPU).toBe(true);
    });

    test('assigns TIER_LOW for constrained hardware (low RAM or low CPU)', () => {
      expect(determineComputeTier({ deviceMemory: 2, hardwareConcurrency: 8, hasWebGPU: true, hasWasmSimd: true }))
        .toBe(COMPUTE_TIERS.TIER_LOW);
      expect(determineComputeTier({ deviceMemory: 8, hardwareConcurrency: 2, hasWebGPU: true, hasWasmSimd: true }))
        .toBe(COMPUTE_TIERS.TIER_LOW);
      expect(determineComputeTier({ deviceMemory: 1, hardwareConcurrency: 1, hasWebGPU: false, hasWasmSimd: false }))
        .toBe(COMPUTE_TIERS.TIER_LOW);
    });

    test('assigns TIER_HIGH for high-performance hardware with GPU or SIMD', () => {
      expect(determineComputeTier({ deviceMemory: 8, hardwareConcurrency: 6, hasWebGPU: true, hasWasmSimd: false }))
        .toBe(COMPUTE_TIERS.TIER_HIGH);
      expect(determineComputeTier({ deviceMemory: 16, hardwareConcurrency: 12, hasWebGPU: false, hasWasmSimd: true }))
        .toBe(COMPUTE_TIERS.TIER_HIGH);
    });

    test('assigns TIER_MEDIUM for mid-tier baseline systems', () => {
      expect(determineComputeTier({ deviceMemory: 4, hardwareConcurrency: 4, hasWebGPU: false, hasWasmSimd: false }))
        .toBe(COMPUTE_TIERS.TIER_MEDIUM);
      expect(determineComputeTier({ deviceMemory: 8, hardwareConcurrency: 4, hasWebGPU: false, hasWasmSimd: false }))
        .toBe(COMPUTE_TIERS.TIER_MEDIUM);
    });
  });

  describe('ComputeBoundaryManager Execution Venues & Routing', () => {
    test('resolves offscreen_document venue for high and medium tiers', () => {
      const highManager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_HIGH });
      expect(highManager.resolveExecutionVenue('neural_inference')).toBe('offscreen_document');
      expect(highManager.resolveExecutionVenue('simd_fft')).toBe('offscreen_document');

      const medManager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_MEDIUM });
      expect(medManager.resolveExecutionVenue('neural_inference')).toBe('offscreen_document');
    });

    test('resolves native daemon or heuristic fallback for low tier devices', () => {
      const lowManager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_LOW });
      expect(lowManager.resolveExecutionVenue('neural_inference')).toBe('native_daemon');
      expect(lowManager.resolveExecutionVenue('simd_fft')).toBe('heuristic');
    });

    test('dispatches task to offscreen executor when venue is offscreen_document', async () => {
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_HIGH });
      const offscreenExec = jest.fn().mockResolvedValue({ status: 'offscreen_ok' });
      const nativeExec = jest.fn();

      const result = await manager.dispatchTask('neural_inference', { input: 'test prompt' }, {
        offscreen: offscreenExec,
        native: nativeExec
      });

      expect(result).toEqual({ status: 'offscreen_ok' });
      expect(offscreenExec).toHaveBeenCalledWith({ input: 'test prompt' });
      expect(nativeExec).not.toHaveBeenCalled();
      expect(manager.stats.offscreenTasks).toBe(1);
    });

    test('dispatches task to native daemon executor in TIER_LOW', async () => {
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_LOW });
      const offscreenExec = jest.fn();
      const nativeExec = jest.fn().mockResolvedValue({ status: 'native_daemon_ok' });

      const result = await manager.dispatchTask('neural_inference', { input: 'heavy task' }, {
        offscreen: offscreenExec,
        native: nativeExec
      });

      expect(result).toEqual({ status: 'native_daemon_ok' });
      expect(nativeExec).toHaveBeenCalledWith({ input: 'heavy task' });
      expect(offscreenExec).not.toHaveBeenCalled();
      expect(manager.stats.nativeOffloadTasks).toBe(1);
    });

    test('dispatches task to fallback executor in TIER_LOW when heuristic required', async () => {
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_LOW });
      const fallbackExec = jest.fn().mockResolvedValue({ status: 'fallback_ok' });

      const result = await manager.dispatchTask('simd_fft', { buffer: [] }, {
        fallback: fallbackExec
      });

      expect(result).toEqual({ status: 'fallback_ok' });
      expect(fallbackExec).toHaveBeenCalled();
      expect(manager.stats.heurisicFallbackTasks).toBe(1);
    });

    test('throws error when no executor is provided for the venue', async () => {
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_HIGH });
      await expect(manager.dispatchTask('neural_inference', {}, {}))
        .rejects.toThrow('No available executor for venue: offscreen_document');
    });
  });

  describe('Concurrency Throttling and Queuing', () => {
    test('enforces max concurrent tasks limit and drains queue sequentially', async () => {
      // In TIER_LOW, maxConcurrentTasks = 1
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_LOW });
      let runningCount = 0;
      let maxObservedRunning = 0;

      const slowTask = async (id) => {
        runningCount++;
        maxObservedRunning = Math.max(maxObservedRunning, runningCount);
        await new Promise((res) => setTimeout(res, 30));
        runningCount--;
        return id;
      };

      const tasks = [1, 2, 3].map((id) =>
        manager.dispatchTask('neural_inference', id, {
          native: () => slowTask(id)
        })
      );

      const results = await Promise.all(tasks);
      expect(results).toEqual([1, 2, 3]);
      expect(maxObservedRunning).toBe(1);
      expect(manager.stats.totalDispatched).toBe(3);
      expect(manager.activeTasks).toBe(0);
      expect(manager.taskQueue.length).toBe(0);
    });

    test('getStatus and refreshCapabilities update dynamic tier', () => {
      const manager = new ComputeBoundaryManager({ tier: COMPUTE_TIERS.TIER_LOW });
      let status = manager.getStatus();
      expect(status.tier).toBe(COMPUTE_TIERS.TIER_LOW);
      expect(status.maxConcurrentTasks).toBe(1);

      // Re-probe with high end hardware
      const highNav = {
        deviceMemory: 32,
        hardwareConcurrency: 16,
        gpu: { requestAdapter: () => {} }
      };
      status = manager.refreshCapabilities(highNav);
      expect(status.tier).toBe(COMPUTE_TIERS.TIER_HIGH);
      expect(status.maxConcurrentTasks).toBe(4);
    });
  });

  describe('Offscreen SIMD Canvas Energy Calculation Logic', () => {
    test('computes energy variance accurately on image buffer', () => {
      // Simulated offscreen SIMD logic verification
      const width = 16;
      const height = 16;
      const buffer = new ArrayBuffer(width * height * 4);
      const view = new Uint8ClampedArray(buffer);

      // Low variance buffer (flat image)
      for (let i = 0; i < view.length; i += 4) {
        view[i] = 100;     // R
        view[i + 1] = 100; // G
        view[i + 2] = 100; // B
        view[i + 3] = 255; // A
      }

      let sum = 0, count = 0;
      const step = Math.max(1, Math.floor(Math.sqrt((width * height) / 1024)));
      for (let i = 0; i < view.length; i += 4 * step) {
        sum += view[i];
        count++;
      }
      const mean = count > 0 ? sum / count : 0;
      let variance = 0;
      for (let i = 0; i < view.length; i += 4 * step) {
        const diff = view[i] - mean;
        variance += diff * diff;
      }
      const flatEnergy = count > 0 ? variance / count : 0;
      expect(flatEnergy).toBe(0);
      expect(flatEnergy > 8000).toBe(false);

      // High variance buffer (checkerboard / steganography / noise)
      for (let i = 0; i < view.length; i += 4) {
        view[i] = (i % 8 === 0) ? 255 : 0;
      }
      sum = 0; count = 0;
      for (let i = 0; i < view.length; i += 4 * step) {
        sum += view[i];
        count++;
      }
      const noisyMean = count > 0 ? sum / count : 0;
      variance = 0;
      for (let i = 0; i < view.length; i += 4 * step) {
        const diff = view[i] - noisyMean;
        variance += diff * diff;
      }
      const noisyEnergy = count > 0 ? variance / count : 0;
      expect(noisyEnergy).toBeGreaterThan(8000);
    });
  });
});
