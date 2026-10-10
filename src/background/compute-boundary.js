/**
 * VIGIL Blueprint #4: Dynamic Compute Boundary & Hardware Budgeting
 *
 * Problem: Running heavy WebGPU neural models or Wasm SIMD routines directly
 * in content scripts exposes models and memory to untrusted DOM page scripts,
 * causes UI jank / frame drops on web pages, and can cause out-of-memory crashes
 * or thermal throttling on constrained devices.
 *
 * Solution: Hardware capability probing (GPU, RAM, CPU cores) to dynamically assign
 * a Compute Budget Tier (TIER_HIGH, TIER_MEDIUM, TIER_LOW). Heavy compute tasks
 * (WebGPU sequence classification, Wasm SIMD canvas FFT) are dispatched strictly
 * behind the isolated Offscreen Document compute boundary.
 */
(function (root) {
  'use strict';

  const COMPUTE_TIERS = {
    TIER_HIGH: 'TIER_HIGH',     // WebGPU + full SIMD + concurrent neural models
    TIER_MEDIUM: 'TIER_MEDIUM', // Wasm SIMD + single-threaded quantized model
    TIER_LOW: 'TIER_LOW'        // Heuristics + native daemon offload (conserves memory)
  };

  /**
   * Probes hardware capabilities from the environment
   */
  function probeHardwareCapabilities(customNav = null) {
    const nav = customNav || (typeof navigator !== 'undefined' ? navigator : {});

    const deviceMemory = typeof nav.deviceMemory === 'number' ? nav.deviceMemory : 8; // default 8GB
    const hardwareConcurrency = typeof nav.hardwareConcurrency === 'number' ? nav.hardwareConcurrency : 4;
    const hasWebGPU = !!(nav.gpu && typeof nav.gpu.requestAdapter === 'function');

    // Probe Wasm SIMD
    let hasWasmSimd = false;
    try {
      if (typeof WebAssembly === 'object' && typeof WebAssembly.validate === 'function') {
        const simdBytes = new Uint8Array([
          0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
          0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b,
          0x03, 0x02, 0x01, 0x00,
          0x0a, 0x16, 0x01, 0x14, 0x00,
          0xfd, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x0b
        ]);
        hasWasmSimd = WebAssembly.validate(simdBytes);
      }
    } catch {
      hasWasmSimd = false;
    }

    return {
      deviceMemory,
      hardwareConcurrency,
      hasWebGPU,
      hasWasmSimd
    };
  }

  /**
   * Determines the optimal Compute Budget Tier based on probed capabilities
   */
  function determineComputeTier(capabilities) {
    const { deviceMemory, hardwareConcurrency, hasWebGPU, hasWasmSimd } = capabilities;

    // Constrained devices (<4GB RAM or <=2 cores)
    if (deviceMemory < 4 || hardwareConcurrency <= 2) {
      return COMPUTE_TIERS.TIER_LOW;
    }

    // High performance devices (>=8GB RAM, >=6 cores, and WebGPU or SIMD)
    if (deviceMemory >= 8 && hardwareConcurrency >= 6 && (hasWebGPU || hasWasmSimd)) {
      return COMPUTE_TIERS.TIER_HIGH;
    }

    // Standard baseline
    return COMPUTE_TIERS.TIER_MEDIUM;
  }

  class ComputeBoundaryManager {
    constructor(options = {}) {
      this.capabilities = options.capabilities || probeHardwareCapabilities(options.navigator);
      this.tier = options.tier || determineComputeTier(this.capabilities);
      this.maxConcurrentTasks = this.tier === COMPUTE_TIERS.TIER_HIGH ? 4 : (this.tier === COMPUTE_TIERS.TIER_MEDIUM ? 2 : 1);
      this.activeTasks = 0;
      this.taskQueue = [];
      this.stats = {
        totalDispatched: 0,
        offscreenTasks: 0,
        nativeOffloadTasks: 0,
        heurisicFallbackTasks: 0
      };
    }

    /**
     * Re-probes hardware environment and adjusts budget tier
     */
    refreshCapabilities(customNav = null) {
      this.capabilities = probeHardwareCapabilities(customNav);
      this.tier = determineComputeTier(this.capabilities);
      this.maxConcurrentTasks = this.tier === COMPUTE_TIERS.TIER_HIGH ? 4 : (this.tier === COMPUTE_TIERS.TIER_MEDIUM ? 2 : 1);
      return this.getStatus();
    }

    /**
     * Determines the optimal execution venue for a given task type
     */
    resolveExecutionVenue(taskType, prefersOffscreen = true) {
      // In TIER_LOW, prefer native daemon offload or heuristic to avoid browser OOM
      if (this.tier === COMPUTE_TIERS.TIER_LOW) {
        if (taskType === 'neural_inference') return 'native_daemon';
        return 'heuristic';
      }

      // In TIER_MEDIUM or TIER_HIGH, run heavy compute in isolated Offscreen Document
      if (prefersOffscreen) {
        return 'offscreen_document';
      }

      return 'in_process';
    }

    /**
     * Dispatches a compute task with concurrency and boundary control
     */
    async dispatchTask(taskType, payload, executors = {}) {
      const venue = this.resolveExecutionVenue(taskType);
      this.stats.totalDispatched++;

      if (this.activeTasks >= this.maxConcurrentTasks) {
        // Enforce concurrency limit by queuing
        await new Promise((resolve) => this.taskQueue.push(resolve));
      }

      this.activeTasks++;
      try {
        if (venue === 'offscreen_document' && executors.offscreen) {
          this.stats.offscreenTasks++;
          return await executors.offscreen(payload);
        } else if (venue === 'native_daemon' && executors.native) {
          this.stats.nativeOffloadTasks++;
          return await executors.native(payload);
        } else if (executors.fallback) {
          this.stats.heurisicFallbackTasks++;
          return await executors.fallback(payload);
        } else {
          throw new Error(`No available executor for venue: ${venue}`);
        }
      } finally {
        this.activeTasks--;
        if (this.taskQueue.length > 0) {
          const next = this.taskQueue.shift();
          next();
        }
      }
    }

    getStatus() {
      return {
        tier: this.tier,
        maxConcurrentTasks: this.maxConcurrentTasks,
        activeTasks: this.activeTasks,
        queuedTasks: this.taskQueue.length,
        capabilities: { ...this.capabilities },
        stats: { ...this.stats }
      };
    }
  }

  const computeBoundaryManager = new ComputeBoundaryManager();

  const ComputeBoundaryModule = {
    COMPUTE_TIERS,
    probeHardwareCapabilities,
    determineComputeTier,
    ComputeBoundaryManager,
    computeBoundaryManager
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ComputeBoundaryModule;
  }
  if (root) {
    root.ComputeBoundaryModule = ComputeBoundaryModule;
    root.computeBoundaryManager = computeBoundaryManager;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
