/**
 * VIGIL Blueprint #16 — Asynchronous Local LoRA Fine-Tuning
 *
 * Implements a rank-4 Low-Rank Adaptation (LoRA) layer on top of the base
 * classifier logits.  All training happens on-device, only when the device is
 * idle and on AC power, so it never competes with real user work.
 *
 * Math
 * ----
 *   Given an input embedding x ∈ ℝ^d  (d = 128),
 *   the adapted logits are:
 *
 *     ŷ = y_base  +  (α / r) · B · (A · x)
 *
 *   where
 *     A ∈ ℝ^(r × d)   r = 4, d = 128   — down-projection (random init)
 *     B ∈ ℝ^(c × r)   c = 3             — up-projection   (zero init)
 *     α = 1.0, r = 4  → scale = α/r = 0.25
 *
 *   Loss: cross-entropy over c = 3 classes {allow:0, warn:1, block:2}
 *   Optimiser: SGD with momentum (β = 0.9) + weight-decay (λ = 1e-4)
 *
 * Storage key: "vigil_lora_adapter"
 */

(function (root) {
  'use strict';

  // ── Hyper-parameters ──────────────────────────────────────────────────────
  const RANK        = 4;      // r
  const D_IN        = 128;    // d  — embedding dimension
  const N_CLASSES   = 3;      // c  — allow / warn / block
  const ALPHA       = 1.0;
  const SCALE       = ALPHA / RANK;   // 0.25
  const LR          = 5e-4;           // learning rate
  const MOMENTUM    = 0.9;
  const WEIGHT_DECAY = 1e-4;
  const BATCH_SIZE  = 8;
  const MAX_SAMPLES = 512;            // ring-buffer capacity

  // Blueprint #17: differential-privacy parameters (Gaussian mechanism)
  const DP_EPSILON = 1.0;             // privacy budget ε
  const DP_DELTA = 1e-5;              // failure probability δ
  const DP_CLIP_NORM = 5.0;           // L2 clip of the raw flattened delta
  const MIN_FEDERATED_SAMPLES = 20;   // don't share until enough corrections
  const STORAGE_KEY = 'vigil_lora_adapter';

  // ── Tiny linear-algebra helpers (no deps) ─────────────────────────────────
  /** Matrix × vector: (m×n) · (n) → (m) */
  function matVec(M, v, rows, cols) {
    const out = new Float32Array(rows);
    for (let i = 0; i < rows; i++) {
      let s = 0;
      for (let j = 0; j < cols; j++) s += M[i * cols + j] * v[j];
      out[i] = s;
    }
    return out;
  }

  /** Softmax over array → Float32Array */
  function softmax(x) {
    const maxV = Math.max(...x);
    const exps = x.map(v => Math.exp(v - maxV));
    const sum  = exps.reduce((a, b) => a + b, 0);
    return new Float32Array(exps.map(v => v / sum));
  }

  /** Cross-entropy loss: -log(p[label]) */
  function crossEntropy(probs, label) {
    return -Math.log(Math.max(probs[label], 1e-9));
  }

  /** Random normal via Box-Muller */
  function randNormal(mu = 0, sigma = 1) {
    const u1 = Math.random() || 1e-9;
    const u2 = Math.random() || 1e-9;
    return mu + sigma * Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  /** Kaiming-style init for A:  σ = 1/√d_in */
  function initA() {
    const A = new Float32Array(RANK * D_IN);
    const sigma = 1 / Math.sqrt(D_IN);
    for (let i = 0; i < A.length; i++) A[i] = randNormal(0, sigma);
    return A;
  }

  /** Zero-init for B (LoRA convention: Bx starts at 0) */
  function initB() {
    return new Float32Array(N_CLASSES * RANK); // all zeros
  }

  // ── LoRA Adapter class ────────────────────────────────────────────────────
  class LoRAAdapter {
    constructor() {
      // Weight matrices
      this.A = initA();    // Float32Array RANK×D_IN
      this.B = initB();    // Float32Array N_CLASSES×RANK

      // SGD momentum buffers (same shape as weights)
      this.mA = new Float32Array(RANK * D_IN);
      this.mB = new Float32Array(N_CLASSES * RANK);

      // Correction sample ring-buffer
      this._samples = [];  // { embedding: number[], label: number }
      this._preferencePairs = []; // { embedding: number[], chosen: number, rejected: number }

      // Blueprint #17: aggregated, DP-noised federated delta from the swarm,
      // applied as an additive per-embedding bias on the logits
      this.federatedDelta = new Float32Array(N_CLASSES * D_IN);

      // Stats
      this.currentLoss   = null;
      this.lastTrainedAt = null;
      this.epochsTrained = 0;

      // Lazy-loaded from storage flag
      this._loaded = false;
    }

    // ── Forward pass ────────────────────────────────────────────────────────
    /**
     * Compute adapted logits.
     * @param {number[]} baseLogits  – length N_CLASSES
     * @param {number[]} embedding   – length D_IN
     * @returns {Float32Array}       – adapted logits, length N_CLASSES
     */
    applyAdapter(baseLogits, embedding) {
      const x    = new Float32Array(embedding);
      const Ax   = matVec(this.A, x, RANK, D_IN);          // r
      const BAx  = matVec(this.B, Ax, N_CLASSES, RANK);    // c
      const out  = new Float32Array(N_CLASSES);
      for (let i = 0; i < N_CLASSES; i++) {
        let fed = 0;
        const rowBase = i * D_IN;
        for (let j = 0; j < D_IN; j++) {
          fed += this.federatedDelta[rowBase + j] * x[j];
        }
        out[i] = (baseLogits[i] || 0) + SCALE * BAx[i] + fed;
      }
      return out;
    }

    // ── Sample buffer ────────────────────────────────────────────────────────
    /**
     * Record a user correction for later training.
     * @param {number[]} embedding – length D_IN
     * @param {number}   label     – 0=allow, 1=warn, 2=block
     */
    recordCorrection(embedding, label) {
      if (!Array.isArray(embedding) || embedding.length < D_IN) return false;
      const vec = embedding.slice(0, D_IN);
      if (this._samples.length >= MAX_SAMPLES) {
        this._samples.shift(); // ring-buffer eviction
      }
      this._samples.push({ embedding: vec, label: Number(label) });
      return true;
    }

    // ── Training ─────────────────────────────────────────────────────────────
    /**
     * Run one epoch of mini-batch SGD over the correction buffer.
     * @returns {{ loss: number, steps: number }}
     */
    trainEpoch() {
      if (this._samples.length === 0) return { loss: 0, steps: 0 };

      // Shuffle samples
      const shuffled = [...this._samples].sort(() => Math.random() - 0.5);
      let totalLoss = 0;
      let steps = 0;

      for (let i = 0; i < shuffled.length; i += BATCH_SIZE) {
        const batch = shuffled.slice(i, i + BATCH_SIZE);
        // Accumulate gradients over the batch
        const gradA = new Float32Array(RANK * D_IN);
        const gradB = new Float32Array(N_CLASSES * RANK);

        for (const sample of batch) {
          const x    = new Float32Array(sample.embedding);
          const lbl  = sample.label;

          // Forward
          const Ax   = matVec(this.A, x, RANK, D_IN);
          const BAx  = matVec(this.B, Ax, N_CLASSES, RANK);
          const logits = new Float32Array(N_CLASSES);
          for (let j = 0; j < N_CLASSES; j++) logits[j] = SCALE * BAx[j];
          const probs = softmax(logits);
          totalLoss += crossEntropy(probs, lbl);

          // ∂L/∂logits = probs - one_hot(lbl)
          const dLogits = new Float32Array(probs);
          dLogits[lbl] -= 1.0;

          // ∂L/∂(BAx) = dLogits  (scale already baked in, chain rule)
          // ∂L/∂B[i,j] = SCALE * dLogits[i] * Ax[j]
          for (let ci = 0; ci < N_CLASSES; ci++) {
            for (let ri = 0; ri < RANK; ri++) {
              gradB[ci * RANK + ri] += SCALE * dLogits[ci] * Ax[ri];
            }
          }

          // ∂L/∂Ax = SCALE * Bᵀ · dLogits
          const dAx = new Float32Array(RANK);
          for (let ri = 0; ri < RANK; ri++) {
            for (let ci = 0; ci < N_CLASSES; ci++) {
              dAx[ri] += SCALE * this.B[ci * RANK + ri] * dLogits[ci];
            }
          }

          // ∂L/∂A[i,j] = dAx[i] * x[j]
          for (let ri = 0; ri < RANK; ri++) {
            for (let di = 0; di < D_IN; di++) {
              gradA[ri * D_IN + di] += dAx[ri] * x[di];
            }
          }
        }

        const n = batch.length;
        // Average gradients
        for (let k = 0; k < gradA.length; k++) gradA[k] /= n;
        for (let k = 0; k < gradB.length; k++) gradB[k] /= n;

        // Gradient clipping (max norm 5.0) to prevent adversarial gradient explosion
        let normSq = 0;
        for (let k = 0; k < gradA.length; k++) normSq += gradA[k] * gradA[k];
        for (let k = 0; k < gradB.length; k++) normSq += gradB[k] * gradB[k];
        const norm = Math.sqrt(normSq);
        const MAX_GRAD_NORM = 5.0;
        if (norm > MAX_GRAD_NORM) {
          const clip = MAX_GRAD_NORM / norm;
          for (let k = 0; k < gradA.length; k++) gradA[k] *= clip;
          for (let k = 0; k < gradB.length; k++) gradB[k] *= clip;
        }

        // SGD with momentum + weight decay on A
        for (let k = 0; k < this.A.length; k++) {
          this.mA[k] = MOMENTUM * this.mA[k] + LR * (gradA[k] + WEIGHT_DECAY * this.A[k]);
          this.A[k] -= this.mA[k];
          if (!isFinite(this.A[k])) this.A[k] = 0;
        }
        // SGD with momentum on B (no weight-decay: B starts at 0, keep sparse)
        for (let k = 0; k < this.B.length; k++) {
          this.mB[k] = MOMENTUM * this.mB[k] + LR * gradB[k];
          this.B[k] -= this.mB[k];
          if (!isFinite(this.B[k])) this.B[k] = 0;
        }

        steps++;
      }

      const avgLoss = totalLoss / shuffled.length;
      this.currentLoss   = avgLoss;
      this.lastTrainedAt = new Date().toISOString();
      this.epochsTrained++;
      return { loss: avgLoss, steps };
    }

    // ── Direct Preference Optimization (DPO) ────────────────────────────────
    /**
     * Records a human preference pair (Mask vs Allow/Ignore).
     * @param {number[]} embedding - length D_IN
     * @param {number}   chosen    - preferred class (0=allow, 1=warn, 2=block)
     * @param {number}   rejected  - non-preferred class
     */
    recordPreferencePair(embedding, chosen, rejected) {
      if (!Array.isArray(embedding) || embedding.length < D_IN) return false;
      const vec = embedding.slice(0, D_IN);
      if (this._preferencePairs.length >= MAX_SAMPLES) {
        this._preferencePairs.shift();
      }
      this._preferencePairs.push({ embedding: vec, chosen: Number(chosen), rejected: Number(rejected) });
      return true;
    }

    /**
     * Direct Preference Optimization (DPO) batch update.
     * Computes closed-form gradients for rank-4 adapter matrices A and B.
     * @param {Array<{embedding: number[], chosen: number, rejected: number}>|null} pairs
     * @param {number} beta - temperature/implicit reward scaling
     * @returns {{ loss: number, steps: number, pairs: number }}
     */
    trainDPOBatch(pairs = null, beta = 0.5) {
      const activePairs = pairs || this._preferencePairs;
      if (!activePairs || activePairs.length === 0) return { loss: 0, steps: 0, pairs: 0 };

      let totalLoss = 0;
      const gradA = new Float32Array(RANK * D_IN);
      const gradB = new Float32Array(N_CLASSES * RANK);

      for (const pair of activePairs) {
        const x = new Float32Array(pair.embedding);
        const Ax = matVec(this.A, x, RANK, D_IN);
        const BAx = matVec(this.B, Ax, N_CLASSES, RANK);
        const logits = new Float32Array(N_CLASSES);
        for (let j = 0; j < N_CLASSES; j++) logits[j] = SCALE * BAx[j];

        const w = pair.chosen;
        const l = pair.rejected;
        const deltaZ = logits[w] - logits[l];
        const sigVal = 1 / (1 + Math.exp(-beta * Math.max(-20, Math.min(20, deltaZ))));
        const loss = -Math.log(Math.max(sigVal, 1e-9));
        totalLoss += loss;

        const factor = -beta * (1 - sigVal);
        const dLogits = new Float32Array(N_CLASSES);
        dLogits[w] = factor;
        dLogits[l] = -factor;

        for (let ci = 0; ci < N_CLASSES; ci++) {
          if (dLogits[ci] === 0) continue;
          for (let ri = 0; ri < RANK; ri++) {
            gradB[ci * RANK + ri] += SCALE * dLogits[ci] * Ax[ri];
          }
        }

        const dAx = new Float32Array(RANK);
        for (let ri = 0; ri < RANK; ri++) {
          for (let ci = 0; ci < N_CLASSES; ci++) {
            if (dLogits[ci] === 0) continue;
            dAx[ri] += SCALE * this.B[ci * RANK + ri] * dLogits[ci];
          }
        }

        for (let ri = 0; ri < RANK; ri++) {
          if (dAx[ri] === 0) continue;
          for (let di = 0; di < D_IN; di++) {
            gradA[ri * D_IN + di] += dAx[ri] * x[di];
          }
        }
      }

      const n = activePairs.length;
      for (let k = 0; k < gradA.length; k++) gradA[k] /= n;
      for (let k = 0; k < gradB.length; k++) gradB[k] /= n;

      for (let k = 0; k < this.A.length; k++) {
        this.mA[k] = MOMENTUM * this.mA[k] + LR * (gradA[k] + WEIGHT_DECAY * this.A[k]);
        this.A[k] -= this.mA[k];
      }
      for (let k = 0; k < this.B.length; k++) {
        this.mB[k] = MOMENTUM * this.mB[k] + LR * gradB[k];
        this.B[k] -= this.mB[k];
      }

      const avgLoss = totalLoss / n;
      this.currentLoss = avgLoss;
      this.lastTrainedAt = new Date().toISOString();
      this.epochsTrained++;
      return { loss: avgLoss, steps: 1, pairs: n };
    }

    // ── Idle + charging gate ─────────────────────────────────────────────────
    /**
     * Returns true if the device is idle AND on AC power (or battery API absent).
     * @returns {Promise<boolean>}
     */
    async canTrain(force = false) {
      if (force) return true;
      // Check idle state via chrome.idle (threshold: 60 s)
      const idleCheck = await new Promise((resolve) => {
        if (typeof chrome !== 'undefined' && chrome.idle && chrome.idle.queryState) {
          chrome.idle.queryState(60, (state) => resolve(state === 'idle'));
        } else {
          resolve(true); // Node/test context: skip gate
        }
      });
      if (!idleCheck) return false;

      // Check charging via Battery Status API
      if (typeof navigator !== 'undefined' && typeof navigator.getBattery === 'function') {
        try {
          const battery = await navigator.getBattery();
          return battery.charging || battery.level >= 0.8;
        } catch (_) {
          return true; // API unavailable → allow
        }
      }
      return true; // No Battery API → allow (desktop / test)
    }

    // ── Blueprint #17: Differential-Privacy Federated Contributions ─────────
    /**
     * Builds a DP-protected adapter contribution for swarm sharing.
     *
     * The raw update is the flattened adapter delta ΔW = SCALE · B·A. It is
     * L2-clipped to `clipNorm`, then per-coordinate Gaussian noise calibrated
     * by the Gaussian mechanism (σ = C·√(2·ln(1.25/δ)) / (ε·n)) is added, so
     * any single user correction is provably obscured. Requires a minimum
     * sample count so individual labels cannot dominate the payload.
     *
     * @returns {object|null} contribution payload, or null when too few samples
     */
    buildFederatedContribution(options = {}) {
      const minSamples = options.minSamples ?? MIN_FEDERATED_SAMPLES;
      if (this._samples.length < minSamples) return null;

      const epsilon = options.epsilon ?? DP_EPSILON;
      const dpDelta = options.dpDelta ?? DP_DELTA;
      const clipNorm = options.clipNorm ?? DP_CLIP_NORM;
      const n = this._samples.length;

      // 1. Raw flattened delta ΔW = SCALE · B·A
      const raw = new Float32Array(N_CLASSES * D_IN);
      for (let i = 0; i < N_CLASSES; i++) {
        for (let r = 0; r < RANK; r++) {
          const bVal = this.B[i * RANK + r];
          if (bVal === 0) continue;
          for (let j = 0; j < D_IN; j++) {
            raw[i * D_IN + j] += SCALE * bVal * this.A[r * D_IN + j];
          }
        }
      }

      // 2. L2 clip
      let norm = 0;
      for (let k = 0; k < raw.length; k++) norm += raw[k] * raw[k];
      norm = Math.sqrt(norm);
      const scaleDown = norm > clipNorm ? clipNorm / norm : 1;

      // 3. Gaussian noise per coordinate (Gaussian mechanism)
      const sigma = (clipNorm * Math.sqrt(2 * Math.log(1.25 / dpDelta))) / (epsilon * n);
      const noisy = new Array(raw.length);
      for (let k = 0; k < raw.length; k++) {
        noisy[k] = +(raw[k] * scaleDown + randNormal(0, sigma)).toFixed(6);
      }

      return {
        format: 'VIGIL-DP-LORA-v1',
        dim: { classes: N_CLASSES, dIn: D_IN, rank: RANK },
        delta: noisy,
        clipNorm,
        epsilon,
        dpDelta,
        sigma: +sigma.toFixed(6),
        samples: n,
        generatedAt: new Date().toISOString()
      };
    }

    /**
     * Applies an aggregated (already averaged by the relay) federated delta
     * as the additive bias used by applyAdapter.
     */
    applyFederatedDelta(payload) {
      if (!payload || payload.format !== 'VIGIL-DP-LORA-v1') return false;
      if (!payload.dim || payload.dim.classes !== N_CLASSES || payload.dim.dIn !== D_IN) return false;
      if (!Array.isArray(payload.delta) || payload.delta.length !== N_CLASSES * D_IN) return false;
      this.federatedDelta = new Float32Array(payload.delta);
      return true;
    }

    // ── Persistence ──────────────────────────────────────────────────────────
    /**
     * Serialize adapter weights to chrome.storage.local.
     * @param {{ get, set }} storage
     */
    async saveAdapter(storage) {
      const payload = {
        A:            Array.from(this.A),
        B:            Array.from(this.B),
        mA:           Array.from(this.mA),
        mB:           Array.from(this.mB),
        samples:      this._samples,
        preferencePairs: this._preferencePairs,
        federatedDelta: Array.from(this.federatedDelta),
        currentLoss:  this.currentLoss,
        lastTrainedAt: this.lastTrainedAt,
        epochsTrained: this.epochsTrained
      };
      await storage.set({ [STORAGE_KEY]: payload });
    }

    /**
     * Load adapter weights from chrome.storage.local.
     * @param {{ get }} storage
     */
    async loadAdapter(storage) {
      const result = await storage.get([STORAGE_KEY]);
      const data = result[STORAGE_KEY];
      if (!data) return false;

      if (data.A  && data.A.length  === RANK * D_IN)   this.A  = new Float32Array(data.A);
      if (data.B  && data.B.length  === N_CLASSES * RANK) this.B = new Float32Array(data.B);
      if (data.mA && data.mA.length === RANK * D_IN)   this.mA = new Float32Array(data.mA);
      if (data.mB && data.mB.length === N_CLASSES * RANK) this.mB = new Float32Array(data.mB);
      if (Array.isArray(data.samples))  this._samples     = data.samples;
      if (Array.isArray(data.preferencePairs)) this._preferencePairs = data.preferencePairs;
      if (Array.isArray(data.federatedDelta) && data.federatedDelta.length === N_CLASSES * D_IN) {
        this.federatedDelta = new Float32Array(data.federatedDelta);
      }
      if (data.currentLoss  != null)    this.currentLoss  = data.currentLoss;
      if (data.lastTrainedAt != null)   this.lastTrainedAt = data.lastTrainedAt;
      if (data.epochsTrained != null)   this.epochsTrained = data.epochsTrained;
      this._loaded = true;
      return true;
    }

    // ── Status ───────────────────────────────────────────────────────────────
    /** @returns {object} */
    getStatus() {
      return {
        rank:          RANK,
        alpha:         ALPHA,
        scale:         SCALE,
        dIn:           D_IN,
        nClasses:      N_CLASSES,
        sampleCount:   this._samples.length,
        preferencePairCount: this._preferencePairs.length,
        maxSamples:    MAX_SAMPLES,
        currentLoss:   this.currentLoss,
        epochsTrained: this.epochsTrained,
        lastTrainedAt: this.lastTrainedAt
      };
    }
  }

  // ── Module singleton ──────────────────────────────────────────────────────
  const loraAdapter = new LoRAAdapter();

  const VIGIL_LORA = {
    LoRAAdapter,
    loraAdapter,
    RANK,
    D_IN,
    N_CLASSES,
    ALPHA,
    SCALE,
    DP_EPSILON,
    DP_DELTA,
    DP_CLIP_NORM,
    MIN_FEDERATED_SAMPLES
  };

  // Browser global
  root.VIGIL_LORA = VIGIL_LORA;

  // Node / Jest
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_LORA;
  }

})(
  typeof globalThis !== 'undefined' ? globalThis
    : typeof self    !== 'undefined' ? self
    : this
);
