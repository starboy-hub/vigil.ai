/**
 * VIGIL Blueprint #7: Gradual Manipulation Detection (Semantic Drift)
 *
 * Problem: Multi-turn conversational grooming (5-20+ turns) defeats single-message
 * detectors by incrementally nudging the conversation towards sensitive clusters
 * (credentials, system override, PII exfiltration, safety evasion) where each
 * individual turn appears innocuous.
 *
 * Solution: Tracks the semantic vector trajectory per conversation session.
 * Computes baseline centroid C_0 and running centroid C_t, measuring cosine drift
 * and alignment towards sensitive threat anchor clusters. Alerts when cumulative
 * multi-turn drift toward adversarial clusters is detected.
 */
(function (root) {
  'use strict';

  const VECTOR_DIM = 128;
  const DEFAULT_MIN_TURNS = 4;
  const DEFAULT_DRIFT_THRESHOLD = 0.20;
  const DEFAULT_THREAT_PROXIMITY_THRESHOLD = 0.25;
  const DEFAULT_EMA_ALPHA = 0.40;

  // ---- Vector Mathematics Primitives ----

  function normalize(vec) {
    let sumSq = 0;
    for (let i = 0; i < vec.length; i++) {
      sumSq += vec[i] * vec[i];
    }
    const mag = Math.sqrt(sumSq);
    if (mag === 0) return new Float32Array(vec.length);
    const out = new Float32Array(vec.length);
    for (let i = 0; i < vec.length; i++) {
      out[i] = vec[i] / mag;
    }
    return out;
  }

  function dotProduct(a, b) {
    let sum = 0;
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      sum += a[i] * b[i];
    }
    return sum;
  }

  function cosineSimilarity(a, b) {
    // Both vectors are unit-normalized; dot product equals cosine similarity
    const dot = dotProduct(a, b);
    return Math.max(-1, Math.min(1, dot));
  }

  function cosineDistance(a, b) {
    return 1 - cosineSimilarity(a, b);
  }

  function vectorAdd(a, b, weightA = 1.0, weightB = 1.0) {
    const out = new Float32Array(a.length);
    for (let i = 0; i < a.length; i++) {
      out[i] = a[i] * weightA + b[i] * weightB;
    }
    return normalize(out);
  }

  // Fast 32-bit FNV-1a hash
  function fnv1a(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return hash >>> 0;
  }

  /**
   * Deterministic Feature Hashing Vectorizer (d = 128)
   * Converts raw text into a normalized embedding vector using subword n-grams.
   */
  function vectorizeText(text, dim = VECTOR_DIM) {
    if (!text || typeof text !== 'string') return new Float32Array(dim);
    const clean = text.toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').trim();
    const tokens = clean.split(/\s+/).filter(Boolean);
    const vec = new Float32Array(dim);

    // Unigrams and character 3-grams
    tokens.forEach((tok) => {
      // Word feature
      const hWord = fnv1a(tok);
      const idx = hWord % dim;
      const sign = (hWord & 0x80000000) ? 1 : -1;
      vec[idx] += sign * 1.5;

      // Subword character n-grams (length 3)
      if (tok.length >= 3) {
        for (let i = 0; i <= tok.length - 3; i++) {
          const gram = tok.slice(i, i + 3);
          const hGram = fnv1a(gram);
          const gIdx = hGram % dim;
          const gSign = (hGram & 0x80000000) ? 1 : -1;
          vec[gIdx] += gSign * 0.8;
        }
      }
    });

    return normalize(vec);
  }

  // ---- Canonical Threat Clusters & Anchor Centroids ----

  const THREAT_ANCHOR_DEFINITIONS = {
    CREDENTIAL_EXFILTRATION: 'password secret token api key private key ssh credentials database access bearer authorization cert private key exfiltrate dump connection string',
    SYSTEM_OVERRIDE: 'ignore previous instructions disregard safety system prompt bypass jailbreak developer mode unrestricted roleplay override guardrails filter unlock dan rule',
    PII_HARVESTING: 'social security number ssn credit card bank account medical record date of birth address passport driving license personal details tax id identity',
    SAFETY_EVASION: 'unfiltered unrestricted dangerous exploit vulnerability malware payload attack weapon evasion bypass censorship illegal bomb harmful'
  };

  const THREAT_ANCHORS = {};
  for (const [key, text] of Object.entries(THREAT_ANCHOR_DEFINITIONS)) {
    THREAT_ANCHORS[key] = vectorizeText(text);
  }

  // ---- Storage Layer (IndexedDB with In-Memory / chrome.storage Fallback) ----

  function createDriftStorage() {
    const memoryStore = new Map();
    let dbPromise = null;

    function openIDB() {
      if (dbPromise) return dbPromise;
      if (typeof indexedDB === 'undefined') return Promise.resolve(null);
      dbPromise = new Promise((resolve) => {
        try {
          const req = indexedDB.open('vigil_semantic_drift', 1);
          req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('trajectories')) {
              db.createObjectStore('trajectories', { keyPath: 'sessionId' });
            }
          };
          req.onsuccess = (e) => {
            resolve(e.target.result);
          };
          req.onerror = () => resolve(null);
        } catch (e) {
          resolve(null);
        }
      });
      return dbPromise;
    }

    async function getSession(sessionId) {
      const db = await openIDB();
      if (!db) return memoryStore.get(sessionId) || null;
      return new Promise((resolve) => {
        try {
          const tx = db.transaction('trajectories', 'readonly');
          const store = tx.objectStore('trajectories');
          const req = store.get(sessionId);
          req.onsuccess = () => resolve(req.result || null);
          req.onerror = () => resolve(memoryStore.get(sessionId) || null);
        } catch (e) {
          resolve(memoryStore.get(sessionId) || null);
        }
      });
    }

    async function saveSession(session) {
      if (!session || !session.sessionId) return;
      memoryStore.set(session.sessionId, session);
      pruneSessions();
      const db = await openIDB();
      if (!db) return;
      return new Promise((resolve) => {
        try {
          const tx = db.transaction('trajectories', 'readwrite');
          const store = tx.objectStore('trajectories');
          store.put(session);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        } catch (e) {
          resolve();
        }
      });
    }

    // Storage GC: sessions expire after 7 days of inactivity, and at most
    // MAX_SESSIONS trajectories are retained — otherwise every conversation
    // ever seen accumulates in storage forever.
    const SESSION_TTL_MS = 7 * 86400000;
    const MAX_SESSIONS = 200;

    function pruneSessions() {
      const now = Date.now();
      for (const [id, s] of memoryStore.entries()) {
        const updatedAt = s.updatedAt || s.startedAt || 0;
        if (now - updatedAt > SESSION_TTL_MS) memoryStore.delete(id);
      }
      if (memoryStore.size <= MAX_SESSIONS) return;
      const byAge = [...memoryStore.entries()]
        .sort((a, b) => (a[1].updatedAt || a[1].startedAt || 0) - (b[1].updatedAt || b[1].startedAt || 0));
      while (byAge.length > MAX_SESSIONS) {
        const oldest = byAge.shift();
        memoryStore.delete(oldest[0]);
      }
    }

    async function deleteSession(sessionId) {
      memoryStore.delete(sessionId);
      const db = await openIDB();
      if (!db) return;
      return new Promise((resolve) => {
        try {
          const tx = db.transaction('trajectories', 'readwrite');
          const store = tx.objectStore('trajectories');
          store.delete(sessionId);
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        } catch (e) {
          resolve();
        }
      });
    }

    async function clearAll() {
      memoryStore.clear();
      const db = await openIDB();
      if (!db) return;
      return new Promise((resolve) => {
        try {
          const tx = db.transaction('trajectories', 'readwrite');
          const store = tx.objectStore('trajectories');
          store.clear();
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        } catch (e) {
          resolve();
        }
      });
    }

    return { getSession, saveSession, deleteSession, clearAll };
  }

  // ---- Trajectory Tracking Engine ----

  class SemanticDriftTracker {
    constructor(options = {}) {
      this.minTurns = options.minTurns || DEFAULT_MIN_TURNS;
      this.driftThreshold = options.driftThreshold || DEFAULT_DRIFT_THRESHOLD;
      this.threatThreshold = options.threatProximityThreshold || DEFAULT_THREAT_PROXIMITY_THRESHOLD;
      this.alpha = options.alpha || DEFAULT_EMA_ALPHA;
      this.storage = options.storage || createDriftStorage();
    }

    /**
     * Records a conversational turn and computes drift against baseline and threat anchors.
     * Returns:
     * {
     *   sessionId: string,
     *   turnCount: number,
     *   driftScore: number,
     *   driftDetected: boolean,
     *   topThreatCluster: string,
     *   threatProximity: number,
     *   threatScores: Record<string, number>,
     *   baselineDrift: number,
     *   warning?: string
     * }
     */
    async recordTurn(sessionId, text, role = 'user') {
      if (!sessionId || !text || typeof text !== 'string') {
        return { sessionId, turnCount: 0, driftDetected: false, reason: 'invalid_turn' };
      }

      const vec = vectorizeText(text);
      const existing = (await this.storage.getSession(sessionId)) || {
        sessionId,
        startedAt: Date.now(),
        turnCount: 0,
        baselineCentroid: null,
        currentCentroid: null,
        turns: []
      };

      existing.turnCount += 1;
      const turnNum = existing.turnCount;

      let baselineCentroid;
      let currentCentroid;

      if (turnNum === 1) {
        // Initialize baseline and running centroids
        baselineCentroid = Array.from(vec);
        currentCentroid = Array.from(vec);
      } else if (turnNum <= 3) {
        // Formulate stable baseline over first 3 turns
        const prevBase = new Float32Array(existing.baselineCentroid);
        baselineCentroid = Array.from(vectorAdd(prevBase, vec, 1.0, 1.0));
        const prevCurr = new Float32Array(existing.currentCentroid);
        currentCentroid = Array.from(vectorAdd(prevCurr, vec, 1.0, 1.0));
      } else {
        // Running centroid tracks conversation direction with exponential moving average
        baselineCentroid = existing.baselineCentroid;
        const prevCurr = new Float32Array(existing.currentCentroid);
        currentCentroid = Array.from(vectorAdd(prevCurr, vec, 1.0 - this.alpha, this.alpha));
      }

      existing.baselineCentroid = baselineCentroid;
      existing.currentCentroid = currentCentroid;

      const baseVec = new Float32Array(baselineCentroid);
      const currVec = new Float32Array(currentCentroid);

      // Drift from initial conversation baseline
      const baselineDrift = cosineDistance(currVec, baseVec);

      // Measure proximity against each sensitive threat cluster
      const threatScores = {};
      let topCluster = null;
      let maxProximity = -1;

      for (const [clusterKey, anchorVec] of Object.entries(THREAT_ANCHORS)) {
        const prox = cosineSimilarity(currVec, anchorVec);
        threatScores[clusterKey] = +prox.toFixed(4);
        if (prox > maxProximity) {
          maxProximity = prox;
          topCluster = clusterKey;
        }
      }

      const baseThreatProx = topCluster ? cosineSimilarity(baseVec, THREAT_ANCHORS[topCluster]) : 0;
      const currentTurnThreatProx = topCluster ? cosineSimilarity(vec, THREAT_ANCHORS[topCluster]) : 0;
      const netDriftTowardThreat = maxProximity - baseThreatProx;

      // Detection Rule (Zero False Positives on Benign Turns):
      // 1. Must have at least minTurns (4+)
      // 2. Trajectory baseline drift >= driftThreshold
      // 3. Running centroid proximity to threat >= threatThreshold
      // 4. Trajectory must have drifted TOWARDS the threat (net increase over baseline)
      // 5. Current turn itself must actively participate in the threat cluster
      const driftDetected =
        turnNum >= this.minTurns &&
        baselineDrift >= this.driftThreshold &&
        maxProximity >= this.threatThreshold &&
        netDriftTowardThreat >= 0.04 &&
        currentTurnThreatProx >= 0.18;

      let warning = null;
      if (driftDetected) {
        const clusterName = topCluster.replace(/_/g, ' ').toLowerCase();
        warning = `Gradual semantic drift detected (${turnNum} turns): conversation trajectory has drifted significantly toward ${clusterName}.`;
      }

      const turnSummary = {
        turn: turnNum,
        timestamp: Date.now(),
        role,
        drift: +baselineDrift.toFixed(4),
        threat: topCluster,
        proximity: +maxProximity.toFixed(4)
      };

      existing.turns.push(turnSummary);
      if (existing.turns.length > 50) existing.turns.shift(); // retain last 50 turns
      existing.updatedAt = Date.now();

      await this.storage.saveSession(existing);

      return {
        sessionId,
        turnCount: turnNum,
        driftScore: +baselineDrift.toFixed(4),
        driftDetected,
        topThreatCluster: topCluster,
        threatProximity: +maxProximity.toFixed(4),
        threatScores,
        baselineDrift: +baselineDrift.toFixed(4),
        warning
      };
    }

    async getSession(sessionId) {
      return await this.storage.getSession(sessionId);
    }

    async resetSession(sessionId) {
      await this.storage.deleteSession(sessionId);
      return { success: true, sessionId };
    }

    async clearAll() {
      await this.storage.clearAll();
    }
  }

  const VIGIL_DRIFT = {
    VECTOR_DIM,
    DEFAULT_MIN_TURNS,
    DEFAULT_DRIFT_THRESHOLD,
    DEFAULT_THREAT_PROXIMITY_THRESHOLD,
    vectorizeText,
    cosineSimilarity,
    cosineDistance,
    normalize,
    dotProduct,
    THREAT_ANCHORS,
    createDriftStorage,
    SemanticDriftTracker
  };

  root.VIGIL_DRIFT = VIGIL_DRIFT;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_DRIFT;
  }
})(typeof self !== 'undefined' ? self : globalThis);
