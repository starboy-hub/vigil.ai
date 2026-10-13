/**
 * VIGIL AI - Scanner Web Worker (scanner-worker.js)
 * Offloads heavy Regex detection, Vault candidate extraction,
 * and Blind-Hash cryptographic computations from the main browser thread.
 */

// Environment-adaptive loader: importScripts in Worker, require in Jest
if (typeof importScripts === 'function' && typeof VIGIL === 'undefined') {
  try {
    importScripts(
      'vigil-shared.js',
      'vigil-vault.js',
      'fake-data.js',
      'redos-engine.js',
      'detection-engine.js',
      'secret-engine.js',
      'k-anonymity-auditor.js'
    );
  } catch (err) {
    console.warn('[VIGIL Scanner Worker] importScripts failed:', err);
  }
} else if (typeof require !== 'undefined') {
  try {
    if (typeof VIGIL === 'undefined') global.VIGIL = require('../shared/vigil-shared.js');
    if (typeof VIGIL_VAULT === 'undefined') global.VIGIL_VAULT = require('../background/vigil-vault.js');
    if (typeof VIGIL_FAKE === 'undefined') global.VIGIL_FAKE = require('./modules/fake-data.js');
    if (typeof VIGIL_REDOS === 'undefined') global.VIGIL_REDOS = require('./modules/redos-engine.js');
    if (typeof VIGIL_ENGINE === 'undefined') global.VIGIL_ENGINE = require('./modules/detection-engine.js');
    if (typeof VIGIL_SECRETS === 'undefined') global.VIGIL_SECRETS = require('./modules/secret-engine.js');
    if (typeof VIGIL_K_ANONYMITY === 'undefined') global.VIGIL_K_ANONYMITY = require('./modules/k-anonymity-auditor.js');
  } catch (err) {
    // Tests will inject globals directly if needed
  }
}

// In-worker state
let workerSettings = {
  regexEnabled: true,
  sensitivity: 'medium',
  customPatterns: ''
};

let vaultSalt = null;
let vaultBlindMap = new Map();
let vaultIndexMinLen = 0;
let vaultIndexMaxLen = 0;
let vaultMatchers = [];
const VAULT_MAX_CANDIDATES = 400;

function vaultCandidateNorms(candidate) {
  const t = candidate.trim();
  if (!t) return [];
  const norms = new Set();
  norms.add(t.toLowerCase());
  norms.add(t.toLowerCase().replace(/\s+/g, ' '));
  if (/\d/.test(t)) norms.add(t.replace(/\D/g, ''));
  return [...norms];
}

function vaultExtractCandidates(text) {
  const cands = new Set();
  let m;
  const emailRe = /[^\s@<>]{1,64}@[^\s@<>]{1,255}\.[^\s@<>]{2,}/g;
  while ((m = emailRe.exec(text)) !== null) {
    cands.add(m[0]);
    if (cands.size >= VAULT_MAX_CANDIDATES) return cands;
  }
  const phoneRe = /(?<!\d)\+?[\d][\d\s().+-]{5,24}[\d](?!\d)/g;
  while ((m = phoneRe.exec(text)) !== null) {
    cands.add(m[0]);
    if (cands.size >= VAULT_MAX_CANDIDATES) return cands;
  }
  const words = text.split(/[^\p{L}\p{N}'’-]+/u).filter(w => w.length >= 2 && w.length <= 64);
  for (let i = 0; i < words.length && cands.size < VAULT_MAX_CANDIDATES; i++) {
    let seq = words[i];
    cands.add(seq);
    for (let j = i + 1; j < Math.min(i + 4, words.length); j++) {
      seq += ' ' + words[j];
      cands.add(seq);
      if (cands.size >= VAULT_MAX_CANDIDATES) break;
    }
  }
  return cands;
}

function pushVaultFindingWorker(r, alerts, redactions, seen) {
  if (!alerts.find(x => x.source === 'vault' && x.type === r.type)) {
    alerts.push({ type: r.type, source: 'vault', severity: 'critical' });
  }
  if (!seen.has(r.text)) {
    redactions.push(r);
    seen.add(r.text);
  }
}

async function scanVaultTextWorker(text, alerts, redactions, seen) {
  if (!text) return;

  if (vaultMatchers && vaultMatchers.length) {
    for (const m of vaultMatchers) {
      const re = new RegExp(m.regex.source, m.regex.flags);
      let vm;
      while ((vm = re.exec(text)) !== null) {
        if (vm[0].length === 0) { re.lastIndex++; continue; }
        const matched = vm[0];
        const typeLabel = 'Vault ' + m.kind.charAt(0).toUpperCase() + m.kind.slice(1);
        if (!seen.has(matched)) {
          const opaquePointer = (typeof VIGIL_FAKE !== 'undefined' && VIGIL_FAKE.createOpaquePointer)
            ? VIGIL_FAKE.createOpaquePointer(m.kind, m.entryId)
            : `{{PTR:VAULT_${m.entryId.slice(0, 8)}}}`;
          pushVaultFindingWorker({ text: matched, type: typeLabel, vaultId: m.entryId, vaultKind: m.kind, context: matched, opaquePointer }, alerts, redactions, seen);
        }
      }
    }
  }

  if (!vaultSalt || !vaultBlindMap.size || typeof VIGIL_VAULT === 'undefined' || !VIGIL_VAULT.computeBlindHash) return;
  const matchedIds = new Set();
  for (const cand of vaultExtractCandidates(text)) {
    if (matchedIds.size >= vaultBlindMap.size) break;
    for (const norm of vaultCandidateNorms(cand)) {
      if (norm.length < vaultIndexMinLen || norm.length > vaultIndexMaxLen) continue;
      let blindHash;
      try {
        blindHash = await VIGIL_VAULT.computeBlindHash(vaultSalt, norm);
      } catch (e) { return; }
      const idx = vaultBlindMap.get(blindHash);
      if (idx && !matchedIds.has(idx.id)) {
        matchedIds.add(idx.id);
        const opaquePointer = (typeof VIGIL_FAKE !== 'undefined' && VIGIL_FAKE.createOpaquePointer)
          ? VIGIL_FAKE.createOpaquePointer(idx.kind, idx.id)
          : `{{PTR:VAULT_${idx.id}}}`;
        pushVaultFindingWorker({ text: cand.trim(), type: 'Vault ' + idx.kind.charAt(0).toUpperCase() + idx.kind.slice(1), vaultId: idx.id, vaultKind: idx.kind, context: cand.trim(), opaquePointer }, alerts, redactions, seen);
      }
    }
  }
}

async function scanTextWorker(text, options = {}) {
  const ct = (typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.cleanText) ? VIGIL_ENGINE.cleanText(text) : text;
  const alerts = [];
  const redactions = [];
  const seen = new Set();
  const sensitivity = options.sensitivity || workerSettings.sensitivity || 'medium';
  const isTel = !!options.isTel;

  if (!text || text.length < 5) {
    return { alerts: [], redactions: [] };
  }

  // 1. Regex & Secrets Detection
  if (workerSettings.regexEnabled && typeof VIGIL_ENGINE !== 'undefined') {
    const r = VIGIL_ENGINE.scanWithRegex(ct);
    if (r && r.alerts) alerts.push(...r.alerts);
    if (r && r.redactions) r.redactions.forEach(x => { redactions.push(x); seen.add(x.text); });

    if (typeof VIGIL_SECRETS !== 'undefined' && VIGIL_SECRETS.scanSecrets) {
      const sec = VIGIL_SECRETS.scanSecrets(ct);
      if (sec && sec.alerts) alerts.push(...sec.alerts);
      if (sec && sec.redactions) sec.redactions.forEach(x => { if (!seen.has(x.text)) { redactions.push(x); seen.add(x.text); } });
    }
  }

  // 2. Context-Aware Evaluation
  if ((sensitivity === 'medium' || sensitivity === 'high') && typeof VIGIL_ENGINE !== 'undefined') {
    const ctx = VIGIL_ENGINE.scanWithContext(ct);
    if (ctx && ctx.alerts) {
      ctx.alerts.forEach(a => {
        if (!alerts.find(x => x.type === a.type && x.source === 'context')) alerts.push(a);
      });
    }
    if (ctx && ctx.redactions) {
      ctx.redactions.forEach(r => {
        if (!seen.has(r.text)) { redactions.push(r); seen.add(r.text); }
      });
    }
  }

  // 3. High Sensitivity Heuristics
  if (sensitivity === 'high' && typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.findNamesHeuristic) {
    const names = VIGIL_ENGINE.findNamesHeuristic(ct);
    if (names && Array.isArray(names)) {
      names.forEach(n => {
        if (!seen.has(n)) {
          alerts.push({ type: 'NAME', source: 'heuristic', severity: 'medium' });
          redactions.push({ text: n, type: 'NAME' });
          seen.add(n);
        }
      });
    }
  }

  // 4. Blind Index Vault Scanner (Never accesses cleartext vault corpus)
  await scanVaultTextWorker(ct, alerts, redactions, seen);

  // 5. K-Anonymity & Quasi-Identifier Entropy
  if (typeof VIGIL_K_ANONYMITY !== 'undefined' && VIGIL_K_ANONYMITY.auditPrompt) {
    const ka = VIGIL_K_ANONYMITY.auditPrompt(ct);
    if (ka && ka.isHighRisk) {
      alerts.push({
        type: 'K_ANONYMITY_RISK',
        source: 'k-anonymity',
        severity: 'high',
        details: `Re-identification risk ${Math.round(ka.riskScore * 100)}% (Anonymity pool K~${ka.estimatedK})`,
        recommendations: ka.recommendations
      });
      ka.quasiIdentifiers.forEach(q => {
        if (q.raw && !seen.has(q.raw)) {
          redactions.push({ text: q.raw, type: 'QUASI_IDENTIFIER', recommendation: q.recommendation });
          seen.add(q.raw);
        }
      });
    }
  }

  // 6. Custom Patterns
  const customPatternStr = options.customPatterns || workerSettings.customPatterns;
  if (customPatternStr && typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.scanWithCustomPatterns) {
    const customPatterns = VIGIL_ENGINE.parseCustomPatterns(customPatternStr);
    const custom = VIGIL_ENGINE.scanWithCustomPatterns(ct, customPatterns);
    if (custom && custom.alerts) {
      custom.alerts.forEach(a => {
        if (!alerts.find(x => x.type === a.type && x.source === 'custom')) alerts.push(a);
      });
    }
    if (custom && custom.redactions) {
      custom.redactions.forEach(r => {
        if (!seen.has(r.text)) { redactions.push(r); seen.add(r.text); }
      });
    }
  }

  // 7. Contextual Phone Scoring
  if (!isTel && typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.isLikelyPhoneNumber) {
    const phoneMatches = redactions.filter(r => r.type === 'Phone');
    const anyLikelyPhone = phoneMatches.some(r => VIGIL_ENGINE.isLikelyPhoneNumber(r.text, ct));
    if (phoneMatches.length && !anyLikelyPhone) {
      alerts.forEach(a => { if (a.type === 'Phone') a.severity = 'low'; });
    }
  }

  return { alerts, redactions };
}

// Web Worker message listener
if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
  self.onmessage = async (e) => {
    const { type, id, payload } = e.data || {};
    if (type === 'INIT' || type === 'UPDATE_SETTINGS') {
      if (payload) workerSettings = Object.assign(workerSettings, payload);
    } else if (type === 'UPDATE_VAULT') {
      if (payload) {
        vaultSalt = payload.salt || null;
        vaultBlindMap.clear();
        if (Array.isArray(payload.indices)) {
          payload.indices.forEach(idx => vaultBlindMap.set(idx.blindHash, idx));
          vaultIndexMinLen = payload.indices.reduce((min, idx) => Math.min(min, idx.minLen || Infinity), Infinity);
          vaultIndexMaxLen = payload.indices.reduce((max, idx) => Math.max(max, idx.minLen || 0), 0);
          if (!isFinite(vaultIndexMinLen)) vaultIndexMinLen = 0;
        }
        if (payload.trusted && typeof VIGIL_VAULT !== 'undefined' && VIGIL_VAULT.buildMatchers) {
          vaultMatchers = VIGIL_VAULT.buildMatchers(payload.trusted);
        }
      }
    } else if (type === 'SCAN_TEXT') {
      try {
        const { text, options } = payload || {};
        const result = await scanTextWorker(text, options);
        self.postMessage({ type: 'SCAN_RESULT', id, result });
      } catch (err) {
        self.postMessage({ type: 'SCAN_ERROR', id, error: err.message });
      }
    }
  };
}

// Module export for test harness
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    scanTextWorker,
    scanVaultTextWorker,
    vaultExtractCandidates,
    vaultCandidateNorms,
    setWorkerSettings: (s) => { workerSettings = Object.assign(workerSettings, s); },
    setVaultState: (salt, indices, trusted) => {
      vaultSalt = salt;
      vaultBlindMap = new Map();
      (indices || []).forEach(i => vaultBlindMap.set(i.blindHash, i));
      vaultIndexMinLen = (indices || []).reduce((min, idx) => Math.min(min, idx.minLen || Infinity), Infinity);
      vaultIndexMaxLen = (indices || []).reduce((max, idx) => Math.max(max, idx.minLen || 0), 0);
      if (!isFinite(vaultIndexMinLen)) vaultIndexMinLen = 0;
      if (trusted && typeof VIGIL_VAULT !== 'undefined' && VIGIL_VAULT.buildMatchers) {
        vaultMatchers = VIGIL_VAULT.buildMatchers(trusted);
      }
    }
  };
}

