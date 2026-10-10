/**
 * VIGIL Blueprint #12: Adversarial Replay Mode (Forensics Replay)
 *
 * Problem: Security researchers, enterprise auditors, and power users cannot
 * inspect the internal step-by-step decision pathway of the VIGIL multi-tier
 * defense pipeline when analyzing complex prompt injection or exfiltration attacks.
 *
 * Solution: An instrumented Forensics Replay Engine that executes prompts through
 * all 4 defense tiers with high-precision latency profiling, sub-rule signal attribution,
 * multi-model consensus voting breakdown, and chronological timeline generation.
 */
(function (root) {
  'use strict';

  const FORENSICS_HISTORY_KEY = 'vigil_forensics_history';
  const MAX_HISTORY_ITEMS = 25;

  class ForensicsReplayEngine {
    constructor(options = {}) {
      this.storage = options.storage || null;
      this.customEngines = options.engines || {};
    }

    _getEngine(name, globalName) {
      if (this.customEngines[name]) return this.customEngines[name];
      if (typeof root !== 'undefined' && root[globalName]) return root[globalName];
      try {
        if (typeof require === 'function') {
          switch (name) {
            case 'detection': return require('../content/modules/detection-engine.js');
            case 'injection': return require('../content/modules/injection-engine.js');
            case 'sentinel': return require('../content/modules/sentinel-engine.js');
            case 'redos': return require('../content/modules/redos-engine.js');
            case 'secrets': return require('../content/modules/secret-engine.js');
            case 'leakage': return require('../content/modules/leakage-detector.js');
            case 'shopping': return require('./shopping-detector.js');
            case 'drift': return require('./semantic-drift.js');
            case 'consensus': return require('./consensus-firewall.js');
          }
        }
      } catch {
        // Module not found or in browser context
      }
      return null;
    }

    _now() {
      if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
        return performance.now();
      }
      return Date.now();
    }

    /**
     * Executes prompt through Tier 0: Syntax, ReDoS & Secrets / PII Inspection
     */
    async _executeTier0(prompt) {
      const start = this._now();
      const findings = [];
      let isBlocked = false;
      let isFlagged = false;

      // 1. ReDoS pattern validation
      const redos = this._getEngine('redos', 'VIGIL_REDOS');
      let redosRisk = false;
      if (redos && typeof redos.isSafeRegex === 'function') {
        // If the prompt contains embedded regex-like pattern, check it
        const regexMatch = prompt.match(/\/(.+?)\/([gimsuy]*)/);
        if (regexMatch) {
          const safe = redos.isSafeRegex(regexMatch[1]);
          if (!safe) {
            redosRisk = true;
            findings.push({ rule: 'REDOS_VULNERABILITY', message: 'Vulnerable catastrophic backtracking regex detected' });
            isBlocked = true;
          }
        }
      }

      // 2. Secret & Credential Scanning
      const secrets = this._getEngine('secrets', 'VIGIL_SECRETS');
      let secretHits = 0;
      if (secrets && typeof secrets.scanSecrets === 'function') {
        const found = secrets.scanSecrets(prompt) || [];
        if (found.length > 0) {
          secretHits = found.length;
          isBlocked = true;
          found.forEach(s => findings.push({ rule: 'HARDCODED_SECRET', type: s.type || 'KEY', token: s.token ? '***' : null }));
        }
      }

      // 3. PII Scanning (detection-engine exports scanWithRegex -> {alerts, redactions})
      const detection = this._getEngine('detection', 'VIGIL_ENGINE');
      let piiHits = 0;
      if (detection && typeof detection.scanWithRegex === 'function') {
        const det = detection.scanWithRegex(prompt) || {};
        const piiList = det.redactions || [];
        if (piiList.length > 0) {
          piiHits = piiList.length;
          isFlagged = true;
          piiList.forEach(p => findings.push({ rule: 'PII_DETECTED', type: p.type, sample: p.text ? p.text.slice(0, 4) + '***' : null }));
        }
      }

      const latencyMs = Math.round((this._now() - start) * 100) / 100;
      const verdict = isBlocked ? 'BLOCK' : (isFlagged ? 'FLAG' : 'PASS');

      return {
        tier: 0,
        name: 'Tier 0: Syntax, ReDoS & PII Engine',
        latencyMs,
        verdict,
        metrics: { redosRisk, secretHits, piiHits },
        findings
      };
    }

    /**
     * Executes prompt through Tier 1: Heuristic Security Firewalls (Injection, Sentinel & Leakage)
     */
    async _executeTier1(prompt) {
      const start = this._now();
      const findings = [];
      let isBlocked = false;
      let isFlagged = false;

      // 1. Injection Firewall (injection-engine exports analyzeInjection -> {level, score, signals})
      const injection = this._getEngine('injection', 'VIGIL_INJECTION');
      let injectionResult = null;
      if (injection && typeof injection.analyzeInjection === 'function') {
        injectionResult = injection.analyzeInjection(prompt);
        if (injectionResult && injectionResult.level === 'dangerous') {
          isBlocked = true;
          const signals = injection.topSignals ? injection.topSignals(injectionResult) : [];
          signals.forEach(sig => findings.push({ rule: 'INJECTION_PATTERN', signal: sig }));
        } else if (injectionResult && injectionResult.level === 'suspicious') {
          isFlagged = true;
          findings.push({ rule: 'INJECTION_SUSPICION', level: injectionResult.level });
        }
      }

      // 2. Sentinel Scam Analyzer
      const sentinel = this._getEngine('sentinel', 'VIGIL_SENTINEL');
      let sentinelResult = null;
      if (sentinel && typeof sentinel.analyzeMessage === 'function') {
        sentinelResult = sentinel.analyzeMessage(prompt);
        if (sentinelResult && (sentinelResult.level === 'dangerous' || sentinelResult.level === 'scam')) {
          isBlocked = true;
          const signals = sentinel.topSignals ? sentinel.topSignals(sentinelResult) : [];
          signals.forEach(sig => findings.push({ rule: 'SCAM_MANIPULATION', signal: sig }));
        } else if (sentinelResult && sentinelResult.level === 'suspicious') {
          isFlagged = true;
          findings.push({ rule: 'SUSPICIOUS_HEURISTIC', level: sentinelResult.level });
        }
      }

      // 3. Inbound/Outbound Training Data Leakage (leakage-detector exports checkLeakage)
      const leakage = this._getEngine('leakage', 'VIGIL_LEAKAGE');
      let leakageScore = 0;
      if (leakage && typeof leakage.checkLeakage === 'function') {
        const leakRes = leakage.checkLeakage(prompt) || {};
        if (leakRes.isLeakage) {
          leakageScore = leakRes.similarity || 0.9;
          isFlagged = true;
          findings.push({ rule: 'DATA_LEAKAGE', matchType: leakRes.license || leakRes.matchType || 'FINGERPRINT' });
        }
      }

      const latencyMs = Math.round((this._now() - start) * 100) / 100;
      const verdict = isBlocked ? 'BLOCK' : (isFlagged ? 'FLAG' : 'PASS');

      return {
        tier: 1,
        name: 'Tier 1: Injection & Heuristic Sentinel',
        latencyMs,
        verdict,
        metrics: {
          injectionScore: injectionResult ? injectionResult.score : 0,
          sentinelLevel: sentinelResult ? sentinelResult.level : 'none',
          leakageScore
        },
        findings
      };
    }

    /**
     * Executes prompt through Tier 2: Behavioral Trajectory & Shopping Correlation
     */
    async _executeTier2(prompt, options = {}) {
      const start = this._now();
      const findings = [];
      let isBlocked = false;
      let isWarned = false;

      // 1. Jailbreak Shopping Detector (shopping-detector exports checkAndRecordPrompt;
      // dry-run so a forensics replay never writes into live cross-provider tracking)
      const shopping = this._getEngine('shopping', 'VIGIL_SHOPPING');
      let shoppingMatches = 0;
      if (shopping && typeof shopping.checkAndRecordPrompt === 'function') {
        const shopRes = await shopping.checkAndRecordPrompt(prompt, options.provider || 'default_provider', Date.now(), { record: false });
        if (shopRes && shopRes.shoppingDetected) {
          shoppingMatches = shopRes.count || 3;
          isBlocked = true;
          findings.push({ rule: 'JAILBREAK_SHOPPING', message: `Prompt submitted to ${shopRes.count} distinct providers` });
        }
      }

      // 2. Semantic Drift Detector (semantic-drift exports recordTurn -> {driftDetected, baselineDrift})
      const drift = this._getEngine('drift', 'VIGIL_DRIFT');
      let driftScore = 0;
      if (drift && typeof drift.recordTurn === 'function') {
        const driftRes = await drift.recordTurn(options.conversationId || 'forensics_session', prompt);
        if (driftRes && driftRes.driftDetected) {
          driftScore = driftRes.baselineDrift ?? driftRes.driftScore ?? 0.85;
          isWarned = true;
          findings.push({ rule: 'SEMANTIC_DRIFT', distance: driftRes.baselineDrift ?? driftRes.driftScore });
        }
      }

      const latencyMs = Math.round((this._now() - start) * 100) / 100;
      const verdict = isBlocked ? 'BLOCK' : (isWarned ? 'WARN' : 'PASS');

      return {
        tier: 2,
        name: 'Tier 2: Behavioral Trajectory & Shopping',
        latencyMs,
        verdict,
        metrics: { shoppingMatches, driftScore },
        findings
      };
    }

    /**
     * Executes prompt through Tier 3: Multi-Model Consensus Firewall
     */
    async _executeTier3(prompt) {
      const start = this._now();
      const findings = [];
      let isBlocked = false;
      let isWarned = false;

      const consensus = this._getEngine('consensus', 'VIGIL_CONSENSUS');
      let consensusVerdict = 'UNAVAILABLE';
      let agreement = null;
      let confidence = null;
      let votes = [];

      if (consensus && typeof consensus.evaluate === 'function') {
        const conRes = await consensus.evaluate(prompt, 'injection');
        if (conRes) {
          isBlocked = conRes.verdict === 'blocked';
          isWarned = conRes.verdict === 'soft_block';
          consensusVerdict = conRes.verdict === 'blocked' ? 'BLOCK' : (conRes.verdict === 'soft_block' ? 'SOFT_BLOCK' : (conRes.verdict === 'unclear' ? 'UNCLEAR' : 'ALLOW'));
          agreement = conRes.agreement || null;
          // consensus-firewall confidence is 0-100; the timeline reports 0-1
          confidence = typeof conRes.confidence === 'number' ? Math.min(1, conRes.confidence / 100) : null;
          votes = conRes.votes || [];
          if (isBlocked) {
            findings.push({ rule: 'CONSENSUS_BLOCK', agreement, confidence });
          } else if (isWarned) {
            findings.push({ rule: 'CONSENSUS_SOFT_BLOCK', agreement, confidence });
          }
        }
      }

      const latencyMs = Math.round((this._now() - start) * 100) / 100;
      // When the consensus firewall is unavailable the tier reports SKIPPED —
      // never a simulated verdict. A soft block (1 block + abstentions) is a WARN.
      const verdict = isBlocked ? 'BLOCK' : (isWarned ? 'WARN' : (consensusVerdict === 'UNAVAILABLE' ? 'SKIPPED' : 'PASS'));

      return {
        tier: 3,
        name: 'Tier 3: Multi-Model Consensus Firewall',
        latencyMs,
        verdict,
        metrics: { consensusVerdict, agreement, confidence, votes },
        findings
      };
    }

    /**
     * Replays a prompt through all defense tiers with detailed instrumentation
     */
    async replayPrompt(prompt, options = {}) {
      if (typeof prompt !== 'string') {
        throw new TypeError('Prompt must be a string');
      }

      const pipelineStart = this._now();
      const timeline = [];

      // Execute Tiers Sequentially
      const t0 = await this._executeTier0(prompt);
      timeline.push(t0);

      const t1 = await this._executeTier1(prompt);
      timeline.push(t1);

      const t2 = await this._executeTier2(prompt, options);
      timeline.push(t2);

      const t3 = await this._executeTier3(prompt);
      timeline.push(t3);

      const totalLatencyMs = Math.round((this._now() - pipelineStart) * 100) / 100;

      // Determine Overall Pipeline Verdict
      // Hierarchy: BLOCK > WARN > FLAG > PASS
      let overallVerdict = 'PASS';
      if (t0.verdict === 'BLOCK' || t1.verdict === 'BLOCK' || t2.verdict === 'BLOCK' || t3.verdict === 'BLOCK') {
        overallVerdict = 'BLOCK';
      } else if (t2.verdict === 'WARN' || t3.verdict === 'WARN') {
        overallVerdict = 'WARN';
      } else if (t0.verdict === 'FLAG' || t1.verdict === 'FLAG') {
        overallVerdict = 'FLAG';
      }

      const report = {
        id: 'replay_' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        prompt: prompt.length > 200 ? prompt.slice(0, 200) + '…' : prompt,
        promptLength: prompt.length,
        totalLatencyMs,
        overallVerdict,
        timeline,
        summary: {
          tiersRun: timeline.length,
          totalFindings: timeline.reduce((acc, t) => acc + (t.findings ? t.findings.length : 0), 0),
          fastestTierMs: Math.min(...timeline.map(t => t.latencyMs)),
          slowestTierMs: Math.max(...timeline.map(t => t.latencyMs))
        }
      };

      await this._saveToHistory(report);
      return report;
    }

    async _saveToHistory(report) {
      if (!this.storage) return;
      try {
        const stored = await this.storage.get([FORENSICS_HISTORY_KEY]);
        const history = stored[FORENSICS_HISTORY_KEY] || [];
        history.unshift(report);
        if (history.length > MAX_HISTORY_ITEMS) {
          history.length = MAX_HISTORY_ITEMS;
        }
        await this.storage.set({ [FORENSICS_HISTORY_KEY]: history });
      } catch {
        // Storage write ignored in sandbox / memory mode
      }
    }

    async getHistory() {
      if (!this.storage) return [];
      try {
        const stored = await this.storage.get([FORENSICS_HISTORY_KEY]);
        return stored[FORENSICS_HISTORY_KEY] || [];
      } catch {
        return [];
      }
    }

    async clearHistory() {
      if (!this.storage) return true;
      try {
        await this.storage.set({ [FORENSICS_HISTORY_KEY]: [] });
        return true;
      } catch {
        return false;
      }
    }
  }

  const forensicsReplayEngine = new ForensicsReplayEngine();

  const ForensicsModule = {
    ForensicsReplayEngine,
    forensicsReplayEngine,
    FORENSICS_HISTORY_KEY
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ForensicsModule;
  }
  if (root) {
    root.VIGIL_FORENSICS = ForensicsModule;
    root.forensicsReplayEngine = forensicsReplayEngine;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
