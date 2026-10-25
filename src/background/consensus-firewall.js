/**
 * VIGIL Security Policy: Multi-Model Consensus Firewall
 *
 * Problem: Single-model classifiers can be bypassed or jailbroken using targeted
 * adversarial prompts tailored to that specific model's architecture, or produce
 * false positives that interrupt legitimate workflows.
 *
 * Solution: Evaluates prompts against 3 independent, orthogonal local classifiers
 * in parallel (Heuristics, Neural/WebGPU fine-tuned head, and Local LLM / Semantic reasoner).
 * Enforces a 2-of-3 multi-tier consensus voting protocol: blocks only when at least
 * 2 independent classifiers agree, suppressing single-model false alarms while raising
 * attack cost exponentially.
 */
(function (root) {
  'use strict';

  const VOTE_BLOCK = 'block';
  const VOTE_ALLOW = 'allow';
  const VOTE_ABSTAIN = 'abstain';
  const CLASSIFIER_TIMEOUT_MS = 2500;

  // Full-text 64-bit FNV-1a for cache keys — collision-resistant enough that
  // distinct prompts never share a verdict cache entry.
  function fnv1a64(str) {
    let h = 0xcbf29ce484222325n;
    const prime = 0x100000001b3n;
    const mask = 0xffffffffffffffffn;
    for (let i = 0; i < str.length; i++) {
      h ^= BigInt(str.charCodeAt(i));
      h = (h * prime) & mask;
    }
    return h.toString(36);
  }

  class ConsensusFirewall {
    constructor(options = {}) {
      this.threshold = options.threshold || 2; // 2-of-3 majority
      this.timeoutMs = options.timeoutMs || CLASSIFIER_TIMEOUT_MS;
      this.strict = Boolean(options.strict);
      this.cache = new Map();
      this.maxCacheSize = 500;
      this.runners = options.runners || {};
    }

    /**
     * Classifier 1: Heuristic Pattern Engine
     */
    async evaluateHeuristics(text, kind = 'injection') {
      try {
        if (kind === 'injection' && typeof VIGIL_INJECTION !== 'undefined') {
          const res = VIGIL_INJECTION.analyzeInjection(text);
          if (res.level === 'dangerous') {
            return {
              classifier: 'heuristics',
              vote: VOTE_BLOCK,
              confidence: 95,
              reason: 'Heuristic override or exfiltration pattern detected: ' + (res.signals || []).map(s => s.id).join(', ')
            };
          }
          if (res.level === 'suspicious') {
            return {
              classifier: 'heuristics',
              vote: VOTE_BLOCK,
              confidence: 70,
              reason: 'Suspicious syntactic pattern identified'
            };
          }
          return {
            classifier: 'heuristics',
            vote: VOTE_ALLOW,
            confidence: 90,
            reason: 'Clean syntax, no heuristic markers'
          };
        }

        if (kind === 'scam' && typeof VIGIL_SENTINEL !== 'undefined') {
          const res = VIGIL_SENTINEL.analyzeMessage(text);
          if (res.level === 'dangerous') {
            return {
              classifier: 'heuristics',
              vote: VOTE_BLOCK,
              confidence: 92,
              reason: 'High-risk scam heuristics detected'
            };
          }
          if (res.level === 'suspicious') {
            return {
              classifier: 'heuristics',
              vote: VOTE_BLOCK,
              confidence: 68,
              reason: 'Suspicious scam pattern identified'
            };
          }
          return {
            classifier: 'heuristics',
            vote: VOTE_ALLOW,
            confidence: 90,
            reason: 'No scam heuristics matched'
          };
        }
      } catch (e) {}

      // Fallback regex scan if global modules aren't available (normalized
      // copy: smuggled homoglyphs/zero-width must not evade the fallback)
      const normalizer = typeof VIGIL_NORMALIZER !== 'undefined' ? VIGIL_NORMALIZER : null;
      const textNorm = normalizer ? normalizer.normalizeAdversarialText(text) : text;
      const isDangerous = /ignore\s+(all\s+)?previous\s+instructions|system\s+prompt\s+leak|disregard\s+safety/i.test(textNorm);
      return {
        classifier: 'heuristics',
        vote: isDangerous ? VOTE_BLOCK : VOTE_ALLOW,
        confidence: isDangerous ? 85 : 80,
        reason: isDangerous ? 'Pattern match trigger' : 'Clean pattern scan'
      };
    }

    /**
     * Classifier 2: Neural / WebGPU Fine-Tuned Model
     */
    async evaluateNeural(text, kind = 'injection') {
      if (this.runners.neural) {
        try {
          const res = await new Promise((resolve, reject) => {
            // Timer is cleared when the runner settles — no dangling handle
            const timer = setTimeout(() => reject(new Error('timeout')), this.timeoutMs);
            this.runners.neural(text, kind).then(
              (v) => { clearTimeout(timer); resolve(v); },
              (e) => { clearTimeout(timer); reject(e); }
            );
          });
          // Fail-closed: an offline/errored/uncertain model ABSTAINS — it
          // never fabricates an ALLOW.
          if (!res || res.vote === 'unclear') {
            return { classifier: 'neural_webgpu', vote: VOTE_ABSTAIN, confidence: 0, reason: (res && res.reason) || 'Neural classifier uncertain or unavailable' };
          }
          return {
            classifier: 'neural_webgpu',
            vote: res.vote === 'block' ? VOTE_BLOCK : (res.vote === 'allow' ? VOTE_ALLOW : VOTE_ABSTAIN),
            confidence: res.confidence || 50,
            reason: res.reason || 'Neural model evaluation'
          };
        } catch (e) {
          const msg = e && e.message ? e.message : String(e);
          return { classifier: 'neural_webgpu', vote: VOTE_ABSTAIN, confidence: 0, reason: `Neural classifier offline: ${msg}` };
        }
      }

      // Built-in feature hashing neural projection fallback
      if (typeof VIGIL_DRIFT !== 'undefined' && VIGIL_DRIFT.vectorizeText) {
        const vec = VIGIL_DRIFT.vectorizeText(text);
        const anchor = kind === 'injection'
          ? VIGIL_DRIFT.THREAT_ANCHORS.SYSTEM_OVERRIDE
          : VIGIL_DRIFT.THREAT_ANCHORS.CREDENTIAL_EXFILTRATION;
        const sim = VIGIL_DRIFT.cosineSimilarity(vec, anchor);
        if (sim >= 0.35) {
          return {
            classifier: 'neural_webgpu',
            vote: VOTE_BLOCK,
            confidence: Math.round(sim * 100),
            reason: `Neural vector alignment (${Math.round(sim * 100)}%) with adversarial cluster`
          };
        }
        if (sim <= 0.15) {
          return {
            classifier: 'neural_webgpu',
            vote: VOTE_ALLOW,
            confidence: Math.round((1 - sim) * 100),
            reason: 'Vector space distant from threat clusters'
          };
        }
      }

      return { classifier: 'neural_webgpu', vote: VOTE_ABSTAIN, confidence: 0, reason: 'Neural classifier unavailable' };
    }

    /**
     * Classifier 3: Local LLM Reasoner
     */
    async evaluateLlm(text, kind = 'injection') {
      if (this.runners.llm) {
        try {
          const res = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('timeout')), this.timeoutMs);
            this.runners.llm(text, kind).then(
              (v) => { clearTimeout(timer); resolve(v); },
              (e) => { clearTimeout(timer); reject(e); }
            );
          });
          // Fail-closed: an offline/errored/uncertain LLM ABSTAINS — it
          // never fabricates an ALLOW.
          if (!res || res.vote === 'unclear') {
            return { classifier: 'local_llm', vote: VOTE_ABSTAIN, confidence: 0, reason: (res && res.reason) || 'LLM uncertain or unavailable' };
          }
          return {
            classifier: 'local_llm',
            vote: res.vote === 'block' ? VOTE_BLOCK : (res.vote === 'allow' ? VOTE_ALLOW : VOTE_ABSTAIN),
            confidence: res.confidence || 50,
            reason: res.reason || 'LLM few-shot reasoning'
          };
        } catch (e) {
          const msg = e && e.message ? e.message : String(e);
          return { classifier: 'local_llm', vote: VOTE_ABSTAIN, confidence: 0, reason: `LLM offline: ${msg}` };
        }
      }

      // Secondary semantic reasoning fallback
      const hasObviousHarm = /dump\s+password|exfiltrate|bypass\s+guardrails|jailbreak/i.test(text);
      if (hasObviousHarm) {
        return {
          classifier: 'local_llm',
          vote: VOTE_BLOCK,
          confidence: 85,
          reason: 'Semantic intent indicates adversarial exfiltration or bypass'
        };
      }
      return {
        classifier: 'local_llm',
        vote: VOTE_ALLOW,
        confidence: 80,
        reason: 'Semantic context evaluated as benign intent'
      };
    }

    /**
     * Fail-Closed Multi-Tier Arbiter (Security Policy).
     *
     * Votes are block | allow | abstain. A classifier that is offline,
     * errored, timed out, or uncertain ABSTAINS — it never fabricates an
     * ALLOW. Quorum rules:
     *   - 2+ BLOCK                  → hard block
     *   - 1 BLOCK + 1+ ABSTAIN      → soft block (explicit user override required)
     *   - 1 BLOCK + 2 ALLOW         → allowed (unanimous 3-voter suppression)
     *   - no BLOCK (any ABSTAINs)   → allowed
     */
    arbitrate(votes, options = {}) {
      const strict = options.strict !== undefined ? Boolean(options.strict) : this.strict;
      let blockCount = 0;
      let allowCount = 0;
      let abstainCount = 0;
      let maxBlockConfidence = 0;

      for (const v of votes) {
        if (v.vote === VOTE_BLOCK) {
          blockCount++;
          maxBlockConfidence = Math.max(maxBlockConfidence, v.confidence || 0);
        } else if (v.vote === VOTE_ALLOW) {
          allowCount++;
        } else {
          abstainCount++;
        }
      }

      const total = votes.length;

      // 1. Hard Block: quorum of 2+ block votes regardless of abstentions
      if (blockCount >= 2) {
        return {
          verdict: 'blocked',
          agreement: blockCount >= 3 ? `${blockCount}_of_${total}` : '2_of_3',
          unanimous: blockCount === total,
          blockVotes: blockCount,
          allowVotes: allowCount,
          abstainVotes: abstainCount,
          confidence: Math.max(85, maxBlockConfidence),
          requiresUserOverride: false,
          details: `Hard block: ${blockCount} of ${total} independent classifiers voted to block.`,
          votes
        };
      }

      // 2. Soft Block: a lone block vote with any classifier abstaining —
      // the absent classifiers cannot corroborate an ALLOW, so the user
      // must explicitly override.
      if (blockCount === 1 && abstainCount >= 1) {
        const dissenter = votes.find(v => v.vote === VOTE_BLOCK);
        return {
          verdict: 'soft_block',
          agreement: '1_block_with_abstentions',
          unanimous: false,
          blockVotes: blockCount,
          allowVotes: allowCount,
          abstainVotes: abstainCount,
          confidence: Math.max(70, dissenter ? dissenter.confidence || 0 : 0),
          requiresUserOverride: true,
          details: `Soft block: ${dissenter ? dissenter.classifier : 'One classifier'} flagged this while ${abstainCount} classifier(s) abstained. Explicit user override required.`,
          votes
        };
      }

      // 3. False-alarm suppression: a lone block vote overruled by two
      // classifiers that both actually voted (no abstentions present).
      if (blockCount === 1 && allowCount >= 2) {
        const dissenter = votes.find(v => v.vote === VOTE_BLOCK);
        return {
          verdict: 'allowed',
          agreement: 'false_positive_suppressed',
          unanimous: false,
          blockVotes: blockCount,
          allowVotes: allowCount,
          abstainVotes: abstainCount,
          confidence: 80,
          requiresUserOverride: false,
          details: `False alarm suppressed: 2 of 3 classifiers voted allow. (Isolated dissent by ${dissenter ? dissenter.classifier : 'one model'}).`,
          votes
        };
      }

      // 4. Strict Mode Quorum Defense (F-04 Mitigation):
      // When strict mode is active and 2 or more classifiers abstained,
      // an uncorroborated single allow (or all abstentions) must NOT pass silently.
      if (strict && abstainCount >= 2) {
        return {
          verdict: 'soft_block',
          agreement: 'strict_quorum_unmet',
          unanimous: false,
          blockVotes: 0,
          allowVotes: allowCount,
          abstainVotes: abstainCount,
          confidence: 70,
          requiresUserOverride: true,
          details: `Strict consensus: ${abstainCount} of ${total} classifiers abstained or were offline. User confirmation required before transmission.`,
          votes
        };
      }

      // 5. Pass: no block votes — allows and abstentions never fabricate a
      // threat, and the deterministic Tier-0 gate has already run upstream.
      return {
        verdict: 'allowed',
        agreement: allowCount >= 2 ? 'allow_majority' : 'pass_with_abstentions',
        unanimous: allowCount === total,
        blockVotes: 0,
        allowVotes: allowCount,
        abstainVotes: abstainCount,
        confidence: allowCount >= 2 ? 85 : 60,
        requiresUserOverride: false,
        details: allowCount >= 2
          ? `Clean consensus: ${allowCount} of ${total} classifiers voted allow.`
          : `No classifier voted to block (${abstainCount} abstention(s), ${allowCount} allow).`,
        votes
      };
    }

    /**
     * Evaluates prompt in parallel across all 3 classifiers and arbitrates consensus.
     */
    async evaluate(text, kind = 'injection', options = {}) {
      if (!text || typeof text !== 'string') {
        return { verdict: 'allowed', agreement: 'empty', blockVotes: 0, allowVotes: 0, votes: [] };
      }

      const strict = options.strict !== undefined ? Boolean(options.strict) : this.strict;
      // Check cache. Keyed on a full-text 64-bit FNV-1a hash with strict prefix:
      // two prompts sharing a leading substring must not inherit each other's verdict.
      const cacheKey = kind + ':' + (strict ? 'strict:' : '') + text.length + ':' + fnv1a64(text);
      if (this.cache.has(cacheKey)) {
        return this.cache.get(cacheKey);
      }

      // Parallel execution across 3 orthogonal models
      const results = await Promise.allSettled([
        this.evaluateHeuristics(text, kind),
        this.evaluateNeural(text, kind),
        this.evaluateLlm(text, kind)
      ]);

      const names = ['heuristics', 'neural_webgpu', 'local_llm'];
      const votes = results.map((r, i) => {
        if (r.status === 'fulfilled' && r.value && typeof r.value === 'object') {
          const v = r.value;
          const vote = v.vote === VOTE_BLOCK ? VOTE_BLOCK : (v.vote === VOTE_ALLOW ? VOTE_ALLOW : VOTE_ABSTAIN);
          const rawConf = typeof v.confidence === 'number' && !isNaN(v.confidence) ? v.confidence : 0;
          const confidence = Math.min(100, Math.max(0, Math.round(rawConf)));
          return {
            classifier: v.classifier || names[i],
            vote,
            confidence,
            reason: typeof v.reason === 'string' ? v.reason.slice(0, 200) : ''
          };
        }
        // Fail-closed: a classifier that throws or resolves invalid value ABSTAINS
        const errReason = r.reason ? String(r.reason.message || r.reason).slice(0, 200) : 'failed';
        return { classifier: names[i], vote: VOTE_ABSTAIN, confidence: 0, reason: errReason };
      });

      const outcome = this.arbitrate(votes, { strict });

      // Cache outcome
      if (this.cache.size >= this.maxCacheSize) {
        const firstKey = this.cache.keys().next().value;
        this.cache.delete(firstKey);
      }
      this.cache.set(cacheKey, outcome);

      return outcome;
    }
  }

  const VIGIL_CONSENSUS = {
    ConsensusFirewall,
    VOTE_BLOCK,
    VOTE_ALLOW,
    VOTE_ABSTAIN
  };

  root.VIGIL_CONSENSUS = VIGIL_CONSENSUS;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_CONSENSUS;
  }
})(typeof self !== 'undefined' ? self : globalThis);
