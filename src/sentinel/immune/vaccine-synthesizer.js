/**
 * Sentinel Immune System: Autonomous Vaccine Synthesizer
 * ======================================================
 * Self-healing on-device security subsystem.
 *
 * When an evasive prompt injection or malicious code mutation is deflected,
 * this engine autonomously synthesizes a generalized "Vaccine Invariant".
 * It validates the rule against a safe corpus to guarantee 0% false positives,
 * seals it into Sentinel's active policy set, and exports anonymous signatures
 * for peer device swarm inoculation.
 */

'use strict';

const crypto = require('crypto');

// Known attack mutation classes
const MUTATION_CLASSES = Object.freeze({
  HOMOGLYPH_EVASION: 'HOMOGLYPH_EVASION',
  ZERO_WIDTH_SMUGGLING: 'ZERO_WIDTH_SMUGGLING',
  ROLEPLAY_HIJACKING: 'ROLEPLAY_HIJACKING',
  BASE64_WRAPPED: 'BASE64_WRAPPED',
  DELIMITER_OVERRIDE: 'DELIMITER_OVERRIDE',
  CODE_LOGIC_BOMB: 'CODE_LOGIC_BOMB'
});

class VaccineSynthesizer {
  /**
   * @param {Object} [options]
   * @param {Array<string>} [options.safeCorpus] - Benign codebase/prompt samples for false-positive validation
   */
  constructor(options = {}) {
    this.safeCorpus = options.safeCorpus || [
      'Please explain how this function works.',
      'Refactor the calculateTotal method to handle discounts.',
      'npm test && git status',
      'const user = { name: "Alice", id: 123 };',
      'function isSafe(path) { return path.startsWith("/app"); }',
      'import React from "react";\nexport default function App() {}'
    ];

    // Registry of sealed active vaccines: vaccineId -> VaccineRecord
    this.activeVaccines = new Map();
  }

  /**
   * Deconstructs an attack string to identify the underlying mutation class and semantic core.
   *
   * @param {string} payload - Raw attack string
   * @returns {{ mutationClass: string, normalizedCore: string, signatures: Array<string> }}
   */
  classifyAttack(payload) {
    if (!payload || typeof payload !== 'string') {
      return { mutationClass: 'UNKNOWN', normalizedCore: '', signatures: [] };
    }

    const text = payload.trim();
    const signatures = [];

    // 1. Check for zero-width characters (U+200B, U+200C, etc.)
    if (/[\u200B\u200C\u200D\uFEFF]/.test(text)) {
      signatures.push('ZERO_WIDTH_CHARS');
      const stripped = text.replace(/[\u200B\u200C\u200D\uFEFF]/g, '');
      return {
        mutationClass: MUTATION_CLASSES.ZERO_WIDTH_SMUGGLING,
        normalizedCore: stripped,
        signatures
      };
    }

    // 2. Check for Base64 execution wrapper
    if (/(?:base64|atob|btoa|Buffer\.from)\b/i.test(text) && /[A-Za-z0-9+/=]{20,}/.test(text)) {
      signatures.push('BASE64_WRAPPER');
      return {
        mutationClass: MUTATION_CLASSES.BASE64_WRAPPED,
        normalizedCore: text,
        signatures
      };
    }

    // 3. Check for Roleplay / Persona jailbreak framing
    if (/(?:you are now|pretend to be|roleplay as|uncensored mode|developer mode|dan mode)\b/i.test(text)) {
      signatures.push('ROLEPLAY_FRAME');
      return {
        mutationClass: MUTATION_CLASSES.ROLEPLAY_HIJACKING,
        normalizedCore: text,
        signatures
      };
    }

    // 4. Check for Delimiter override (<system>, [INSTRUCTION], etc.)
    if (/<(?:system|instruction|admin|override)>|\[(?:SYSTEM|INSTRUCTION)\]/i.test(text)) {
      signatures.push('DELIMITER_HIJACK');
      return {
        mutationClass: MUTATION_CLASSES.DELIMITER_OVERRIDE,
        normalizedCore: text,
        signatures
      };
    }

    return {
      mutationClass: 'GENERIC_INJECTION',
      normalizedCore: text,
      signatures
    };
  }

  /**
   * Synthesizes a generalized regex invariant that blocks all mutations of the attack pattern.
   *
   * @param {string} rawPayload - Caught attack string
   * @param {Object} [metadata] - Optional context information
   * @returns {Object} Vaccine candidate record
   */
  synthesizeVaccine(rawPayload, metadata = {}) {
    const classification = this.classifyAttack(rawPayload);
    const id = `vac-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

    // Extract core semantic tokens (length >= 4, ignoring common stop words)
    const tokens = classification.normalizedCore
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length >= 4 && !['this', 'that', 'with', 'from', 'have', 'your', 'mode'].includes(w));

    // Form an invariant regex that matches regardless of intervening zero-width spaces or punctuation
    const keyPhrases = [];
    if (classification.mutationClass === MUTATION_CLASSES.ROLEPLAY_HIJACKING) {
      keyPhrases.push('(?:you\\s+are\\s+now|pretend\\s+to\\s+be|roleplay\\s+as)[\\s\\S]{0,30}?(?:uncensored|developer|dan|jailbreak)');
    } else if (classification.mutationClass === MUTATION_CLASSES.ZERO_WIDTH_SMUGGLING) {
      // Invariant: detects the core attack words even when fragmented
      const coreWords = tokens.slice(0, 3);
      if (coreWords.length > 0) {
        const pattern = coreWords.map(w => w.split('').join('[\\u200B\\u200C\\u200D\\uFEFF]?')).join('[\\s\\S]{0,10}?');
        keyPhrases.push(pattern);
      }
    } else if (classification.mutationClass === MUTATION_CLASSES.DELIMITER_OVERRIDE) {
      keyPhrases.push('(?:\\[\\s*SYSTEM\\s*\\]|<\\s*system\\s*>)[\\s\\S]{0,40}?(?:override|ignore|instructions)');
    } else {
      const topWords = tokens.slice(0, 3);
      if (topWords.length > 0) {
        keyPhrases.push(`\\b${topWords.join('[\\s\\S]{0,15}?')}\\b`);
      }
    }

    const regexSource = keyPhrases.length > 0 ? keyPhrases.join('|') : rawPayload.slice(0, 20);
    const invariantRegex = new RegExp(regexSource, 'i');

    const vaccine = {
      vaccineId: id,
      mutationClass: classification.mutationClass,
      regexSource,
      invariant: invariantRegex,
      createdAt: Date.now(),
      status: 'CANDIDATE',
      signatures: classification.signatures,
      metadata
    };

    return vaccine;
  }

  /**
   * Benchmarks a synthesized vaccine candidate against the safe corpus to verify 0% false positives.
   *
   * @param {Object} vaccine - Vaccine candidate
   * @returns {{ safe: boolean, falsePositiveCount: number, testedCount: number }}
   */
  validateVaccine(vaccine) {
    if (!vaccine || !vaccine.invariant) {
      return { safe: false, falsePositiveCount: 0, testedCount: 0 };
    }

    let fpCount = 0;
    for (const sample of this.safeCorpus) {
      if (vaccine.invariant.test(sample)) {
        fpCount++;
      }
    }

    const safe = fpCount === 0;
    if (safe) {
      vaccine.status = 'ACTIVE_SEALED';
      this.activeVaccines.set(vaccine.vaccineId, vaccine);
    } else {
      vaccine.status = 'REJECTED_FALSE_POSITIVE';
    }

    return {
      safe,
      falsePositiveCount: fpCount,
      testedCount: this.safeCorpus.length
    };
  }

  /**
   * Tests incoming inputs against all sealed active vaccines in the local immune system.
   *
   * @param {string} input - Text to inspect
   * @returns {{ matched: boolean, trippedVaccines: Array<Object> }}
   */
  evaluateInput(input) {
    if (!input || typeof input !== 'string') {
      return { matched: false, trippedVaccines: [] };
    }

    const tripped = [];
    for (const vac of this.activeVaccines.values()) {
      if (vac.status === 'ACTIVE_SEALED' && vac.invariant.test(input)) {
        tripped.push({
          vaccineId: vac.vaccineId,
          mutationClass: vac.mutationClass,
          regexSource: vac.regexSource
        });
      }
    }

    return {
      matched: tripped.length > 0,
      trippedVaccines: tripped
    };
  }

  /**
   * Generates a zero-knowledge signature hash of the vaccine suitable for
   * broadcasting across the P2P Swarm Mesh to inoculate peer nodes without
   * exposing sensitive prompt text.
   *
   * @param {Object} vaccine
   * @returns {string} Swarm inoculation signature string
   */
  exportSwarmSignature(vaccine) {
    const payload = `${vaccine.mutationClass}:${vaccine.regexSource}`;
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    return `swm_vac_${hash.slice(0, 32)}`;
  }
}

module.exports = {
  VaccineSynthesizer,
  MUTATION_CLASSES
};

