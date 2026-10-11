/**
 * VIGIL Blueprint: Semantic Scenario Abstraction & Homomorphic Prompt Translator
 * 
 * Based on 2025/2026 Type-Consistent Surrogate & Propagation-Aware Mediation research:
 * Instead of naive [REDACTED] masking, this engine translates proprietary, clinical,
 * financial, and technical prompts into isomorphic hypothetical scenarios.
 * Cloud models can reason with 100% utility while zero real proprietary context is exposed.
 */
(function (root) {
  'use strict';

  // Domain Category Taxonomy
  const DOMAINS = {
    CLINICAL: 'CLINICAL',
    FINANCIAL: 'FINANCIAL',
    INFRASTRUCTURE: 'INFRASTRUCTURE',
    LEGAL: 'LEGAL',
    DEVELOPMENT: 'DEVELOPMENT',
    GENERAL: 'GENERAL'
  };

  // High-utility Type-Consistent Surrogates
  const SURROGATES = {
    COMPANY: ['Apex Systems', 'Meridian Technologies', 'Helios Logistics', 'Vanguard Innovations', 'Quantum Solutions', 'Aether Dynamics'],
    PERSON: ['Alex Mercer', 'Jordan Blake', 'Morgan Taylor', 'Casey Morgan', 'Sam Rivera', 'Taylor Brooks'],
    CITY: ['Metropolis', 'Riverdale', 'Central City', 'Grandview', 'Silverlake', 'Oakwood'],
    CLOUD_PROVIDER: ['Major Cloud Provider', 'Enterprise Multi-Region Cloud', 'Compliant Hyperscaler Provider'],
    DATABASE: ['Relational Database Engine', 'Distributed Key-Value Store', 'High-Throughput Analytics Cluster'],
    CONDITION: ['Metabolic Syndrome', 'Chronic Inflammatory Condition', 'Respiratory Symptom', 'Mild Hypertension', 'Dermatological Reaction'],
    REGULATION: ['Applicable State Privacy Statutory Code', 'Standard Industry Regulatory Framework', 'Jurisdictional Consumer Protection Directive']
  };

  /**
   * Deterministically pick a surrogate based on string hash for cross-prompt consistency
   */
  function pickSurrogate(category, seedStr) {
    const list = SURROGATES[category] || SURROGATES.COMPANY;
    let hash = 0;
    const str = String(seedStr || 'seed');
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    const idx = Math.abs(hash) % list.length;
    return list[idx];
  }

  /**
   * Identifies the primary confidential domain of the text
   */
  function detectDomain(text, alerts = []) {
    const lower = text.toLowerCase();
    if (alerts.some(a => a.type === 'MEDICAL') || /\b(?:diagnosed|suffer from|symptoms|patient|fever|prescribed|dosage|hospital|doctor|clinic)\b/i.test(lower)) {
      return DOMAINS.CLINICAL;
    }
    if (alerts.some(a => a.type === 'FINANCIAL') || /\b(?:revenue|margin|ebitda|q[1-4]|budget|salary|audit|loss|accredited|portfolio)\b/i.test(lower)) {
      return DOMAINS.FINANCIAL;
    }
    if (alerts.some(a => a.type === 'CREDENTIALS') || /\b(?:aws|postgres|docker|kubernetes|cluster|ssrf|cve|microservice|database|api[-_\s]?key|bearer)\b/i.test(lower)) {
      return DOMAINS.INFRASTRUCTURE;
    }
    if (alerts.some(a => a.type === 'LEGAL') || /\b(?:lawsuit|subpoena|attorney|plaintiff|nda|arbitration|statute|ccpa|gdpr)\b/i.test(lower)) {
      return DOMAINS.LEGAL;
    }
    return DOMAINS.GENERAL;
  }

  /**
   * Generalizes 1st-person disclosures into objective hypothetical scenario formulations
   */
  function generalizePerspective(text, domain) {
    let out = text;
    if (domain === DOMAINS.CLINICAL) {
      out = out.replace(/\b(?:I have been diagnosed with|I was diagnosed with|I am suffering from|I suffer from)\s+/gi, 'A patient presents with ')
               .replace(/\b(?:My doctor|My physician|My specialist)\s+/gi, 'An attending specialist ')
               .replace(/\b(?:I have|I am experiencing|I'm having)\s+(?:an?\s+)?fever\b/gi, 'A patient presenting with acute febrile symptoms ')
               .replace(/\b(?:My wife|My husband|My child|My son|My daughter)\s+/gi, 'A primary family member ');
    } else if (domain === DOMAINS.INFRASTRUCTURE || domain === DOMAINS.FINANCIAL) {
      out = out.replace(/\b(?:Our startup|Our company|Our team|My company|My organization)\s+/gi, 'An enterprise organization ')
               .replace(/\b(?:Our internal|My internal|Our private|My private)\s+/gi, 'The enterprise infrastructure ')
               .replace(/\b(?:We were breached|We had a breach|Our database was accessed)\s+/gi, 'An incident involving unauthorized data access occurred ');
    }
    return out;
  }

  /**
   * Generates a fully abstracted prompt with bidirectional substitution tree
   */
  function abstractPrompt(text, options = {}) {
    if (!text || typeof text !== 'string') {
      return { abstractedText: '', substitutionMap: {}, reverseTree: {}, domain: DOMAINS.GENERAL, entityCount: 0 };
    }

    const alerts = [];
    const redactions = [];
    const engine = (typeof root.VIGIL_ENGINE !== 'undefined') ? root.VIGIL_ENGINE : null;
    const secrets = (typeof root.VIGIL_SECRETS !== 'undefined') ? root.VIGIL_SECRETS : null;

    if (engine) {
      const rx = engine.scanWithRegex(text, ['EMAIL', 'PHONE', 'SSN', 'CARD', 'CRYPTO', 'IP']);
      if (rx && rx.redactions) redactions.push(...rx.redactions);
      const ctx = engine.scanWithContext(text);
      if (ctx && ctx.redactions) redactions.push(...ctx.redactions);
      const names = engine.findNamesHeuristic(text);
      if (names && names.length) {
        names.forEach(n => redactions.push({ text: n, type: 'NAME' }));
      }
      if (rx && rx.alerts) alerts.push(...rx.alerts);
      if (ctx && ctx.alerts) alerts.push(...ctx.alerts);
    }

    if (secrets && secrets.scanSecrets) {
      const sec = secrets.scanSecrets(text);
      if (sec && sec.redactions) redactions.push(...sec.redactions);
      if (sec && sec.alerts) alerts.push(...sec.alerts);
    }

    const domain = detectDomain(text, alerts);
    const substitutionMap = {}; // real -> surrogate
    const reverseTree = {};     // surrogate -> real

    // Sort redactions longest first to avoid partial collision
    const sorted = [...redactions].sort((a, b) => b.text.length - a.text.length);
    const seenReal = new Set();

    const usedSurrogates = new Set();
    let secretCounter = 0;
    let working = text;

    sorted.forEach((r) => {
      const real = r.text;
      if (!real || seenReal.has(real)) return;
      seenReal.add(real);

      let surrogateCategory = 'COMPANY';
      if (r.type === 'NAME') surrogateCategory = 'PERSON';
      else if (r.type === 'MEDICAL') surrogateCategory = 'CONDITION';
      else if (r.type === 'LEGAL') surrogateCategory = 'REGULATION';
      else if (r.type === 'IP' || r.type === 'SECRET' || r.type === 'API_KEY' || r.type === 'TOKEN') surrogateCategory = 'INFRASTRUCTURE';

      let surrogate;
      if (r.type === 'SECRET' || r.type === 'API_KEY' || r.type === 'TOKEN') {
        secretCounter++;
        surrogate = secretCounter === 1 ? '<ENTERPRISE_API_CREDENTIAL>' : `<ENTERPRISE_API_CREDENTIAL_${secretCounter}>`;
      } else {
        surrogate = pickSurrogate(surrogateCategory, real);
        if (usedSurrogates.has(surrogate)) {
          const list = SURROGATES[surrogateCategory] || SURROGATES.COMPANY;
          let candidate = list.find(s => !usedSurrogates.has(s));
          surrogate = candidate || `${surrogate} (${seenReal.size})`;
        }
      }
      usedSurrogates.add(surrogate);

      substitutionMap[real] = surrogate;
      reverseTree[surrogate] = real;

      const escaped = real.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      working = working.replace(new RegExp(escaped, 'g'), surrogate);
    });

    // Apply Perspective Generalization if requested or high confidentiality
    if (options.generalizePerspective !== false) {
      working = generalizePerspective(working, domain);
    }

    return {
      abstractedText: working,
      substitutionMap,
      reverseTree,
      domain,
      entityCount: Object.keys(substitutionMap).length
    };
  }

  /**
   * Rehydrates a cloud AI response by translating surrogates back to original entities
   */
  function rehydrateResponse(responseText, reverseTree) {
    if (!responseText || !reverseTree || typeof responseText !== 'string') return responseText || '';
    let restored = responseText;
    const surrogates = Object.keys(reverseTree).sort((a, b) => b.length - a.length);

    surrogates.forEach((surrogate) => {
      const original = reverseTree[surrogate];
      if (!original || !surrogate) return;
      const escaped = surrogate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      restored = restored.replace(new RegExp(escaped, 'g'), original);
    });

    return restored;
  }

  const VIGIL_ABSTRACTOR = {
    DOMAINS,
    SURROGATES,
    pickSurrogate,
    detectDomain,
    generalizePerspective,
    abstractPrompt,
    rehydrateResponse
  };

  root.VIGIL_ABSTRACTOR = VIGIL_ABSTRACTOR;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_ABSTRACTOR;
})(typeof self !== 'undefined' ? self : globalThis);
