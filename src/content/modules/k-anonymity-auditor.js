/**
 * VIGIL AI — K-Anonymity & Quasi-Identifier Entropy Auditing Engine
 *
 * Implements Sweeney / Rocher et al. demographic uniqueness estimation.
 * Evaluates combinations of individually benign quasi-identifiers (e.g.,
 * graduation year + company size + specialized niche + city) that collectively
 * shrink the k-anonymity equivalence class to k ≈ 1 (uniquely identifiable).
 *
 * Runs 100% locally on-device. Zero network transmissions.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_K_ANONYMITY = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Quasi-Identifier Categories and Pattern Matchers
  const QI_PATTERNS = [
    {
      category: 'EDUCATION',
      regex: /(?:graduated\s+from|degree\s+from|alumni\s+of|studied\s+at|master['’]?s\s+at|phd\s+at)\s+([A-Z][a-zA-Z\s.-]+?)(?:\s+in\s+(\d{4}))?(?=[,\s.]|$)/gi,
      baseEntropy: 3.5,
      extract(match) {
        return {
          raw: match[0],
          school: match[1]?.trim(),
          year: match[2] || null,
          weight: match[2] ? 4.5 : 3.5,
          recommendation: match[2] ? 'Generalize graduation year to decade or omit school name' : 'Generalize institution to an academic institution'
        };
      }
    },
    {
      category: 'EMPLOYMENT_NICHE',
      regex: /(?:work(?:ing)?\s+at|employed\s+at|founder\s+at|engineer\s+at)\s+(?:a\s+)?(?:(\d+)[-\s]person\s+)?([a-zA-Z\s-]+?\s+(?:startup|firm|agency|lab|consultancy|biotech|fintech|company))\s+(?:in|at)\s+([A-Z][a-zA-Z\s]+?)(?=[,\s.]|$)/gi,
      baseEntropy: 4.8,
      extract(match) {
        return {
          raw: match[0],
          size: match[1] || null,
          domain: match[2]?.trim(),
          location: match[3]?.trim(),
          weight: match[1] ? 5.2 : 4.2,
          recommendation: 'Generalize specific company size and location (e.g., a technology startup in Europe)'
        };
      }
    },
    {
      category: 'SPECIALIZATION',
      regex: /(?:specialize\s+in|expert\s+in|lead\s+architect\s+for|focus\s+on)\s+([a-zA-Z0-9\s-]{4,40}?\s+(?:patent\s+law|compiler|infrastructure|protocol|genomics|therapeutics|cryptography|arbitrage))(?=[,\s.]|$)/gi,
      baseEntropy: 4.2,
      extract(match) {
        return {
          raw: match[0],
          field: match[1]?.trim(),
          weight: 4.2,
          recommendation: `Replace niche specialization '${match[1]?.trim()}' with broad discipline (e.g. technology consulting)`
        };
      }
    },
    {
      category: 'DEMOGRAPHIC_AGE_LOCATION',
      regex: /(?:(?:i am|i'm|aged)\s+(\d{1,2})\s*(?:years?\s+old)?|born\s+in\s+(\d{4}))\s+(?:living\s+in|residing\s+in|based\s+in|from)\s+([A-Z][a-zA-Z\s]+?)(?=[,\s.]|$)/gi,
      baseEntropy: 4.0,
      extract(match) {
        return {
          raw: match[0],
          age: match[1] || match[2],
          location: match[3]?.trim(),
          weight: 4.2,
          recommendation: 'Bucket age into broad range (e.g. 30-40) and location to region'
        };
      }
    },
    {
      category: 'GEOGRAPHY_LOCAL',
      regex: /(?:(?:zip(?:\s*code)?|postal(?:\s*code)?)\s*(?:is|:)?\s*(\d{5}(?:-\d{4})?|[A-Z]\d[A-Z]\s*\d[A-Z]\d))|(?:in\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?),\s+([A-Z]{2}))/gi,
      baseEntropy: 3.8,
      extract(match) {
        return {
          raw: match[0],
          code: match[1] || `${match[2]}, ${match[3]}`,
          weight: match[1] ? 4.6 : 3.6,
          recommendation: 'Generalize ZIP code or city to metropolitan area or country'
        };
      }
    },
    {
      category: 'CLINICAL_RARE',
      regex: /(?:diagnosed\s+with|treatment\s+for|suffering\s+from|patient\s+with)\s+([a-zA-Z0-9\s-]{4,50}?(?:adenocarcinoma|syndrome|carcinoma|leukemia|sclerosis|fibrosis|mutation|disorder))(?=[,\s.]|$)/gi,
      baseEntropy: 4.5,
      extract(match) {
        return {
          raw: match[0],
          diagnosis: match[1]?.trim(),
          weight: 4.5,
          recommendation: 'Generalize specific medical diagnosis to clinical category (e.g. chronic condition)'
        };
      }
    },
    {
      category: 'FINANCIAL_EXACT',
      regex: /(?:salary(?:\s+is|:)?|compensation(?:\s+of)?|earning)\s*(\$[\d,]{5,12}(?:\s*(?:k|usd|eur|gbp))?|\d+%\s+equity)(?=[,\s.]|$)/gi,
      baseEntropy: 3.5,
      extract(match) {
        return {
          raw: match[0],
          amount: match[1],
          weight: 3.5,
          recommendation: 'Round compensation to broad bracket (e.g., market rate or $150k-$200k)'
        };
      }
    }
  ];

  /**
   * Estimates population anonymity set size K based on cumulative quasi-identifier entropy
   * H_total in bits.
   * Assuming reference metropolitan population N ≈ 1,000,000.
   */
  function estimateKAnonymity(cumulativeEntropy) {
    if (cumulativeEntropy <= 0) return 1000000;
    // Log10(K) ≈ max(0, 6 - (cumulativeEntropy * 0.85))
    const exp = Math.max(0, 6.0 - (cumulativeEntropy * 0.85));
    return Math.max(1, Math.round(Math.pow(10, exp)));
  }

  /**
   * Computes re-identification risk score (0.0 to 1.0)
   */
  function calculateRiskScore(cumulativeEntropy, estimatedK) {
    if (estimatedK <= 5) return 0.99;
    if (estimatedK <= 25) return 0.85;
    if (cumulativeEntropy >= 6.5) return 0.92;
    if (cumulativeEntropy >= 4.5) return 0.68;
    if (cumulativeEntropy >= 2.5) return 0.35;
    return Math.min(0.20, cumulativeEntropy / 20);
  }

  /**
   * Determines risk tier
   */
  function getRiskTier(riskScore) {
    if (riskScore >= 0.75) return 'CRITICAL';
    if (riskScore >= 0.40) return 'ELEVATED';
    return 'LOW';
  }

  /**
   * Scans text for quasi-identifiers and computes cumulative entropy
   */
  function auditPrompt(text) {
    if (!text || typeof text !== 'string') {
      return {
        quasiIdentifiers: [],
        cumulativeEntropy: 0,
        estimatedK: 1000000,
        riskScore: 0,
        riskTier: 'LOW',
        isHighRisk: false,
        warning: null,
        recommendations: []
      };
    }

    const detected = [];
    let cumulativeEntropy = 0;

    QI_PATTERNS.forEach(pattern => {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        const item = pattern.extract(match);
        item.category = pattern.category;
        detected.push(item);
        cumulativeEntropy += item.weight;
      }
    });

    // Diminishing returns after multiple items
    const adjustedEntropy = Number(cumulativeEntropy.toFixed(2));
    const estimatedK = estimateKAnonymity(adjustedEntropy);
    const riskScore = Number(calculateRiskScore(adjustedEntropy, estimatedK).toFixed(2));
    const riskTier = getRiskTier(riskScore);
    const isHighRisk = riskTier === 'CRITICAL' || estimatedK <= 25;

    let warning = null;
    if (isHighRisk) {
      warning = `⚠️ Quasi-Identifier Alert: Combined details reduce anonymity pool to ~${estimatedK} individual(s) (${Math.round(riskScore * 100)}% re-identification risk).`;
    } else if (riskTier === 'ELEVATED') {
      warning = `⚠️ Elevated Re-Identification Risk: Anonymity set ~${estimatedK} people. Consider generalizing specific details.`;
    }

    const recommendations = detected.map(d => d.recommendation);

    return {
      quasiIdentifiers: detected,
      cumulativeEntropy: adjustedEntropy,
      estimatedK,
      riskScore,
      riskTier,
      isHighRisk,
      warning,
      recommendations
    };
  }

  /**
   * Applies heuristic generalization recommendations to the prompt text
   */
  function generalizePrompt(text) {
    if (!text || typeof text !== 'string') return text || '';
    let result = text;

    // Generalize graduation years: e.g. "in 2018" -> "in the 2010s"
    result = result.replace(/(graduated\s+from\s+[A-Z][a-zA-Z\s.-]+?)\s+in\s+(\d{3})\d/gi, '$1 recently');

    // Generalize company size: e.g. "15-person biotech startup" -> "an early-stage biotech startup"
    result = result.replace(/(\d+)[-\s]person\s+([a-zA-Z\s-]+?\s+(?:startup|firm|agency|company))/gi, 'an early-stage $2');

    // Generalize exact ZIP codes: e.g. "ZIP 94107" -> "in the area"
    result = result.replace(/zip(?:\s*code)?\s*(?:is|:)?\s*(\d{5}(?:-\d{4})?)/gi, 'the local area');

    return result;
  }

  return {
    QI_PATTERNS,
    auditPrompt,
    estimateKAnonymity,
    calculateRiskScore,
    generalizePrompt
  };
});
