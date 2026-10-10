/**
 * VIGIL Injection Firewall Engine
 * Detects prompt-injection patterns in page text: content crafted to hijack
 * an AI system (agent browsing the page, model reading pasted text) instead
 * of the human reader. Pure and offline; scoring mirrors the Sentinel engine.
 */
(function (root) {
  'use strict';

  // Score thresholds (mirrors Sentinel's ladder).
  const THRESHOLDS = { dangerousScore: 55, suspiciousScore: 30, lowScore: 12 };

  const INJECTION_SIGNALS = [
    // matches: "ignore all previous instructions", "disregard your training", "system override"
    { id: 'override', label: 'Tries to override AI instructions', weight: 60, re: /\b(?:ignore|disregard|forget|override) (?:all |any |the |your |previous |prior |above |earlier |original )*?(?:previous |prior |above |earlier |original |system |developer |safety |content )?(?:instructions?|prompts?|rules?|guidelines?|guardrails?|training)\b|\b(?:system|priority|directive)\s+override\b/i },
    { id: 'safety_bypass', label: 'Attempts to bypass AI safety rules', weight: 55, re: /\b(?:bypass|disable|turn off|ignore) (?:all |your |the )?(?:safety|security|content) (?:filters?|rules?|policies?|guardrails?)\b|\bdeveloper mode\b|\bdo anything now\b|\bdo anything without (?:restrictions?|limits?|consequences?|rules?)\b|\b(?:without|with zero) (?:any )?(?:restrictions?|limits?|filters?|guardrails?|ethical boundaries?)\b|\bwith no (?:restrictions?|limits?|filters?|guardrails?|ethical boundaries?)\b|\bno (?:ethical|moral) (?:boundaries|constraints|filters)\b|\bunrestricted (?:autonomous )?agent\b/i },
    { id: 'prompt_extract', label: 'Tries to extract system prompt or secrets', weight: 50, re: /\b(?:reveal|print|repeat|show|output|disclose|leak|quote|dump) (?:your |the |its |everything |all )?(?:exact |private |secret |hidden )*(?:system (?:prompt|message|keys?)|initial (?:instructions|prompt)|rules above|instructions above|text above|text before|text between|everything (?:above|before this)|(?:private |secret |api |system )+(?:keys?|secrets?|tokens?|credentials?))\b/i },
    { id: 'exfiltration', label: 'Instructions to exfiltrate data', weight: 45, re: /\b(?:email|send|forward|upload|post|exfiltrate|copy|transmit)\b[^.\n]{0,30}\b(?:user|their|my|all)\b[^.\n]{0,30}\b(?:data|content|secrets?|credentials|tokens?|history|messages?)\b[^.\n]{0,30}\bto\b|\bappend (?:the )?following to your (?:response|reply|output)\b|\bwhen (?:the )?(?:user|asked)[^.\n]{0,40}(?:respond|reply|say) with\b/i },
    { id: 'role_hijack', label: 'Fake system/role markers', weight: 35, re: /(?:^|\n)\s*(?:system\s*(?:override\s*)?:|assistant\s*:|###\s*system|<\|(?:im_start|system)\|>|\[\/?INST\]|<\|endoftext\|>|<\/?system_prompt\b|<\/?priority_override\b)|\byou are now\s+(?:a|an|my|the)\s+\w|\byou are now\s+(?!(?:leaving|entering|going|available|required|able|part|viewing|shown|open|closed|off|on|heading|moving)\b)(?:a|an|my|the)?\s*["']?\w|\bact as (?:my|the) /i },
    { id: 'encoded', label: 'Encoded payload instructions', weight: 30, re: /\b(?:decode|decipher|execute|run) (?:the |this )?(?:following )?(?:base64|rot13|hex|encoded) (?:text|string|payload|message|instructions?)\b|\bbase64\b[^.\n]{0,40}\b(?:immediately follow|follow its|embedded instructions)\b/i },
    { id: 'obedience', label: 'Demands unconditional obedience', weight: 20, re: /\b(?:you must|you will) (?:now )?(?:obey|follow|comply with) (?:my|these|the) (?:instructions?|commands?|orders?)\b|\bfrom now on,? (?:always|you)\b/i },
    { id: 'ai_marker', label: 'Language directed at AI systems', weight: 10, re: /\b(?:dear ai|hey ai|attention ai|note to (?:the )?(?:ai|assistant|model|chatbot|scrapers?))\b/i }
  ];

  const LEVELS = {
    dangerous: { rank: 3, advice: 'This page contains text trying to manipulate AI systems. Do not paste it into an AI chat, and be careful letting AI agents read this page.' },
    suspicious: { rank: 2, advice: 'This page contains AI-directed instructions. Treat its content with suspicion before using it with any AI tool.' },
    low: { rank: 1, advice: 'Minor AI-directed language detected on this page.' },
    none: { rank: 0, advice: '' }
  };

  /**
   * Analyze a text block for prompt-injection patterns.
   * @returns {{level: string, score: number, signals: Array<{id,label,weight}>, advice: string}}
   */
  function analyzeInjection(text) {
    if (!text || text.length < 15) return { level: 'none', score: 0, signals: [], advice: LEVELS.none.advice };
    // Blueprint #3: score the canonicalized copy — zero-width smuggling,
    // homoglyphs, fullwidth forms and leet must not evade the patterns.
    const normalizer = typeof VIGIL_NORMALIZER !== 'undefined' ? VIGIL_NORMALIZER : null;
    const textNorm = normalizer ? normalizer.normalizeAdversarialText(text) : text;
    let score = 0;
    const signals = [];
    for (const sig of INJECTION_SIGNALS) {
      if (sig.re.test(textNorm)) {
        score += sig.weight;
        signals.push({ id: sig.id, label: sig.label, weight: sig.weight });
      }
    }
    // Flag adversarial homoglyph or zero-width character evasion
    if (normalizer && normalizer.isObfuscated(text) && signals.length > 0) {
      score += 40;
      signals.push({ id: 'obfuscation', label: 'Adversarial homoglyph/zero-width obfuscation detected', weight: 40 });
    }
    const has = id => signals.some(s => s.id === id);
    let level = 'none';
    if (score >= THRESHOLDS.dangerousScore || has('override') || has('safety_bypass') || has('prompt_extract') || has('encoded') || has('exfiltration')) level = 'dangerous';
    else if (score >= THRESHOLDS.suspiciousScore) level = 'suspicious';
    else if (score >= THRESHOLDS.lowScore) level = 'low';
    return { level, score, signals, advice: LEVELS[level].advice };
  }

  function topSignals(result, n) {
    return result.signals
      .slice()
      .sort((a, b) => b.weight - a.weight)
      .slice(0, n || 2)
      .map(s => s.label);
  }

  const VIGIL_INJECTION = { analyzeInjection, topSignals, INJECTION_SIGNALS, LEVELS };
  root.VIGIL_INJECTION = VIGIL_INJECTION;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_INJECTION;
})(typeof self !== 'undefined' ? self : globalThis);
