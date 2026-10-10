/**
 * VIGIL Sentinel Engine
 * Inbound scam/phishing analysis for AI-generated and AI-delivered messages.
 * Pure and offline: weighted signal detection -> risk score -> level + advice.
 * Features Foundational Cryptographic Alignment (The Ultimate Whitelist) to eliminate
 * false positives on authentic corporate transactional traffic while maintaining zero telemetry.
 * Features Foundational Cryptographic Alignment (The Ultimate Whitelist), Link Target
 * Misdirection detection, and multi-signal corroboration to eliminate false positives
 * on authentic corporate transactional traffic while maintaining zero telemetry.
 */
(function (root) {
  'use strict';

  // Score thresholds. "warn" = suspicious or dangerous (family mode: low too).
  const THRESHOLDS = { dangerousScore: 60, suspiciousScore: 30, lowScore: 12 };
  const SENTINEL_SIGNALS = [
    // Active credential harvesting solicitation (demands user submit/send/reveal secrets)
    { id: 'credential_request', label: 'Requests credentials or codes', weight: 40, re: /\b(?:send|provide|confirm|enter|give|share|reveal|import|update|verify|resend|submit|reply|collect|need)[^.\n]{0,30}\b(?:password|passcode|\botp\b|one[-\s]?time (?:code|password)|verification code|security code|\bpin\b|\bcvv\b|card number|card details|seed phrase|recovery phrase|private key|login (?:credentials|details)|account details|credentials|social security number|\bssn\b)\b|\b(?:your )?(?:password|passcode|seed phrase|private key)\b[^.\n]{0,20}(?:is|are|:)\s*\S+/i },
    // Inbound OTP delivery notification
    { id: 'otp_delivery', label: 'Inbound verification code delivery', weight: 15, re: /\b(?:your|one[-\s]?time|verification|authentication|security) (?:code|otp|passcode)\b[^.\n]{0,20}(?:is|are|:)\s*[\w\d-]{4,10}/i },
    // Action link points to external mismatched destination or raw phishing redirect
    { id: 'link_misdirection', label: 'Action link points to mismatched external destination', weight: 45, re: /(?:login|verify|signin|banking|account)\s*(?:at|on|via)\s*https?:\/\/(?![\w.-]*(?:github|google|apple|microsoft|amazon|paypal|stripe)\.com)\S+/i },
    // Hidden destination via URL shortener
    { id: 'url_shortener', label: 'Hidden destination link via URL shortener', weight: 25, re: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|ow\.ly|buff\.ly|cutt\.ly|rb\.gy)\/\S+/i },
    // Demands urgent payment / wire / gift cards
    { id: 'payment_pressure', label: 'Demands urgent payment', weight: 40, re: /\b(?:wire transfer|wire the (?:money|funds)|gift cards?|itunes card|bitcoin|crypto(?:currency)? wallet|\busdt\b|western union|money ?gram|send (?:money|us|me) (?:\$|\d)|(?:activation|processing|release|registration|administration|administrative|customs|delivery|redelivery|unpaid|recruitment) (?:charge|fee)|release the funds|unclaimed funds)\b/i },
    { id: 'personal_info_fishing', label: 'Fishes for personal details', weight: 30, re: /\b(?:confirm|verify|provide|update|need|send|give|share|enter)[^.\n]{0,15}\byour (?:full name|date of birth|address|phone|bank|billing|identity|details|information)\b|\b(?:give|provide|confirm|share|tell) (?:me )?(?:your )?mother'?s maiden name\b/i },
    { id: 'authority_threat', label: 'Impersonates authority or threatens', weight: 30, re: /\b(?:\birs\b|tax (?:office|department)|police(?: department)?|\bfbi\b|fraud (?:department|division|team|unit|investigation)|security (?:department|division|team)|anti-fraud|government (?:agency|official|grant)|social security administration|immigration (?:check|status|notice))\b|\baccount (?:will be |has been )?(?:suspended|closed|terminated|frozen|deleted)\b|\blegal action\b|\blawsuit\b|\barrest warrant\b|\bdeportation\b/i },
    // Coercive safe-wallet or asset transfer demand
    { id: 'safe_wallet_scam', label: 'Coercive safe-wallet or asset transfer', weight: 45, re: /\b(?:move|transfer|send|deposit|withdraw)\s+(?:your\s+)?(?:money|funds|crypto|assets|balance|coins|savings)\s+to\s+(?:this\s+)?(?:safe|secure|protection|temporary|recovery)\s+(?:wallet|account|vault|address)\b/i },
    // Extreme loss or forfeiture ultimatum
    { id: 'loss_ultimatum', label: 'Extreme loss or forfeiture ultimatum', weight: 30, re: /\b(?:or\s+)?lose\s+(?:everything|all(?:\s+your)?(?:\s+(?:money|funds|crypto|assets|savings))?)\b|\bforfeit\s+(?:all|everything)\b/i },
    { id: 'too_good', label: 'Too-good-to-be-true offer', weight: 25, re: /\b(?:you(?:'ve| have| are)? ?(?:been )?won|you are (?:our )?winner|prize|lottery|jackpot|sweepstak|lucky (?:dip|winner|draw)|claim your|entitled to [\d,.]+|\bfree (?:money|iphone|gift card)\b|double your (?:money|crypto|income)|risk[-\s]?free (?:investment|profit)|government (?:relief )?grant|pandemic relief grant)\b/i },
    { id: 'investment_scam', label: 'Investment/returns pressure', weight: 35, re: /\b(?:double|triple|x\d+) your (?:money|crypto|income|investment)|\bguaranteed (?:returns?|profit)\b|\bprofit guaranteed\b|\b\d{2,4}\s?(?:percent|%) (?:returns?|profit|weekly|daily)\b|\b(?:investment|trading) (?:opportunity|platform|group)\b|\b(?:crypto|token|coin) (?:presale|giveaway)\b|\breturns? (?:of )?\d/i },
    { id: 'emergency_money', label: 'Emergency money request', weight: 25, re: /\b(?:i am |im )?(?:stuck|stranded|robbed|mugged|held)[^.\n]{0,60}\b(?:fee|money|cash|funds|transfer|payment|western union)\b|\b(?:customs|embassy|hotel|airport|hospital|clinic)\b[^.\n]{0,60}\b(?:fee|release|costs?|payment|bill|transfer)\b|\btransfer fee\b|\brelease fee\b|\bwestern union\b|\bmoney ?gram\b|\b(?:never met|never seen) (?:each other|in person|you)\b/i },
    { id: 'relationship_pressure', label: 'Unmet-contact money pressure', weight: 20, re: /\b(?:i know|we have) (?:we have )?never (?:met|seen)\b|\b(?:online|internet) (?:relationship|romance|boyfriend|girlfriend)\b|\btreatment costs?\b/i },
    { id: 'job_scam', label: 'Too-good job offer with fees', weight: 30, re: /\b(?:earn|make|get paid)\b[^.\n]{0,40}\b(?:per (?:day|week|hour)|daily|weekly)\b|\b(?:work from home|remote) (?:job|opportunity|role)[^.\n]{0,60}(?:no experience|easy money|fee)\b|\b(?:registration|activation|background check) fee\b|\breceive payments? (?:from|into)\b/i },
    { id: 'delivery_scam', label: 'Fake delivery/customs fee', weight: 25, re: /\b(?:package|parcel|shipment|delivery)\b[^.\n]{0,70}\b(?:customs|redelivery|reschedule|delivery fee|shipping fee|customs charge|customs duty|unpaid)\b|\b(?:usps|dhl|fedex|ups)\b[^.\n]{0,60}\b(?:fee|charge|customs|redelivery|tracking problem)\b/i },
    { id: 'invoice_fraud', label: 'Fraudulent invoice/bank-change', weight: 30, re: /\b(?:overdue|unpaid) invoice\b|\binvoice\b[^.\n]{0,60}\b(?:overdue|unpaid|failed|declined|settle (?:the |your )?balance)\b|\b(?:updated|new) bank details\b|\bsettle (?:the |your )?(?:outstanding|unpaid|invoice|balance)\b/i },
    { id: 'account_lock', label: 'Account lock/delete threat', weight: 25, re: /\b(?:account|mailbox|access|email)\b[^.\n]{0,40}\b(?:suspended|locked|frozen|deleted|terminated)\b|\blose (?:your )?access (?:forever|permanently)\b/i },
    { id: 'tech_support', label: 'Fake tech support', weight: 30, re: /\b(?:computer|pc|device|windows|mac)\b[^.\n]{0,40}\b(?:infected|at risk|viruses?|license (?:has )?expired)\b|\bcertified technicians?\b|\ballow remote (?:access|connection)\b|\bcall (?:the )?(?:toll ?free|helpline|support line)\b/i },
    { id: 'secrecy', label: 'Asks for secrecy', weight: 25, re: /\b(?:don'?t tell|do not tell|keep this (?:confidential|secret|between us)|confidential (?:transaction|matter)|not (?:tell|inform) (?:your|anyone|the))\b/i },
    { id: 'channel_shift', label: 'Moves you off-platform', weight: 20, re: /\b(?:whatsapp|telegram|\bsignal\b|dm me|text me|whatsapp me|call me (?:back )?at|contact me on|continue (?:this )?(?:on|via) (?:whatsapp|telegram|signal|email))\b/i },
    { id: 'urgency', label: 'Artificial urgency', weight: 15, re: /\b(?:act now|immediately|right away|within (?:24|48|12|2) hours?|expires? (?:today|tomorrow|in \d+ (?:hours?|minutes?|days?))|last (?:chance|warning)|final notice|don'?t (?:delay|wait)|time[-\s]sensitive|urgent(ly)?)\b/i },
    { id: 'link_pressure', label: 'Pushes a link or login page', weight: 10, re: /(?:click (?:the|this) (?:link|button)|verify via|log ?in at|bit\.ly\/|tinyurl\.com\/|https?:\/\/\S{0,40}(?:login|verify|secure|account[-_]update))/i }
  ];

  const LEVELS = {
    dangerous: { rank: 3, advice: 'Do not reply, click links, or send anything. Verify through a channel you trust (official app or the number on your card).' },
    suspicious: { rank: 2, advice: 'Be cautious. Verify the sender through a known channel before acting on anything here.' },
    low: { rank: 1, advice: 'Stay alert — some common pressure patterns appear in this text.' },
    none: { rank: 0, advice: '' }
  };

  /**
   * Analyze one message/text block for scam patterns.
   * @param {string} text
   * @param {Set|Array} [muted]
   * @param {object} [options] Context options:
   *        - isCryptographicallyAligned: boolean
   *        - isSpamFolder: boolean
   *        - hasProviderWarning: boolean
   *        - hasMisdirection: boolean
   *        - hasShortener: boolean
   *        - userTrustedSender: boolean
   * @returns {{level: string, score: number, signals: Array<{id,label,weight}>, advice: string}}
   */
  function analyzeMessage(text, muted, options) {
    if (!text || text.length < 25) return { level: 'none', score: 0, signals: [], advice: LEVELS.none.advice };
    const opts = options || {};
    // Canonicalized copy (homoglyphs/zero-width/fullwidth/leet)
    const normalizer = (typeof VIGIL_NORMALIZER !== 'undefined' && VIGIL_NORMALIZER) ||
      (typeof root !== 'undefined' && root.VIGIL_NORMALIZER) ||
      (typeof global !== 'undefined' && global.VIGIL_NORMALIZER) ||
      (typeof require === 'function' ? (function () { try { return require('./adversarial-normalizer.js'); } catch (e) { return null; } })() : null);
    if (normalizer && typeof normalizer.normalizeAdversarialText === 'function') {
      text = normalizer.normalizeAdversarialText(text);
    }
    const skip = muted instanceof Set ? muted : (Array.isArray(muted) ? new Set(muted) : null);
    let signals = [];

    for (const sig of SENTINEL_SIGNALS) {
      if (skip && skip.has(sig.id)) continue;
      if (sig.re.test(text)) {
        signals.push({ id: sig.id, label: sig.label, weight: sig.weight });
      }
    }

    // Provider warning injection: mail client displayed unverified/spoofed sender banner
    if (opts.hasProviderWarning) {
      signals.push({ id: 'provider_spoof_warning', label: 'Mail provider warned: unverified or spoofed sender', weight: 50 });
    }

    // Link misdirection: action buttons claim to be trusted service but target foreign host
    if (opts.hasMisdirection && !signals.some(s => s.id === 'link_misdirection')) {
      signals.push({ id: 'link_misdirection', label: 'Action link points to mismatched external destination', weight: 45 });
    }

    // URL shortener: link destination obfuscation
    if (opts.hasShortener && !signals.some(s => s.id === 'url_shortener')) {
      signals.push({ id: 'url_shortener', label: 'Hidden destination link via URL shortener', weight: 25 });
    }

    // Explicit user-trusted sender whitelist dampening (from settings.trustedSites or vault contacts)
    if (opts.userTrustedSender && !opts.isSpamFolder && !opts.hasProviderWarning) {
      const hasSevereMalice = signals.some(s =>
        s.id === 'channel_shift' ||
        s.id === 'secrecy' ||
        s.id === 'link_misdirection' ||
        (s.id === 'payment_pressure' && /\b(?:wire transfer|gift card|bitcoin|crypto|usdt|western union|money ?gram)\b/i.test(text))
      );
      if (!hasSevereMalice) {
        const SUPPRESS_FOR_TRUSTED = ['credential_request', 'otp_delivery', 'invoice_fraud', 'delivery_scam', 'payment_pressure', 'link_pressure', 'personal_info_fishing', 'urgency', 'authority_threat'];
        signals = signals.filter(s => !SUPPRESS_FOR_TRUSTED.includes(s.id));
      }
    }

    // Foundational Cryptographic Alignment (The Ultimate Whitelist):
    // Inbound messages cryptographically verified from authentic corporate roots
    // without security warning banners and not in the spam folder.
    if (opts.isCryptographicallyAligned && !opts.isSpamFolder && !opts.hasProviderWarning) {
      const hasSevereMalice = signals.some(s =>
        s.id === 'channel_shift' ||
        s.id === 'secrecy' ||
        s.id === 'investment_scam' ||
        s.id === 'job_scam' ||
        s.id === 'link_misdirection' ||
        (s.id === 'payment_pressure' && /\b(?:wire transfer|gift card|bitcoin|crypto|usdt|western union|money ?gram)\b/i.test(text)) ||
        (s.id === 'authority_threat' && /\b(?:arrest warrant|lawsuit|deportation|police|fbi)\b/i.test(text))
      );
      if (!hasSevereMalice) {
        // Suppress routine transactional patterns
        const TRANSACTIONAL_IDS = ['credential_request', 'otp_delivery', 'invoice_fraud', 'delivery_scam', 'payment_pressure', 'link_pressure', 'personal_info_fishing', 'authority_threat'];
        signals = signals.filter(s => !TRANSACTIONAL_IDS.includes(s.id));
      }
    }

    let score = signals.reduce((sum, s) => sum + s.weight, 0);
    const has = id => signals.some(s => s.id === id);
    let level = 'none';

    // Spam folder handling: never allow threats in spam folder to pass silently
    if (opts.isSpamFolder && signals.length > 0) {
      if (score >= 25 || has('credential_request') || has('payment_pressure') || has('provider_spoof_warning') || has('link_misdirection')) {
        level = 'dangerous';
      } else {
        level = 'suspicious';
      }
    } else {
      if (score >= THRESHOLDS.dangerousScore || has('provider_spoof_warning') || has('link_misdirection') || has('safe_wallet_scam')) {
        level = 'dangerous';
      } else if (score >= THRESHOLDS.suspiciousScore) {
        level = 'suspicious';
      } else if (score >= THRESHOLDS.lowScore) {
        level = 'low';
      }
    }

    // Weak signals alone never escalate past 'low' in non-spam contexts
    const WEAK = ['urgency', 'link_pressure', 'ai_marker', 'otp_delivery'];
    if (level !== 'none' && !opts.isSpamFolder && signals.length && signals.every(s => WEAK.includes(s.id))) {
      level = 'low';
    }

    return { level, score, signals, advice: LEVELS[level].advice };
  }

  /** Human summary of the strongest matched signals, for UI display. */
  function topSignals(result, n) {
    return result.signals
      .slice()
      .sort((a, b) => b.weight - a.weight)
      .slice(0, n || 2)
      .map(s => s.label);
  }

  /**
   * Trust-graph escalation: a pressure message that names one of the user's
   * OWN trusted organizations is impersonation — escalate to dangerous.
   */
  function escalateForTrust(result, trustedHits) {
    if (!trustedHits || !trustedHits.length) return result;
    if (result.level === 'none' || result.level === 'low') return result;
    if (result.signals.some(s => s.id === 'trusted_impersonation')) return result;
    return {
      ...result,
      level: 'dangerous',
      signals: [...result.signals, { id: 'trusted_impersonation', label: 'Impersonates YOUR trusted organization (' + trustedHits.join(', ') + ')', weight: 45 }]
    };
  }

  /**
   * Should this level surface a banner? Family Guardian mode warns even on
   * 'low' so loved ones see every pressure pattern.
   */
  function shouldWarn(level, familyMode) {
    if (familyMode) return level !== 'none';
    return level === 'suspicious' || level === 'dangerous';
  }

  /**
   * Sliding-Window Slicer:
   * Slices long text into overlapping windows and returns max-risk verdict.
   */
  function analyzeSlidingWindows(text, muted, windowSize = 50, stepSize = 25, options = {}) {
    if (!text || text.length < 25) return analyzeMessage(text, muted, options);
    const words = text.split(/\s+/);
    if (words.length <= windowSize) {
      return analyzeMessage(text, muted, options);
    }
    let maxResult = analyzeMessage(text, muted, options);
    for (let i = 0; i < words.length; i += stepSize) {
      const windowText = words.slice(i, i + windowSize).join(' ');
      const windowRes = analyzeMessage(windowText, muted, options);
      if (windowRes.score > maxResult.score) {
        maxResult = windowRes;
      }
      if (maxResult.level === 'dangerous') break;
    }
    return maxResult;
  }

  /**
   * Fold extra signals (e.g. webmail sender checks) into a result and
   * recompute the level with the standard thresholds.
   */
  function applySignals(result, extra) {
    if (!extra || !extra.length) return result;
    const signals = [...result.signals, ...extra.filter(e => !result.signals.some(s => s.id === e.id))];
    const score = signals.reduce((sum, s) => sum + s.weight, 0);
    const has = id => signals.some(s => s.id === id);
    let level = 'none';
    if (score >= THRESHOLDS.dangerousScore || has('credential_request') || has('payment_pressure') || has('provider_spoof_warning') || has('link_misdirection')) {
      level = 'dangerous';
    } else if (score >= THRESHOLDS.suspiciousScore) {
      level = 'suspicious';
    } else if (score >= THRESHOLDS.lowScore) {
      level = 'low';
    }
    return { level, score, signals, advice: LEVELS[level].advice };
  }

  const VIGIL_SENTINEL = {
    analyzeMessage,
    analyzeSlidingWindows,
    topSignals,
    escalateForTrust,
    shouldWarn,
    applySignals,
    SENTINEL_SIGNALS,
    LEVELS
  };
  root.VIGIL_SENTINEL = VIGIL_SENTINEL;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_SENTINEL;
})(typeof self !== 'undefined' ? self : globalThis);

