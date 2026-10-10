/**
 * VIGIL Developer Secret & Code Sanitizer Module
 * Detects API keys, tokens, database connection strings, and private keys.
 */
(function (root) {
  'use strict';

  const SECRET_PATTERNS = [
    { type: 'API_KEY', label: 'AWS Access Key ID', pattern: /\b(AKIA[0-9A-Z]{16}|FAKE_AWS_KEY)\b/g },
    { type: 'API_KEY', label: 'GitHub Access Token', pattern: /\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9_]{36}|ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|ghr_[A-Za-z0-9_]{36}|FAKE_GITHUB_TOKEN)\b/g },
    { type: 'API_KEY', label: 'OpenAI / Anthropic API Key', pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,64}|sk-ant-[A-Za-z0-9_-]{32,64})\b/g },
    { type: 'API_KEY', label: 'Stripe Secret Key', pattern: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g },
    { type: 'CREDENTIALS', label: 'JWT Bearer Token', pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
    { type: 'PRIVATE_KEY', label: 'Private RSA / SSH Key', pattern: /-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----/gi },
    { type: 'DATABASE_URI', label: 'Database Connection String', pattern: /\b((?:mongodb(?:\+srv)?|postgres|postgresql|mysql|redis):\/\/[^\s"'<>]+)\b/gi }
  ];

  function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const frequencies = {};
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      frequencies[ch] = (frequencies[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in frequencies) {
      const p = frequencies[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  function scanSecrets(text) {
    if (!text || text.length < 15) return { alerts: [], redactions: [] };
    const alerts = [], redactions = [], seen = new Set();
    
    // 1. Pattern-based detection
    SECRET_PATTERNS.forEach(rule => {
      const re = new RegExp(rule.pattern.source, rule.pattern.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!m[0]) { re.lastIndex++; continue; }
        const matched = m[1] || m[0];
        // Blueprint 11: Suppress mock/test keys and placeholder prefixes
        if (/^(?:sk-test-|pk_test_|dummy|mock|placeholder|example)/i.test(matched)) {
          continue;
        }
        if (!seen.has(matched)) {
          seen.add(matched);
          alerts.push({ type: rule.type, label: rule.label, source: 'secret-engine', severity: 'critical' });
          redactions.push({ text: matched, type: rule.type, label: rule.label, context: matched.slice(0, 40) });
        }
      }
    });

    // 2. Shannon Entropy Analyzer for novel/unpatterned high-entropy keys
    const candidateTokens = text.match(/[A-Za-z0-9_\-+/=!@#$%^&*]{18,128}/g) || [];
    candidateTokens.forEach(token => {
      if (seen.has(token)) return;
      // Blueprint 11: Ignore git commit hashes, SHA-256 hex strings, or mock prefixes
      if (/^[0-9a-fA-F]{32,64}$/.test(token)) return;
      if (/^(?:sk-test-|pk_test_|dummy|mock|placeholder|example)/i.test(token)) return;

      // Must have character diversity (mixed case, digits or symbols)
      const hasUpper = /[A-Z]/.test(token);
      const hasLower = /[a-z]/.test(token);
      const hasDigit = /[0-9]/.test(token);
      const hasSpecial = /[^A-Za-z0-9]/.test(token);
      const varietyScore = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);
      
      if (varietyScore >= 3 && token.length >= 20) {
        const entropy = calculateShannonEntropy(token);
        if (entropy >= 4.5) {
          seen.add(token);
          alerts.push({ type: 'API_KEY', label: 'High-Entropy Secret Key', source: 'entropy-engine', severity: 'critical' });
          redactions.push({ text: token, type: 'API_KEY', label: 'High-Entropy Secret Key', context: token.slice(0, 40) });
        }
      }
    });

    return { alerts, redactions };
  }

  const VIGIL_SECRETS = {
    SECRET_PATTERNS,
    calculateShannonEntropy,
    scanSecrets
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_SECRETS;
  else root.VIGIL_SECRETS = VIGIL_SECRETS;
})(typeof self !== 'undefined' ? self : this);
