/**
 * Sentinel Unified Diff & Trojan Source Unicode Analyzer
 * Part of Vigil AI + Sentinel
 *
 * Generates git-compatible unified syntax diffs for human approval flows,
 * inspects incoming code modifications for Trojan Source (CVE-2021-42574)
 * bidirectional overrides and invisible zero-width character obfuscation,
 * and performs pre-write semantic AST & logic-bomb detection.
 */
'use strict';

const { REASON_CODES } = require('../constants.js');

// Critical Unicode Anomaly Definitions
const TROJAN_SOURCE_MAP = {
  '\u202A': 'U+202A', // Left-to-Right Embedding
  '\u202B': 'U+202B', // Right-to-Left Embedding
  '\u202C': 'U+202C', // Pop Directional Formatting
  '\u202D': 'U+202D', // Left-to-Right Override
  '\u202E': 'U+202E', // Right-to-Left Override
  '\u2066': 'U+2066', // Left-to-Right Isolate
  '\u2067': 'U+2067', // Right-to-Left Isolate
  '\u2068': 'U+2068', // First Strong Isolate
  '\u2069': 'U+2069', // Pop Directional Isolate
  '\u200B': 'U+200B', // Zero Width Space
  '\u200C': 'U+200C', // Zero Width Non-Joiner
  '\u200D': 'U+200D', // Zero Width Joiner
  '\uFEFF': 'U+FEFF'  // Zero Width No-Break Space / BOM
};

class DiffAnalyzer {
  constructor() {
    this.trojanRegex = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]/g;
  }

  /**
   * Generates a unified diff, checks for Trojan Source, and performs semantic code inspection.
   * @param {object} params
   * @param {string} params.filePath
   * @param {string} [params.oldContent]
   * @param {string} params.newContent
   * @returns {object} Analysis result
   */
  analyze({ filePath, oldContent = '', newContent = '' }) {
    const cleanPath = filePath || 'unknown.txt';
    const cleanOld = (oldContent || '').replace(/\r?\n$/, '');
    const cleanNew = (newContent || '').replace(/\r?\n$/, '');
    const oldLines = cleanOld ? cleanOld.split(/\r?\n/) : [];
    const newLines = cleanNew ? cleanNew.split(/\r?\n/) : [];

    // 1. Detect Trojan Source & Invisible Unicode
    const anomalies = new Set();
    let match;
    this.trojanRegex.lastIndex = 0;
    while ((match = this.trojanRegex.exec(newContent)) !== null) {
      const code = TROJAN_SOURCE_MAP[match[0]];
      if (code) anomalies.add(code);
    }

    const detectedUnicodeAnomalies = Array.from(anomalies);
    const hasTrojanSource = detectedUnicodeAnomalies.length > 0;

    // 2. Semantic Code & Logic-Bomb Inspection
    const semanticAnomalies = this._inspectSemanticAnomalies(cleanPath, cleanNew, cleanOld);
    const hasSemanticAnomaly = semanticAnomalies.length > 0;

    // 3. Generate Unified Diff
    const { unifiedDiff, stats } = this._generateDiff(cleanPath, oldLines, newLines);

    if (hasTrojanSource) {
      return {
        isSafe: false,
        hasTrojanSource: true,
        hasSemanticAnomaly: false,
        semanticAnomalies: [],
        reasonCode: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE,
        explanation: `Trojan Source Unicode injection detected: ${detectedUnicodeAnomalies.join(', ')}`,
        detectedUnicodeAnomalies,
        unifiedDiff,
        stats
      };
    }

    if (hasSemanticAnomaly) {
      const isLogicBomb = semanticAnomalies.some(a => a.type.startsWith('LOGIC_BOMB'));
      const reasonCode = isLogicBomb
        ? REASON_CODES.DENY_SEMANTIC_LOGIC_BOMB
        : REASON_CODES.DENY_CRYPTOGRAPHIC_DEGRADATION;

      return {
        isSafe: false,
        hasTrojanSource: false,
        hasSemanticAnomaly: true,
        semanticAnomalies,
        reasonCode,
        explanation: `Semantic code safety violation: ${semanticAnomalies.map(a => a.description).join('; ')}`,
        detectedUnicodeAnomalies: [],
        unifiedDiff,
        stats
      };
    }

    return {
      isSafe: true,
      hasTrojanSource: false,
      hasSemanticAnomaly: false,
      semanticAnomalies: [],
      reasonCode: REASON_CODES.ALLOW_SAFE_COMMAND,
      detectedUnicodeAnomalies: [],
      unifiedDiff,
      stats
    };
  }

  /**
   * Helper: check for logic bombs, cryptographic degradation, and execution sinks
   * @private
   */
  _inspectSemanticAnomalies(filePath, newContent, oldContent) {
    const anomalies = [];
    const lowerPath = filePath.toLowerCase();
    const isSecuritySensitive = /(?:auth|token|secret|key|vault|crypto|cipher|sentinel|security)/.test(lowerPath);

    // 1. Logic-bomb temporal tripwires: Date.now() > timestamp, new Date() > new Date(...)
    const temporalRegex = /(?:Date\.now\(\)\s*>\s*\d{10,}|new\s+Date\([^)]*\)\s*>\s*new\s+Date\([^)]*\)|\.getTime\(\)\s*>\s*\d{10,})/i;
    if (temporalRegex.test(newContent) && !temporalRegex.test(oldContent)) {
      anomalies.push({
        type: 'LOGIC_BOMB_TEMPORAL',
        description: 'Hardcoded temporal trigger condition detected (potential time-bomb backdoor)'
      });
    }

    // 2. Logic-bomb environment tripwires: process.env.USER === ..., os.hostname() === ...
    const envTripwire = /(?:process\.env\.(?:USER|USERNAME|HOSTNAME|TARGET|HOST)\s*===\s*['"][^'"]+['"]|os\.hostname\(\)\s*===\s*['"][^'"]+['"])/i;
    if (envTripwire.test(newContent) && !envTripwire.test(oldContent)) {
      anomalies.push({
        type: 'LOGIC_BOMB_ENVIRONMENT',
        description: 'Targeted environment or host identity trigger condition detected'
      });
    }

    // 3. Cryptographic degradation: Math.random() in security sensitive paths
    if (isSecuritySensitive && /\bMath\.random\(\)/.test(newContent) && !/\bMath\.random\(\)/.test(oldContent)) {
      anomalies.push({
        type: 'CRYPTO_DEGRADATION',
        description: 'Insecure pseudo-random number generator (Math.random) introduced in security-sensitive module'
      });
    }

    // 4. Deprecated broken ciphers: des, rc4, md5
    const brokenCipher = /(?:createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|blowfish)['"]|createHash\s*\(\s*['"]md5['"])/i;
    if (brokenCipher.test(newContent) && !brokenCipher.test(oldContent)) {
      anomalies.push({
        type: 'BROKEN_CIPHER',
        description: 'Deprecated or insecure cryptographic algorithm (DES/RC4/MD5) introduced'
      });
    }

    // 5. Dynamic code execution sinks
    const dynamicExec = /(?:\bnew\s+Function\s*\(|\bvm\.runInContext\s*\(|\bvm\.runInThisContext\s*\()/;
    if (dynamicExec.test(newContent) && !dynamicExec.test(oldContent)) {
      anomalies.push({
        type: 'DYNAMIC_EXECUTION_SINK',
        description: 'Unsafe dynamic code execution sink introduced'
      });
    }

    return anomalies;
  }

  /**
   * Helper: compute line-by-line unified diff
   * @private
   */
  _generateDiff(filePath, oldLines, newLines) {
    const diffLines = [
      `--- a/${filePath}`,
      `+++ b/${filePath}`
    ];

    let additions = 0;
    let deletions = 0;

    const hunkBody = [];

    let i = 0;
    let j = 0;

    while (i < oldLines.length || j < newLines.length) {
      const oldLine = oldLines[i];
      const newLine = newLines[j];

      if (i < oldLines.length && j < newLines.length && oldLine === newLine) {
        hunkBody.push(` ${oldLine}`);
        i++;
        j++;
      } else {
        if (i < oldLines.length && (j >= newLines.length || oldLine !== newLine)) {
          hunkBody.push(`-${oldLine}`);
          deletions++;
          i++;
        }
        if (j < newLines.length && (i >= oldLines.length || oldLine !== newLine)) {
          hunkBody.push(`+${newLine}`);
          additions++;
          j++;
        }
      }
    }

    const startLineOld = oldLines.length > 0 ? 1 : 0;
    const startLineNew = newLines.length > 0 ? 1 : 0;
    diffLines.push(`@@ -${startLineOld},${oldLines.length} +${startLineNew},${newLines.length} @@`);
    diffLines.push(...hunkBody);

    return {
      unifiedDiff: diffLines.join('\n'),
      stats: { additions, deletions }
    };
  }
}

module.exports = {
  DiffAnalyzer,
  TROJAN_SOURCE_MAP
};
