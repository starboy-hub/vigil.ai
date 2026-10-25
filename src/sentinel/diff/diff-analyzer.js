/**
 * Sentinel Unified Diff & Trojan Source Unicode Analyzer
 * Part of Vigil AI + Sentinel
 *
 * Generates git-compatible unified syntax diffs for human approval flows
 * and inspects incoming code modifications for Trojan Source (CVE-2021-42574)
 * bidirectional overrides and invisible zero-width character obfuscation.
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
   * Generates a unified diff and checks for Trojan Source attacks.
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
    while ((match = this.trojanRegex.exec(newContent)) !== null) {
      const code = TROJAN_SOURCE_MAP[match[0]];
      if (code) anomalies.add(code);
    }

    const detectedUnicodeAnomalies = Array.from(anomalies);
    const hasTrojanSource = detectedUnicodeAnomalies.length > 0;

    // 2. Generate Unified Diff
    const { unifiedDiff, stats } = this._generateDiff(cleanPath, oldLines, newLines);

    if (hasTrojanSource) {
      return {
        isSafe: false,
        hasTrojanSource: true,
        reasonCode: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE,
        explanation: `Trojan Source Unicode injection detected: ${detectedUnicodeAnomalies.join(', ')}`,
        detectedUnicodeAnomalies,
        unifiedDiff,
        stats
      };
    }

    return {
      isSafe: true,
      hasTrojanSource: false,
      reasonCode: REASON_CODES.ALLOW_SAFE_COMMAND,
      detectedUnicodeAnomalies: [],
      unifiedDiff,
      stats
    };
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

    // Quick single-hunk diff calculation
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
