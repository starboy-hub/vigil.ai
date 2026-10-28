'use strict';

const { DiffAnalyzer } = require('../src/sentinel/diff/diff-analyzer.js');
const { REASON_CODES } = require('../src/sentinel/constants.js');

describe('Sentinel Enhancement: Unified Diff & Trojan Source Analyzer', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new DiffAnalyzer();
  });

  describe('1. Unified Diff Generation', () => {
    test('generates valid git-style unified diff for code modifications', () => {
      const oldCode = 'function auth() {\n  return false;\n}\n';
      const newCode = 'function auth() {\n  return true;\n}\n';

      const result = analyzer.analyze({
        filePath: 'src/auth.js',
        oldContent: oldCode,
        newContent: newCode
      });

      expect(result.isSafe).toBe(true);
      expect(result.unifiedDiff).toContain('--- a/src/auth.js');
      expect(result.unifiedDiff).toContain('+++ b/src/auth.js');
      expect(result.unifiedDiff).toContain('-  return false;');
      expect(result.unifiedDiff).toContain('+  return true;');
      expect(result.stats.additions).toBe(1);
      expect(result.stats.deletions).toBe(1);
    });

    test('handles new file creation cleanly (empty old content)', () => {
      const newCode = 'console.log("hello world");\n';
      const result = analyzer.analyze({
        filePath: 'src/new-file.js',
        oldContent: '',
        newContent: newCode
      });

      expect(result.isSafe).toBe(true);
      expect(result.unifiedDiff).toContain('+++ b/src/new-file.js');
      expect(result.unifiedDiff).toContain('+console.log("hello world");');
      expect(result.stats.additions).toBe(1);
      expect(result.stats.deletions).toBe(0);
    });
  });

  describe('2. Trojan Source Unicode Detection (CVE-2021-42574)', () => {
    test('detects right-to-left override character (\\u202E) hiding malicious payload', () => {
      // In Trojan Source, \u202E flips visually apparent comments into executable code
      const maliciousCode = '/* Check permissions: \u202E } return true; // \u202D */\nreturn false;';
      const result = analyzer.analyze({
        filePath: 'src/perm.js',
        oldContent: 'return false;',
        newContent: maliciousCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasTrojanSource).toBe(true);
      expect(result.reasonCode).toBe(REASON_CODES.DENY_TROJAN_SOURCE_UNICODE);
      expect(result.detectedUnicodeAnomalies).toContain('U+202E');
    });

    test('detects zero-width space characters (\\u200B) used for identifier obfuscation', () => {
      const obfuscatedCode = 'const sec\u200Bret = "leaked";';
      const result = analyzer.analyze({
        filePath: 'src/obfuscated.js',
        oldContent: '',
        newContent: obfuscatedCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasTrojanSource).toBe(true);
      expect(result.detectedUnicodeAnomalies).toContain('U+200B');
    });
  });

  describe('3. Clean Code Pass-Through', () => {
    test('passes standard UTF-8 source code with normal comments without false positives', () => {
      const cleanCode = '// Standard English comment\nconst PI = 3.14159;\nmodule.exports = { PI };\n';
      const result = analyzer.analyze({
        filePath: 'src/math.js',
        oldContent: '',
        newContent: cleanCode
      });

      expect(result.isSafe).toBe(true);
      expect(result.hasTrojanSource).toBe(false);
      expect(result.detectedUnicodeAnomalies.length).toBe(0);
    });
  });

  describe('4. Semantic Code & Logic-Bomb Verification', () => {
    test('detects hardcoded temporal logic-bomb triggers', () => {
      const sleeperCode = 'function verifyLicense() {\n  if (Date.now() > 1799999999999) return true;\n  return check();\n}';
      const result = analyzer.analyze({
        filePath: 'src/license.js',
        oldContent: 'function verifyLicense() {\n  return check();\n}',
        newContent: sleeperCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasSemanticAnomaly).toBe(true);
      expect(result.reasonCode).toBe(REASON_CODES.DENY_SEMANTIC_LOGIC_BOMB);
      expect(result.semanticAnomalies.some(a => a.type === 'LOGIC_BOMB_TEMPORAL')).toBe(true);
    });

    test('detects targeted environment/host identity tripwires', () => {
      const targetedCode = 'if (process.env.USER === "victim-admin") { exfiltrate(); }';
      const result = analyzer.analyze({
        filePath: 'src/config.js',
        oldContent: '',
        newContent: targetedCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasSemanticAnomaly).toBe(true);
      expect(result.reasonCode).toBe(REASON_CODES.DENY_SEMANTIC_LOGIC_BOMB);
      expect(result.semanticAnomalies.some(a => a.type === 'LOGIC_BOMB_ENVIRONMENT')).toBe(true);
    });

    test('detects cryptographic degradation (Math.random in auth path)', () => {
      const weakTokenCode = 'function generateSessionToken() {\n  return "tok_" + Math.random();\n}';
      const result = analyzer.analyze({
        filePath: 'src/auth/token-generator.js',
        oldContent: 'function generateSessionToken() {\n  return crypto.randomUUID();\n}',
        newContent: weakTokenCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasSemanticAnomaly).toBe(true);
      expect(result.reasonCode).toBe(REASON_CODES.DENY_CRYPTOGRAPHIC_DEGRADATION);
      expect(result.semanticAnomalies.some(a => a.type === 'CRYPTO_DEGRADATION')).toBe(true);
    });

    test('detects unsafe dynamic code execution sinks', () => {
      const dynamicExecCode = 'const runner = new Function("arg", payload);';
      const result = analyzer.analyze({
        filePath: 'src/utils/runner.js',
        oldContent: '',
        newContent: dynamicExecCode
      });

      expect(result.isSafe).toBe(false);
      expect(result.hasSemanticAnomaly).toBe(true);
      expect(result.semanticAnomalies.some(a => a.type === 'DYNAMIC_EXECUTION_SINK')).toBe(true);
    });
  });
});

