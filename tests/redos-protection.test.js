/**
 * Unit tests for VIGIL Blueprint #2: ReDoS Hardening Engine
 * Verifies static AST analysis of catastrophic regex backtracking,
 * detection of nested quantifiers, overlapping alternations, wildcard cascades,
 * and watchdog execution protection against pathological inputs.
 */
const { analyzePattern, isSafeRegex, safeMatch, safeExecAll, VULN_TYPES } = require('../src/content/modules/redos-engine.js');
const { parseCustomPatterns, scanWithCustomPatterns } = require('../src/content/modules/detection-engine.js');

describe('Blueprint #2: ReDoS Hardening Engine', () => {

  describe('1. Static Vulnerability Analysis', () => {
    test('detects nested quantifiers causing exponential backtracking', () => {
      const evilPatterns = [
        '(a+)+',
        '([a-z]+)*',
        '(.*)*',
        '((a+)+)+',
        '([0-9]+)+$'
      ];

      evilPatterns.forEach(pattern => {
        const analysis = analyzePattern(pattern);
        expect(analysis.safe).toBe(false);
        expect(analysis.vulnerability).toBe(VULN_TYPES.NESTED_QUANTIFIERS);
        expect(isSafeRegex(pattern)).toBe(false);
      });
    });

    test('detects overlapping alternations under repetition', () => {
      const overlapping = [
        '(a|aa)+',
        '(a|a)+',
        '(cat|catalog)+',
        '(token|token_id)+'
      ];

      overlapping.forEach(pattern => {
        const analysis = analyzePattern(pattern);
        expect(analysis.safe).toBe(false);
        expect(analysis.vulnerability).toBe(VULN_TYPES.OVERLAPPING_ALTERNATIONS);
      });
    });

    test('detects unbounded wildcard cascades', () => {
      const wildcards = [
        '.*.*',
        '.+.*',
        '.*foo.*',
        '.+bar.+'
      ];

      wildcards.forEach(pattern => {
        const analysis = analyzePattern(pattern);
        expect(analysis.safe).toBe(false);
        expect(analysis.vulnerability).toBe(VULN_TYPES.UNBOUNDED_WILDCARD_CASCADE);
      });
    });

    test('detects excessive quantifier repetition bounds', () => {
      const excessive = [
        'a{5001,}',
        '[0-9]{10000}',
        '\\w{3000,6000}'
      ];

      excessive.forEach(pattern => {
        const analysis = analyzePattern(pattern);
        expect(analysis.safe).toBe(false);
        expect(analysis.vulnerability).toBe(VULN_TYPES.EXCESSIVE_REPETITION_BOUNDS);
      });
    });

    test('allows benign, linear regular expressions (no false positives)', () => {
      const safePatterns = [
        '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b', // Email
        '\\b\\d{3}-\\d{2}-\\d{4}\\b',                             // SSN
        '\\b4[0-9]{12}(?:[0-9]{3})?\\b',                          // Visa
        'sk-[a-zA-Z0-9]{32,64}',                                  // API Key
        'https?://[\\w.-]+(?:/[\\w.-]*)*'                         // URL
      ];

      safePatterns.forEach(pattern => {
        const analysis = analyzePattern(pattern);
        expect(analysis.safe).toBe(true);
        expect(analysis.vulnerability).toBeNull();
        expect(isSafeRegex(pattern)).toBe(true);
      });
    });
  });

  describe('2. Watchdog Execution Protection (safeMatch & safeExecAll)', () => {
    test('safeMatch refuses execution of vulnerable pattern without freezing', () => {
      const evilRegex = new RegExp('(a+)+$');
      const pathologicalInput = 'a'.repeat(30) + '!';

      // Executing raw V8 evilRegex.test(pathologicalInput) would freeze the process.
      // safeMatch statically preempts it.
      const res = safeMatch(evilRegex, pathologicalInput);
      expect(res).toBeNull();
    });

    test('safeMatch succeeds normally for safe regexes', () => {
      const safeRegex = /\bsecret_key_[a-z0-9]+\b/i;
      const text = 'Authorization: Bearer secret_key_abc123999 in header';
      const match = safeMatch(safeRegex, text);

      expect(match).not.toBeNull();
      expect(match[0]).toBe('secret_key_abc123999');
    });

    test('safeExecAll limits execution and truncates safely', () => {
      const regex = /\bword\d+\b/g;
      const text = 'word1 word2 word3 word4 word5 word6';
      const matches = safeExecAll(regex, text, 3);

      expect(matches).toHaveLength(3);
      expect(matches[0][0]).toBe('word1');
      expect(matches[2][0]).toBe('word3');
    });
  });

  describe('3. Integration with Detection Engine', () => {
    test('parseCustomPatterns strips ReDoS vectors from user custom patterns', () => {
      const config = [
        'SAFE_API:/sk-[a-zA-Z0-9]{32}/g',
        'MALICIOUS_REDOS:/(a+)+$/g',
        'OVERLAPPING_REDOS:/(foo|foobar)+/g',
        'SAFE_ID:/ID-\\d{6}/g'
      ].join('\n');

      const parsed = parseCustomPatterns(config);

      expect(parsed).toHaveLength(2);
      expect(parsed.map(p => p.type)).toEqual(['SAFE_API', 'SAFE_ID']);
    });

    test('scanWithCustomPatterns runs cleanly with watchdog protection', () => {
      const safeCustom = [
        { type: 'PROJECT_CODE', pattern: /\bPROJ-[0-9]{4}\b/g }
      ];
      const text = 'Working on task PROJ-8812 today.';
      const res = scanWithCustomPatterns(text, safeCustom);

      expect(res.alerts).toHaveLength(1);
      expect(res.alerts[0].type).toBe('PROJECT_CODE');
      expect(res.redactions[0].text).toBe('PROJ-8812');
    });
  });
});
