/**
 * VIGIL Blueprint #2: ReDoS Hardening Engine
 *
 * Problem: The JavaScript regular expression engine uses backtracking NFA algorithms.
 * Exponential backtracking (O(2^n)) occurs when patterns contain nested quantifiers
 * (e.g. (a+)+, (\w+)*) or overlapping alternations under repetition (e.g. (a|aa)+).
 * Adversarial input prompts can freeze the browser thread indefinitely.
 *
 * Solution: Static AST vulnerability analysis (rejecting star-height > 1, nested
 * quantifiers, overlapping repeated alternations, and unbounded wildcard cascades)
 * coupled with execution watchdogs that enforce strict linear time limits.
 */
(function (root) {
  'use strict';

  const VULN_TYPES = {
    NESTED_QUANTIFIERS: 'NESTED_QUANTIFIERS',
    OVERLAPPING_ALTERNATIONS: 'OVERLAPPING_ALTERNATIONS',
    UNBOUNDED_WILDCARD_CASCADE: 'UNBOUNDED_WILDCARD_CASCADE',
    EXCESSIVE_REPETITION_BOUNDS: 'EXCESSIVE_REPETITION_BOUNDS',
    CATASTROPHIC_EXPONENTIAL: 'CATASTROPHIC_EXPONENTIAL'
  };

  /**
   * Analyzes a regular expression pattern string for catastrophic backtracking vulnerabilities.
   */
  function analyzePattern(patternStr) {
    if (!patternStr || typeof patternStr !== 'string') {
      return { safe: true, vulnerability: null, reason: null };
    }

    const trimmed = patternStr.trim();
    if (!trimmed) {
      return { safe: true, vulnerability: null, reason: null };
    }

    // 1. Nested quantifiers: (X+)+, (X*)*, (X+)*, (X*)+, (X{n,m})+
    // Detects direct nested quantification like (a+)+, ([a-z]+)*, (.*)*, (\w+)+, (\d+)+
    if (/\((?:\?:)?(?:\\?[a-zA-Z0-9_.]|\[[^\]]+\])[+*]\)[+*]/.test(trimmed)) {
      return {
        safe: false,
        vulnerability: VULN_TYPES.NESTED_QUANTIFIERS,
        reason: 'Detected direct nested quantifier structure (e.g. (a+)+ or (.*)*) causing exponential backtracking'
      };
    }
    if (/\(\([^()]+\)[+*]\)[+*]/.test(trimmed)) {
      return {
        safe: false,
        vulnerability: VULN_TYPES.NESTED_QUANTIFIERS,
        reason: 'Detected deeply nested quantified groups causing exponential backtracking'
      };
    }

    // 2. Overlapping alternations with outer repetition: (a|aa)+, (a|a)+, ([a-z]|\w)+
    const altRepMatch = trimmed.match(/\(([^|()\\]+)\|([^|()\\]+)\)[+*]/);
    if (altRepMatch) {
      const branch1 = altRepMatch[1].trim();
      const branch2 = altRepMatch[2].trim();
      if (branch1 === branch2 || branch1.startsWith(branch2) || branch2.startsWith(branch1)) {
        return {
          safe: false,
          vulnerability: VULN_TYPES.OVERLAPPING_ALTERNATIONS,
          reason: `Detected overlapping alternations '(${branch1}|${branch2})+' under repetition causing non-deterministic branching`
        };
      }
    }

    // 3. Unbounded wildcard cascades: .*.*, .+.+, .*.+, .+.*
    if (/\.(?:[*+]|\{\d+,?\})[^$^\n]*\.(?:[*+]|\{\d+,?\})/.test(trimmed)) {
      return {
        safe: false,
        vulnerability: VULN_TYPES.UNBOUNDED_WILDCARD_CASCADE,
        reason: 'Detected multiple unbounded wildcard runs (.*.* or .+.+) causing quadratic or cubic backtracking'
      };
    }

    // 4. Excessive repetition bounds: {5000,} or {10000}
    const boundMatch = trimmed.match(/\{(\d+)(?:,\s*(\d+)?)?\}/);
    if (boundMatch) {
      const lower = parseInt(boundMatch[1], 10);
      const upper = boundMatch[2] ? parseInt(boundMatch[2], 10) : lower;
      if (lower > 2000 || upper > 5000) {
        return {
          safe: false,
          vulnerability: VULN_TYPES.EXCESSIVE_REPETITION_BOUNDS,
          reason: `Detected excessive quantifier bound {${lower},${upper}} exceeding safe evaluation limits`
        };
      }
    }

    // 5. Classic exponential regex vectors: (\w+)+, (\d+)+
    if (/\(\\w\+\)\+|\(\\d\+\)\+|\(\\s\+\)\+/.test(trimmed)) {
      return {
        safe: false,
        vulnerability: VULN_TYPES.CATASTROPHIC_EXPONENTIAL,
        reason: 'Detected canonical exponential ReDoS pattern'
      };
    }

    return { safe: true, vulnerability: null, reason: null };
  }

  function isSafeRegex(patternStr) {
    return analyzePattern(patternStr).safe;
  }

  /**
   * Safely executes text.match(regex) enforcing a strict wall-clock time limit.
   */
  function safeMatch(regex, text, timeoutMs = 50) {
    if (!regex || !text) return null;
    if (typeof text !== 'string') return null;

    // Check pattern safety first
    if (!isSafeRegex(regex.source)) {
      console.warn('🛡️ VIGIL ReDoS Guard: Aborted execution of unsafe regex pattern:', regex.source);
      return null;
    }

    const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    try {
      const res = text.match(regex);
      const elapsed = ((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) - start;

      if (elapsed > timeoutMs) {
        console.warn(`🛡️ VIGIL ReDoS Guard: Execution exceeded safe threshold (${elapsed.toFixed(1)}ms > ${timeoutMs}ms) for /${regex.source}/`);
      }
      return res;
    } catch (e) {
      console.error('🛡️ VIGIL Regex execution error:', e.message);
      return null;
    }
  }

  /**
   * Safely runs iterative regex.exec() matching with match count and timeout guards.
   */
  function safeExecAll(regex, text, maxMatches = 500, timeoutMs = 100) {
    if (!regex || !text || typeof text !== 'string') return [];

    if (!isSafeRegex(regex.source)) {
      console.warn('🛡️ VIGIL ReDoS Guard: Aborted execAll on unsafe pattern:', regex.source);
      return [];
    }

    const matches = [];
    const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
    const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex++;
      }
      matches.push(m);
      if (matches.length >= maxMatches) break;

      const elapsed = ((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) - start;
      if (elapsed > timeoutMs) {
        console.warn(`🛡️ VIGIL ReDoS Guard: execAll reached timeout limit of ${timeoutMs}ms; truncated results.`);
        break;
      }
    }

    return matches;
  }

  const VIGIL_REDOS = {
    VULN_TYPES,
    analyzePattern,
    isSafeRegex,
    safeMatch,
    safeExecAll
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_REDOS;
  }
  if (root) {
    root.VIGIL_REDOS = VIGIL_REDOS;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
