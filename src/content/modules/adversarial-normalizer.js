/**
 * VIGIL Security Policy: Adversarial Pre-Processing Engine
 *
 * Attackers evade keyword classifiers with zero-width character smuggling,
 * Cyrillic/Greek homoglyph substitution, fullwidth forms, and separator
 * padding. This module produces a canonicalized COPY of the input purely for
 * classification (injection / scam scoring). It must NOT be used for PII or
 * secret scanning: leet-substitutions there would corrupt card/secret patterns.
 *
 * Pure and synchronous — safe to run on every scored text.
 */
(function (root) {
  'use strict';

  // Zero-width & format characters that silently split keywords (alternatives
  // only — no-misleading-character-class false positive suppressed)
  // eslint-disable-next-line no-misleading-character-class
  const INVISIBLE_RE = new RegExp('[\\u200B-\\u200F\\u2060\\uFEFF\\u00AD\\u180E\\u2061-\\u2064]', 'g');

  // Cyrillic → Latin homoglyph table (the letters attackers actually swap)
  const CYRILLIC_TO_LATIN = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'գ': 'q', 'ѵ': 'v', 'ӂ': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
    'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'І': 'I', 'Ѕ': 'S'
  };

  // Greek → Latin homoglyph table
  const GREEK_TO_LATIN = {
    'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'ν': 'v', 'κ': 'k', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z',
    'Η': 'H', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
    'Υ': 'Y', 'Χ': 'X'
  };

  const HOMOGLYPHS = Object.assign({}, CYRILLIC_TO_LATIN, GREEK_TO_LATIN);

  // Common leet substitutions seen in jailbreak prompts (classification copy only).
  // '1' folds to 'i': it dominates real-world "1gn0r3"-style substitutions,
  // and pure-digit runs never reach the leet pass at all.
  const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's' };

  function stripInvisible(text) {
    return text.replace(INVISIBLE_RE, '');
  }

  function foldHomoglyphs(text) {
    let out = '';
    for (const ch of text) {
      out += Object.prototype.hasOwnProperty.call(HOMOGLYPHS, ch) ? HOMOGLYPHS[ch] : ch;
    }
    return out;
  }

  function unfoldLeet(text) {
    // Only inside runs that contain at least one LETTER — pure numbers
    // (order IDs, prices, card digits) must pass through untouched. This
    // copy feeds classifiers, not secret patterns, but stay conservative.
    return text.replace(/[a-z0134578@$]{2,}/gi, (run) => {
      if (!/[a-z]/i.test(run)) return run;
      let changed = false;
      const mapped = run.replace(/[0134578@$]/g, (c) => {
        changed = true;
        return LEET[c];
      });
      return changed ? mapped : run;
    });
  }

  /**
   * Canonicalizes text for classification:
   *  1. NFKD fold (fullwidth → ASCII, strip combining marks)
   *  2. remove zero-width/format characters
   *  3. fold Cyrillic/Greek homoglyphs to Latin
   *  4. unfold leet inside letter runs
   *  5. collapse whitespace runs to single spaces
   */
  function normalizeAdversarialText(text) {
    if (typeof text !== 'string' || !text) return text || '';
    let out = text.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');
    out = stripInvisible(out);
    out = foldHomoglyphs(out);
    out = unfoldLeet(out);
    out = out.replace(/\s+/g, ' ');
    return out;
  }

  /** True when the canonical form differs from the input (obfuscation was present) */
  function isObfuscated(text) {
    if (typeof text !== 'string' || !text) return false;
    return normalizeAdversarialText(text) !== text;
  }

  const VIGIL_NORMALIZER = { normalizeAdversarialText, isObfuscated, stripInvisible, foldHomoglyphs, HOMOGLYPHS };

  root.VIGIL_NORMALIZER = VIGIL_NORMALIZER;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_NORMALIZER;
})(typeof self !== 'undefined' ? self : globalThis);
