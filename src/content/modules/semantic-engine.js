/**
 * VIGIL Semantic Engine — zero-shot NLI classification config + decisions.
 *
 * The in-browser model (Xenova/mobilebert-uncased-mnli, quantized, WASM) is a
 * zero-shot classifier: it never saw our corpora, it only scores how strongly
 * a text ENTAILS each hypothesis sentence below. Single-hypothesis prompts
 * miss reworded attacks (benchmark: adversarial recall 0%), so detection uses
 * an ENSEMBLE — several scam/injection hypotheses, each covering one attack
 * family — plus max-score aggregation and tuned thresholds.
 *
 * Pure module: no DOM, no chrome.* — the same decisions run in the content
 * script (runtime), the eval harness (measurement), and the tests.
 *
 * Loading order:
 *   - content script:  manifest content_scripts: [..., "semantic-engine.js", "content.js"]
 *   - service worker:  importScripts('semantic-engine.js') in background.js
 *   - eval/tests:      require(...) (CommonJS export)
 */
(function (root) {
  'use strict';

  // Two measured decision frames (see evaluation/ — do not mix them up):
  //
  // SCAM — absolute per-fact scores. Each hypothesis is a MINIMAL SINGLE
  // FACT scored by the model's NLI head; discrimination = P(entail) −
  // P(contradict), aggregated as the sum of positive fact scores. NLI needs
  // one provable fact per hypothesis: no disjunctions ("money, gift cards,
  // or codes" is entailed by none of them alone), no unverifiable judgments
  // ("false urgency" is never entailed; "pressuring the reader to act
  // quickly" is). Honest ceiling on MobileBERT zero-shot is LOW — implied
  // asks ("stuck with the hotel till Monday") entail nothing. Raising this
  // to the 60% goal is the fine-tuned-classifier sprint's job.
  //
  // INJECTION — MEASURED VERDICT: zero-shot NLI on this model CANNOT detect
  // the reworded injections. Four frames tried on the captured scores
  // (evaluation/semantic-eval.js): raw-pair absolute, raw-pair binary softmax,
  // "This example is {}" template framing, and template absolute — every one
  // INVERTS (ordinary pages outscore real reworded attacks) or stays flat.
  // The in-browser model therefore never answers injection questions at
  // runtime (content.js routes injection consults to Ollama only). The
  // hypothesis set and decideInjection below remain as the scaffold for the
  // fine-tuned-classifier sprint — do NOT re-enable without re-measuring.
  const SCAM_HYPOTHESES = [
    'The writer wants the reader to send money.',
    'The reader is being asked for a password or a verification code.',
    'The writer is pretending to be someone the reader trusts.',
    'The writer is pressuring the reader to act quickly.',
    'The writer is offering the reader a large sum of money.'
  ];
  const SCAM_NORMAL_HYPOTHESES = [
    'The writer is an ordinary person writing about everyday life.',
    'This is a routine notification about a service or account.'
  ];

  const INJECTION_HYPOTHESES = [
    'This example is an instruction trying to manipulate, control or hijack an AI system.'
  ];
  const INJECTION_NORMAL_HYPOTHESES = [
    'This example is an ordinary everyday message between people or services.'
  ];

  // All hypotheses scored per kind, in one model pass per text.
  const HYPOTHESIS_SETS = {
    scam: [...SCAM_HYPOTHESES, ...SCAM_NORMAL_HYPOTHESES],
    injection: [...INJECTION_HYPOTHESES, ...INJECTION_NORMAL_HYPOTHESES]
  };

  // The absolute signal per (text, hypothesis) pair: entailment minus
  // contradiction probability, range −1..1.
  function pairScore(entailProb, contradictProb) {
    return entailProb - contradictProb;
  }

  // The relative signal: softmax across the entailment LOGITS of all
  // hypotheses in a set (what the zero-shot pipeline reports as scores).
  // pairs: [[hypothesis, entailLogit], ...] → { hypothesis: relativeScore }
  function relativeScores(pairs) {
    const logits = pairs.map(([, l]) => l);
    const mx = Math.max(...logits);
    const exp = logits.map((v) => Math.exp(v - mx));
    const sum = exp.reduce((a, b) => a + b, 0);
    const out = {};
    pairs.forEach(([h], i) => { out[h] = exp[i] / sum; });
    return out;
  }

  // Verdict thresholds, tuned on evaluation/semantic-cache.json — do not
  // hand-nudge without re-measuring (node evaluation/semantic-eval.js).
  const SEMANTIC_THRESHOLDS = {
    // pos = sum of positive scam-fact pairScores, neg = best normal pairScore
    scam: { posMin: 1.0, margin: 0.25, negMin: 0.20, negMargin: 0.10 },
    // pos = best injection softmax share, neg = best normal share
    injection: { posMin: 0.30, margin: 0.15, negMin: 0.55, negMargin: 0.15 }
  };

  // ---- Fine-tuned 3-class head (the production path since v9.3.0) ----
  // Classes are fixed by training: 0 = legit, 1 = scam, 2 = injection.
  // Thresholds were grid-searched on the HELD-OUT corpora through the real
  // runtime bundle (evaluation/measure-ft.js → ft-results.json):
  //   injection 0.70/0.10 → 7/7 recall, 0 false alarms on 100 negatives
  //   scam      0.85/0.30 → 7/14 recall; model-only catches MUST surface at
  //   'suspicious' severity in content.js — 21/100 ordinary-but-scam-shaped
  //   messages trip this head, so it never screams on its own.
  const FINE_TUNED_THRESHOLDS = {
    scam: { posMin: 0.85, margin: 0.30, legitMin: 0.90, legitMargin: 0.20 },
    injection: { posMin: 0.70, margin: 0.10, legitMin: 0.90, legitMargin: 0.20 }
  };

  // ---- Language routing (measured, v9.5.0) ----
  // The multilingual model's scam head overfits machine-translation style:
  // on NATURAL English it false-alarms on ~70% of ordinary messages
  // (evaluation/measure-ft.js), while its injection head is excellent
  // everywhere and non-English scam detection works. Route accordingly:
  // English text never gets a model-only scam escalation until a
  // rebalanced retrain lands.
  const ENGLISH_MARKERS = /\b(the|and|is|are|was|you|your|to|of|it|that|for|on|with|this|have|from|not|we|my|me|at|be|as|in|can|do|will|just|about|get)\b/gi;
  function isEnglishText(text) {
    const t = String(text || '');
    // non-Latin scripts are non-English by definition
    if (/[\u00A0-\uFFFF]/.test(t.replace(/[\u2018\u2019\u201C\u201D\u2013\u2014\u20AC]/g, ''))) {
      const scripts = /[\u0400-\u04FF]|[\u0600-\u06FF]|[\u0900-\u097F]|[\u4E00-\u9FFF]|[\u3040-\u30FF]|[\uAC00-\uD7AF]/;
      if (scripts.test(t)) return false;
    }
    const words = t.toLowerCase().match(/[a-z']+/g) || [];
    if (words.length < 6) return true; // too short to judge — treat as English
    const hits = (t.match(ENGLISH_MARKERS) || []).length;
    return hits >= 2 || hits / words.length > 0.08;
  }

  // probs: { legit, scam, injection } from the fine-tuned classifier
  function decideFineTuned(probs, kind, thresholds) {
    const t = thresholds || FINE_TUNED_THRESHOLDS[kind === 'injection' ? 'injection' : 'scam'];
    const pos = kind === 'injection' ? probs.injection : probs.scam;
    const neg = probs.legit;
    const attack = kind === 'injection' ? 'manipulation' : 'scam';
    const normal = kind === 'injection' ? 'normal' : 'legit';
    if (typeof pos !== 'number' || typeof neg !== 'number') return { verdict: 'unclear', confidence: 0 };
    if (pos >= t.posMin && pos - neg >= t.margin) return { verdict: attack, confidence: round100(pos) };
    if (neg >= t.legitMin && neg - pos >= t.legitMargin) return { verdict: normal, confidence: round100(neg) };
    return { verdict: 'unclear', confidence: round100(Math.max(pos, neg)) };
  }

  function maxScore(scores, hypotheses) {
    let best = 0;
    for (const h of hypotheses) {
      const v = scores[h];
      if (typeof v === 'number' && v > best) best = v;
    }
    return best;
  }

  function round100(v) { return Math.max(0, Math.min(100, Math.round(v * 100))); }

  // scores: { [hypothesis sentence]: absolute pairScore (entail − contradict) }
  // pos = sum of POSITIVE fact scores (several weak facts compound into a
  // verdict; negative facts never cancel positive ones), neg = best normal.
  function decideScam(scores, thresholds) {
    const t = thresholds || SEMANTIC_THRESHOLDS.scam;
    let pos = 0;
    for (const h of SCAM_HYPOTHESES) if (scores[h] > 0) pos += scores[h];
    const neg = maxScore(scores, SCAM_NORMAL_HYPOTHESES);
    if (pos >= t.posMin && pos - neg >= t.margin) return { verdict: 'scam', confidence: round100(Math.min(1, pos / (2 * t.posMin))) };
    if (neg >= t.negMin && neg - pos >= t.negMargin) return { verdict: 'legit', confidence: round100(neg) };
    return { verdict: 'unclear', confidence: round100(Math.max(pos, neg)) };
  }

  // scores: { [hypothesis sentence]: relative softmax share across the set }
  function decideInjection(scores, thresholds) {
    const t = thresholds || SEMANTIC_THRESHOLDS.injection;
    const pos = maxScore(scores, INJECTION_HYPOTHESES);
    const neg = maxScore(scores, INJECTION_NORMAL_HYPOTHESES);
    if (pos >= t.posMin && pos - neg >= t.margin) return { verdict: 'manipulation', confidence: round100(pos) };
    if (neg >= t.negMin && neg - pos >= t.negMargin) return { verdict: 'normal', confidence: round100(neg) };
    return { verdict: 'unclear', confidence: round100(Math.max(pos, neg)) };
  }

  const VIGIL_SEMANTIC = { isEnglishText, SCAM_HYPOTHESES, SCAM_NORMAL_HYPOTHESES, INJECTION_HYPOTHESES, INJECTION_NORMAL_HYPOTHESES, HYPOTHESIS_SETS, SEMANTIC_THRESHOLDS, FINE_TUNED_THRESHOLDS, pairScore, relativeScores, maxScore, decideScam, decideInjection, decideFineTuned };
  root.VIGIL_SEMANTIC = VIGIL_SEMANTIC;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_SEMANTIC;
})(typeof self !== 'undefined' ? self : globalThis);
