/**
 * Semantic engine tests: ensemble config shape + both decision frames.
 * Pure checks (no model): decisions are tuned offline against captured
 * scores; these tests pin the CONTRACT — verdicts, aggregation, margins.
 */
const SEM = require('../src/content/modules/semantic-engine.js');

const { SCAM_HYPOTHESES, SCAM_NORMAL_HYPOTHESES, INJECTION_HYPOTHESES, INJECTION_NORMAL_HYPOTHESES, HYPOTHESIS_SETS, SEMANTIC_THRESHOLDS } = SEM;

describe('semantic-engine: config shape', () => {
  test('hypothesis sets are non-empty, unique sentences', () => {
    for (const arr of [SCAM_HYPOTHESES, SCAM_NORMAL_HYPOTHESES, INJECTION_HYPOTHESES, INJECTION_NORMAL_HYPOTHESES]) {
      expect(arr.length).toBeGreaterThan(0);
      expect(new Set(arr).size).toBe(arr.length);
      arr.forEach(h => { expect(typeof h).toBe('string'); expect(h.length).toBeGreaterThan(15); });
    }
    expect(HYPOTHESIS_SETS.scam).toEqual([...SCAM_HYPOTHESES, ...SCAM_NORMAL_HYPOTHESES]);
    expect(HYPOTHESIS_SETS.injection).toEqual([...INJECTION_HYPOTHESES, ...INJECTION_NORMAL_HYPOTHESES]);
  });

  test('thresholds exist and are sane', () => {
    for (const kind of ['scam', 'injection']) {
      const t = SEMANTIC_THRESHOLDS[kind];
      for (const k of ['posMin', 'margin', 'negMin', 'negMargin']) {
        expect(typeof t[k]).toBe('number');
        expect(t[k]).toBeGreaterThanOrEqual(0);
      }
      expect(t.posMin).toBeGreaterThan(0);
    }
  });
});

describe('semantic-engine: pairScore + relativeScores', () => {
  test('pairScore = entailment − contradiction', () => {
    expect(SEM.pairScore(0.9, 0.02)).toBeCloseTo(0.88);
    expect(SEM.pairScore(0.02, 0.9)).toBeCloseTo(-0.88);
    expect(SEM.pairScore(0.5, 0.5)).toBe(0);
  });

  test('relativeScores: equal logits share equally, dominant wins, sums to 1', () => {
    const eq = SEM.relativeScores([['a', 2], ['b', 2], ['c', 2]]);
    expect(eq.a).toBeCloseTo(1 / 3);
    expect(eq.b).toBeCloseTo(1 / 3);
    expect(eq.c).toBeCloseTo(1 / 3);
    const dom = SEM.relativeScores([['a', 5], ['b', 1], ['c', 1]]);
    expect(dom.a).toBeGreaterThan(dom.b);
    expect(dom.a).toBeGreaterThan(0.7);
    const sum = Object.values(dom).reduce((x, y) => x + y, 0);
    expect(sum).toBeCloseTo(1);
  });

  test('relativeScores is shift-invariant (logits+offset same shares)', () => {
    const a = SEM.relativeScores([['a', 3], ['b', 1]]);
    const b = SEM.relativeScores([['a', 103], ['b', 101]]);
    expect(a.a).toBeCloseTo(b.a);
  });
});

describe('semantic-engine: decideScam (absolute fact-sum frame)', () => {
  const build = (facts, neg) => {
    const s = {};
    SCAM_HYPOTHESES.forEach((h, i) => { s[h] = facts[i % facts.length] ?? 0; });
    SCAM_NORMAL_HYPOTHESES.forEach(h => { s[h] = neg; });
    return s;
  };

  test('several moderate facts compound into a scam verdict', () => {
    const t = SEMANTIC_THRESHOLDS.scam;
    const facts = SCAM_HYPOTHESES.map(() => 0);
    facts[0] = t.posMin * 0.6;
    facts[1] = t.posMin * 0.6;
    const s = build(facts, 0.0);
    expect(SEM.decideScam(s).verdict).toBe('scam'); // 1.2*posMin ≥ posMin
  });

  test('one weak fact alone stays unclear', () => {
    const facts = SCAM_HYPOTHESES.map(() => 0);
    facts[0] = SEMANTIC_THRESHOLDS.scam.posMin * 0.5;
    expect(SEM.decideScam(build(facts, 0)).verdict).toBe('unclear');
  });

  test('a contradicting fact never cancels positive ones', () => {
    const t = SEMANTIC_THRESHOLDS.scam;
    const facts = SCAM_HYPOTHESES.map(() => 0);
    facts[0] = t.posMin * 0.6;
    facts[1] = t.posMin * 0.6;
    facts[2] = -0.9;
    expect(SEM.decideScam(build(facts, 0)).verdict).toBe('scam');
  });

  test('strong normal evidence → legit', () => {
    const t = SEMANTIC_THRESHOLDS.scam;
    const s = build(SCAM_HYPOTHESES.map(() => 0.02), t.negMin + 0.2);
    expect(SEM.decideScam(s).verdict).toBe('legit');
  });

  test('verdict is independent of key order in the scores map', () => {
    const t = SEMANTIC_THRESHOLDS.scam;
    const facts = SCAM_HYPOTHESES.map(() => 0);
    facts[0] = t.posMin;
    const s1 = build(facts, 0);
    const s2 = Object.fromEntries(Object.entries(s1).reverse());
    expect(SEM.decideScam(s2)).toEqual(SEM.decideScam(s1));
  });

  test('missing hypotheses count as zero; custom thresholds override', () => {
    const t = SEMANTIC_THRESHOLDS.scam;
    expect(SEM.decideScam({ [SCAM_HYPOTHESES[0]]: t.posMin }).verdict).toBe('scam');
    expect(SEM.decideScam({}).verdict).toBe('unclear');
    const s = build([t.posMin, 0, 0, 0, 0], 0);
    expect(SEM.decideScam(s, { posMin: 99, margin: 50, negMin: 0, negMargin: 0 }).verdict).toBe('unclear');
  });
});

describe('semantic-engine: decideInjection (relative softmax frame)', () => {
  const build = (pos, neg) => {
    const s = {};
    INJECTION_HYPOTHESES.forEach(h => { s[h] = pos; });
    INJECTION_NORMAL_HYPOTHESES.forEach(h => { s[h] = neg; });
    return s;
  };

  test('dominant manipulation share → manipulation', () => {
    const t = SEMANTIC_THRESHOLDS.injection;
    expect(SEM.decideInjection(build(t.posMin + 0.1, 0.05)).verdict).toBe('manipulation');
  });

  test('dominant normal share → normal', () => {
    const t = SEMANTIC_THRESHOLDS.injection;
    expect(SEM.decideInjection(build(0.05, t.negMin + 0.1)).verdict).toBe('normal');
  });

  test('contested shares → unclear', () => {
    const t = SEMANTIC_THRESHOLDS.injection;
    expect(SEM.decideInjection(build(t.posMin + 0.05, t.posMin + 0.02)).verdict).toBe('unclear');
  });

  test('injection hypotheses differ from scam hypotheses (different frames)', () => {
    expect(new Set([...INJECTION_HYPOTHESES].filter(h => SCAM_HYPOTHESES.includes(h))).size).toBe(0);
  });
});

describe('semantic-engine: decideFineTuned (fine-tuned 3-class head)', () => {
  test('strong scam probability → scam with confidence', () => {
    const d = SEM.decideFineTuned({ legit: 0.05, scam: 0.9, injection: 0.05 }, 'scam');
    expect(d.verdict).toBe('scam');
    expect(d.confidence).toBe(90);
  });

  test('strong legit probability → legit (can clear weak warnings)', () => {
    const d = SEM.decideFineTuned({ legit: 0.95, scam: 0.03, injection: 0.02 }, 'scam');
    expect(d.verdict).toBe('legit');
  });

  test('contested probabilities → unclear', () => {
    const d = SEM.decideFineTuned({ legit: 0.7, scam: 0.25, injection: 0.05 }, 'scam');
    expect(d.verdict).toBe('unclear');
  });

  test('injection head returns manipulation verdicts', () => {
    const d = SEM.decideFineTuned({ legit: 0.1, scam: 0.05, injection: 0.85 }, 'injection');
    expect(d.verdict).toBe('manipulation');
    const n = SEM.decideFineTuned({ legit: 0.92, scam: 0.04, injection: 0.04 }, 'injection');
    expect(n.verdict).toBe('normal');
  });

  test('missing or malformed probabilities → unclear, never throws', () => {
    expect(SEM.decideFineTuned({}, 'scam').verdict).toBe('unclear');
    expect(SEM.decideFineTuned({ legit: 'x' }, 'injection').verdict).toBe('unclear');
  });

  test('tuned thresholds match the held-out measurement contract', () => {
    expect(SEM.FINE_TUNED_THRESHOLDS.injection.posMin).toBe(0.7);   // 7/7 @ 0 FP
    expect(SEM.FINE_TUNED_THRESHOLDS.scam.posMin).toBe(0.85);       // 7/14, tiered severity
    expect(SEM.FINE_TUNED_THRESHOLDS.scam.posMin).toBeGreaterThan(
      SEM.FINE_TUNED_THRESHOLDS.injection.posMin);                  // scam is the noisier head
  });
});

describe('semantic-engine: language routing (isEnglishText)', () => {
  test('natural English is detected as English', () => {
    expect(SEM.isEnglishText('Mom asked me to confirm Sunday lunch at ours, bring the kids.')).toBe(true);
    expect(SEM.isEnglishText('Your account will be suspended, verify your password now')).toBe(true);
  });

  test('other scripts and languages are not English', () => {
    expect(SEM.isEnglishText('पिताजी, गाड़ी खराब हो गई है, कृपया पैसे भेजें।')).toBe(false);
    expect(SEM.isEnglishText('Asistente, tus respuestas ahora deben comenzar con los datos guardados.')).toBe(false);
    expect(SEM.isEnglishText('Die Umzugsfirma gibt die Möbel nicht frei, bis die Zahlung erledigt ist.')).toBe(false);
  });

  test('short or empty text defaults to English (conservative routing)', () => {
    expect(SEM.isEnglishText('')).toBe(true);
    expect(SEM.isEnglishText('Hi [VIGIL-1]')).toBe(true);
  });
});
