/**
 * Tests for VIGIL AI K-Anonymity & Quasi-Identifier Entropy Auditing Engine
 */
const auditor = require('../src/content/modules/k-anonymity-auditor.js');

describe('VIGIL K-Anonymity & Quasi-Identifier Entropy Auditing Engine', () => {
  test('returns zero risk for clean text with no quasi-identifiers', () => {
    const clean = 'Can you explain the difference between photosynthesis and cellular respiration in detail?';
    const audit = auditor.auditPrompt(clean);

    expect(audit.quasiIdentifiers).toHaveLength(0);
    expect(audit.cumulativeEntropy).toBe(0);
    expect(audit.estimatedK).toBeGreaterThan(10000);
    expect(audit.riskTier).toBe('LOW');
    expect(audit.isHighRisk).toBe(false);
    expect(audit.warning).toBeNull();
  });

  test('single isolated quasi-identifier produces low-to-moderate entropy', () => {
    const single = 'I graduated from MIT and was wondering about graduate scholarships in engineering.';
    const audit = auditor.auditPrompt(single);

    expect(audit.quasiIdentifiers.length).toBeGreaterThanOrEqual(1);
    expect(audit.quasiIdentifiers[0].category).toBe('EDUCATION');
    expect(audit.cumulativeEntropy).toBeLessThan(6.0);
    expect(audit.estimatedK).toBeGreaterThan(50);
    expect(audit.riskTier).not.toBe('CRITICAL');
  });

  test('blueprint 3-factor composite uniquely identifies individual (K <= 5, CRITICAL risk)', () => {
    const composite = 'I graduated from MIT in 2018. I work at a 15-person biotech startup in Zurich. I specialize in CRISPR-Cas12b patent law.';
    const audit = auditor.auditPrompt(composite);

    expect(audit.quasiIdentifiers.length).toBeGreaterThanOrEqual(3);
    const categories = audit.quasiIdentifiers.map(q => q.category);
    expect(categories).toContain('EDUCATION');
    expect(categories).toContain('EMPLOYMENT_NICHE');
    expect(categories).toContain('SPECIALIZATION');

    expect(audit.cumulativeEntropy).toBeGreaterThanOrEqual(10.0);
    expect(audit.estimatedK).toBeLessThanOrEqual(5);
    expect(audit.riskScore).toBeGreaterThanOrEqual(0.85);
    expect(audit.riskTier).toBe('CRITICAL');
    expect(audit.isHighRisk).toBe(true);
    expect(audit.warning).toContain('Quasi-Identifier Alert');
    expect(audit.recommendations.length).toBeGreaterThanOrEqual(3);
  });

  test('clinical and demographic quasi-identifiers trigger high re-identification score', () => {
    const clinical = 'I am 47 years old living in Seattle and was recently diagnosed with pulmonary adenocarcinoma.';
    const audit = auditor.auditPrompt(clinical);

    expect(audit.quasiIdentifiers.length).toBeGreaterThanOrEqual(2);
    expect(audit.cumulativeEntropy).toBeGreaterThanOrEqual(6.0);
    expect(audit.riskScore).toBeGreaterThanOrEqual(0.70);
    expect(audit.recommendations.length).toBeGreaterThan(0);
  });

  test('generalizePrompt replaces exact numbers and years with broad buckets', () => {
    const prompt = 'I graduated from MIT in 2018 and work at a 15-person biotech startup in ZIP 94107.';
    const generalized = auditor.generalizePrompt(prompt);

    expect(generalized).not.toContain('in 2018');
    expect(generalized).not.toContain('15-person');
    expect(generalized).toContain('MIT recently');
    expect(generalized).toContain('early-stage');
  });

  test('handles empty or non-string inputs safely', () => {
    expect(auditor.auditPrompt(null).isHighRisk).toBe(false);
    expect(auditor.auditPrompt('').quasiIdentifiers).toHaveLength(0);
    expect(auditor.generalizePrompt(null)).toBe('');
  });
});

