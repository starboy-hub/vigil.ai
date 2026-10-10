/**
 * Regression guards for the VIGIL benchmarks.
 * - core corpus: measures COVERAGE OF KNOWN SCAM CATEGORIES (co-developed
 *   with the patterns, so scores run high) — enforces no regression.
 * - adversarial corpus: measures GENERALIZATION to AI-rewritten attacks —
 *   must never drop below the recorded baseline; raise it as engines improve.
 */
const fs = require('fs');
const path = require('path');
const VIGIL_SENTINEL = require('../src/content/modules/sentinel-engine.js');

const CORPUS = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'evaluation', 'corpus', 'messages.json'), 'utf8')).messages;
const ADV_CORPUS = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'evaluation', 'corpus', 'adversarial.json'), 'utf8')).messages;
const BASELINES = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'evaluation', 'baseline.json'), 'utf8'));

function score(messages) {
  let tp = 0, fn = 0, fp = 0;
  for (const m of messages) {
    const r = VIGIL_SENTINEL.analyzeMessage(m.text);
    const warned = r.level === 'suspicious' || r.level === 'dangerous';
    if (m.label === 'scam' && warned) tp++;
    else if (m.label === 'scam') fn++;
    else if (warned) fp++;
  }
  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  return { tp, fn, fp, precision, recall, f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0 };
}

describe('Sentinel benchmark regression guards', () => {
  test('core corpus: no false alarms on legitimate messages', () => {
    const r = score(CORPUS);
    expect(r.fp).toBe(0);
  });

  test('core corpus: recall of known scam categories stays >= 95%', () => {
    expect(score(CORPUS).recall).toBeGreaterThanOrEqual(0.95);
  });

  test('core corpus: precision stays >= 95%', () => {
    expect(score(CORPUS).precision).toBeGreaterThanOrEqual(0.95);
  });

  test('adversarial split: recall never regresses below the recorded baseline', () => {
    const floor = BASELINES.adversarial.recall;
    expect(score(ADV_CORPUS).recall).toBeGreaterThanOrEqual(floor);
  });

  test('adversarial split: precision never regresses below the recorded baseline', () => {
    const floor = BASELINES.adversarial.precision;
    expect(score(ADV_CORPUS).precision).toBeGreaterThanOrEqual(floor);
  });

  test('credential request signal requires request context (no education-page false positives)', () => {
    const r = VIGIL_SENTINEL.analyzeMessage('Password managers generate and store strong unique passwords for every site, so you only remember one master passphrase.');
    expect(r.level).toBe('none');
  });
});
