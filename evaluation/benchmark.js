#!/usr/bin/env node
/**
 * VIGIL Benchmark (Phase 0 — measure honestly)
 *
 * Runs the real detection engines over the labeled corpora:
 *   - core corpus (messages.json): known scam categories + hard negatives
 *   - adversarial corpus (adversarial.json): AI-rewritten attacks, zero
 *     keyword overlap — measures GENERALIZATION (expect honest gaps)
 *   - injection adversarial corpus (injection-adversarial.json)
 *
 * Usage: npm run benchmark [-- --update-baseline] [--compare]
 */
const fs = require('fs');
const path = require('path');
const VIGIL_SENTINEL = require('../src/content/modules/sentinel-engine.js');
const VIGIL_INJECTION = require('../src/content/modules/injection-engine.js');

const BASELINE = path.join(__dirname, 'baseline.json');
const RESULTS = path.join(__dirname, 'results.json');

function loadCorpus(name) {
  const p = path.join(__dirname, 'corpus', name);
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')).messages : null;
}

function scoreSentinel(messages) {
  const c = { tp: 0, fp: 0, tn: 0, fn: 0 };
  const misses = [], falseAlarms = [];
  for (const m of messages) {
    const r = VIGIL_SENTINEL.analyzeMessage(m.text);
    const warned = r.level === 'suspicious' || r.level === 'dangerous';
    if (m.label === 'scam') { warned ? c.tp++ : (c.fn++, misses.push({ category: m.category, level: r.level, text: m.text.slice(0, 90) })); }
    else if (warned) { c.fp++; falseAlarms.push({ category: m.category, level: r.level, text: m.text.slice(0, 90) }); }
    else c.tn++;
  }
  const precision = c.tp / (c.tp + c.fp) || 0;
  const recall = c.tp / (c.tp + c.fn) || 0;
  return { counts: c, precision: +precision.toFixed(3), recall: +recall.toFixed(3), f1: +((precision + recall) ? (2 * precision * recall) / (precision + recall) : 0).toFixed(3), misses, falseAlarms };
}

function scoreInjection(messages) {
  const c = { tp: 0, fp: 0, tn: 0, fn: 0 };
  const misses = [], falseAlarms = [];
  for (const m of messages) {
    const r = VIGIL_INJECTION.analyzeInjection(m.text);
    const flagged = r.level === 'suspicious' || r.level === 'dangerous';
    if (m.label === 'injection') { flagged ? c.tp++ : (c.fn++, misses.push({ category: m.category, level: r.level, text: m.text.slice(0, 90) })); }
    else if (flagged) { c.fp++; falseAlarms.push({ category: m.category, level: r.level, text: m.text.slice(0, 90) }); }
    else c.tn++;
  }
  const precision = c.tp / (c.tp + c.fp) || 0;
  const recall = c.tp / (c.tp + c.fn) || 0;
  return { counts: c, precision: +precision.toFixed(3), recall: +recall.toFixed(3), f1: +((precision + recall) ? (2 * precision * recall) / (precision + recall) : 0).toFixed(3), misses, falseAlarms };
}

// ---- Core corpus ----
const CORE = loadCorpus('messages.json');
const coreCounts = { tp: 0, fp: 0, tn: 0, fn: 0 };
const coreMisses = [], coreFalseAlarms = [];
const perCategory = {};

for (const m of CORE) {
  const r = VIGIL_SENTINEL.analyzeMessage(m.text);
  const warned = r.level === 'suspicious' || r.level === 'dangerous';
  perCategory[m.category] = perCategory[m.category] || { total: 0, flagged: 0 };
  perCategory[m.category].total++;
  if (warned) perCategory[m.category].flagged++;

  if (m.label === 'scam') {
    if (warned) coreCounts.tp++;
    else {
      coreCounts.fn++;
      coreMisses.push({ category: m.category, level: r.level, text: m.text.slice(0, 90) });
    }
  } else if (warned) {
    coreCounts.fp++;
    coreFalseAlarms.push({ category: m.category, level: r.level, signals: VIGIL_SENTINEL.topSignals(r, 2), text: m.text.slice(0, 90) });
  } else {
    coreCounts.tn++;
  }
}

const corePrecision = coreCounts.tp / (coreCounts.tp + coreCounts.fp) || 0;
const coreRecall = coreCounts.tp / (coreCounts.tp + coreCounts.fn) || 0;
const core = {
  counts: coreCounts,
  precision: +corePrecision.toFixed(3),
  recall: +coreRecall.toFixed(3),
  f1: +((corePrecision + coreRecall) ? (2 * corePrecision * coreRecall) / (corePrecision + coreRecall) : 0).toFixed(3),
  perCategory,
  misses: coreMisses,
  falseAlarms: coreFalseAlarms
};

// ---- Adversarial split ----
const ADV = loadCorpus('adversarial.json');
const advScoring = scoreSentinel(ADV);

// ---- Injection adversarial split ----
const INJADV = loadCorpus('injection-adversarial.json');
const injScoring = scoreInjection(INJADV);

// ---- Report ----
console.log('════════════════════════════════════════════');
console.log(' VIGIL Benchmark');
console.log('════════════════════════════════════════════');
console.log(` core corpus:     ${CORE.length} labeled messages`);
console.log(` true pos:        ${coreCounts.tp}   false neg: ${coreCounts.fn}`);
console.log(` false pos:       ${coreCounts.fp}   true neg:  ${coreCounts.tn}`);
console.log(` precision:       ${(core.precision * 100).toFixed(1)}%`);
console.log(` recall:          ${(core.recall * 100).toFixed(1)}%`);
console.log(` f1:              ${core.f1}`);
console.log('');
console.log('── ADVERSARIAL SPLIT (AI-rewritten attacks — generalization) ──');
console.log(` texts:           ${ADV.length}`);
console.log(` precision:       ${(advScoring.precision * 100).toFixed(1)}%`);
console.log(` recall:          ${(advScoring.recall * 100).toFixed(1)}%   <- the honest gap`);
console.log(` f1:              ${advScoring.f1}`);
console.log('');
console.log('── INJECTION ADVERSARIAL SPLIT ──');
console.log(` texts:           ${INJADV.length}`);
console.log(` precision:       ${(injScoring.precision * 100).toFixed(1)}%`);
console.log(` recall:          ${(injScoring.recall * 100).toFixed(1)}%   <- the honest gap`);
console.log(` f1:              ${injScoring.f1}`);
if (advScoring.misses.length) {
  console.log('');
  console.log(' adversarial misses:');
  advScoring.misses.forEach(m => console.log(`  [${m.category}] ${m.text}`));
}
if (injScoring.misses.length) {
  console.log(' injection misses:');
  injScoring.misses.forEach(m => console.log(`  [${m.category}] ${m.text}`));
}

const results = {
  generated: new Date().toISOString(),
  core,
  adversarial: { counts: advScoring.counts, precision: advScoring.precision, recall: advScoring.recall, f1: advScoring.f1, misses: advScoring.misses, falseAlarms: advScoring.falseAlarms },
  injectionAdversarial: { counts: injScoring.counts, precision: injScoring.precision, recall: injScoring.recall, f1: injScoring.f1, misses: injScoring.misses, falseAlarms: injScoring.falseAlarms }
};

const baseline = fs.existsSync(BASELINE) ? JSON.parse(fs.readFileSync(BASELINE, 'utf8')) : null;
if (baseline && baseline.core && process.argv.includes('--compare')) {
  console.log('');
  console.log(' vs baseline (core):');
  console.log(`  precision ${baseline.core.precision} -> ${core.precision}   recall ${baseline.core.recall} -> ${core.recall}   f1 ${baseline.core.f1} -> ${core.f1}`);
}
if (baseline && baseline.adversarial && process.argv.includes('--compare')) {
  console.log(`  adversarial recall ${baseline.adversarial.recall} -> ${advScoring.recall}`);
}

if (process.argv.includes('--update-baseline')) {
  fs.writeFileSync(BASELINE, JSON.stringify({
    core: { precision: core.precision, recall: core.recall, f1: core.f1, counts: coreCounts },
    adversarial: { precision: advScoring.precision, recall: advScoring.recall, f1: advScoring.f1 }
  }, null, 2));
  console.log('\n baseline updated');
}
fs.writeFileSync(RESULTS, JSON.stringify(results, null, 2));
console.log('\n full report: evaluation/results.json');
