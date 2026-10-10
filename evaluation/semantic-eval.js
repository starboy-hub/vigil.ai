#!/usr/bin/env node
/**
 * VIGIL Semantic Eval — offline tuner for the per-hypothesis NLI decisions.
 *
 * Reads evaluation/semantic-cache.json (P(entailment) per hypothesis, captured
 * by capture-scores.js through the real runtime bundle) and grid-searches the
 * decision thresholds in semantic-engine.js against the RUNTIME constraint
 * set, not a naive model-only one:
 *   - the heuristics already catch the core corpus (recall 1.0, FP 0), so the
 *     model's job is escalation, and its FP budget on negatives is small:
 *     <= 3 core negatives and <= 2 adversarial negatives (keeps combined
 *     core precision >= 0.95)
 *   - maximize adversarial scam recall; sprint goal >= 0.60 (was 0%)
 *   - injection split: <= 2 FPs over 166 negatives, maximize recall
 *
 * Usage:
 *   node evaluation/semantic-eval.js          # grid search + recommendation
 *   node evaluation/semantic-eval.js --verify # metrics for thresholds baked
 *                                             # into semantic-engine.js
 */
const fs = require('fs');
const path = require('path');
const SEM = require('../src/content/modules/semantic-engine.js');

const CACHE = path.join(__dirname, 'semantic-cache.json');
const CORPUS_FILES = { core: 'messages.json', adversarial: 'adversarial.json', 'injection-adversarial': 'injection-adversarial.json' };

function loadCorpus(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'corpus', name), 'utf8')).messages;
}

function rowSet(cache, corpus, kind) {
  return loadCorpus(CORPUS_FILES[corpus]).map((m, i) => {
    const pairs = cache.results[`${corpus}|${i}|${kind}`];
    // decision frame per kind, mirroring background.js exactly
    const s = kind === 'injection'
      ? SEM.relativeScores((pairs || []).map(([h, , , l]) => [h, l]))
      : (pairs || []).reduce((acc, [h, ent, con]) => { acc[h] = SEM.pairScore(ent, con); return acc; }, {});
    return { label: m.label, text: m.text, scores: s, missing: !pairs };
  });
}

function metrics(rows, verdictFn, attackLabel) {
  const c = { tp: 0, fp: 0, tn: 0, fn: 0 };
  const misses = [], falseAlarms = [];
  for (const r of rows) {
    const d = verdictFn(r.scores);
    const v = (d && typeof d === 'object') ? d.verdict : d;
    const flagged = v === attackLabel;
    if (r.label === attackLabel) {
      if (flagged) c.tp++; else { c.fn++; misses.push(r.text.slice(0, 80)); }
    } else if (flagged) { c.fp++; falseAlarms.push(r.text.slice(0, 80)); } else c.tn++;
  }
  const precision = c.tp / (c.tp + c.fp) || 0;
  const recall = c.tp / (c.tp + c.fn) || 0;
  return { ...c, precision: +precision.toFixed(3), recall: +recall.toFixed(3), f1: +((precision + recall) ? 2 * precision * recall / (precision + recall) : 0).toFixed(3), misses, falseAlarms };
}

function fmt(m) {
  return `P ${m.precision}  R ${m.recall}  F1 ${m.f1}  (tp ${m.tp} fp ${m.fp} tn ${m.tn} fn ${m.fn})`;
}

function main() {
  if (!fs.existsSync(CACHE)) { console.error('no semantic-cache.json — run capture-scores.js first'); process.exit(1); }
  const cache = JSON.parse(fs.readFileSync(CACHE, 'utf8'));

  const coreRows = rowSet(cache, 'core', 'scam');
  const advRows = rowSet(cache, 'adversarial', 'scam');
  const injRows = rowSet(cache, 'injection-adversarial', 'injection');
  const injNegRows = rowSet(cache, 'core', 'injection').concat(rowSet(cache, 'adversarial', 'injection'));
  console.log(`rows: core ${coreRows.length}, adversarial ${advRows.length}, injection ${injRows.length}, injection-negatives ${injNegRows.length}`);
  if (coreRows.some(r => r.missing) || advRows.some(r => r.missing) || injRows.some(r => r.missing)) {
    console.error('cache incomplete — rerun capture-scores.js');
    process.exit(1);
  }

  const coreNeg = coreRows.filter(r => r.label !== 'scam');
  const advNeg = advRows.filter(r => r.label !== 'scam');
  const injNeg = injNegRows.filter(r => r.label !== 'scam'); // injection-kind scores, not scam!
  const advScams = advRows.filter(r => r.label === 'scam');

  const curScamTh = SEM.SEMANTIC_THRESHOLDS.scam, curInjTh = SEM.SEMANTIC_THRESHOLDS.injection;
  const curCore = metrics(coreRows, s => SEM.decideScam(s, curScamTh), 'scam');
  const curAdv = metrics(advRows, s => SEM.decideScam(s, curScamTh), 'scam');
  const curInj = metrics(injRows, s => SEM.decideInjection(s, curInjTh), 'injection');
  const curInjFP = metrics(injNeg, s => SEM.decideInjection(s, curInjTh), 'injection');
  console.log('\n── CURRENT semantic-engine thresholds ──');
  console.log(' scam ' + JSON.stringify(curScamTh) + '  injection ' + JSON.stringify(curInjTh));
  console.log(' core:        ' + fmt(curCore));
  console.log(' adversarial: ' + fmt(curAdv));
  console.log(' injection:   ' + fmt(curInj) + '   FPs on ' + injNeg.length + ' negatives: ' + curInjFP.fp);

  if (process.argv.includes('--verify')) {
    console.log('\nadversarial misses:');
    curAdv.misses.forEach(t => console.log('  · ' + t));
    console.log('core false alarms:');
    curCore.falseAlarms.forEach(t => console.log('  · ' + t));
    console.log('injection false alarms (on negatives):');
    curInjFP.falseAlarms.slice(0, 10).forEach(t => console.log('  · ' + t));
    return;
  }

  const isFlagged = (fn) => (s) => { const d = fn(s); return (d && typeof d === 'object') ? d.verdict : d; };

  console.log('\n── scam frontier (meets FP budget; posMin = sum of positive fact scores) ──');
  const scamFeasible = [];
  for (const posMin of [0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0]) for (const margin of [0.05, 0.15, 0.25, 0.4]) {
    const t = { posMin, margin, negMin: 0.20, negMargin: 0.10 };
    const v = isFlagged(s => SEM.decideScam(s, t));
    const coreFP = coreNeg.filter(r => v(r.scores) === 'scam').length;
    const advFP = advNeg.filter(r => v(r.scores) === 'scam').length;
    if (coreFP > 3 || advFP > 2) continue;
    const rec = advScams.filter(r => v(r.scores) === 'scam').length / advScams.length;
    scamFeasible.push({ t, coreFP, advFP, rec });
  }
  scamFeasible.sort((a, b) => b.rec - a.rec || (a.coreFP + a.advFP) - (b.coreFP + b.advFP));
  scamFeasible.slice(0, 6).forEach((x, i) => console.log(` ${i + 1}. ${JSON.stringify(x.t)} → adv recall ${x.rec.toFixed(3)}  coreFP ${x.coreFP}  advFP ${x.advFP}`));

  console.log('\n── injection frontier (meets FP budget) ──');
  const injFeasible = [];
  for (const posMin of [0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9]) for (const margin of [0.0, 0.1, 0.2]) {
    const t = { posMin, margin, negMin: 0.6, negMargin: 0.1 };
    const v = isFlagged(s => SEM.decideInjection(s, t));
    const fp = injNeg.filter(r => v(r.scores) === 'manipulation').length;
    if (fp > 2) continue;
    const rec = injRows.filter(r => r.label === 'injection' && v(r.scores) === 'manipulation').length;
    injFeasible.push({ t, fp, rec });
  }
  injFeasible.sort((a, b) => b.rec - a.rec || a.fp - b.fp);
  injFeasible.slice(0, 6).forEach((x, i) => console.log(` ${i + 1}. ${JSON.stringify(x.t)} → recall ${x.rec}/7  FP ${x.fp}`));

  // Full constraint check (incl. legit side) for the best of each
  const bestScam = scamFeasible[0], bestInj = injFeasible[0];
  if (bestScam) {
    const core = metrics(coreRows, s => SEM.decideScam(s, bestScam.t), 'scam');
    const adv = metrics(advRows, s => SEM.decideScam(s, bestScam.t), 'scam');
    console.log('\n RECOMMENDED scam: ' + JSON.stringify(bestScam.t));
    console.log('   core:        ' + fmt(core));
    console.log('   adversarial: ' + fmt(adv));
    console.log('   adversarial misses:');
    adv.misses.forEach(t => console.log('     · ' + t));
    console.log('   core false alarms:');
    core.falseAlarms.forEach(t => console.log('     · ' + t));
  }
  if (bestInj) {
    const inj = metrics(injRows, s => SEM.decideInjection(s, bestInj.t), 'injection');
    const injFP = metrics(injNeg, s => SEM.decideInjection(s, bestInj.t), 'injection');
    console.log('\n RECOMMENDED injection: ' + JSON.stringify(bestInj.t));
    console.log('   injection: ' + fmt(inj) + '   FPs on negatives: ' + injFP.fp);
    injFP.falseAlarms.slice(0, 5).forEach(t => console.log('     · ' + t));
  }
}

main();
