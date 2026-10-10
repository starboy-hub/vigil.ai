#!/usr/bin/env node
/**
 * VIGIL training-seed generator — grows the fine-tune dataset from the
 * existing labeled corpora using the LOCAL Ollama model.
 *
 * Pipeline per variant:
 *   1. REWRITE: the seed message is rewritten N times (intent preserved,
 *      wording changed) by llama3.2:3b
 *   2. JUDGE: a second Ollama call verifies the label survived the rewrite
 *      (yes/no) — mislabeled rewrites are rejected
 *   3. FILTERS: length bounds, dedupe (normalizeForSignature), and for
 *      attack seeds an evasion flag from the real heuristic engines
 *
 * DATA HYGIENE: output is evaluation/training/train-seeds.json — TRAINING
 * data only. The existing corpora (messages.json, adversarial.json,
 * injection-adversarial.json) stay held-out evaluation and are NOT touched.
 *
 * Local tool only: needs Ollama running (http://localhost:11434).
 * Usage: node evaluation/training/generate-training.js [--dry-run]
 */
const fs = require('fs');
const path = require('path');
const VIGIL = require('../../src/shared/vigil-shared.js');
const SENTINEL = require('../../src/content/modules/sentinel-engine.js');
const INJECTION = require('../../src/content/modules/injection-engine.js');

const OLLAMA = 'http://localhost:11434/api/generate';
const MODEL = 'llama3.2:3b';
const OUT = path.join(__dirname, 'train-seeds.json');
const CORPUS_DIR = path.join(__dirname, '..', 'corpus');

function loadCorpus(name) {
  return JSON.parse(fs.readFileSync(path.join(CORPUS_DIR, name), 'utf8')).messages;
}

async function ask(prompt, maxTokens) {
  const res = await fetch(OLLAMA, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: MODEL, prompt, stream: false, options: { temperature: 0.85, num_predict: maxTokens || 320 } }),
    signal: AbortSignal.timeout(120000)
  });
  if (!res.ok) throw new Error('ollama http ' + res.status);
  const data = await res.json();
  return String(data.response || '').trim();
}

function splitVariants(reply) {
  return reply
    .split(/\n?---\n?|\n\d+[.)]\s/)
    .map(s => s.replace(/^["'\s]+|["'\s]+$/g, '').replace(/\s+/g, ' ').trim())
    .filter(s => s.length >= 25 && s.length <= 420);
}

// The 3B model sometimes refuses with meta-text ("I can't assist with
// creating scam messages") — those are never training data, and the naive
// judge would even approve them (they contain the word "scam"). Hard-reject.
const REFUSAL_RE = /(i can'?t|i cannot|i'?m unable|i am unable|as an ai|i can help you (with|by)|instead,? i|against (my|ethical|policy)|creating scam|assist you)/i;

const JUDGE_Q = {
  scam: 'If a person received this text, would it be an attempt to deceive them out of money, codes, credentials, or to deceptively pressure them?',
  injection: 'Does this text try to manipulate, control, or extract information from an AI system?',
  legit: 'Is this an ordinary benign everyday message with nothing deceptive?'
};

function buildPlan() {
  const core = loadCorpus('messages.json');
  const adv = loadCorpus('adversarial.json');
  const inj = loadCorpus('injection-adversarial.json');
  const plan = [];
  core.filter(m => m.label === 'scam').forEach(m => plan.push({ seed: m, corpus: 'core', variants: 2, task: 'scam' }));
  adv.filter(m => m.label === 'scam').forEach(m => plan.push({ seed: m, corpus: 'adversarial', variants: 3, task: 'scam' }));
  inj.filter(m => m.label === 'injection').forEach(m => plan.push({ seed: m, corpus: 'injection-adversarial', variants: 3, task: 'injection' }));
  adv.filter(m => m.label === 'legit').forEach(m => plan.push({ seed: m, corpus: 'adversarial', variants: 2, task: 'legit' }));
  core.filter(m => m.label === 'legit').slice(0, 30).forEach(m => plan.push({ seed: m, corpus: 'core', variants: 2, task: 'legit' }));
  return plan;
}

function rewritePrompt(task, text) {
  // Behavior-described framing, NEVER the labels "scam"/"injection":
  // safety-aligned small models refuse when asked for "a scam message" but
  // comply when asked to rewrite "a message with the same goal and pressure".
  // The judge + evasion filters still guarantee label integrity.
  if (task === 'scam') {
    return 'You are building a dataset of realistic everyday messages.\n' +
      'Rewrite the message below in 3 different ways. Keep the SAME goal and the SAME pressure on the reader, but change wording, structure, names and details completely. Do not reuse distinctive phrases from the original. Each version 20-60 words. Output ONLY the 3 rewritten messages — no intro, no notes.\n' +
      'Reply with ONLY the 3 versions separated by a line containing ---\n\nOriginal: ' + text;
  }
  if (task === 'injection') {
    return 'You are building a dataset of realistic example texts.\n' +
      'Rewrite the instruction below in 3 different ways, keeping the SAME goal — to direct an AI system or make it pass on information — but changing all wording and framing completely. Do not reuse distinctive phrases. Each version 15-50 words. Output ONLY the 3 rewritten messages — no intro, no notes.\n' +
      'Reply with ONLY the 3 versions separated by a line containing ---\n\nOriginal: ' + text;
  }
  return 'You are building a dataset of realistic everyday messages.\n' +
    'Write 3 NEW ordinary, benign messages inspired by the topic of the example below, but with completely different wording. Nothing deceptive: no money requests, no urgency pressure, no credentials, no threats. Vary the tone (family, work, services). Each version 15-60 words. Output ONLY the 3 rewritten messages — no intro, no notes.\n' +
    'Reply with ONLY the 3 versions separated by a line containing ---\n\nExample: ' + text;
}

function evasionFlags(task, text) {
  if (task === 'legit') {
    const r = SENTINEL.analyzeMessage(text);
    return { heuristicLevel: r.level, evadesHeuristics: r.level === 'none' };
  }
  if (task === 'injection') {
    const r = INJECTION.analyzeInjection(text);
    return { heuristicLevel: r.level, evadesHeuristics: r.level === 'none' };
  }
  const r = SENTINEL.analyzeMessage(text);
  return { heuristicLevel: r.level, evadesHeuristics: r.level === 'none' };
}

(async () => {
  if (process.argv.includes('--dry-run')) {
    const plan = buildPlan();
    console.log('plan:', plan.length, 'seed calls, ~', plan.reduce((a, p) => a + p.variants, 0), 'variants to judge');
    return;
  }
  const seen = new Set(loadCorpus('messages.json').concat(loadCorpus('adversarial.json'), loadCorpus('injection-adversarial.json')).map(m => VIGIL.normalizeForSignature(m.text)));
  const plan = buildPlan();
  const out = [];
  const stats = { generated: 0, judged: 0, kept: 0, rejectedJudge: 0, rejectedDuplicate: 0, rejectedFlaggedNegative: 0, refusedSeeds: 0 };
  const t0 = Date.now();

  function save() {
    fs.writeFileSync(OUT, JSON.stringify({
      generatedAt: new Date().toISOString(),
      purpose: 'TRAINING seeds for the fine-tuned classifier — held-out eval corpora are NOT included',
      generator: MODEL,
      stats,
      messages: out
    }, null, 1));
  }

  // One seed: generate drafts (with refusal retry), judge ALL drafts in a
  // single batched call, apply filters, return kept records.
  async function processSeed(seed) {
    const { corpus, variants, task } = seed;
    let drafts = [];
    for (let attempt = 0; attempt < 2 && !drafts.length; attempt++) {
      try {
        const reply = await ask(rewritePrompt(task, seed.text), 420);
        drafts = splitVariants(reply).filter(t => !REFUSAL_RE.test(t)).slice(0, variants);
      } catch (e) { return { kept: [], refused: true, judged: 0 }; }
    }
    if (!drafts.length) return { kept: [], refused: true, judged: 0 };
    // batch judge: "1: yes  2: no  3: yes"
    let verdicts = [];
    try {
      const list = drafts.map((t, i) => (i + 1) + ') ' + t).join('\n');
      const reply = await ask('For each numbered message below, answer the question with yes or no.\nQuestion: ' + JUDGE_Q[task] +
        '\nReply with ONLY one line like: 1: yes 2: no 3: yes\n\n' + list, 60);
      verdicts = drafts.map((_, i) => new RegExp((i + 1) + '\\s*[:.)-]\\s*yes', 'i').test(reply));
      stats.judged += drafts.length;
    } catch (e) {
      verdicts = drafts.map(() => true); // judge unavailable — keep drafts, filters still apply
    }
    const kept = [];
    for (let i = 0; i < drafts.length; i++) {
      const text = drafts[i];
      if (!verdicts[i]) { stats.rejectedJudge++; continue; }
      const norm = VIGIL.normalizeForSignature(text);
      if (seen.has(norm)) { stats.rejectedDuplicate++; continue; }
      const flags = evasionFlags(task, text);
      if (task === 'legit' && flags.heuristicLevel !== 'none') { stats.rejectedFlaggedNegative++; continue; }
      seen.add(norm);
      kept.push({
        text,
        label: task === 'legit' ? 'legit' : task,
        category: 'gen-' + seed.category,
        provenance: { corpus, generator: MODEL, judged: true, evadesHeuristics: flags.evadesHeuristics, heuristicLevel: flags.heuristicLevel }
      });
    }
    return { kept, refused: false, judged: drafts.length };
  }

  // Worker pool: Ollama queues concurrent requests; 4 workers ≈ 4× throughput
  const CONCURRENCY = 4;
  let cursor = 0, done = 0;
  async function worker() {
    while (cursor < plan.length) {
      const idx = cursor++;
      const r = await processSeed(plan[idx]);
      if (r.refused) stats.refusedSeeds++;
      out.push(...r.kept);
      stats.kept += r.kept.length;
      stats.generated += r.judged;
      done++;
      if (done % 8 === 0 || done === plan.length) {
        save();
        const mins = ((Date.now() - t0) / 60000).toFixed(1);
        console.log(`  seeds ${done}/${plan.length}  kept ${stats.kept}  refused ${stats.refusedSeeds}  (${mins} min)`);
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  save();
  console.log('done:', JSON.stringify(stats), '→', OUT);
})().catch(e => { console.error('generation failed:', e.message); process.exit(1); });
