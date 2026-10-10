#!/usr/bin/env node
/**
 * VIGIL Semantic Capture — runs the EXACT runtime model (vendored
 * transformers.min.js + WASM, same dtype/device as offscreen.js) inside a
 * headless Chromium over the labeled corpora, and records raw scores to
 * evaluation/semantic-cache.json.
 *
 * Unlike the zero-shot pipeline (which softmaxes ACROSS candidate labels and
 * dilutes absolute quality), this captures each hypothesis independently:
 * P(entailment) from the model's own 3-way NLI head. The runtime (offscreen.js)
 * scores the same way, so measured numbers ARE runtime numbers.
 *
 * Usage:  node evaluation/capture-scores.js
 * Output: evaluation/semantic-cache.json (resumable — re-run skips done items)
 * Local tool only: not part of CI, needs network once for the ~25MB model.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const SEM = require('../src/content/modules/semantic-engine.js');

const ROOT = path.join(__dirname, '..');
const CACHE = path.join(__dirname, 'semantic-cache.json');
const CAPTURE_HTML = path.join(__dirname, '.capture.html');
const MODEL = 'Xenova/mobilebert-uncased-mnli';

function loadCorpus(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'corpus', name), 'utf8')).messages;
}

(async () => {
  const core = loadCorpus('messages.json');
  const adv = loadCorpus('adversarial.json');
  const inj = loadCorpus('injection-adversarial.json');
  const all = [
    ...core.map((m, i) => ({ corpus: 'core', i, text: m.text })),
    ...adv.map((m, i) => ({ corpus: 'adversarial', i, text: m.text })),
    ...inj.map((m, i) => ({ corpus: 'injection-adversarial', i, text: m.text }))
  ];

  const items = [];
  for (const t of all) {
    if (t.corpus !== 'injection-adversarial') items.push({ key: `${t.corpus}|${t.i}|scam`, text: t.text, kind: 'scam' });
    items.push({ key: `${t.corpus}|${t.i}|injection`, text: t.text, kind: 'injection' });
  }

  const cache = fs.existsSync(CACHE)
    ? JSON.parse(fs.readFileSync(CACHE, 'utf8'))
    : { capturedAt: new Date().toISOString(), model: MODEL, metric: '[h, P(entail), P(contradict), entailLogit] per hypothesis', results: {} };
  const done = Object.keys(cache.results).length;
  const todo = items.filter(it => !cache.results[it.key]);
  console.log(`capture: ${done}/${items.length} already cached, ${todo.length} to score`);

  if (!fs.existsSync(path.join(ROOT, 'dist', 'vendor', 'transformers.min.js'))) {
    console.error('dist/vendor/transformers.min.js missing — run npm run build first');
    process.exit(1);
  }

  // Module page: imports the vendored build from file:// (flag relaxes file CORS)
  fs.writeFileSync(CAPTURE_HTML, '<!doctype html><html><body><script type="module">\n' +
    'import * as T from \'../dist/vendor/transformers.min.js\';\n  window.T = T;\n' +
    '</script></body></html>');

  const browser = await chromium.launchPersistentContext(path.join(__dirname, '.chrome-profile'), {
    headless: true,
    args: ['--allow-file-access-from-files']
  });
  const page = await browser.newPage();
  page.on('console', (m) => {
    const t = m.text();
    if (t.startsWith('load:') && !t.includes('progress')) console.log('  [browser]', t.slice(0, 160));
    else if (t.toLowerCase().includes('error')) console.log('  [browser]', t.slice(0, 160));
  });
  await page.goto('file://' + CAPTURE_HTML);
  await page.waitForFunction(() => !!window.T, null, { timeout: 30000 });
  await page.evaluate(() => { window.T.env.allowLocalModels = false; });
  await page.evaluate(() => {
    let p = null;
    window.__clf = () => {
      if (!p) {
        p = (async () => {
          const T = window.T;
          const MODEL = 'Xenova/mobilebert-uncased-mnli';
          const cfg = await T.AutoConfig.from_pretrained(MODEL);
          const id2label = cfg.id2label || {};
          const entIdx = Object.keys(id2label).find(k => String(id2label[k]).toLowerCase() === 'entailment');
          const conIdx = Object.keys(id2label).find(k => String(id2label[k]).toLowerCase() === 'contradiction');
          if (entIdx === undefined || conIdx === undefined) throw new Error('model config lacks entailment/contradiction labels');
          const tok = await T.AutoTokenizer.from_pretrained(MODEL);
          const mdl = await T.AutoModelForSequenceClassification.from_pretrained(MODEL, {
            dtype: 'q8', device: 'wasm',
            progress_callback: (pr) => { try { console.log('load: ' + pr.status + ' ' + (pr.file || '')); } catch (e) {} }
          });
          const ent = async (text, hyp) => {
            // v4 tokenizer: the pair goes via options.text_pair (a second
            // positional string is silently ignored!)
            const inputs = await tok(text, { text_pair: hyp, truncation: true });
            const out = await mdl(inputs);
            const logits = out.logits.tolist()[0];
            const mx = Math.max(...logits);
            const exp = logits.map(v => Math.exp(v - mx));
            const sum = exp.reduce((a, b) => a + b, 0);
            return { ent: exp[Number(entIdx)] / sum, con: exp[Number(conIdx)] / sum, entLogit: logits[Number(entIdx)] };
          };
          const sanity = await ent('The cat sat on the mat and fell asleep.', 'A cat is sleeping.');
          const contra = await ent('The cat sat on the mat and fell asleep.', 'The cat is flying to the moon.');
          console.log('load: sanity entail=' + sanity.ent.toFixed(3) + ' contra=' + contra.ent.toFixed(3));
          // strict separation — identical scores would mean the hypothesis
          // text is being ignored (the v4 text_pair trap this guards against)
          if (sanity.ent < sanity.con + 0.3 || contra.con < contra.ent + 0.3) {
            throw new Error('NLI head sanity check failed — hypothesis ignored or label order wrong');
          }
          return ent;
        })();
      }
      return p;
    };
  });

  let n = 0;
  for (const it of todo) {
    const hyps = it.kind === 'scam' ? SEM.HYPOTHESIS_SETS.scam : SEM.HYPOTHESIS_SETS.injection;
    const t0 = Date.now();
    const pairs = await page.evaluate(async ({ text, hyps }) => {
      const ent = await window.__clf();
      const out = [];
      for (const h of hyps) {
        const { ent: e, con: c, entLogit: l } = await ent(String(text), h);
        out.push([h, e, c, l]);
      }
      return out;
    }, { text: it.text, hyps });
    cache.results[it.key] = pairs;
    n++;
    if (n % 10 === 0 || n === todo.length) {
      fs.writeFileSync(CACHE, JSON.stringify(cache, null, 1));
      console.log(`  ${n}/${todo.length} (${Date.now() - t0}ms last) saved`);
    }
  }
  fs.writeFileSync(CACHE, JSON.stringify(cache, null, 1));

  await browser.close();
  fs.rmSync(CAPTURE_HTML, { force: true });
  console.log('capture complete →', CACHE);
})().catch((e) => { console.error('capture failed:', e.message); process.exit(1); });
