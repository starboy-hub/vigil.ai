#!/usr/bin/env node
/**
 * VIGIL fine-tuned model measurement — runs the trained 3-class classifier
 * (src/offscreen-model, quantized) inside headless Chromium over the HELD-OUT
 * evaluation corpora and reports scam/injection metrics at candidate
 * thresholds. This is the honest generalization number.
 *
 * Local tool only: needs dist/vendor/transformers.min.js (npm run build).
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const REPO = path.join(__dirname, '..');

function loadCorpus(name) {
  return JSON.parse(fs.readFileSync(path.join(REPO, 'evaluation', 'corpus', name), 'utf8')).messages;
}

(async () => {
  // Serve src/ over localhost; the library is pointed at it via
  // remoteHost + remotePathTemplate (the same mechanism the extension uses
  // with chrome.runtime.getURL as remoteHost)
  const http = require('http');
  const MIME = { '.json': 'application/json', '.onnx': 'application/octet-stream', '.txt': 'text/plain' };
  const SRC_DIR = path.join(REPO, 'src');
  const server = http.createServer((req, res) => {
    let rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '');
    const file = path.join(SRC_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(SRC_DIR) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Access-Control-Allow-Origin': '*' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  fs.writeFileSync(path.join(REPO, 'evaluation', '.probe.html'),
    '<!doctype html><html><body><script type="module">\n' +
    'import * as T from \'../dist/vendor/transformers.min.js\';\n  window.T = T;\n' +
    '</script></body></html>');

  const browser = await chromium.launchPersistentContext(path.join(REPO, 'evaluation', '.chrome-profile'), {
    headless: true, args: ['--allow-file-access-from-files', '--disable-web-security', '--disable-features=BlockInsecurePrivateNetworkRequests']
  });
  const page = await browser.newPage();
  await page.goto('file://' + path.join(REPO, 'evaluation', '.probe.html'));
  await page.waitForFunction(() => !!window.T, null, { timeout: 30000 });
  await page.evaluate(() => { window.T.env.allowLocalModels = false; });

  const texts = [];
  loadCorpus('messages.json').forEach((m, i) => texts.push({ id: 'core|' + i, label: m.label, text: m.text }));
  loadCorpus('adversarial.json').forEach((m, i) => texts.push({ id: 'adversarial|' + i, label: m.label, text: m.text }));
  loadCorpus('injection-adversarial.json').forEach((m, i) => texts.push({ id: 'injection-adversarial|' + i, label: m.label, text: m.text }));
  loadCorpus('adversarial-multilingual.json').forEach((m, i) => texts.push({ id: 'multilingual|' + i, label: m.label, text: m.text, lang: m.lang }));

  const results = await page.evaluate(async ({ texts, baseURL }) => {
    const T = window.T;
    T.env.allowLocalModels = false;
    T.env.allowRemoteModels = true;
    T.env.remoteHost = baseURL;
    T.env.remotePathTemplate = '{model}/';
    const tok = await T.AutoTokenizer.from_pretrained('offscreen-model');
    const mdl = await T.AutoModelForSequenceClassification.from_pretrained('offscreen-model', { dtype: 'q8', device: 'wasm' });
    const NEG = -3.4028235e38;
    const out = [];
    for (const t of texts) {
      // contract: exactly 128 tokens + 4D float mask (0=real, NEG=pad)
      const enc = await tok(t.text, { padding: 'max_length', max_length: 128, truncation: true });
      const am = enc.attention_mask.tolist()[0];
      const mask4 = new T.Tensor('float32', Float32Array.from(am, v => (Number(v) === 1 ? 0 : NEG)), [1, 1, 1, 128]);
      const logits = (await mdl({ input_ids: enc.input_ids, attention_mask: mask4 })).logits.tolist()[0];
      const mx = Math.max(...logits);
      const exp = logits.map(v => Math.exp(v - mx));
      const sum = exp.reduce((a, b) => a + b, 0);
      out.push({ id: t.id, label: t.label, lang: t.lang, legit: exp[0] / sum, scam: exp[1] / sum, injection: exp[2] / sum });
    }
    return out;
  }, { texts, baseURL: `http://127.0.0.1:${port}/` });
  await browser.close();
  server.close();
  fs.rmSync(path.join(REPO, 'evaluation', '.probe.html'), { force: true });
  fs.writeFileSync(path.join(REPO, 'evaluation', 'ft-results.json'), JSON.stringify({ measuredAt: new Date().toISOString(), results }, null, 1));

  // ---- metrics ----
  const scamRows = results.filter(r => r.id.startsWith('core|') || r.id.startsWith('adversarial|'));
  const adv = results.filter(r => r.id.startsWith('adversarial|'));
  const advScam = adv.filter(r => r.label === 'scam'), advNeg = adv.filter(r => r.label !== 'scam');
  const coreNeg = scamRows.filter(r => (r.id.startsWith('core|')) && r.label !== 'scam');
  const injRows = results.filter(r => r.id.startsWith('injection-adversarial|'));
  const injAttacks = injRows.filter(r => r.label === 'injection');
  const injNegs = scamRows.filter(r => r.label !== 'scam');

  console.log('── scam head (P_scam vs P_legit) ──');
  for (const [t, m] of [[0.5, 0], [0.5, 0.2], [0.6, 0.1], [0.7, 0.1], [0.8, 0.1]]) {
    const flag = r => r.scam >= t && r.scam - r.legit >= m;
    console.log(`  t ${t} margin ${m}: advRecall ${advScam.filter(flag).length}/14  advFP ${advNeg.filter(flag).length}/12  coreFP ${coreNeg.filter(flag).length}/${coreNeg.length}`);
  }
  console.log('── injection head (P_injection vs P_legit) ──');
  for (const [t, m] of [[0.3, 0], [0.3, 0.1], [0.5, 0.1], [0.7, 0.1]]) {
    const flag = r => r.injection >= t && r.injection - r.legit >= m;
    console.log(`  t ${t} margin ${m}: injRecall ${injAttacks.filter(flag).length}/7  FP ${injNegs.filter(flag).length}/${injNegs.length}`);
  }
  // ---- multilingual transfer (eval-only, never trained) ----
  const ml = results.filter(r => r.id.startsWith('multilingual|'));
  if (ml.length) {
    console.log('\n── multilingual transfer (eval-only corpus) ──');
    for (const lang of [...new Set(ml.map(r => r.lang))]) {
      const rows = ml.filter(r => r.lang === lang);
      const scams = rows.filter(r => r.label === 'scam');
      const inj = rows.filter(r => r.label === 'injection');
      const leg = rows.filter(r => r.label === 'legit');
      const sOk = scams.filter(r => r.scam >= 0.85 && r.scam - r.legit >= 0.3).length;
      const iOk = inj.filter(r => r.injection >= 0.7 && r.injection - r.legit >= 0.1).length;
      const lOk = leg.filter(r => r.legit >= 0.9 && r.legit - r.scam >= 0.2).length;
      console.log(`  ${lang}: scam ${sOk}/${scams.length} · injection ${iOk}/${inj.length} · legit-clear ${lOk}/${leg.length}`);
    }
  }

  console.log('\nadversarial scam P_scam distribution (desc):');
  advScam.map(r => r.scam).sort((a, b) => b - a).forEach(p => process.stdout.write(p.toFixed(2) + ' '));
  console.log('\ncore negative P_scam (top 10):');
  coreNeg.map(r => r.scam).sort((a, b) => b - a).slice(0, 10).forEach(p => process.stdout.write(p.toFixed(2) + ' '));
  console.log('\n');
})().catch(e => { console.error('measure failed:', e.message); process.exit(1); });
