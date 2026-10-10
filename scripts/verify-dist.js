/**
 * CI dist verification — fails the build if any file referenced by
 * dist/manifest.json is missing from dist/.
 */
const fs = require('fs');

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const m = JSON.parse(fs.readFileSync('dist/manifest.json', 'utf8'));
if (m.version !== pkg.version) {
  console.error('VERSION DRIFT: dist manifest ' + m.version + ' != package.json ' + pkg.version);
  process.exit(1);
}
const refs = [
  m.background.service_worker,
  m.content_scripts[0].js,
  m.action.default_popup,
  m.options_page,
  ...Object.values(m.action.default_icon || {}),
  ...Object.values(m.icons || {})
].flat();

const missing = refs.filter(f => !fs.existsSync('dist/' + f));
if (missing.length) {
  console.error('MISSING from dist:', missing);
  process.exit(1);
}

// HTML asset links (stylesheets/scripts) must also exist in dist
for (const page of ['popup.html', 'options.html', 'offscreen.html']) {
  const html = fs.readFileSync('dist/' + page, 'utf8');
  const assets = [...html.matchAll(/(?:href|src)="([^"#][^"]*)"/g)].map(m => m[1])
    .filter(u => !u.startsWith('http') && !u.startsWith('chrome'));
  const pageMissing = assets.filter(u => !fs.existsSync('dist/' + u));
  if (pageMissing.length) {
    console.error(`MISSING assets referenced by ${page}:`, pageMissing);
    process.exit(1);
  }
}
// The vendored in-browser AI runtime must be present if the offscreen page exists
if (fs.existsSync('dist/offscreen.js') && !fs.existsSync('dist/vendor/transformers.min.js')) {
  console.error('MISSING dist/vendor/transformers.min.js (required by offscreen.js)');
  process.exit(1);
}
// The fine-tuned classifier must ship with the build (offscreen.js loads it
// through the extension origin at dist/offscreen-model/)
if (fs.existsSync('dist/offscreen.js')) {
  for (const f of ['dist/offscreen-model/config.json', 'dist/offscreen-model/tokenizer.json', 'dist/offscreen-model/onnx/model_quantized.onnx']) {
    if (!fs.existsSync(f)) { console.error('MISSING ' + f + ' (required by the fine-tuned semantic layer)'); process.exit(1); }
  }
}
console.log('dist complete, version', m.version);
