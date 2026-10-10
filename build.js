#!/usr/bin/env node
/**
 * VIGIL build script.
 *   npm run build            → dist/ (Chromium: Chrome/Edge/Brave)
 *   npm run build:firefox    → dist-firefox/ (Firefox-adapted manifest)
 *
 * The Firefox variant adapts the manifest (gecko id, background scripts
 * instead of a service worker) and drops the offscreen in-browser AI model
 * (Firefox has no chrome.offscreen). Everything else is identical.
 */
const fs = require('fs');
const path = require('path');

const CHROME_OUT = 'dist';
const FIREFOX_OUT = 'dist-firefox';

function firefoxManifest(manifest) {
  const m = JSON.parse(JSON.stringify(manifest));
  m.background = {
    scripts: ['vigil-shared.js', 'vigil-vault.js', 'reality-engine.js', 'signing-engine.js', 'threat-store.js', 'shopping-detector.js', 'semantic-drift.js', 'consensus-firewall.js', 'token-budget.js', 'file-integrity.js', 'compute-boundary.js', 'forensics-replay.js', 'redteam-agent.js', 'zk-compliance.js', 'prompt-git.js', 'local-lora.js', 'semantic-engine.js', 'native-bridge.js', 'background.js']
  };
  m.browser_specific_settings = { gecko: { id: 'vigil@starboy-hub.github.io', strict_min_version: '115.0' } };
  // No chrome.offscreen in Firefox: the in-browser AI model + its permission
  // are removed; Sentinel falls back to heuristics (+ Ollama, which works)
  m.permissions = (m.permissions || []).filter(p => p !== 'offscreen');
  if (m.content_scripts && m.content_scripts[0]) {
    m.content_scripts[0].js = m.content_scripts[0].js.filter(f => f !== 'injection-engine.js');
  }
  return m;
}

/** Copy every source file for a target; returns the list written. */
function copySources(out, files) {
  const written = [];
  files.forEach(file => {
    if (fs.existsSync(file.src)) {
      fs.copyFileSync(file.src, path.join(out, file.dest));
      written.push(file.dest);
    } else {
      console.error(`✗ Missing: ${file.src}`);
    }
  });
  return written;
}

function copyIcons(out) {
  fs.mkdirSync(path.join(out, 'icons'), { recursive: true });
  ['icon16.png', 'icon32.png', 'icon48.png', 'icon128.png'].forEach(icon => {
    const src = path.join('src', 'icons', icon);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(out, 'icons', icon));
    else console.error(`✗ Missing icon: ${src}`);
  });
}

/** SHA-256 manifest of extension files (Blueprint #6: File Integrity Monitor). */
function writeIntegrityManifest(out) {
  const crypto = require('crypto');
  const manifest = {};

  function scanDir(dir, base) {
    if (!fs.existsSync(dir)) return;
    for (const f of fs.readdirSync(dir)) {
      if (f === 'vigil-integrity.json' || f === '.DS_Store' || f.endsWith('.tmp')) continue;
      const full = path.join(dir, f);
      const rel = base ? (base + '/' + f) : f;
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        scanDir(full, rel);
      } else if (stat.isFile()) {
        manifest[rel] = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
      }
    }
  }

  scanDir(out, '');
  fs.writeFileSync(path.join(out, 'vigil-integrity.json'), JSON.stringify(manifest, null, 2));

  // Maintain vendor/vigil-integrity.json for offscreen.js backward compatibility
  const vendorDir = path.join(out, 'vendor');
  if (fs.existsSync(vendorDir)) {
    const vendorManifest = {};
    for (const f of fs.readdirSync(vendorDir)) {
      if (f === 'vigil-integrity.json') continue;
      vendorManifest['vendor/' + f] = crypto.createHash('sha256').update(fs.readFileSync(path.join(vendorDir, f))).digest('hex');
    }
    fs.writeFileSync(path.join(vendorDir, 'vigil-integrity.json'), JSON.stringify(vendorManifest, null, 1));
  }
}

/** Copy the fine-tuned classifier into the build (Chromium target only). */
function vendorFineTunedModel(out) {
  const srcDir = 'src/offscreen-model';
  const modelPath = path.join(srcDir, 'onnx', 'model_quantized.onnx');
  if (!fs.existsSync(modelPath)) {
    // GitHub caps files at 100 MB, so the model is committed as parts and
    // reassembled here (deterministic byte concatenation)
    const parts = fs.readdirSync(path.join(srcDir, 'onnx')).filter(f => f.startsWith('model_quantized.onnx.part-')).sort();
    if (!parts.length) {
      console.warn('! fine-tuned model missing — semantic layer inert');
      return false;
    }
    fs.writeFileSync(modelPath, Buffer.concat(parts.map(p => fs.readFileSync(path.join(srcDir, 'onnx', p)))));
  }
  fs.cpSync(srcDir, path.join(out, 'offscreen-model'), { recursive: true });
  // the committed parts are build inputs, not runtime files
  const distOnnx = path.join(out, 'offscreen-model', 'onnx');
  fs.readdirSync(distOnnx).filter(f => f.includes('.part-')).forEach(f => fs.rmSync(path.join(distOnnx, f)));
  return true;
}

/** Vendor the in-browser AI runtime (Chromium target only). */
function vendorAIRuntime(out) {
  const hfDist = 'node_modules/@huggingface/transformers/dist';
  const ortDist = 'node_modules/onnxruntime-web/dist';
  if (!fs.existsSync(hfDist + '/transformers.min.js')) {
    console.warn('! @huggingface/transformers not installed — in-browser AI omitted');
    return false;
  }
  fs.mkdirSync(path.join(out, 'vendor'), { recursive: true });
  fs.copyFileSync(hfDist + '/transformers.min.js', path.join(out, 'vendor', 'transformers.min.js'));
  if (fs.existsSync(ortDist)) {
    fs.readdirSync(ortDist).filter(f => f.endsWith('.wasm') || f.endsWith('.mjs')).forEach(f => {
      fs.copyFileSync(path.join(ortDist, f), path.join(out, 'vendor', f));
    });
  }
  return true;
}

/** Build the Chromium target into `out` (default dist). Returns file count. */
function buildChromium(out = CHROME_OUT) {
  if (fs.existsSync(out)) fs.rmSync(out, { recursive: true });
  fs.mkdirSync(out, { recursive: true });

  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const manifest = JSON.parse(fs.readFileSync('src/manifest.json', 'utf8'));
  manifest.version = pkg.version;
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  const files = [
    { src: 'src/shared/vigil-shared.js', dest: 'vigil-shared.js' },
    { src: 'src/shared/siem-exporter.js', dest: 'siem-exporter.js' },
    { src: 'src/shared/zk-compliance.js', dest: 'zk-compliance.js' },
    { src: 'src/shared/phash.js', dest: 'phash.js' },
    { src: 'src/background/enterprise-policy.js', dest: 'enterprise-policy.js' },
    { src: 'src/background/native-bridge.js', dest: 'native-bridge.js' },
    { src: 'src/background/vigil-vault.js', dest: 'vigil-vault.js' },
    { src: 'src/background/reality-engine.js', dest: 'reality-engine.js' },
    { src: 'src/background/signing-engine.js', dest: 'signing-engine.js' },
    { src: 'src/background/threat-store.js', dest: 'threat-store.js' },
    { src: 'src/background/shopping-detector.js', dest: 'shopping-detector.js' },
    { src: 'src/background/semantic-drift.js', dest: 'semantic-drift.js' },
    { src: 'src/background/consensus-firewall.js', dest: 'consensus-firewall.js' },
    { src: 'src/background/token-budget.js', dest: 'token-budget.js' },
    { src: 'src/background/file-integrity.js', dest: 'file-integrity.js' },
    { src: 'src/background/compute-boundary.js', dest: 'compute-boundary.js' },
    { src: 'src/background/forensics-replay.js', dest: 'forensics-replay.js' },
    { src: 'src/background/redteam-agent.js', dest: 'redteam-agent.js' },
    { src: 'src/background/prompt-git.js', dest: 'prompt-git.js' },
    { src: 'src/background/local-lora.js', dest: 'local-lora.js' },
    { src: 'src/background/background.js', dest: 'background.js' },
    { src: 'src/background/offscreen-error.js', dest: 'offscreen-error.js' },
    { src: 'src/background/offscreen.html', dest: 'offscreen.html' },
    { src: 'src/background/offscreen.js', dest: 'offscreen.js' },
    { src: 'src/content/modules/adversarial-normalizer.js', dest: 'adversarial-normalizer.js' },
    { src: 'src/content/modules/fake-data.js', dest: 'fake-data.js' },
    { src: 'src/content/modules/redos-engine.js', dest: 'redos-engine.js' },
    { src: 'src/content/modules/detection-engine.js', dest: 'detection-engine.js' },
    { src: 'src/content/modules/secret-engine.js', dest: 'secret-engine.js' },
    { src: 'src/content/modules/wasm-simd-fft.js', dest: 'wasm-simd-fft.js' },
    { src: 'src/content/modules/vision-canary.js', dest: 'vision-canary.js' },
    { src: 'src/content/modules/rag-file-scanner.js', dest: 'rag-file-scanner.js' },
    { src: 'src/content/modules/vision-firewall.js', dest: 'vision-firewall.js' },
    { src: 'src/background/swarm-mesh.js', dest: 'swarm-mesh.js' },
    { src: 'src/background/webgpu-engine.js', dest: 'webgpu-engine.js' },
    { src: 'src/content/modules/sentinel-engine.js', dest: 'sentinel-engine.js' },
    { src: 'src/content/modules/injection-engine.js', dest: 'injection-engine.js' },
    { src: 'src/content/modules/webmail-profile.js', dest: 'webmail-profile.js' },
    { src: 'src/content/modules/semantic-engine.js', dest: 'semantic-engine.js' },
    { src: 'src/content/modules/leakage-detector.js', dest: 'leakage-detector.js' },
    { src: 'src/content/content.js', dest: 'content.js' },
    { src: 'src/popup/popup.html', dest: 'popup.html' },
    { src: 'src/popup/popup.css', dest: 'popup.css' },
    { src: 'src/popup/popup.js', dest: 'popup.js' },
    { src: 'src/options/options.html', dest: 'options.html' },
    { src: 'src/options/options.css', dest: 'options.css' },
    { src: 'src/options/options.js', dest: 'options.js' }
  ];
  const written = copySources(out, files);
  copyIcons(out);
  const hasAI = vendorAIRuntime(out);
  if (!hasAI) console.warn('! in-browser AI runtime omitted');
  const hasModel = vendorFineTunedModel(out);
  if (hasModel) written.push('offscreen-model/*');
  writeIntegrityManifest(out);
  return written.length;
}

/** Build the Firefox target: same files, adapted manifest, no offscreen AI. */
function buildFirefox(out = FIREFOX_OUT) {
  if (fs.existsSync(out)) fs.rmSync(out, { recursive: true });
  fs.mkdirSync(out, { recursive: true });

  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const manifest = firefoxManifest(JSON.parse(fs.readFileSync('src/manifest.json', 'utf8')));
  manifest.version = pkg.version;
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  const files = [
    { src: 'src/shared/vigil-shared.js', dest: 'vigil-shared.js' },
    { src: 'src/shared/siem-exporter.js', dest: 'siem-exporter.js' },
    { src: 'src/shared/zk-compliance.js', dest: 'zk-compliance.js' },
    { src: 'src/shared/phash.js', dest: 'phash.js' },
    { src: 'src/background/enterprise-policy.js', dest: 'enterprise-policy.js' },
    { src: 'src/background/native-bridge.js', dest: 'native-bridge.js' },
    { src: 'src/background/vigil-vault.js', dest: 'vigil-vault.js' },
    { src: 'src/background/reality-engine.js', dest: 'reality-engine.js' },
    { src: 'src/background/signing-engine.js', dest: 'signing-engine.js' },
    { src: 'src/background/threat-store.js', dest: 'threat-store.js' },
    { src: 'src/background/shopping-detector.js', dest: 'shopping-detector.js' },
    { src: 'src/background/semantic-drift.js', dest: 'semantic-drift.js' },
    { src: 'src/background/consensus-firewall.js', dest: 'consensus-firewall.js' },
    { src: 'src/background/token-budget.js', dest: 'token-budget.js' },
    { src: 'src/background/file-integrity.js', dest: 'file-integrity.js' },
    { src: 'src/background/compute-boundary.js', dest: 'compute-boundary.js' },
    { src: 'src/background/forensics-replay.js', dest: 'forensics-replay.js' },
    { src: 'src/background/redteam-agent.js', dest: 'redteam-agent.js' },
    { src: 'src/background/prompt-git.js', dest: 'prompt-git.js' },
    { src: 'src/background/local-lora.js', dest: 'local-lora.js' },
    { src: 'src/background/background.js', dest: 'background.js' },
    { src: 'src/content/modules/adversarial-normalizer.js', dest: 'adversarial-normalizer.js' },
    { src: 'src/content/modules/fake-data.js', dest: 'fake-data.js' },
    { src: 'src/content/modules/redos-engine.js', dest: 'redos-engine.js' },
    { src: 'src/content/modules/detection-engine.js', dest: 'detection-engine.js' },
    { src: 'src/content/modules/secret-engine.js', dest: 'secret-engine.js' },
    { src: 'src/content/modules/wasm-simd-fft.js', dest: 'wasm-simd-fft.js' },
    { src: 'src/content/modules/vision-canary.js', dest: 'vision-canary.js' },
    { src: 'src/content/modules/rag-file-scanner.js', dest: 'rag-file-scanner.js' },
    { src: 'src/content/modules/vision-firewall.js', dest: 'vision-firewall.js' },
    { src: 'src/background/swarm-mesh.js', dest: 'swarm-mesh.js' },
    { src: 'src/background/webgpu-engine.js', dest: 'webgpu-engine.js' },
    { src: 'src/content/modules/sentinel-engine.js', dest: 'sentinel-engine.js' },
    { src: 'src/content/modules/injection-engine.js', dest: 'injection-engine.js' },
    { src: 'src/content/modules/webmail-profile.js', dest: 'webmail-profile.js' },
    { src: 'src/content/modules/semantic-engine.js', dest: 'semantic-engine.js' },
    { src: 'src/content/modules/leakage-detector.js', dest: 'leakage-detector.js' },
    { src: 'src/content/content.js', dest: 'content.js' },
    { src: 'src/popup/popup.html', dest: 'popup.html' },
    { src: 'src/popup/popup.css', dest: 'popup.css' },
    { src: 'src/popup/popup.js', dest: 'popup.js' },
    { src: 'src/options/options.html', dest: 'options.html' },
    { src: 'src/options/options.css', dest: 'options.css' },
    { src: 'src/options/options.js', dest: 'options.js' }
  ];
  const written = copySources(out, files);
  copyIcons(out);
  writeIntegrityManifest(out);
  return written.length;
}

if (require.main === module) {
  const target = process.argv.includes('--firefox') ? 'firefox' : 'chromium';
  if (target === 'firefox') {
    const count = buildFirefox();
    console.log(`✅ Firefox build complete (${count} files) — load dist-firefox/ via about:debugging`);
  } else {
    const count = buildChromium();
    console.log(`✅ Build complete! Load the "${CHROME_OUT}" folder in Chrome. (${count} files)`);
  }
}

module.exports = { buildChromium, buildFirefox, firefoxManifest, copySources, vendorAIRuntime, CHROME_OUT, FIREFOX_OUT };
