#!/usr/bin/env node
/**
 * Package dist/ into releases/vigil-v<version>.zip for store upload.
 * Requires the `zip` CLI (preinstalled on macOS and GitHub runners).
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const version = pkg.version;
const outDir = path.join('releases');
const name = `vigil-v${version}.zip`;
const legacyName = `vigil-v${version}.zip`;

if (!fs.existsSync('dist/manifest.json')) {
  console.log('ℹ️  Building Chromium distribution before packaging...');
  require('../build.js').buildChromium();
}
fs.mkdirSync(outDir, { recursive: true });
if (fs.existsSync(path.join(outDir, name))) fs.rmSync(path.join(outDir, name));
if (fs.existsSync(path.join(outDir, legacyName))) fs.rmSync(path.join(outDir, legacyName));

const stage = path.join(outDir, `vigil-v${version}`);
if (fs.existsSync(stage)) fs.rmSync(stage, { recursive: true });
fs.cpSync('dist', stage, { recursive: true });

execSync(`cd "${outDir}" && zip -rq "${name}" "vigil-v${version}"`, { stdio: 'inherit' });
fs.copyFileSync(path.join(outDir, name), path.join(outDir, legacyName));
fs.rmSync(stage, { recursive: true });

const size = (fs.statSync(path.join(outDir, name)).size / 1024).toFixed(1);
console.log(`✅ Packaged ${outDir}/${name} (${size} KB) — ready for store upload.`);
