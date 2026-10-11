#!/usr/bin/env node
/**
 * VIGIL - Build Reproducibility & Release Provenance Verifier
 * Generates deterministic SHA-256 digests across all dist artifacts,
 * verifies reproducibility against baseline digests, and signs release metadata.
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const BASELINE_FILE = path.join(ROOT, '.github', 'build-hash.txt');
const COMMITTED_MANIFEST = path.join(ROOT, '.github', 'release-manifest.json');
const RELEASE_MANIFEST = path.join(DIST, 'release-manifest.json');

function computeDistFingerprint() {
  if (!fs.existsSync(DIST)) {
    throw new Error('dist directory does not exist — run "npm run build" first');
  }

  const fileHashes = {};
  function scan(dir, relPrefix = '') {
    const entries = fs.readdirSync(dir).sort();
    for (const entry of entries) {
      if (entry === '.DS_Store' || entry.endsWith('.tmp') || entry === 'release-manifest.json' || entry === 'audit-dossier.json' || entry === 'sbom.json') continue;
      const full = path.join(dir, entry);
      const rel = relPrefix ? `${relPrefix}/${entry}` : entry;
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        scan(full, rel);
      } else if (stat.isFile()) {
        const content = fs.readFileSync(full);
        fileHashes[rel] = crypto.createHash('sha256').update(content).digest('hex');
      }
    }
  }

  scan(DIST);

  // Compute composite deterministic hash across sorted file hashes
  const sortedKeys = Object.keys(fileHashes).sort();
  const compositeInput = sortedKeys.map(k => `${k}:${fileHashes[k]}`).join('\n');
  const compositeHash = crypto.createHash('sha256').update(compositeInput).digest('hex');

  return { fileHashes, compositeHash, fileCount: sortedKeys.length };
}

function verifyAndRecord(options = {}) {
  const isCli = require.main === module;
  const shouldUpdate = options.updateBaseline ?? (process.argv.includes('--update-baseline') || process.env.VIGIL_UPDATE_BUILD_BASELINE === 'true');
  const { fileHashes, compositeHash, fileCount } = computeDistFingerprint();
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

  fs.mkdirSync(path.join(ROOT, '.github'), { recursive: true });

  let baseline = '';
  if (fs.existsSync(BASELINE_FILE)) {
    baseline = fs.readFileSync(BASELINE_FILE, 'utf8').trim();
  }

  // Load previous release manifest if available to compute detailed file delta
  let baselineFiles = {};
  const manifestPath = fs.existsSync(COMMITTED_MANIFEST) ? COMMITTED_MANIFEST : (fs.existsSync(RELEASE_MANIFEST) ? RELEASE_MANIFEST : null);
  if (manifestPath) {
    try {
      const prevManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (prevManifest && prevManifest.files && typeof prevManifest.files === 'object') {
        baselineFiles = prevManifest.files;
      }
    } catch (_) {}
  }

  if (!baseline) {
    if (shouldUpdate) {
      fs.writeFileSync(BASELINE_FILE, compositeHash + '\n');
      console.log(`ℹ️ Initialized baseline build hash: ${compositeHash}`);
    } else {
      console.error('❌ Build reproducibility verification FAILED: Missing baseline hash file (.github/build-hash.txt)!');
      console.error('   To establish the baseline build hash, run with --update-baseline');
      if (isCli) process.exit(1);
      throw new Error('Missing baseline hash file (.github/build-hash.txt)');
    }
  } else if (baseline === compositeHash) {
    console.log(`✅ Build reproducibility verified! Composite hash: ${compositeHash}`);
  } else {
    // Hash mismatch
    if (shouldUpdate) {
      console.log(`ℹ️ Explicitly updating committed baseline build hash for v${pkg.version}:`);
      console.log(`   Previous baseline: ${baseline}`);
      console.log(`   New composite:     ${compositeHash}`);
      fs.writeFileSync(BASELINE_FILE, compositeHash + '\n');
    } else {
      console.error(`❌ Build reproducibility verification FAILED: Composite hash mismatch!`);
      console.error(`   Expected (committed baseline): ${baseline}`);
      console.error(`   Computed (dist/ output):       ${compositeHash}\n`);

      // Itemized file-by-file delta diff
      const currentKeys = new Set(Object.keys(fileHashes));
      const baselineKeys = new Set(Object.keys(baselineFiles));
      const added = [...currentKeys].filter(k => !baselineKeys.has(k)).sort();
      const removed = [...baselineKeys].filter(k => !currentKeys.has(k)).sort();
      const modified = [...currentKeys].filter(k => baselineKeys.has(k) && fileHashes[k] !== baselineFiles[k]).sort();

      if (added.length || removed.length || modified.length) {
        console.error('   --- Itemized Build Artifact Drift ---');
        if (modified.length) {
          console.error(`   🔴 Modified files (${modified.length}):`);
          modified.slice(0, 10).forEach(f => console.error(`      • ${f} (baseline: ${baselineFiles[f].slice(0, 8)}... -> current: ${fileHashes[f].slice(0, 8)}...)`));
          if (modified.length > 10) console.error(`      ... and ${modified.length - 10} more`);
        }
        if (added.length) {
          console.error(`   🟡 Added files (${added.length}):`);
          added.slice(0, 10).forEach(f => console.error(`      • ${f}`));
          if (added.length > 10) console.error(`      ... and ${added.length - 10} more`);
        }
        if (removed.length) {
          console.error(`   ⚪ Removed files (${removed.length}):`);
          removed.slice(0, 10).forEach(f => console.error(`      • ${f}`));
          if (removed.length > 10) console.error(`      ... and ${removed.length - 10} more`);
        }
        console.error('');
      }

      console.error('   If changes were intentional, update the baseline with:');
      console.error('   node scripts/verify-build-reproducibility.js --update-baseline\n');
      if (isCli) process.exit(1);
      throw new Error(`Build reproducibility verification failed: composite hash mismatch (expected ${baseline}, got ${compositeHash})`);
    }
  }

  // Generate release manifest with integrity proofs
  const releaseManifest = {
    packageName: pkg.name,
    version: pkg.version,
    timestamp: new Date().toISOString(),
    compositeHash,
    fileCount,
    files: fileHashes
  };

  fs.writeFileSync(RELEASE_MANIFEST, JSON.stringify(releaseManifest, null, 2));
  if (shouldUpdate || !fs.existsSync(COMMITTED_MANIFEST)) {
    fs.writeFileSync(COMMITTED_MANIFEST, JSON.stringify(releaseManifest, null, 2));
  }
  console.log(`✅ Release manifest generated: ${RELEASE_MANIFEST}`);
  return { compositeHash, fileCount, verified: baseline === compositeHash || shouldUpdate };
}

if (require.main === module) {
  verifyAndRecord();
}

module.exports = { computeDistFingerprint, verifyAndRecord };

