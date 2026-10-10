#!/usr/bin/env node
/**
 * VIGIL - Cryptographic Extension Key Pin Verification
 * Computes the 32-character Chrome extension ID directly from the
 * manifest's base64 SubjectPublicKeyInfo DER buffer using Chromium's
 * standard SHA-256 nibble-to-char algorithm (first 128 bits mapped to [a-p]).
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const EXPECTED_EXTENSION_ID = 'emkokehejldjlfljlhhcimnfefcjcmon';

function deriveExtensionId(pubKeyBase64) {
  if (!pubKeyBase64 || typeof pubKeyBase64 !== 'string') {
    throw new Error('Missing or invalid public key base64 string');
  }
  const derBuffer = Buffer.from(pubKeyBase64.replace(/\s+/g, ''), 'base64');
  const hash = crypto.createHash('sha256').update(derBuffer).digest();
  let id = '';
  for (let i = 0; i < 16; i++) {
    const byte = hash[i];
    id += String.fromCharCode(97 + ((byte >> 4) & 0x0f));
    id += String.fromCharCode(97 + (byte & 0x0f));
  }
  return id;
}

function verifyManifestKey(manifestPath) {
  if (!fs.existsSync(manifestPath)) {
    console.error(`❌ Manifest file not found: ${manifestPath}`);
    process.exit(1);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const key = manifest.key;

  if (!key) {
    console.error(`❌ FATAL: ${manifestPath} is missing the "key" property!`);
    process.exit(1);
  }

  const computedId = deriveExtensionId(key);

  if (computedId !== EXPECTED_EXTENSION_ID) {
    console.error(`❌ FATAL: Extension key mismatch in ${manifestPath}!`);
    console.error(`   Expected ID: ${EXPECTED_EXTENSION_ID}`);
    console.error(`   Computed ID: ${computedId}`);
    process.exit(1);
  }

  console.log(`✅ Extension key verified in ${manifestPath}: ${computedId}`);
  return computedId;
}

// Verify both src and dist manifests
const rootDir = path.resolve(__dirname, '..');
verifyManifestKey(path.join(rootDir, 'src', 'manifest.json'));
if (fs.existsSync(path.join(rootDir, 'dist', 'manifest.json'))) {
  verifyManifestKey(path.join(rootDir, 'dist', 'manifest.json'));
}

console.log('✅ Extension key pin verification PASSED.');

