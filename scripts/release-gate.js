#!/usr/bin/env node
/**
 * VIGIL - Automated 10/10 Security Release Gate
 * Validates that all cryptographic pins, reproducible builds, CSP headers,
 * audit dossiers, and security policies pass before any release can ship.
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

const gates = [
  {
    name: 'Gate 1: Cryptographic Extension Key Pinning',
    run: () => {
      execSync('node scripts/verify-extension-key.js', { cwd: ROOT, stdio: 'inherit' });
    }
  },
  {
    name: 'Gate 2: Distribution Package Completeness & Integrity',
    run: () => {
      execSync('node scripts/verify-dist.js', { cwd: ROOT, stdio: 'inherit' });
    }
  },
  {
    name: 'Gate 3: Deterministic Build Reproducibility',
    run: () => {
      execSync('node scripts/verify-build-reproducibility.js', { cwd: ROOT, stdio: 'inherit' });
    }
  },
  {
    name: 'Gate 4: Security Audit Dossier Generation',
    run: () => {
      execSync('node scripts/generate-audit-pack.js', { cwd: ROOT, stdio: 'inherit' });
    }
  },
  {
    name: 'Gate 5: Strict CSP Least-Privilege Verification',
    run: () => {
      const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'src', 'manifest.json'), 'utf8'));
      const csp = manifest.content_security_policy?.extension_pages || '';
      if (!csp.includes("default-src 'none'") || !csp.includes("object-src 'none'")) {
        throw new Error('CSP fails least-privilege gate: must enforce default-src "none" and object-src "none"');
      }
      console.log('   ✅ CSP verified strictly locked down');
    }
  },
  {
    name: 'Gate 6: Sensitive Context Injection Policy Integrity',
    run: () => {
      const policy = require(path.join(ROOT, 'src', 'content', 'modules', 'injection-policy.js'));
      if (policy.shouldInjectContentScript('https://accounts.google.com/signin')) {
        throw new Error('Gate failure: injection-policy allowed Google Accounts');
      }
      if (policy.shouldInjectContentScript('https://passwords.google.com/')) {
        throw new Error('Gate failure: injection-policy allowed Google Passwords');
      }
      if (policy.shouldInjectContentScript('https://myaccount.google.com/security')) {
        throw new Error('Gate failure: injection-policy allowed Google Account Security settings');
      }
      if (policy.shouldInjectContentScript('https://login.salesforce.com/')) {
        throw new Error('Gate failure: injection-policy allowed Salesforce SSO');
      }
      if (policy.shouldInjectContentScript('https://vault.bitwarden.com/')) {
        throw new Error('Gate failure: injection-policy allowed password manager vault');
      }
      if (policy.shouldInjectContentScript('https://www.chase.com/')) {
        throw new Error('Gate failure: injection-policy allowed banking portal');
      }
      if (policy.shouldInjectContentScript('https://checkout.stripe.com/pay')) {
        throw new Error('Gate failure: injection-policy allowed payment gateway');
      }
      console.log('   ✅ Sensitive auth/vault/banking injection denial verified');
    }
  },
  {
    name: 'Gate 7: Security Disclosure & RFC 9116 Policy Documents',
    run: () => {
      if (!fs.existsSync(path.join(ROOT, 'SECURITY.md'))) throw new Error('Missing SECURITY.md');
      if (!fs.existsSync(path.join(ROOT, '.well-known', 'security.txt'))) throw new Error('Missing .well-known/security.txt');
      if (!fs.existsSync(path.join(ROOT, 'docs', 'THREAT_MATRIX.md'))) throw new Error('Missing docs/THREAT_MATRIX.md');
      console.log('   ✅ SECURITY.md, security.txt, and THREAT_MATRIX.md verified');
    }
  }
];

console.log('=====================================================');
console.log(`🛡️  VIGIL AI: EXECUTING ${gates.length}-GATE SECURITY RELEASE PIPELINE`);
console.log('=====================================================\n');

let failed = 0;
for (const gate of gates) {
  try {
    console.log(`▶ Running ${gate.name}...`);
    gate.run();
    console.log(`✅ PASSED: ${gate.name}\n`);
  } catch (err) {
    console.error(`❌ FAILED: ${gate.name} - ${err.message}\n`);
    failed++;
  }
}

if (failed > 0) {
  console.error(`🚫 SECURITY RELEASE GATE FAILED (${failed} gates failed). Release blocked.`);
  process.exit(1);
} else {
  console.log(`🎉 ALL ${gates.length} SECURITY RELEASE GATES PASSED! Distribution approved.`);
  process.exit(0);
}

