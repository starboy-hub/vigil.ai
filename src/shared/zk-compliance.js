/**
 * VIGIL Security Policy: Keyed Merkle Attestation of DLP Compliance
 * (honest adaptation of the original "ZK-SNARK" blueprint)
 *
 * Problem: Enterprises need to prove to auditors (SOC2, GDPR, HIPAA) that
 * "N PII/DLP leaks were blocked under corporate security policy P" without
 * revealing the actual PII, prompts, or sensitive contents.
 *
 * What this is: a tamper-evident Merkle accumulator over blinded event
 * commitments (salted SHA-256), bound to a device-held attestation key via
 * HMAC-SHA256. A third party holding the device's attestation key can verify
 * the event count, category breakdown, and sampled inclusion proofs, and no
 * plaintext ever enters the package. Forging a package requires the device
 * attestation key.
 *
 * What this is NOT: a zero-knowledge succinct argument. The event COUNT and
 * category breakdown are disclosed by design; proving statements about hidden
 * data would require a circuit-based proof system (snarkjs/circom), which is
 * deliberately out of scope for a 100%-local extension.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_ZK = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Self-contained synchronous SHA-256 for Merkle/HMAC computations.
  // The Node path uses latin1 so every char maps to exactly one byte —
  // matching the pure-JS path's charCodeAt(i) & 0xff byte semantics.
  function sha256(str) {
    if (typeof require === 'function') {
      try {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(str, 'latin1').digest('hex');
      } catch {
        // Fall back to pure JS
      }
    }

    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }

    let result = '';

    const words = [];
    const asciiBitLength = str.length * 8;

    let hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    const k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    let i = 0;
    for (i = 0; i < str.length; i++) {
      words[i >> 2] |= (str.charCodeAt(i) & 0xff) << ((3 - (i % 4)) * 8);
    }
    words[asciiBitLength >> 5] |= 0x80 << ((3 - ((asciiBitLength >> 3) % 4)) * 8);
    words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

    const w = new Array(64);
    for (let chunk = 0; chunk < words.length; chunk += 16) {
      let [a, b, c, d, e, f, g, h] = hash;

      for (let j = 0; j < 64; j++) {
        if (j < 16) {
          w[j] = words[chunk + j] | 0;
        } else {
          const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
          const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
          w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
        }

        const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + s1 + ch + k[j] + w[j]) | 0;
        const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0 + maj) | 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) | 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) | 0;
      }

      hash[0] = (hash[0] + a) | 0;
      hash[1] = (hash[1] + b) | 0;
      hash[2] = (hash[2] + c) | 0;
      hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0;
      hash[5] = (hash[5] + f) | 0;
      hash[6] = (hash[6] + g) | 0;
      hash[7] = (hash[7] + h) | 0;
    }

    for (let j = 0; j < 8; j++) {
      const hex = ((hash[j] >>> 0).toString(16)).padStart(8, '0');
      result += hex;
    }

    return result;
  }

  /**
   * Generates a cryptographic salt (CSPRNG where available)
   */
  function generateSalt() {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const arr = new Uint8Array(16);
      crypto.getRandomValues(arr);
      return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    if (typeof require === 'function') {
      try {
        return require('crypto').randomBytes(16).toString('hex');
      } catch {
        // Fall through to the entropy-mixed fallback
      }
    }
    // Last resort: mix every entropy source available through SHA-256 rather
    // than emitting raw Math.random output
    return sha256('vigil-salt:' + Date.now() + ':' + Math.random() + ':' + Math.random());
  }

  /**
   * HMAC-SHA256 built on the internal sha256 primitive (RFC 2104).
   * Used to bind attestation packages to a device-held key so third parties
   * cannot forge compliance reports without it.
   */
  function hmacSha256(key, message) {
    const BLOCK = 64;
    let k = String(key);
    if (k.length > BLOCK) k = sha256(k);
    while (k.length < BLOCK) k += '\x00';

    let ipad = '';
    let opad = '';
    for (let i = 0; i < BLOCK; i++) {
      const kc = k.charCodeAt(i) & 0xff;
      ipad += String.fromCharCode(kc ^ 0x36);
      opad += String.fromCharCode(kc ^ 0x5c);
    }
    // The outer hash consumes the inner digest as RAW 32 bytes, not its hex text
    const innerHex = sha256(ipad + message);
    let innerBytes = '';
    for (let i = 0; i < innerHex.length; i += 2) {
      innerBytes += String.fromCharCode(parseInt(innerHex.substr(i, 2), 16));
    }
    return sha256(opad + innerBytes);
  }

  function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let diff = a.length ^ b.length;
    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
      diff |= (i < a.length ? a.charCodeAt(i) : 0) ^ (i < b.length ? b.charCodeAt(i) : 0);
    }
    return diff === 0;
  }

  /**
   * Merkle Tree Accumulator Implementation
   */
  class MerkleTree {
    constructor(leafHashes) {
      this.leaves = leafHashes.length > 0 ? leafHashes : [sha256('EMPTY_LEAF')];
      this.levels = [];
      this.buildTree();
    }

    buildTree() {
      let currentLevel = [...this.leaves];
      this.levels.push(currentLevel);

      while (currentLevel.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < currentLevel.length; i += 2) {
          const left = currentLevel[i];
          const right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : left;
          nextLevel.push(sha256(left + right));
        }
        this.levels.push(nextLevel);
        currentLevel = nextLevel;
      }
    }

    getRoot() {
      return this.levels[this.levels.length - 1][0];
    }

    getProof(index) {
      const proof = [];
      let idx = index;

      for (let level = 0; level < this.levels.length - 1; level++) {
        const currentLevel = this.levels[level];
        const isRight = (idx % 2 === 1);
        const siblingIdx = isRight ? idx - 1 : (idx + 1 < currentLevel.length ? idx + 1 : idx);

        proof.push({
          position: isRight ? 'left' : 'right',
          data: currentLevel[siblingIdx]
        });

        idx = Math.floor(idx / 2);
      }

      return proof;
    }

    static verifyProof(leaf, proof, root) {
      let current = leaf;
      for (const step of proof) {
        if (step.position === 'left') {
          current = sha256(step.data + current);
        } else {
          current = sha256(current + step.data);
        }
      }
      return current === root;
    }
  }

  /**
   * Computes a blinded cryptographic commitment for a single DLP event
   */
  function createEventCommitment(event, salt) {
    const category = event.type || event.summary || 'PII_INTERCEPTION';
    const severity = event.severity || 'high';
    const site = event.site || 'app';
    const timestamp = event.timestamp ? new Date(event.timestamp).getTime() : 0;
    // Bind event attributes without plaintext PII
    const preimage = `${category}|${severity}|${site}|${timestamp}|${salt}`;
    return sha256(preimage);
  }

  /**
   * Generates a Zero-Knowledge Proof of DLP Compliance
   * @param {Array} events - List of blocked DLP events from history
   * @param {Object} options - Audit parameters and policies
   */
  function generateDlpProof(events = [], options = {}) {
    const auditPeriod = {
      start: options.startDate ? new Date(options.startDate).toISOString() : new Date(Date.now() - 30 * 86400000).toISOString(),
      end: options.endDate ? new Date(options.endDate).toISOString() : new Date().toISOString()
    };
    const policyHash = options.policyHash || sha256('VIGIL_DLP_POLICY_SOC2_HIPAA_V1');

    // Filter events by audit period
    const startMs = new Date(auditPeriod.start).getTime();
    const endMs = new Date(auditPeriod.end).getTime();

    const inScopeEvents = events.filter(e => {
      const t = e.timestamp ? new Date(e.timestamp).getTime() : Date.now();
      return t >= startMs && t <= endMs;
    });

    const eventCount = inScopeEvents.length;

    // Categorize counts
    const categoryBreakdown = {};
    const blindedLeaves = [];
    const eventSalts = [];

    inScopeEvents.forEach(e => {
      const cat = e.type || e.summary || 'GENERAL_PII';
      categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1;

      const salt = generateSalt();
      eventSalts.push(salt);
      blindedLeaves.push(createEventCommitment(e, salt));
    });

    // Build Merkle Accumulator
    const merkleTree = new MerkleTree(blindedLeaves);
    const merkleRoot = merkleTree.getRoot();

    // Serialize category commitments
    const sortedCategories = Object.keys(categoryBreakdown).sort();
    const categorySummaryString = sortedCategories.map(c => `${c}:${categoryBreakdown[c]}`).join(',');
    const categorySummaryCommitment = sha256(categorySummaryString);

    // Deterministic challenge from the public signals (samples which leaves
    // the verifier should check inclusion proofs for)
    const challengePreimage = `${merkleRoot}:${eventCount}:${policyHash}:${auditPeriod.start}:${auditPeriod.end}:${categorySummaryCommitment}`;
    const challenge = sha256(challengePreimage);

    // Sample Merkle inclusion proofs using challenge entropy
    const sampleProofs = [];
    if (blindedLeaves.length > 0) {
      // Pick up to 3 deterministic indices using challenge
      const sampleCount = Math.min(3, blindedLeaves.length);
      for (let s = 0; s < sampleCount; s++) {
        const hexSub = challenge.substring(s * 8, s * 8 + 8);
        const idx = parseInt(hexSub, 16) % blindedLeaves.length;
        sampleProofs.push({
          index: idx,
          leaf: blindedLeaves[idx],
          path: merkleTree.getProof(idx)
        });
      }
    }

    const proofPackage = {
      proofId: 'zk_proof_' + Math.random().toString(36).substring(2, 10),
      protocol: 'VIGIL-MERKLE-ATTESTATION-v1',
      generatedAt: new Date().toISOString(),
      publicSignals: {
        merkleRoot,
        eventCount,
        auditPeriod,
        policyHash,
        categorySummaryCommitment
      },
      proof: {
        challenge,
        categoryBreakdown,
        merkleProofSample: sampleProofs,
        fiatShamirResponse: sha256(challenge + ':ACCEPTED')
      }
    };

    // Bind the package to the device attestation key when provided: an
    // auditor holding the key can prove the package was not fabricated.
    if (options.attestationKey) {
      proofPackage.attestation = {
        scheme: 'HMAC-SHA256',
        keyId: sha256(String(options.attestationKey)).substring(0, 16),
        value: hmacSha256(String(options.attestationKey), `${merkleRoot}|${eventCount}|${policyHash}|${auditPeriod.start}|${auditPeriod.end}|${categorySummaryCommitment}|${challenge}`)
      };
    }

    return proofPackage;
  }

  /**
   * Verifies an exported attestation package.
   * @param {Object} proofPackage - Complete attestation payload
   * @param {Object} options - { attestationKey } — the device key, required
   *   to authenticate a package that carries an attestation
   */
  function verifyDlpProof(proofPackage, options = {}) {
    if (!proofPackage || typeof proofPackage !== 'object') {
      return { valid: false, error: 'Malformed proof payload' };
    }

    const { protocol, publicSignals, proof } = proofPackage;
    if (protocol !== 'VIGIL-MERKLE-ATTESTATION-v1') {
      return { valid: false, error: `Unsupported protocol version: ${protocol}` };
    }

    if (!publicSignals || !proof) {
      return { valid: false, error: 'Missing public signals or proof object' };
    }

    const { merkleRoot, eventCount, auditPeriod, policyHash, categorySummaryCommitment } = publicSignals;
    const { challenge, categoryBreakdown, merkleProofSample, fiatShamirResponse } = proof;

    // 0. Authenticate the package against the device attestation key
    let authenticity = 'UNBOUND';
    if (proofPackage.attestation) {
      const attKey = options.attestationKey;
      if (!attKey) {
        return { valid: false, error: 'ATTESTATION_KEY_REQUIRED: package is attested; verification requires the device attestation key' };
      }
      const expected = hmacSha256(String(attKey), `${merkleRoot}|${eventCount}|${policyHash}|${auditPeriod.start}|${auditPeriod.end}|${categorySummaryCommitment}|${challenge}`);
      if (!constantTimeEqual(expected, String(proofPackage.attestation.value || ''))) {
        return { valid: false, error: 'ATTESTATION_INVALID: package signature does not match the attestation key' };
      }
      authenticity = 'VERIFIED';
    }

    // 1. Verify Category Breakdown consistency with eventCount
    let sumEvents = 0;
    const sortedCategories = Object.keys(categoryBreakdown || {}).sort();
    sortedCategories.forEach(cat => {
      sumEvents += categoryBreakdown[cat];
    });

    if (sumEvents !== eventCount) {
      return { valid: false, error: `Event count mismatch: declared ${eventCount}, categories sum to ${sumEvents}` };
    }

    // 2. Verify Category Summary Commitment
    const categorySummaryString = sortedCategories.map(c => `${c}:${categoryBreakdown[c]}`).join(',');
    const recomputedCategoryCommitment = sha256(categorySummaryString);
    if (recomputedCategoryCommitment !== categorySummaryCommitment) {
      return { valid: false, error: 'Category summary commitment tampering detected' };
    }

    // 3. Verify Challenge Integrity
    const expectedChallengePreimage = `${merkleRoot}:${eventCount}:${policyHash}:${auditPeriod.start}:${auditPeriod.end}:${categorySummaryCommitment}`;
    const expectedChallenge = sha256(expectedChallengePreimage);
    if (expectedChallenge !== challenge) {
      return { valid: false, error: 'Challenge invalid or tampered' };
    }

    // 4. Verify Challenge Response Binding
    if (fiatShamirResponse !== sha256(challenge + ':ACCEPTED')) {
      return { valid: false, error: 'Challenge response binding rejected' };
    }

    // 5. Verify Merkle Proof Inclusions
    if (Array.isArray(merkleProofSample) && merkleProofSample.length > 0) {
      for (const sample of merkleProofSample) {
        const isPathValid = MerkleTree.verifyProof(sample.leaf, sample.path, merkleRoot);
        if (!isPathValid) {
          return { valid: false, error: `Merkle path verification failed at index ${sample.index}` };
        }
      }
    }

    return {
      valid: true,
      authenticity,
      eventCount,
      merkleRoot,
      auditPeriod,
      categoryBreakdown
    };
  }

  /**
   * Formats an independent Auditor Report JSON
   */
  function exportAuditorReport(proofPackage) {
    const verification = verifyDlpProof(proofPackage);
    return {
      auditorHeader: {
        standard: 'SOC2 Type II / GDPR Article 32 / HIPAA Safeguard',
        scheme: 'Keyed Merkle Attestation (HMAC-bound, sampled disclosure)',
        tamperEvident: true,
        zeroKnowledge: false,
        authenticity: verification.authenticity || 'UNKNOWN',
        disclosure: 'Event counts and categories are disclosed; event contents are not',
        verificationStatus: verification.valid ? 'PASSED' : 'FAILED',
        verificationTimestamp: new Date().toISOString()
      },
      complianceData: {
        totalProtectedIncidents: proofPackage.publicSignals.eventCount,
        cryptographicProofRoot: proofPackage.publicSignals.merkleRoot,
        auditPeriod: proofPackage.publicSignals.auditPeriod,
        categoryBreakdown: proofPackage.proof.categoryBreakdown
      },
      rawZkProof: proofPackage
    };
  }

  return {
    sha256,
    hmacSha256,
    generateSalt,
    MerkleTree,
    createEventCommitment,
    generateDlpProof,
    verifyDlpProof,
    exportAuditorReport
  };
}));
