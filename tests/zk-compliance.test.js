/**
 * Tests for Blueprint #9: Zero-Knowledge Proof of DLP Compliance
 */
const {
  sha256,
  generateSalt,
  MerkleTree,
  createEventCommitment,
  hmacSha256,
  generateDlpProof,
  verifyDlpProof,
  exportAuditorReport
} = require('../src/shared/zk-compliance.js');

describe('Blueprint #9: Zero-Knowledge Proof of DLP Compliance', () => {
  describe('Cryptographic Primitives & Merkle Accumulator', () => {
    test('computes deterministic SHA-256 hashes matching reference', () => {
      const h1 = sha256('hello world');
      const h2 = sha256('hello world');
      expect(h1).toBe(h2);
      expect(h1).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
    });

    test('generates random hex salts', () => {
      const s1 = generateSalt();
      const s2 = generateSalt();
      expect(typeof s1).toBe('string');
      expect(s1.length).toBeGreaterThanOrEqual(16);
      expect(s1).not.toBe(s2);
    });

    test('builds Merkle tree and generates valid inclusion proofs', () => {
      const leaves = [
        sha256('leaf_0'),
        sha256('leaf_1'),
        sha256('leaf_2'),
        sha256('leaf_3')
      ];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();
      expect(typeof root).toBe('string');

      for (let i = 0; i < leaves.length; i++) {
        const proof = tree.getProof(i);
        const isValid = MerkleTree.verifyProof(leaves[i], proof, root);
        expect(isValid).toBe(true);
      }
    });

    test('rejects tampered leaf in Merkle verification', () => {
      const leaves = [sha256('leaf_A'), sha256('leaf_B')];
      const tree = new MerkleTree(leaves);
      const root = tree.getRoot();

      const proof = tree.getProof(0);
      const isTamperedValid = MerkleTree.verifyProof(sha256('fake_leaf'), proof, root);
      expect(isTamperedValid).toBe(false);
    });
  });

  describe('Event Blinding & Zero-Knowledge Commitments', () => {
    test('creates blinded commitment without leaking raw secret payload', () => {
      const sensitiveEvent = {
        type: 'SSN',
        severity: 'critical',
        site: 'chatgpt.com',
        timestamp: '2026-10-01T12:00:00Z',
        secretCleartext: '123-45-6789'
      };
      const salt = generateSalt();
      const commitment = createEventCommitment(sensitiveEvent, salt);

      expect(typeof commitment).toBe('string');
      expect(commitment.length).toBe(64);
      // Commitment must not contain or be reversible to the raw SSN
      expect(commitment).not.toContain('123-45-6789');

      // Different salt creates completely different commitment
      const commitment2 = createEventCommitment(sensitiveEvent, generateSalt());
      expect(commitment).not.toBe(commitment2);
    });
  });

  describe('Zero-Knowledge DLP Proof Generation & Verification', () => {
    const mockEvents = [
      { type: 'SSN', severity: 'critical', site: 'ai.google.com', timestamp: new Date().toISOString() },
      { type: 'CREDIT_CARD', severity: 'critical', site: 'claude.ai', timestamp: new Date().toISOString() },
      { type: 'FINANCIAL', severity: 'high', site: 'openai.com', timestamp: new Date().toISOString() },
      { type: 'MEDICAL', severity: 'high', site: 'chatgpt.com', timestamp: new Date().toISOString() },
      { type: 'CREDENTIALS', severity: 'critical', site: 'huggingface.co', timestamp: new Date().toISOString() }
    ];

    test('generates valid attestation package and verifies successfully', () => {
      const proofPackage = generateDlpProof(mockEvents);

      expect(proofPackage.protocol).toBe('VIGIL-MERKLE-ATTESTATION-v1');
      expect(proofPackage.publicSignals.eventCount).toBe(5);
      expect(typeof proofPackage.publicSignals.merkleRoot).toBe('string');
      expect(proofPackage.proof.challenge).toBeDefined();

      const verification = verifyDlpProof(proofPackage);
      expect(verification.valid).toBe(true);
      expect(verification.authenticity).toBe('UNBOUND'); // structurally valid, no device key bound
      expect(verification.eventCount).toBe(5);
      expect(verification.merkleRoot).toBe(proofPackage.publicSignals.merkleRoot);
    });

    test('strictly preserves zero-disclosure (0% PII in proof package)', () => {
      const sensitiveLeakEvents = [
        { type: 'SSN', original: '000-11-2222', fake: '555-00-1111', timestamp: new Date().toISOString() },
        { type: 'PATIENT_RECORD', original: 'Patient diagnosed with HIV', timestamp: new Date().toISOString() }
      ];

      const proofPackage = generateDlpProof(sensitiveLeakEvents);
      const serialized = JSON.stringify(proofPackage);

      expect(serialized).not.toContain('000-11-2222');
      expect(serialized).not.toContain('HIV');
      expect(serialized).not.toContain('diagnosed');
    });

    test('rejects tampered event count in public signals', () => {
      const proofPackage = generateDlpProof(mockEvents);
      // Fraudulent attempt: enterprise inflates blocked count from 5 to 10
      proofPackage.publicSignals.eventCount = 10;

      const verification = verifyDlpProof(proofPackage);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Event count mismatch');
    });

    test('rejects tampered Merkle root', () => {
      const proofPackage = generateDlpProof(mockEvents);
      proofPackage.publicSignals.merkleRoot = sha256('fraudulent_root');

      const verification = verifyDlpProof(proofPackage);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Challenge invalid');
    });

    test('rejects tampered category breakdown', () => {
      const proofPackage = generateDlpProof(mockEvents);
      // Shift 1 event from SSN to MEDICAL while keeping sum = 5
      proofPackage.proof.categoryBreakdown.SSN -= 1;
      proofPackage.proof.categoryBreakdown.MEDICAL += 1;

      const verification = verifyDlpProof(proofPackage);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Category summary commitment tampering detected');
    });

    test('rejects corrupted Merkle inclusion proof sample', () => {
      const proofPackage = generateDlpProof(mockEvents);
      if (proofPackage.proof.merkleProofSample.length > 0) {
        proofPackage.proof.merkleProofSample[0].leaf = sha256('corrupted_leaf');
      }

      const verification = verifyDlpProof(proofPackage);
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('Merkle path verification failed');
    });

    test('exports formatted auditor compliance report', () => {
      const proofPackage = generateDlpProof(mockEvents);
      const report = exportAuditorReport(proofPackage);

      expect(report.auditorHeader.standard).toContain('SOC2');
      expect(report.auditorHeader.verificationStatus).toBe('PASSED');
      // Honest claims: tamper-evident yes, zero-knowledge no
      expect(report.auditorHeader.tamperEvident).toBe(true);
      expect(report.auditorHeader.zeroKnowledge).toBe(false);
      expect(report.auditorHeader.disclosure).toContain('counts and categories are disclosed');
      expect(report.complianceData.totalProtectedIncidents).toBe(5);
      expect(report.complianceData.cryptographicProofRoot).toBe(proofPackage.publicSignals.merkleRoot);
    });
  });

  describe('Device attestation binding (HMAC-SHA256)', () => {
    const attEvents = [
      { type: 'EMAIL', severity: 'high', site: 'chat.openai.com', timestamp: new Date().toISOString() },
      { type: 'PHONE', severity: 'medium', site: 'gemini.google.com', timestamp: new Date().toISOString() }
    ];

    test('hmacSha256 matches the RFC/envelope known-answer vector', () => {
      // HMAC-SHA256(key="key", msg="The quick brown fox jumps over the lazy dog")
      const mac = hmacSha256('key', 'The quick brown fox jumps over the lazy dog');
      expect(mac).toBe('f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
    });

    test('attested package verifies with the correct device key', () => {
      const key = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
      const proofPackage = generateDlpProof(attEvents, { attestationKey: key });
      expect(proofPackage.attestation).toBeDefined();
      expect(proofPackage.attestation.scheme).toBe('HMAC-SHA256');

      const verification = verifyDlpProof(proofPackage, { attestationKey: key });
      expect(verification.valid).toBe(true);
      expect(verification.authenticity).toBe('VERIFIED');
    });

    test('attested package with tampered signals fails authentication', () => {
      const key = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
      const proofPackage = generateDlpProof(attEvents, { attestationKey: key });
      // Fabricate a bigger number — the HMAC can no longer match
      proofPackage.publicSignals.eventCount = 99;

      const verification = verifyDlpProof(proofPackage, { attestationKey: key });
      expect(verification.valid).toBe(false);
      expect(verification.error).toContain('ATTESTATION_INVALID');
    });

    test('attested package requires the key and rejects a wrong key', () => {
      const key = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
      const proofPackage = generateDlpProof(attEvents, { attestationKey: key });

      const noKey = verifyDlpProof(proofPackage);
      expect(noKey.valid).toBe(false);
      expect(noKey.error).toContain('ATTESTATION_KEY_REQUIRED');

      const wrongKey = verifyDlpProof(proofPackage, { attestationKey: 'f'.repeat(64) });
      expect(wrongKey.valid).toBe(false);
      expect(wrongKey.error).toContain('ATTESTATION_INVALID');
    });
  });
});
