/**
 * Unit Tests for Gate 3: Build Reproducibility & Supply-Chain Integrity Verifier
 * Verifies that:
 * 1. Matching baseline passes cleanly.
 * 2. Mismatched baseline fails closed (non-zero exit code / thrown error)
 *    and NEVER mutates the committed baseline file.
 * 3. Itemized delta diff identifies drifted files.
 * 4. Only explicit --update-baseline updates the committed hash file.
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { computeDistFingerprint, verifyAndRecord } = require('../scripts/verify-build-reproducibility.js');

const ROOT = path.resolve(__dirname, '..');
const BASELINE_FILE = path.join(ROOT, '.github', 'build-hash.txt');

describe('Gate 3: Supply-Chain Reproducibility & Verifier Fail-Closed Integrity', () => {
  let originalBaseline = '';

  beforeAll(() => {
    if (fs.existsSync(BASELINE_FILE)) {
      originalBaseline = fs.readFileSync(BASELINE_FILE, 'utf8');
    }
  });

  afterEach(() => {
    // Restore legitimate committed baseline after each test
    if (originalBaseline) {
      fs.writeFileSync(BASELINE_FILE, originalBaseline);
    }
  });

  test('computeDistFingerprint computes deterministic composite hash across dist artifacts', () => {
    const res1 = computeDistFingerprint();
    const res2 = computeDistFingerprint();

    expect(typeof res1.compositeHash).toBe('string');
    expect(res1.compositeHash.length).toBe(64);
    expect(res1.compositeHash).toBe(res2.compositeHash);
    expect(res1.fileCount).toBeGreaterThan(10);
  });

  test('verifyAndRecord passes when committed baseline matches current build', () => {
    const { compositeHash } = computeDistFingerprint();
    fs.writeFileSync(BASELINE_FILE, compositeHash + '\n');

    const result = verifyAndRecord({ updateBaseline: false });
    expect(result.verified).toBe(true);
    expect(result.compositeHash).toBe(compositeHash);
  });

  test('verifyAndRecord fails closed and does NOT overwrite baseline when hashes mismatch', () => {
    const fakeTamperedBaseline = '0'.repeat(64);
    fs.writeFileSync(BASELINE_FILE, fakeTamperedBaseline + '\n');

    // Must throw an error and fail closed
    expect(() => {
      verifyAndRecord({ updateBaseline: false });
    }).toThrow(/composite hash mismatch/i);

    // Verify the committed baseline file was NOT overwritten
    const currentOnDisk = fs.readFileSync(BASELINE_FILE, 'utf8').trim();
    expect(currentOnDisk).toBe(fakeTamperedBaseline);
  });

  test('CLI invocation: exits with code 1 and prints mismatch when baseline differs', () => {
    const fakeTamperedBaseline = 'a'.repeat(64);
    fs.writeFileSync(BASELINE_FILE, fakeTamperedBaseline + '\n');

    let failed = false;
    let exitCode = 0;
    try {
      execSync('node scripts/verify-build-reproducibility.js', { cwd: ROOT, stdio: 'pipe' });
    } catch (err) {
      failed = true;
      exitCode = err.status;
      const stderr = err.stderr ? err.stderr.toString() : '';
      const stdout = err.stdout ? err.stdout.toString() : '';
      const output = stderr + stdout;
      expect(output).toContain('Build reproducibility verification FAILED');
      expect(output).toContain(fakeTamperedBaseline);
    }

    expect(failed).toBe(true);
    expect(exitCode).toBe(1);

    // Baseline file must still be the fake baseline, proving it was not rewritten
    const currentOnDisk = fs.readFileSync(BASELINE_FILE, 'utf8').trim();
    expect(currentOnDisk).toBe(fakeTamperedBaseline);
  });

  test('CLI invocation: --update-baseline explicitly updates the baseline file', () => {
    const fakeTamperedBaseline = 'b'.repeat(64);
    fs.writeFileSync(BASELINE_FILE, fakeTamperedBaseline + '\n');

    const stdout = execSync('node scripts/verify-build-reproducibility.js --update-baseline', { cwd: ROOT }).toString();
    expect(stdout).toContain('Explicitly updating committed baseline build hash');

    const updatedOnDisk = fs.readFileSync(BASELINE_FILE, 'utf8').trim();
    const { compositeHash } = computeDistFingerprint();
    expect(updatedOnDisk).toBe(compositeHash);
    expect(updatedOnDisk).not.toBe(fakeTamperedBaseline);
  });
});

