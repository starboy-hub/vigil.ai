/**
 * VIGIL Blueprint #6: Self-Healing File Integrity Monitor
 *
 * Problem: Attackers with local access, malware, or compromised scripts can alter
 * extension JavaScript files, manifest rules, or ONNX neural models to disable security
 * filters without the user noticing.
 *
 * Solution: Computes and verifies SHA-256 hashes of all extension assets against
 * a cryptographic baseline manifest (vigil-integrity.json) on startup and periodically.
 * Integrates with native daemon for filesystem audits and self-healing restoration from backup.
 */
(function (root) {
  'use strict';

  function bufToHex(buf) {
    const bytes = new Uint8Array(buf);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  class FileIntegrityClient {
    constructor(options = {}) {
      this.manifestUrl = options.manifestUrl || 'vigil-integrity.json';
      this.cachedManifest = null;
      this.subtle = options.subtle || (typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null);
    }

    /**
     * Computes SHA-256 hash of a string or ArrayBuffer
     */
    async computeSha256(content) {
      const subtle = this.subtle || (typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : null);
      if (!subtle) {
        // Fallback for Node/test environment without WebCrypto subtle
        if (typeof require === 'function') {
          const crypto = require('crypto');
          return crypto.createHash('sha256').update(typeof content === 'string' ? content : Buffer.from(content)).digest('hex');
        }
        throw new Error('SubtleCrypto unavailable for file integrity calculation');
      }

      let data;
      if (typeof content === 'string') {
        data = (typeof TextEncoder !== 'undefined' ? new TextEncoder() : new (require('util').TextEncoder)()).encode(content);
      } else if (content instanceof ArrayBuffer) {
        data = new Uint8Array(content);
      } else if (ArrayBuffer.isView(content)) {
        data = content;
      } else {
        throw new Error('Invalid content type for hashing');
      }

      const digest = await subtle.digest('SHA-256', data);
      return bufToHex(digest);
    }

    /**
     * Loads the baseline cryptographic manifest
     */
    async loadManifest() {
      if (this.cachedManifest) return this.cachedManifest;

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
        try {
          const url = chrome.runtime.getURL(this.manifestUrl);
          const resp = await fetch(url);
          if (resp.ok) {
            this.cachedManifest = await resp.json();
            return this.cachedManifest;
          }
        } catch {
          // Continue to fallback
        }
      }

      return {};
    }

    /**
     * Verifies an in-memory file or response against expected SHA-256
     */
    async verifyContent(relPath, content, expectedHash) {
      const actualHash = await this.computeSha256(content);
      const passed = actualHash.toLowerCase() === (expectedHash || '').toLowerCase();
      return {
        path: relPath,
        passed,
        actualHash,
        expectedHash,
        kind: passed ? 'valid' : 'modified'
      };
    }

    /**
     * Audits a map of local files against a baseline manifest
     */
    async auditFiles(filesMap, manifest) {
      const refManifest = manifest || await this.loadManifest();
      const passed = [];
      const tampered = [];

      for (const [relPath, content] of Object.entries(filesMap)) {
        const expected = refManifest[relPath];
        if (!expected) {
          // Unauthorized unexpected file
          const actualHash = await this.computeSha256(content);
          tampered.push({
            path: relPath,
            passed: false,
            actualHash,
            expectedHash: null,
            kind: 'unauthorized_new'
          });
          continue;
        }

        const res = await this.verifyContent(relPath, content, expected);
        if (res.passed) {
          passed.push(relPath);
        } else {
          tampered.push(res);
        }
      }

      // Check for missing expected files
      for (const [expectedPath, expectedHash] of Object.entries(refManifest)) {
        if (!(expectedPath in filesMap)) {
          tampered.push({
            path: expectedPath,
            passed: false,
            actualHash: null,
            expectedHash,
            kind: 'missing'
          });
        }
      }

      const isValid = tampered.length === 0;
      return {
        isValid,
        totalChecked: passed.length + tampered.length,
        passedCount: passed.length,
        tamperedCount: tampered.length,
        passedFiles: passed,
        tamperedFiles: tampered,
        timestamp: Date.now()
      };
    }

    /**
     * Audits the extension's own packaged files against the baseline manifest.
     * Fetches every file listed in the manifest, hashes the bytes, and runs
     * the standard audit. This is what the periodic chrome.alarms scan drives.
     */
    async selfAudit() {
      const manifest = await this.loadManifest();
      if (!manifest || Object.keys(manifest).length === 0) {
        return { error: 'manifest_unavailable', timestamp: Date.now() };
      }
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.getURL) {
        return { error: 'no_runtime', timestamp: Date.now() };
      }
      const filesMap = {};
      for (const relPath of Object.keys(manifest)) {
        try {
          const resp = await fetch(chrome.runtime.getURL(relPath));
          if (!resp.ok) continue; // absence is caught by the missing-file check
          // Uint8Array (not raw ArrayBuffer) so hashing works across realms
          filesMap[relPath] = new Uint8Array(await resp.arrayBuffer());
        } catch {
          // fetch failure is caught by the missing-file check
        }
      }
      return this.auditFiles(filesMap, manifest);
    }

    /**
     * Triggers native daemon deep filesystem scan via nativeBridge
     */
    async scanViaNativeDaemon(nativeBridge, targetDir = null, customManifest = null) {
      if (!nativeBridge || !nativeBridge.isConnected) {
        return { isConnected: false, error: 'Native companion daemon is not connected' };
      }

      const manifest = customManifest || await this.loadManifest();
      try {
        // sendRequest resolves with the JSON-RPC `result` and rejects on error
        const report = await nativeBridge.sendRequest('vigil.verifyFileIntegrity', { targetDir, manifest });
        return { isConnected: true, success: true, report };
      } catch (err) {
        return { isConnected: true, success: false, error: err && err.message ? err.message : 'Unknown daemon error' };
      }
    }

    /**
     * Requests native daemon to self-heal and restore tampered files from golden backup
     */
    async restoreViaNativeDaemon(nativeBridge, targetDir, backupDir, filesToRestore) {
      if (!nativeBridge || !nativeBridge.isConnected) {
        return { isConnected: false, error: 'Native companion daemon is not connected' };
      }

      const safeFiles = Array.isArray(filesToRestore)
        ? filesToRestore.filter(f => typeof f === 'string' && f.length > 0 && !f.includes('..') && !f.startsWith('/') && !f.startsWith('\\'))
        : [];

      try {
        const result = await nativeBridge.sendRequest('vigil.restoreFileIntegrity', { targetDir, backupDir, files: safeFiles });
        return { isConnected: true, success: true, result };
      } catch (err) {
        return { isConnected: true, success: false, error: err && err.message ? err.message : 'Unknown restore error' };
      }
    }
  }

  const integrityClient = new FileIntegrityClient();

  const VIGIL_INTEGRITY = {
    FileIntegrityClient,
    integrityClient,
    bufToHex
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_INTEGRITY;
  }
  if (root) {
    root.VIGIL_INTEGRITY = VIGIL_INTEGRITY;
    root.integrityClient = integrityClient;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
