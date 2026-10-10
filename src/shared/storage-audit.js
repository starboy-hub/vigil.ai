/**
 * VIGIL - Storage Access Audit Proxy
 * Blueprint #14: Zero-Trust Local Storage Telemetry & Compliance Ring Buffer
 * Tracks all local storage read/write operations without persisting sensitive secret payloads.
 */
(function (root) {
  'use strict';

  class StorageAuditProxy {
    constructor(maxEntries = 500) {
      this.maxEntries = maxEntries;
      this.auditLog = [];
    }

    logAccess(operation, keys, count = 0, elapsedMs = 0) {
      const normalizedKeys = Array.isArray(keys)
        ? keys
        : (typeof keys === 'string' ? [keys] : Object.keys(keys || {}));

      const entry = {
        timestamp: new Date().toISOString(),
        operation: String(operation).toUpperCase(),
        keys: normalizedKeys,
        keyCount: normalizedKeys.length,
        resultCount: count,
        elapsedMs: typeof elapsedMs === 'number' ? parseFloat(elapsedMs.toFixed(2)) : 0
      };

      this.auditLog.push(entry);

      if (this.auditLog.length > this.maxEntries) {
        this.auditLog.shift();
      }

      return entry;
    }

    async wrapGet(storageArea, keys) {
      const start = typeof performance !== 'undefined' ? performance.now() : Date.now();
      const result = await storageArea.get(keys);
      const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - start;
      const count = result ? Object.keys(result).length : 0;
      this.logAccess('GET', keys, count, elapsed);
      return result;
    }

    async wrapSet(storageArea, items) {
      const start = typeof performance !== 'undefined' ? performance.now() : Date.now();
      await storageArea.set(items);
      const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - start;
      const keys = items ? Object.keys(items) : [];
      this.logAccess('SET', keys, keys.length, elapsed);
    }

    async wrapRemove(storageArea, keys) {
      const start = typeof performance !== 'undefined' ? performance.now() : Date.now();
      await storageArea.remove(keys);
      const elapsed = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - start;
      this.logAccess('REMOVE', keys, 0, elapsed);
    }

    getAuditLog() {
      return [...this.auditLog];
    }

    exportAuditLogJSON() {
      return JSON.stringify(this.auditLog, null, 2);
    }

    clear() {
      this.auditLog = [];
    }
  }

  const defaultInstance = new StorageAuditProxy();

  const api = {
    StorageAuditProxy,
    defaultInstance,
    logAccess: defaultInstance.logAccess.bind(defaultInstance),
    getAuditLog: defaultInstance.getAuditLog.bind(defaultInstance),
    exportAuditLogJSON: defaultInstance.exportAuditLogJSON.bind(defaultInstance),
    clear: defaultInstance.clear.bind(defaultInstance)
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof root !== 'undefined') {
    root.VIGIL_STORAGE_AUDIT = api;
  }
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));

