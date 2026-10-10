/**
 * Unit Tests for Blueprint #14: Storage Access Audit Proxy
 * Verifies logging of GET, SET, and REMOVE operations, redaction of sensitive
 * payloads, ring buffer capping, and JSON export capabilities.
 */
const { StorageAuditProxy } = require('../src/shared/storage-audit.js');

describe('Blueprint #14: Storage Access Audit Proxy', () => {
  let audit;
  let mockStorage;

  beforeEach(() => {
    audit = new StorageAuditProxy(5);
    const store = new Map();
    mockStorage = {
      get: jest.fn(async (keys) => {
        const res = {};
        if (typeof keys === 'string') {
          if (store.has(keys)) res[keys] = store.get(keys);
        } else if (Array.isArray(keys)) {
          keys.forEach(k => { if (store.has(k)) res[k] = store.get(k); });
        }
        return res;
      }),
      set: jest.fn(async (items) => {
        Object.entries(items).forEach(([k, v]) => store.set(k, v));
      }),
      remove: jest.fn(async (keys) => {
        const arr = Array.isArray(keys) ? keys : [keys];
        arr.forEach(k => store.delete(k));
      })
    };
  });

  test('records SET operations without recording secret values', async () => {
    await audit.wrapSet(mockStorage, { api_key: 'sk-secret-123', username: 'testuser' });

    const logs = audit.getAuditLog();
    expect(logs.length).toBe(1);
    expect(logs[0].operation).toBe('SET');
    expect(logs[0].keys).toEqual(['api_key', 'username']);
    expect(logs[0].keyCount).toBe(2);
    // Crucial: values themselves are never logged
    expect(JSON.stringify(logs[0])).not.toContain('sk-secret-123');
    expect(logs[0].timestamp).toBeDefined();
  });

  test('records GET operations with key counts and timing', async () => {
    await audit.wrapGet(mockStorage, ['api_key', 'theme']);

    const logs = audit.getAuditLog();
    expect(logs.length).toBe(1);
    expect(logs[0].operation).toBe('GET');
    expect(logs[0].keys).toEqual(['api_key', 'theme']);
    expect(logs[0].elapsedMs).toBeGreaterThanOrEqual(0);
  });

  test('records REMOVE operations', async () => {
    await audit.wrapRemove(mockStorage, 'cached_token');

    const logs = audit.getAuditLog();
    expect(logs.length).toBe(1);
    expect(logs[0].operation).toBe('REMOVE');
    expect(logs[0].keys).toEqual(['cached_token']);
  });

  test('enforces ring buffer limit and evicts oldest entries', async () => {
    for (let i = 0; i < 7; i++) {
      audit.logAccess('GET', `key_${i}`, 1, 0.5);
    }

    const logs = audit.getAuditLog();
    expect(logs.length).toBe(5);
    // Keys 0 and 1 were evicted
    expect(logs[0].keys).toEqual(['key_2']);
    expect(logs[4].keys).toEqual(['key_6']);
  });

  test('exportAuditLogJSON generates parseable compliance JSON', () => {
    audit.logAccess('SET', ['setting1'], 1, 1.2);
    const jsonStr = audit.exportAuditLogJSON();
    const parsed = JSON.parse(jsonStr);

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].operation).toBe('SET');
    expect(parsed[0].keys).toContain('setting1');
  });

  test('clear empties the ring buffer', () => {
    audit.logAccess('GET', ['test'], 1, 0.1);
    expect(audit.getAuditLog().length).toBe(1);
    audit.clear();
    expect(audit.getAuditLog().length).toBe(0);
  });
});

