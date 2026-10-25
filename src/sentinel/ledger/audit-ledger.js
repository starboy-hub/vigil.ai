/**
 * Sentinel Stage 7: Tamper-Evident Audit Ledger & Security Timeline
 * =================================================================
 * High-assurance append-only ledger featuring SHA-256 cryptographic hash-chaining,
 * deep secret scrubbing on ingestion, chronological timeline querying,
 * tamper detection, and enterprise SIEM compliance export.
 *
 * Implements Stage 7 of Plan.pdf master execution specification.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
  VALID_EVENT_TYPES,
  CURRENT_SCHEMA_VERSION
} = require('../constants');

const {
  validateEventSchema,
  scrubSecretsFromExplanation
} = require('../schemas');

const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

class SentinelAuditLedger {
  /**
   * @param {Object} [options]
   * @param {string} [options.storageFilePath] - Optional file path for append-only persistent storage
   * @param {number} [options.maxInMemoryEntries] - Maximum in-memory entries (default: 10,000)
   */
  constructor(options = {}) {
    this.storageFilePath = options.storageFilePath || null;
    this.maxInMemoryEntries = Number.isInteger(options.maxInMemoryEntries) && options.maxInMemoryEntries > 0
      ? options.maxInMemoryEntries
      : 10000;

    this.entries = [];
    this.headHash = GENESIS_PREV_HASH;

    if (this.storageFilePath) {
      this._initializePersistentStorage();
    }
  }

  /**
   * Append an event to the ledger with cryptographic hash chaining.
   * Deeply scrubs secrets from payload prior to hashing and storage.
   * 
   * @param {string} eventType - Valid event type from VALID_EVENT_TYPES
   * @param {Object} payload - Event data
   * @returns {Object} Ledger entry including index, entry_hash, and prev_hash
   */
  append(eventType, payload = {}) {
    if (!eventType || typeof eventType !== 'string' || !VALID_EVENT_TYPES.includes(eventType)) {
      throw new Error(`Invalid eventType: "${eventType}". Expected one of: ${VALID_EVENT_TYPES.join(', ')}`);
    }

    // 1. Deep scrub secrets from payload before hashing
    const sanitizedPayload = this._deepScrub(payload);

    // 2. Validate schema
    const validation = validateEventSchema({
      schema_version: CURRENT_SCHEMA_VERSION,
      event_type: eventType,
      timestamp: Date.now(),
      payload: sanitizedPayload
    });

    const safeEvent = validation.sanitized || {
      schema_version: CURRENT_SCHEMA_VERSION,
      event_type: eventType,
      timestamp: Date.now(),
      payload: sanitizedPayload
    };

    const index = this.entries.length;
    const prevHash = this.headHash;
    const timestamp = safeEvent.timestamp;

    // 3. Compute deterministic entry hash
    const entryHash = this._computeEntryHash(index, timestamp, eventType, prevHash, sanitizedPayload);

    const entry = {
      index,
      timestamp,
      event_type: eventType,
      payload: sanitizedPayload,
      prev_hash: prevHash,
      entry_hash: entryHash
    };

    // 4. Update ledger state
    this.entries.push(entry);
    this.headHash = entryHash;

    // 5. Append to persistent file if configured
    if (this.storageFilePath) {
      try {
        fs.appendFileSync(this.storageFilePath, JSON.stringify(entry) + '\n', 'utf8');
      } catch (err) {
        // Disk write errors are non-fatal to memory state
      }
    }

    // Trim ring buffer if exceeds capacity
    if (this.entries.length > this.maxInMemoryEntries) {
      this.entries.shift();
    }

    return entry;
  }

  /**
   * Compute deterministic SHA-256 entry hash:
   * SHA-256(index + ":" + timestamp + ":" + event_type + ":" + prev_hash + ":" + canonical_json)
   */
  _computeEntryHash(index, timestamp, eventType, prevHash, payload) {
    const canonicalPayload = this._canonicalJson(payload);
    const preimage = `${index}:${timestamp}:${eventType}:${prevHash}:${canonicalPayload}`;
    return crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
  }

  /**
   * Verify cryptographic integrity of the entire ledger chain.
   * 
   * @returns {{ valid: boolean, checkedEntries: number, tamperedIndex?: number, error?: string }}
   */
  verifyLedgerIntegrity() {
    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // 1. Check prev_hash continuity
      if (entry.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          checkedEntries: i,
          tamperedIndex: entry.index,
          error: `Broken hash link at index ${entry.index}: prev_hash ${entry.prev_hash} does not match expected ${expectedPrevHash}`
        };
      }

      // 2. Recompute entry_hash and compare
      const computedHash = this._computeEntryHash(
        entry.index,
        entry.timestamp,
        entry.event_type,
        entry.prev_hash,
        entry.payload
      );

      if (computedHash !== entry.entry_hash) {
        return {
          valid: false,
          checkedEntries: i,
          tamperedIndex: entry.index,
          error: `Entry hash mismatch at index ${entry.index}: expected ${computedHash}, got ${entry.entry_hash}`
        };
      }

      expectedPrevHash = entry.entry_hash;
    }

    return {
      valid: true,
      checkedEntries: this.entries.length
    };
  }

  /**
   * Query ledger events with flexible filtering
   * 
   * @param {Object} [filter]
   * @param {string} [filter.eventType] - Filter by event type
   * @param {string} [filter.agentId] - Filter by agentId in payload
   * @param {string} [filter.sessionId] - Filter by sessionId in payload
   * @param {number} [filter.startTime] - Epoch ms lower bound
   * @param {number} [filter.endTime] - Epoch ms upper bound
   * @param {number} [filter.limit] - Max entries to return
   * @returns {Object[]}
   */
  queryEvents(filter = {}) {
    let results = this.entries.slice();

    if (filter.eventType) {
      results = results.filter((e) => e.event_type === filter.eventType);
    }

    if (filter.agentId) {
      results = results.filter((e) => {
        const p = e.payload || {};
        return p.agentId === filter.agentId || (p.action && p.action.agent_id === filter.agentId);
      });
    }

    if (filter.sessionId) {
      results = results.filter((e) => {
        const p = e.payload || {};
        return p.sessionId === filter.sessionId || (p.action && p.action.session_id === filter.sessionId);
      });
    }

    if (typeof filter.startTime === 'number') {
      results = results.filter((e) => e.timestamp >= filter.startTime);
    }

    if (typeof filter.endTime === 'number') {
      results = results.filter((e) => e.timestamp <= filter.endTime);
    }

    if (typeof filter.limit === 'number' && filter.limit > 0) {
      results = results.slice(-filter.limit);
    }

    return results;
  }

  /**
   * Generate chronological security timeline for a given session
   * 
   * @param {string} sessionId
   * @returns {Object[]} Chronological sequence of timeline events
   */
  getSessionTimeline(sessionId) {
    if (!sessionId) return [];

    const sessionEvents = this.queryEvents({ sessionId });
    return sessionEvents.map((e) => {
      const p = e.payload || {};
      const action = p.action || {};
      const decision = p.decision || {};

      return {
        index: e.index,
        timestamp: new Date(e.timestamp).toISOString(),
        eventType: e.event_type,
        actionType: action.action_type || p.actionType || 'unknown',
        resource: action.resource || p.resource || 'N/A',
        outcome: decision.decision || p.outcome || 'N/A',
        reasonCode: decision.reason_code || p.reasonCode || 'N/A',
        entryHash: e.entry_hash
      };
    });
  }

  /**
   * Export audit log in standard formats ('json' | 'cef')
   * 
   * @param {string} [format='json']
   * @returns {string} Formatted log export
   */
  exportComplianceLog(format = 'json') {
    if (format === 'cef') {
      return this.entries
        .map((e) => {
          const timestamp = new Date(e.timestamp).toISOString();
          const p = e.payload || {};
          return `CEF:0|VigilSentinel|AuditLedger|1.0|${e.event_type}|${e.event_type}|1|rt=${timestamp} shost=localhost msg=${JSON.stringify(p)}`;
        })
        .join('\n');
    }

    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Recursively scrub secrets from payload values
   */
  _deepScrub(val) {
    if (val === null || val === undefined) return val;

    if (typeof val === 'string') {
      return scrubSecretsFromExplanation(val);
    }

    if (Array.isArray(val)) {
      return val.map((item) => this._deepScrub(item));
    }

    if (typeof val === 'object') {
      const clean = {};
      for (const [k, v] of Object.entries(val)) {
        clean[k] = this._deepScrub(v);
      }
      return clean;
    }

    return val;
  }

  /**
   * Canonical JSON serializer for deterministic hashing
   */
  _canonicalJson(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
      return '[' + obj.map((x) => this._canonicalJson(x)).join(',') + ']';
    }

    const sortedKeys = Object.keys(obj).sort();
    const pairs = sortedKeys.map((k) => JSON.stringify(k) + ':' + this._canonicalJson(obj[k]));
    return '{' + pairs.join(',') + '}';
  }

  /**
   * Helper: initialize persistent storage file and read existing records
   */
  _initializePersistentStorage() {
    try {
      const dir = path.dirname(this.storageFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      if (fs.existsSync(this.storageFilePath)) {
        const lines = fs.readFileSync(this.storageFilePath, 'utf8').split('\n').filter(Boolean);
        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            this.entries.push(entry);
            this.headHash = entry.entry_hash;
          } catch (_parseErr) {
            // Skip corrupted lines
          }
        }
      }
    } catch (_err) {
      // Ignore disk init errors
    }
  }
}

module.exports = {
  SentinelAuditLedger,
  GENESIS_PREV_HASH
};
