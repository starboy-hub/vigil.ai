/**
 * Sentinel Stage 7: Tamper-Evident Audit Ledger Tests
 * ===================================================
 * Verifies append-only cryptographic hash chaining, tamper detection,
 * secret scrubbing on ingestion, chronological timeline queries, and CEF export.
 */

'use strict';

const {
  SentinelAuditLedger,
  GENESIS_PREV_HASH
} = require('../src/sentinel/ledger/audit-ledger');

const {
  EVENT_ACTION_PROPOSED,
  EVENT_POLICY_EVALUATED,
  EVENT_APPROVAL_REQUESTED,
  EVENT_APPROVAL_GRANTED,
  EVENT_ACTION_EXEC_STARTED,
  EVENT_ACTION_COMPLETED
} = require('../src/sentinel/constants');

describe('Sentinel Stage 7: Tamper-Evident Audit Ledger', () => {
  let ledger;

  beforeEach(() => {
    ledger = new SentinelAuditLedger({
      maxInMemoryEntries: 1000
    });
  });

  describe('1. Hash Chaining & Sequential Nonces', () => {
    test('initializes with genesis hash and increments index monotonically', () => {
      expect(ledger.headHash).toBe(GENESIS_PREV_HASH);
      expect(ledger.entries.length).toBe(0);

      const entry0 = ledger.append(EVENT_ACTION_PROPOSED, {
        action: { action_type: 'fs:read', resource: 'package.json' }
      });

      expect(entry0.index).toBe(0);
      expect(entry0.prev_hash).toBe(GENESIS_PREV_HASH);
      expect(entry0.entry_hash).toHaveLength(64);
      expect(ledger.headHash).toBe(entry0.entry_hash);

      const entry1 = ledger.append(EVENT_POLICY_EVALUATED, {
        decision: { decision: 'allow', reason_code: 'ALLOW_WORKSPACE_READ' }
      });

      expect(entry1.index).toBe(1);
      expect(entry1.prev_hash).toBe(entry0.entry_hash);
      expect(entry1.entry_hash).toHaveLength(64);
      expect(ledger.headHash).toBe(entry1.entry_hash);
    });

    test('cryptographic chain verifies successfully on untampered ledger', () => {
      ledger.append(EVENT_ACTION_PROPOSED, { step: 1 });
      ledger.append(EVENT_POLICY_EVALUATED, { step: 2 });
      ledger.append(EVENT_APPROVAL_REQUESTED, { step: 3 });
      ledger.append(EVENT_APPROVAL_GRANTED, { step: 4 });
      ledger.append(EVENT_ACTION_EXEC_STARTED, { step: 5 });
      ledger.append(EVENT_ACTION_COMPLETED, { step: 6 });

      const check = ledger.verifyLedgerIntegrity();
      expect(check.valid).toBe(true);
      expect(check.checkedEntries).toBe(6);
    });
  });

  describe('2. Tamper Detection & Forensic Integrity', () => {
    test('detects payload tampering and returns exact tampered index', () => {
      ledger.append(EVENT_ACTION_PROPOSED, { step: 1 });
      ledger.append(EVENT_POLICY_EVALUATED, { step: 2, authorized: false });
      ledger.append(EVENT_ACTION_COMPLETED, { step: 3 });

      // Attacker attempts to forge entry 1 to say authorized: true
      ledger.entries[1].payload.authorized = true;

      const check = ledger.verifyLedgerIntegrity();
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(1);
      expect(check.error).toContain('Entry hash mismatch at index 1');
    });

    test('detects entry deletion (broken hash linkage)', () => {
      ledger.append(EVENT_ACTION_PROPOSED, { step: 1 });
      ledger.append(EVENT_APPROVAL_REQUESTED, { step: 2 });
      ledger.append(EVENT_ACTION_COMPLETED, { step: 3 });

      // Attacker attempts to delete entry 1 (the approval request)
      ledger.entries.splice(1, 1);

      const check = ledger.verifyLedgerIntegrity();
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(2);
      expect(check.error).toContain('Broken hash link');
    });

    test('detects timestamp tampering', () => {
      ledger.append(EVENT_ACTION_PROPOSED, { step: 1 });
      ledger.append(EVENT_ACTION_COMPLETED, { step: 2 });

      // Attacker attempts to backdate entry 0
      ledger.entries[0].timestamp = 1000000;

      const check = ledger.verifyLedgerIntegrity();
      expect(check.valid).toBe(false);
      expect(check.tamperedIndex).toBe(0);
      expect(check.error).toContain('Entry hash mismatch at index 0');
    });
  });

  describe('3. Secret Scrubbing on Ingestion', () => {
    test('scrubs GitHub PATs and API keys from payload before computing entry hash', () => {
      const rawSecret = 'ghp_supersecretgithubtoken1234567890abcdef1234';

      const entry = ledger.append(EVENT_ACTION_PROPOSED, {
        command: `git clone https://${rawSecret}@github.com/org/repo.git`,
        token_preview: rawSecret,
        nested: {
          embedded_secret: `Token: ${rawSecret}`
        }
      });

      // Assert that raw secret was scrubbed
      expect(JSON.stringify(entry.payload)).not.toContain(rawSecret);
      expect(entry.payload.token_preview).toContain('[REDACTED_GITHUB_PAT]');
      expect(entry.payload.nested.embedded_secret).toContain('[REDACTED_GITHUB_PAT]');

      // Assert integrity check still succeeds on the scrubbed entry
      const check = ledger.verifyLedgerIntegrity();
      expect(check.valid).toBe(true);
    });
  });

  describe('4. Timeline & Query Engine', () => {
    test('filters events by eventType, agentId, and sessionId', () => {
      ledger.append(EVENT_ACTION_PROPOSED, {
        agentId: 'agent-1',
        sessionId: 'session-alpha',
        action: { action_type: 'fs:read', resource: 'file1.txt' }
      });

      ledger.append(EVENT_ACTION_PROPOSED, {
        agentId: 'agent-2',
        sessionId: 'session-beta',
        action: { action_type: 'fs:write', resource: 'file2.txt' }
      });

      ledger.append(EVENT_ACTION_COMPLETED, {
        agentId: 'agent-1',
        sessionId: 'session-alpha'
      });

      const alphaEvents = ledger.queryEvents({ sessionId: 'session-alpha' });
      expect(alphaEvents.length).toBe(2);

      const agent2Events = ledger.queryEvents({ agentId: 'agent-2' });
      expect(agent2Events.length).toBe(1);
      expect(agent2Events[0].payload.action.resource).toBe('file2.txt');

      const completedEvents = ledger.queryEvents({ eventType: EVENT_ACTION_COMPLETED });
      expect(completedEvents.length).toBe(1);
    });

    test('generates chronological security timeline for a session', () => {
      ledger.append(EVENT_ACTION_PROPOSED, {
        sessionId: 'session-timeline-1',
        action: { action_type: 'fs:delete', resource: 'old_cache.log' }
      });

      ledger.append(EVENT_POLICY_EVALUATED, {
        sessionId: 'session-timeline-1',
        decision: { decision: 'require_approval', reason_code: 'REQUIRE_APPROVAL_DELETION' }
      });

      const timeline = ledger.getSessionTimeline('session-timeline-1');
      expect(timeline.length).toBe(2);
      expect(timeline[0].actionType).toBe('fs:delete');
      expect(timeline[0].resource).toBe('old_cache.log');
      expect(timeline[1].outcome).toBe('require_approval');
      expect(timeline[1].reasonCode).toBe('REQUIRE_APPROVAL_DELETION');
    });

    test('exports audit log to CEF format', () => {
      ledger.append(EVENT_ACTION_PROPOSED, { action: 'read' });
      const cefExport = ledger.exportComplianceLog('cef');
      expect(cefExport).toContain('CEF:0|VigilSentinel|AuditLedger|1.0|action:proposed');
    });
  });
});

