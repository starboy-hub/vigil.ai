/**
 * Sentinel Security Layer: Schema, Contract & Normalizer Tests
 * Part of Vigil AI + Sentinel (Plan.pdf - Stage 2, Section 4.8)
 */
'use strict';

const path = require('path');
const {
  DECISION_ALLOW,
  ACTION_FS_READ,
  ACTION_FS_WRITE,
  REASON_CODES,
  EVENT_ACTION_PROPOSED
} = require('../src/sentinel/constants');

const {
  CURRENT_SCHEMA_VERSION,
  validateActionSchema,
  validateDecisionSchema,
  validateEventSchema,
  computeActionHash,
  scrubSecretsFromExplanation
} = require('../src/sentinel/schemas');

const {
  normalizeFilesystemPath,
  normalizeNetworkDestination,
  isPathContained
} = require('../src/sentinel/normalizer');

describe('Sentinel Stage 2: Shared Contracts & Schemas', () => {

  describe('1. Action Schema Validation', () => {
    const validAction = {
      schema_version: CURRENT_SCHEMA_VERSION,
      request_id: 'req-uuid-1234',
      session_id: 'sess-abc-5678',
      agent_id: 'claude-code-agent',
      adapter: {
        id: 'sentinel-mcp-gateway',
        version: '1.0.0',
        type: 'mcp'
      },
      action_type: ACTION_FS_READ,
      resource: 'src/content/content.js',
      parameters: { offset: 0, length: 100 },
      requested_scope: 'workspace',
      timestamp: Date.now()
    };

    test('accepts fully compliant Action Schema', () => {
      const result = validateActionSchema(validAction);
      expect(result.valid).toBe(true);
      expect(result.sanitized.request_id).toBe('req-uuid-1234');
      expect(result.sanitized.action_type).toBe(ACTION_FS_READ);
      expect(result.sanitized.resource).toBe('src/content/content.js');
    });

    test('rejects missing or null action object', () => {
      expect(validateActionSchema(null).valid).toBe(false);
      expect(validateActionSchema(undefined).valid).toBe(false);
      expect(validateActionSchema('not an object').valid).toBe(false);
    });

    test('rejects missing or empty request_id, session_id, and agent_id', () => {
      const bad = { ...validAction, request_id: '   ' };
      expect(validateActionSchema(bad).valid).toBe(false);
      expect(validateActionSchema({ ...validAction, session_id: '' }).valid).toBe(false);
      expect(validateActionSchema({ ...validAction, agent_id: '' }).valid).toBe(false);
    });

    test('rejects unknown or invalid action_type (prevents fail-open)', () => {
      const bad = { ...validAction, action_type: 'system:arbitrary_hack' };
      const res = validateActionSchema(bad);
      expect(res.valid).toBe(false);
      expect(res.errors[0]).toContain('Invalid action_type');
    });

    test('rejects malformed adapter metadata', () => {
      const bad = { ...validAction, adapter: { id: 'only-id' } };
      const res = validateActionSchema(bad);
      expect(res.valid).toBe(false);
      expect(res.errors.length).toBeGreaterThan(0);
    });

    test('rejects invalid timestamps', () => {
      expect(validateActionSchema({ ...validAction, timestamp: -100 }).valid).toBe(false);
      expect(validateActionSchema({ ...validAction, timestamp: 'invalid-date' }).valid).toBe(false);
    });
  });

  describe('2. Decision Schema Validation', () => {
    const validDecision = {
      schema_version: CURRENT_SCHEMA_VERSION,
      decision: DECISION_ALLOW,
      reason_code: REASON_CODES.ALLOW_WORKSPACE_READ,
      explanation: 'Path resides safely within permitted workspace root.',
      matched_policy_ids: ['rule-workspace-boundary-v1'],
      policy_version: '1.0.0',
      request_id: 'req-uuid-1234',
      required_constraints: { read_only: true },
      decision_expiry: Date.now() + 60000,
      audit_reference: 'audit-ref-9876',
      action_hash: 'a'.repeat(64) // 64-char hex SHA-256
    };

    test('accepts valid Decision Schema', () => {
      const res = validateDecisionSchema(validDecision);
      expect(res.valid).toBe(true);
      expect(res.decision.decision).toBe(DECISION_ALLOW);
    });

    test('rejects invalid decision outcomes', () => {
      const bad = { ...validDecision, decision: 'maybe_allow' };
      const res = validateDecisionSchema(bad);
      expect(res.valid).toBe(false);
      expect(res.errors[0]).toContain('Invalid decision');
    });

    test('rejects unrecognized reason_code', () => {
      const bad = { ...validDecision, reason_code: 'NON_EXISTENT_REASON' };
      const res = validateDecisionSchema(bad);
      expect(res.valid).toBe(false);
      expect(res.errors[0]).toContain('Invalid or unrecognized reason_code');
    });

    test('rejects missing or malformed action_hash (TOCTOU guard)', () => {
      const bad = { ...validDecision, action_hash: 'too-short' };
      const res = validateDecisionSchema(bad);
      expect(res.valid).toBe(false);
      expect(res.errors[0]).toContain('action_hash');
    });
  });

  describe('3. Event Schema Validation', () => {
    const validEvent = {
      schema_version: CURRENT_SCHEMA_VERSION,
      event_id: 'evt-1111',
      event_type: EVENT_ACTION_PROPOSED,
      timestamp: new Date().toISOString(),
      request_id: 'req-uuid-1234',
      session_id: 'sess-abc-5678',
      agent_id: 'claude-code-agent',
      adapter_id: 'sentinel-mcp-gateway',
      action_type: ACTION_FS_READ,
      canonical_resource: '/workspace/src/content/content.js',
      telemetry_state: 'inspected'
    };

    test('accepts valid Event Schema', () => {
      const res = validateEventSchema(validEvent);
      expect(res.valid).toBe(true);
    });

    test('rejects unknown event_type', () => {
      const bad = { ...validEvent, event_type: 'unknown:event' };
      expect(validateEventSchema(bad).valid).toBe(false);
    });
  });

  describe('4. Resource Normalization & Boundary Checks', () => {
    const mockWorkspace = path.resolve(__dirname, '..');

    test('normalizes relative path inside workspace', () => {
      const res = normalizeFilesystemPath('package.json', mockWorkspace);
      expect(res.error).toBeNull();
      expect(res.isInsideWorkspace).toBe(true);
      expect(res.isSensitiveSystemPath).toBe(false);
      expect(res.canonicalPath).toBe(path.join(mockWorkspace, 'package.json'));
    });

    test('detects path traversal attempts escaping workspace root', () => {
      const res = normalizeFilesystemPath('../../../../../../../etc/passwd', mockWorkspace);
      expect(res.isInsideWorkspace).toBe(false);
      expect(res.isSensitiveSystemPath).toBe(true);
    });

    test('detects null-byte injection attempts in path', () => {
      const res = normalizeFilesystemPath('package.json\0.exe', mockWorkspace);
      expect(res.error).toBe('PATH_INJECTION_NULL_BYTE');
      expect(res.isInsideWorkspace).toBe(false);
    });

    test('strictly rejects prefix collision attacks (/workspace-evil vs /workspace)', () => {
      const parent = '/home/user/project';
      const fakeSibling = '/home/user/project-evil/file.txt';
      const realChild = '/home/user/project/sub/file.txt';

      expect(isPathContained(fakeSibling, parent)).toBe(false);
      expect(isPathContained(realChild, parent)).toBe(true);
    });

    test('normalizes network destinations & detects cloud metadata endpoints', () => {
      const meta = normalizeNetworkDestination('http://169.254.169.254/latest/meta-data');
      expect(meta.isCloudMetadata).toBe(true);
      expect(meta.canonicalHost).toBe('169.254.169.254');

      const loop = normalizeNetworkDestination('http://localhost:8080/api');
      expect(loop.isLoopback).toBe(true);
      expect(loop.isPrivateNetwork).toBe(true);
      expect(loop.isCloudMetadata).toBe(false);

      const pub = normalizeNetworkDestination('https://api.github.com:443');
      expect(pub.isPrivateNetwork).toBe(false);
      expect(pub.isCloudMetadata).toBe(false);
      expect(pub.port).toBe(443);
    });
  });

  describe('5. TOCTOU Binding: Canonical Action Hashing', () => {
    const action = {
      schema_version: '1.0.0',
      request_id: 'req-1',
      agent_id: 'agent-1',
      action_type: ACTION_FS_WRITE,
      resource: '/workspace/build.js',
      parameters: { mode: 'prod', clean: true }
    };

    test('produces deterministic 64-char hex SHA-256 hash', () => {
      const h1 = computeActionHash(action);
      const h2 = computeActionHash(action);
      expect(h1).toHaveLength(64);
      expect(h1).toBe(h2);
    });

    test('action parameter mutation alters the hash (invalidating stale approval)', () => {
      const h1 = computeActionHash(action);
      const mutated = { ...action, parameters: { mode: 'prod', clean: false } };
      const h2 = computeActionHash(mutated);
      expect(h1).not.toBe(h2);
    });

    test('resource mutation alters the hash', () => {
      const h1 = computeActionHash(action);
      const mutated = { ...action, resource: '/workspace/other.js' };
      const h2 = computeActionHash(mutated);
      expect(h1).not.toBe(h2);
    });
  });

  describe('6. Secret Scrubber in Explanations', () => {
    test('redacts synthetic API keys and private keys from human explanations', () => {
      const raw = 'Denied access to key AKIAIOSFODNN7EXAMPLE and sk-mockapi1234567890abcdef and ghp_mockpersonalaccesstoken1234567890';
      const scrubbed = scrubSecretsFromExplanation(raw);

      expect(scrubbed).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(scrubbed).not.toContain('sk-mockapi1234567890abcdef');
      expect(scrubbed).not.toContain('ghp_mockpersonalaccesstoken1234567890');
      expect(scrubbed).toContain('[REDACTED_AWS_KEY]');
      expect(scrubbed).toContain('[REDACTED_API_KEY]');
      expect(scrubbed).toContain('[REDACTED_GITHUB_PAT]');
    });
  });
});
