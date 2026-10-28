'use strict';

const { CapabilityManager } = require('../src/sentinel/credentials/capability-manager.js');

describe('Sentinel Stage 4: Cryptographic Tool Capability Token Manager (MCP Hardening)', () => {
  let manager;

  beforeEach(() => {
    manager = new CapabilityManager({
      defaultTtlMs: 5000
    });
  });

  describe('1. Issuance and Cryptographic Verification', () => {
    test('issues a valid signed base64url capability token', () => {
      const token = manager.issueCapability({
        agentId: 'cursor-agent-01',
        sessionId: 'session-xyz',
        actionType: 'fs:write',
        resource: 'src/components/'
      });

      expect(typeof token).toBe('string');
      const verification = manager.verifyToken(token);
      expect(verification.valid).toBe(true);
      expect(verification.capability.aid).toBe('cursor-agent-01');
      expect(verification.capability.act).toBe('fs:write');
      expect(verification.capability.res).toBe('src/components/');
    });

    test('rejects capability tokens with tampered signatures', () => {
      const token = manager.issueCapability({
        agentId: 'agent-1',
        sessionId: 'session-1',
        actionType: 'fs:read',
        resource: 'src/'
      });

      const decoded = manager.decodeToken(token);
      decoded.res = 'etc/shadow'; // Attacker attempts to modify scope without resign
      const forgedToken = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64url');

      const verification = manager.verifyToken(forgedToken);
      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe('INVALID_CAPABILITY_SIGNATURE');
    });

    test('rejects expired capability tokens', async () => {
      const token = manager.issueCapability({
        agentId: 'agent-1',
        sessionId: 'session-1',
        actionType: 'fs:read',
        resource: 'src/',
        ttlMs: 50 // 50ms TTL
      });

      await new Promise(r => setTimeout(r, 60));

      const verification = manager.verifyToken(token);
      expect(verification.valid).toBe(false);
      expect(verification.reason).toBe('EXPIRED_CAPABILITY_TOKEN');
    });
  });

  describe('2. Action Authorization & Scope Bounds', () => {
    test('authorizes actions within the permitted resource scope', () => {
      const token = manager.issueCapability({
        agentId: 'developer-agent',
        sessionId: 'sess-123',
        actionType: 'fs:write',
        resource: 'src/utils/'
      });

      const safeAction = {
        agent_id: 'developer-agent',
        action_type: 'fs:write',
        resource: 'src/utils/math.js'
      };

      const result = manager.authorizeAction(token, safeAction);
      expect(result.allowed).toBe(true);
    });

    test('denies actions that exceed resource scope boundaries', () => {
      const token = manager.issueCapability({
        agentId: 'developer-agent',
        sessionId: 'sess-123',
        actionType: 'fs:write',
        resource: 'src/utils/'
      });

      const outOfScopeAction = {
        agent_id: 'developer-agent',
        action_type: 'fs:write',
        resource: 'src/auth/secrets.js'
      };

      const result = manager.authorizeAction(token, outOfScopeAction);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('RESOURCE_SCOPE_EXCEEDED');
    });

    test('denies actions with mismatched agent identity', () => {
      const token = manager.issueCapability({
        agentId: 'trusted-agent',
        sessionId: 'sess-123',
        actionType: 'fs:read',
        resource: 'src/'
      });

      const maliciousAction = {
        agent_id: 'rogue-agent',
        action_type: 'fs:read',
        resource: 'src/main.js'
      };

      const result = manager.authorizeAction(token, maliciousAction);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('AGENT_IDENTITY_MISMATCH');
    });
  });

  describe('3. Token Attenuation & Replay Defense', () => {
    test('attenuates a parent token into a narrower subpath capability', () => {
      const parentToken = manager.issueCapability({
        agentId: 'agent-1',
        sessionId: 'sess-1',
        actionType: 'fs:write',
        resource: 'src/'
      });

      const childToken = manager.attenuate(parentToken, {
        subResource: 'src/safe-zone/'
      });

      expect(manager.verifyToken(childToken).valid).toBe(true);

      // Child can touch sub-resource
      expect(manager.authorizeAction(childToken, {
        agent_id: 'agent-1',
        action_type: 'fs:write',
        resource: 'src/safe-zone/output.txt'
      }).allowed).toBe(true);

      // Child cannot touch parent resource outside sub-resource
      expect(manager.authorizeAction(childToken, {
        agent_id: 'agent-1',
        action_type: 'fs:write',
        resource: 'src/auth.js'
      }).allowed).toBe(false);
    });

    test('prevents replay when single-use nonce is consumed', () => {
      const token = manager.issueCapability({
        agentId: 'agent-1',
        sessionId: 'sess-1',
        actionType: 'fs:write',
        resource: 'src/'
      });

      // First consumption succeeds
      const firstCheck = manager.verifyToken(token, true);
      expect(firstCheck.valid).toBe(true);

      // Second consumption with same token fails replay check
      const secondCheck = manager.verifyToken(token, true);
      expect(secondCheck.valid).toBe(false);
      expect(secondCheck.reason).toBe('REPLAYED_CAPABILITY_NONCE');
    });
  });
});

