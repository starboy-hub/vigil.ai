/**
 * Sentinel Stage 6: Credentials & Capability Management Tests
 * ==========================================================
 * Verifies Capability Token issuance, cryptographic signing, expiration,
 * agent/session binding, secret brokering, and zero-exposure scrubbing.
 */

'use strict';

const {
  CapabilityTokenManager,
  SentinelSecretBroker,
  CAPABILITY_ERRORS
} = require('../src/sentinel/credentials/secret-broker');

describe('Sentinel Stage 6: Capability Tokens & Secret Brokering', () => {
  let tokenManager;
  let secretBroker;
  let auditEvents;

  const mockSigningKey = 'test-signing-key-0123456789abcdef0123456789abcdef';
  const mockRawApiKey = 'ghp_secrettoken9876543210zyxwvutsrqponmlkjihgfedcba';
  const mockStripeKey = 'sk-live-mockstripekey9876543210abcdef';

  beforeEach(() => {
    auditEvents = [];
    tokenManager = new CapabilityTokenManager({
      signingKey: mockSigningKey,
      defaultTtlSecs: 60
    });

    secretBroker = new SentinelSecretBroker({
      tokenManager,
      auditCallback: (event) => auditEvents.push(event)
    });

    // Register test secrets with narrow scopes
    secretBroker.registerSecret('github-api', mockRawApiKey, ['api.github.com:read', 'api.github.com:repos']);
    secretBroker.registerSecret('stripe-billing', mockStripeKey, ['api.stripe.com:charges:read']);
  });

  describe('1. Capability Token Minting & Cryptographic Validation', () => {
    test('mints a valid cryptographically signed capability token', () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-claude-01',
        sessionId: 'session-xyz',
        scopes: ['api.github.com:read'],
        ttlSecs: 120
      });

      expect(minted.tokenString).toBeDefined();
      expect(typeof minted.tokenString).toBe('string');
      expect(minted.tokenId).toMatch(/^cap-/);
      expect(minted.agentId).toBe('agent-claude-01');
      expect(minted.scopes).toEqual(['api.github.com:read']);

      // Validate the token
      const val = tokenManager.validateToken(minted.tokenString, 'api.github.com:read', {
        agentId: 'agent-claude-01',
        sessionId: 'session-xyz'
      });

      expect(val.valid).toBe(true);
      expect(val.token.tokenId).toBe(minted.tokenId);
    });

    test('rejects tampered capability token signature', () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-01',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      // Tamper with token payload
      const [payloadB64, sig] = minted.tokenString.split('.');
      const decoded = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
      decoded.scopes = ['*']; // Escalate to wildcard
      const tamperedB64 = Buffer.from(JSON.stringify(decoded)).toString('base64url');
      const tamperedToken = `${tamperedB64}.${sig}`;

      const val = tokenManager.validateToken(tamperedToken, 'api.github.com:read');
      expect(val.valid).toBe(false);
      expect(val.error).toBe(CAPABILITY_ERRORS.TOKEN_SIGNATURE_INVALID);
    });

    test('rejects expired capability token', () => {
      const fastManager = new CapabilityTokenManager({
        signingKey: mockSigningKey,
        defaultTtlSecs: -10 // expired in the past
      });

      const minted = fastManager.mintToken({
        agentId: 'agent-01',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      const val = fastManager.validateToken(minted.tokenString, 'api.github.com:read');
      expect(val.valid).toBe(false);
      expect(val.error).toBe(CAPABILITY_ERRORS.TOKEN_EXPIRED);
    });

    test('rejects token when agent ID or session ID does not match binding', () => {
      const minted = tokenManager.mintToken({
        agentId: 'legit-agent',
        sessionId: 'legit-session',
        scopes: ['api.github.com:read']
      });

      // Mismatched agent
      const res1 = tokenManager.validateToken(minted.tokenString, 'api.github.com:read', {
        agentId: 'imposter-agent',
        sessionId: 'legit-session'
      });
      expect(res1.valid).toBe(false);
      expect(res1.error).toBe(CAPABILITY_ERRORS.AGENT_MISMATCH);

      // Mismatched session
      const res2 = tokenManager.validateToken(minted.tokenString, 'api.github.com:read', {
        agentId: 'legit-agent',
        sessionId: 'stolen-session'
      });
      expect(res2.valid).toBe(false);
      expect(res2.error).toBe(CAPABILITY_ERRORS.SESSION_MISMATCH);
    });

    test('rejects token when requested scope is not authorized', () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-01',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      const res = tokenManager.validateToken(minted.tokenString, 'api.github.com:write');
      expect(res.valid).toBe(false);
      expect(res.error).toBe(CAPABILITY_ERRORS.INSUFFICIENT_SCOPE);
    });

    test('supports prefix wildcard scope matching', () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-01',
        sessionId: 'session-01',
        scopes: ['api.github.com:*']
      });

      const res1 = tokenManager.validateToken(minted.tokenString, 'api.github.com:read');
      expect(res1.valid).toBe(true);

      const res2 = tokenManager.validateToken(minted.tokenString, 'api.github.com:write');
      expect(res2.valid).toBe(true);

      const res3 = tokenManager.validateToken(minted.tokenString, 'api.stripe.com:read');
      expect(res3.valid).toBe(false);
    });

    test('revoked tokens are rejected immediately', () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-01',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      tokenManager.revokeToken(minted.tokenId);

      const val = tokenManager.validateToken(minted.tokenString, 'api.github.com:read');
      expect(val.valid).toBe(false);
      expect(val.error).toBe(CAPABILITY_ERRORS.TOKEN_REVOKED);
    });
  });

  describe('2. Secret Brokering & Boundary Injection', () => {
    test('injects secret at execution boundary and scrubs all return values', async () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-worker',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      let receivedSecretInDispatcher = null;

      const result = await secretBroker.executeBrokeredRequest({
        capabilityToken: minted.tokenString,
        requiredScope: 'api.github.com:read',
        secretId: 'github-api',
        callerContext: { agentId: 'agent-worker', sessionId: 'session-01' },
        dispatcher: async (secret) => {
          receivedSecretInDispatcher = secret;
          // Downstream service accidentally echoes or embeds the token in output
          return {
            status: 200,
            data: {
              repository: 'vigil.ai',
              reflected_auth: `Bearer ${secret}`,
              nested: [
                `Token used: ${secret}`,
                'Clean message'
              ]
            }
          };
        }
      });

      // Verify the dispatcher received the raw credential behind the boundary
      expect(receivedSecretInDispatcher).toBe(mockRawApiKey);

      // Verify the agent NEVER receives the raw credential in the returned result!
      expect(JSON.stringify(result)).not.toContain(mockRawApiKey);
      expect(result.data.reflected_auth).toContain('[REDACTED_BROKERED_SECRET]');
      expect(result.data.nested[0]).toContain('[REDACTED_BROKERED_SECRET]');
      expect(result.data.nested[1]).toBe('Clean message');

      // Verify audit event emitted without secret leakage
      const execEvent = auditEvents.find((e) => e.event_type === 'capability:executed');
      expect(execEvent).toBeDefined();
      expect(JSON.stringify(execEvent)).not.toContain(mockRawApiKey);
    });

    test('scrubs raw secret and stack traces if downstream dispatcher throws an error', async () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-worker',
        sessionId: 'session-01',
        scopes: ['api.stripe.com:charges:read']
      });

      const executePromise = secretBroker.executeBrokeredRequest({
        capabilityToken: minted.tokenString,
        requiredScope: 'api.stripe.com:charges:read',
        secretId: 'stripe-billing',
        callerContext: { agentId: 'agent-worker', sessionId: 'session-01' },
        dispatcher: async (secret) => {
          throw new Error(`Payment gateway failed with key: ${secret}`);
        }
      });

      await expect(executePromise).rejects.toThrow();

      try {
        await executePromise;
      } catch (err) {
        expect(err.message).not.toContain(mockStripeKey);
        expect(err.message).toContain('[REDACTED_BROKERED_SECRET]');
      }

      const failEvent = auditEvents.find((e) => e.event_type === 'capability:dispatch_failed');
      expect(failEvent).toBeDefined();
      expect(JSON.stringify(failEvent)).not.toContain(mockStripeKey);
    });

    test('rejects execution when capability token does not permit requested scope', async () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-worker',
        sessionId: 'session-01',
        scopes: ['api.github.com:read']
      });

      await expect(
        secretBroker.executeBrokeredRequest({
          capabilityToken: minted.tokenString,
          requiredScope: 'api.stripe.com:charges:read',
          secretId: 'stripe-billing',
          callerContext: { agentId: 'agent-worker', sessionId: 'session-01' },
          dispatcher: async () => 'ok'
        })
      ).rejects.toThrow(/Capability authorization failed: INSUFFICIENT_SCOPE/);
    });

    test('rejects execution when secretId does not exist', async () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-worker',
        sessionId: 'session-01',
        scopes: ['nonexistent:scope']
      });

      await expect(
        secretBroker.executeBrokeredRequest({
          capabilityToken: minted.tokenString,
          requiredScope: 'nonexistent:scope',
          secretId: 'nonexistent-secret',
          callerContext: { agentId: 'agent-worker', sessionId: 'session-01' },
          dispatcher: async () => 'ok'
        })
      ).rejects.toThrow(/Secret not found/);
    });
  });
});

