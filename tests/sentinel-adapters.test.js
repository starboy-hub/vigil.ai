/**
 * Sentinel Stage 10: Expanded Adapters Tests (CLI Shim & REST Proxy)
 * =================================================================
 * Verifies secondary enforcement points:
 * 1. CLI Shim: Command-line interception, exit codes, destructive command blocking.
 * 2. REST Proxy: Outbound HTTP interception, IMDS blocking, capability brokering.
 */

'use strict';

const path = require('path');
const {
  SentinelCliShim,
  EXIT_CODE_POLICY_DENIED,
  EXIT_CODE_SUCCESS
} = require('../src/sentinel/gateway/cli-shim');

const { SentinelRestProxy } = require('../src/sentinel/gateway/rest-proxy');
const { SentinelPolicyEngine } = require('../src/sentinel/policy-engine');
const {
  CapabilityTokenManager,
  SentinelSecretBroker
} = require('../src/sentinel/credentials/secret-broker');

const {
  PROFILE_BALANCED,
  REASON_CODES
} = require('../src/sentinel/constants');

describe('Sentinel Stage 10: Adapter Expansion (CLI Shim & REST Proxy)', () => {
  const workspaceRoot = path.resolve(__dirname, '..');
  let policyEngine;
  let mockSpawn;
  let cliShim;

  let tokenManager;
  let secretBroker;
  let mockForwardHandler;
  let restProxy;

  beforeEach(() => {
    policyEngine = new SentinelPolicyEngine({
      workspaceRoot,
      activeProfile: PROFILE_BALANCED
    });

    mockSpawn = jest.fn(async (cmd) => ({
      exitCode: 0,
      stdout: `Output for: ${cmd}`,
      stderr: ''
    }));

    cliShim = new SentinelCliShim({
      workspaceRoot,
      policyEngine,
      spawnFunction: mockSpawn
    });

    tokenManager = new CapabilityTokenManager({ defaultTtlSecs: 300 });
    secretBroker = new SentinelSecretBroker({ tokenManager });
    secretBroker.registerSecret('github-key', 'ghp_mocksupersecrettoken1234567890abcdef', ['api.github.com:read']);

    mockForwardHandler = jest.fn(async (url, method, headers) => ({
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: {
        url,
        method,
        reflected_auth: headers.authorization || 'none'
      }
    }));

    restProxy = new SentinelRestProxy({
      policyEngine,
      secretBroker,
      forwardHandler: mockForwardHandler
    });
  });

  describe('1. CLI Shim Enforcement Adapter', () => {
    test('allows safe allowlisted command (npm test) and invokes spawnFunction', async () => {
      const res = await cliShim.execute('npm test');

      expect(res.exitCode).toBe(EXIT_CODE_SUCCESS);
      expect(res.stdout).toContain('Output for: npm test');
      expect(mockSpawn).toHaveBeenCalledTimes(1);
      expect(mockSpawn).toHaveBeenCalledWith('npm test', expect.any(Object));
      expect(res.decision.decision).toBe('allow');
    });

    test('dry-run checkPolicy inspects command without executing spawn', async () => {
      const decision = await cliShim.checkPolicy('git status');
      expect(decision.decision).toBe('allow');
      expect(mockSpawn).not.toHaveBeenCalled();
    });

    test('blocks destructive shell commands (rm -rf /) with exit code 126 and never spawns', async () => {
      const res = await cliShim.execute('rm -rf /');

      expect(res.exitCode).toBe(EXIT_CODE_POLICY_DENIED);
      expect(res.stderr).toContain('[SENTINEL_POLICY_DENIED]');
      expect(res.stderr).toContain(REASON_CODES.DENY_UNSAFE_SHELL_COMMAND);
      expect(mockSpawn).not.toHaveBeenCalled();
    });

    test('blocks fork bomb with exit code 126', async () => {
      const res = await cliShim.execute(':(){ :|:& };:');

      expect(res.exitCode).toBe(EXIT_CODE_POLICY_DENIED);
      expect(mockSpawn).not.toHaveBeenCalled();
    });

    test('requires approval for unknown or non-allowlisted shell commands', async () => {
      const res = await cliShim.execute('python custom_worker.py');

      expect(res.exitCode).toBe(EXIT_CODE_POLICY_DENIED);
      expect(res.stderr).toContain('[SENTINEL_REQUIRE_APPROVAL]');
      expect(mockSpawn).not.toHaveBeenCalled();
    });
  });

  describe('2. REST / HTTP Proxy Enforcement Adapter', () => {
    test('blocks cloud metadata endpoint requests with HTTP 403', async () => {
      const req = {
        url: 'http://169.254.169.254/latest/meta-data/credentials',
        method: 'GET'
      };

      const res = await restProxy.handleRequest(req);

      expect(res.statusCode).toBe(403);
      expect(res.body.error).toBe('SENTINEL_POLICY_DENIED');
      expect(res.body.reason_code).toBe(REASON_CODES.DENY_CLOUD_METADATA_BLOCKED);
      expect(mockForwardHandler).not.toHaveBeenCalled();
    });

    test('forwards permitted requests and injects brokered credential via capability token', async () => {
      const minted = tokenManager.mintToken({
        agentId: 'agent-bot',
        sessionId: 'session-101',
        scopes: ['api.github.com:read']
      });

      const req = {
        url: 'https://api.github.com/repos/org/repo',
        method: 'GET',
        headers: {
          'x-sentinel-capability-token': minted.tokenString,
          'x-sentinel-secret-id': 'github-key',
          'x-sentinel-required-scope': 'api.github.com:read',
          'x-sentinel-agent-id': 'agent-bot',
          'x-sentinel-session-id': 'session-101'
        }
      };

      const res = await restProxy.handleRequest(req);

      expect(res.statusCode).toBe(200);
      expect(mockForwardHandler).toHaveBeenCalledTimes(1);

      // Verify the downstream service received the injected credential
      const calledHeaders = mockForwardHandler.mock.calls[0][2];
      expect(calledHeaders.authorization).toBe('Bearer ghp_mocksupersecrettoken1234567890abcdef');

      // Verify the returned body to the agent has the credential scrubbed!
      expect(JSON.stringify(res.body)).not.toContain('ghp_mocksupersecrettoken1234567890abcdef');
      expect(res.body.reflected_auth).toContain('[REDACTED_BROKERED_SECRET]');
    });

    test('rejects request with invalid capability token with HTTP 401', async () => {
      const req = {
        url: 'https://api.github.com/user',
        method: 'GET',
        headers: {
          'x-sentinel-capability-token': 'invalid.tampered.token',
          'x-sentinel-secret-id': 'github-key'
        }
      };

      const res = await restProxy.handleRequest(req);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toBe('BROKER_AUTHORIZATION_FAILED');
      expect(mockForwardHandler).not.toHaveBeenCalled();
    });

    test('rejects malformed requests missing URL with HTTP 400', async () => {
      const res = await restProxy.handleRequest({});
      expect(res.statusCode).toBe(400);
      expect(res.body.error).toBe('BAD_REQUEST');
    });
  });
});
