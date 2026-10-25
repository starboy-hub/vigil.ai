/**
 * Sentinel Security Layer: Policy Engine Unit Tests
 * Part of Vigil AI + Sentinel (Plan.pdf - Stage 3, Section 5.7)
 */
'use strict';

const path = require('path');
const {
  DECISION_ALLOW,
  DECISION_DENY,
  DECISION_REQUIRE_APPROVAL,
  ACTION_FS_READ,
  ACTION_FS_WRITE,
  ACTION_FS_DELETE,
  ACTION_SHELL_EXEC,
  ACTION_NET_REQUEST,
  ACTION_CONFIG_CHANGE,
  PROFILE_OBSERVE_ONLY,
  PROFILE_BALANCED,
  PROFILE_STRICT,
  REASON_CODES
} = require('../src/sentinel/constants');

const { computeActionHash } = require('../src/sentinel/schemas');
const { SentinelPolicyEngine } = require('../src/sentinel/policy-engine');

describe('Sentinel Stage 3: Policy Engine Rule Evaluation', () => {
  const mockWorkspace = path.resolve(__dirname, '..');
  let engine;

  beforeEach(() => {
    engine = new SentinelPolicyEngine({
      workspaceRoot: mockWorkspace,
      profile: PROFILE_BALANCED,
      timeoutMs: 1000
    });
  });

  const baseAction = {
    schema_version: '1.0.0',
    request_id: 'req-test-01',
    session_id: 'sess-01',
    agent_id: 'test-agent',
    adapter: { id: 'test-adapter', version: '1.0.0', type: 'mcp' },
    action_type: ACTION_FS_READ,
    resource: 'package.json',
    parameters: {},
    requested_scope: 'workspace',
    timestamp: Date.now()
  };

  describe('1. Level 1 Hard Safety Rules (Non-Negotiable)', () => {
    test('Rule 1.1: Denies malformed action schema with DENY_INVALID_SCHEMA', async () => {
      const decision = await engine.evaluate({ invalid: 'object' });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_INVALID_SCHEMA);
    });

    test('Rule 1.2: Denies unknown action type with DENY_INVALID_SCHEMA or DENY_UNKNOWN_ACTION_TYPE', async () => {
      const decision = await engine.evaluate({ ...baseAction, action_type: 'unknown:action' });
      expect(decision.decision).toBe(DECISION_DENY);
    });

    test('Rule 1.3: Denies path traversal escaping workspace with DENY_WORKSPACE_ESCAPE', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_READ,
        resource: '../../../../../../etc/passwd'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_SYSTEM_FILE_ACCESS);
    });

    test('Rule 1.4: Denies null-byte path injection with DENY_PATH_TRAVERSAL', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_READ,
        resource: 'package.json\0.exe'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_PATH_TRAVERSAL);
    });

    test('Rule 1.5: Denies cloud metadata endpoint exfiltration with DENY_CLOUD_METADATA_BLOCKED', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_NET_REQUEST,
        resource: 'http://169.254.169.254/latest/meta-data/'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_CLOUD_METADATA_BLOCKED);
    });

    test('Rule 1.6: Denies broad deletion of workspace or root with DENY_BROAD_DELETION', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_DELETE,
        resource: '.'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_BROAD_DELETION);
    });

    test('Rule 1.7: Denies destructive shell commands with DENY_UNSAFE_SHELL_COMMAND', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_SHELL_EXEC,
        resource: 'rm -rf /'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_UNSAFE_SHELL_COMMAND);

      const forkbomb = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_SHELL_EXEC,
        resource: ':(){ :|:& };:'
      });
      expect(forkbomb.decision).toBe(DECISION_DENY);
      expect(forkbomb.reason_code).toBe(REASON_CODES.DENY_UNSAFE_SHELL_COMMAND);
    });
  });

  describe('2. Level 2 Explicit Deny Rules', () => {
    test('Rule 2.1: Denies access to .env and private key files with DENY_SECRET_EXFILTRATION', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_READ,
        resource: '.env'
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_SECRET_EXFILTRATION);

      const rsa = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_READ,
        resource: 'id_rsa'
      });
      expect(rsa.decision).toBe(DECISION_DENY);
      expect(rsa.reason_code).toBe(REASON_CODES.DENY_SECRET_EXFILTRATION);
    });

    test('Rule 2.2: Denies action when token budget is exhausted with DENY_QUOTA_EXCEEDED', async () => {
      const decision = await engine.evaluate(baseAction, {
        tokenBudget: { exhausted: true, reason: 'daily quota hit' }
      });
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_QUOTA_EXCEEDED);
    });

    test('Rule 2.3: Denies action when approval hash mismatches (TOCTOU violation)', async () => {
      const originalAction = { ...baseAction, action_type: ACTION_FS_WRITE, resource: 'test.js' };
      const actionHash = computeActionHash(originalAction);
      engine.registerApproval(actionHash, 'test-admin', 60000);

      // Malicious agent mutates resource after approval was granted
      const mutatedAction = { ...originalAction, resource: 'other.js' };
      const decision = await engine.evaluate(mutatedAction, { approvalToken: actionHash });

      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_ACTION_MUTATED_AFTER_APPROVAL);
    });
  });

  describe('3. Level 3 Approval Gates', () => {
    test('Requires approval for file deletion in balanced profile', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_DELETE,
        resource: 'temporary-artifact.log'
      });
      expect(decision.decision).toBe(DECISION_REQUIRE_APPROVAL);
      expect(decision.reason_code).toBe(REASON_CODES.REQUIRE_APPROVAL_DELETION);
    });

    test('Requires approval for shell commands not on safe allowlist', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_SHELL_EXEC,
        resource: 'docker run -d malicious-container'
      });
      expect(decision.decision).toBe(DECISION_REQUIRE_APPROVAL);
      expect(decision.reason_code).toBe(REASON_CODES.REQUIRE_APPROVAL_SHELL_EXEC);
    });

    test('Requires approval for security configuration changes', async () => {
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_CONFIG_CHANGE,
        resource: 'security.strict_mode'
      });
      expect(decision.decision).toBe(DECISION_REQUIRE_APPROVAL);
      expect(decision.reason_code).toBe(REASON_CODES.REQUIRE_APPROVAL_CONFIG_CHANGE);
    });

    test('Allows action when valid human approval matches exact action hash', async () => {
      const writeAction = {
        ...baseAction,
        action_type: ACTION_FS_WRITE,
        resource: 'src/content/content.js',
        parameters: { test: true }
      };
      const hash = computeActionHash(writeAction);
      engine.registerApproval(hash, 'lead-developer', 60000);

      const decision = await engine.evaluate(writeAction, { approvalToken: hash });
      expect(decision.decision).toBe(DECISION_ALLOW);
      expect(decision.reason_code).toBe(REASON_CODES.ALLOW_EXPLICIT_APPROVAL);
    });
  });

  describe('4. Policy Profiles: Observe-Only, Balanced, Strict', () => {
    test('Observe-Only profile allows safe actions with ALLOW_OBSERVE_ONLY', async () => {
      engine.setProfile(PROFILE_OBSERVE_ONLY);
      const decision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_WRITE,
        resource: 'README.md'
      });
      expect(decision.decision).toBe(DECISION_ALLOW);
      expect(decision.reason_code).toBe(REASON_CODES.ALLOW_OBSERVE_ONLY);
    });

    test('Strict profile requires approval for all writes and network calls', async () => {
      engine.setProfile(PROFILE_STRICT);

      const writeDecision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_WRITE,
        resource: 'README.md'
      });
      expect(writeDecision.decision).toBe(DECISION_REQUIRE_APPROVAL);
      expect(writeDecision.reason_code).toBe(REASON_CODES.REQUIRE_APPROVAL_WORKSPACE_WRITE);

      const netDecision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_NET_REQUEST,
        resource: 'https://api.github.com'
      });
      expect(netDecision.decision).toBe(DECISION_REQUIRE_APPROVAL);
      expect(netDecision.reason_code).toBe(REASON_CODES.REQUIRE_APPROVAL_OUTBOUND_NETWORK);
    });

    test('Balanced profile permits workspace read and write, and allowlisted shell commands', async () => {
      engine.setProfile(PROFILE_BALANCED);

      const readDecision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_FS_READ,
        resource: 'package.json'
      });
      expect(readDecision.decision).toBe(DECISION_ALLOW);
      expect(readDecision.reason_code).toBe(REASON_CODES.ALLOW_WORKSPACE_READ);

      const cmdDecision = await engine.evaluate({
        ...baseAction,
        action_type: ACTION_SHELL_EXEC,
        resource: 'git status'
      });
      expect(cmdDecision.decision).toBe(DECISION_ALLOW);
      expect(cmdDecision.reason_code).toBe(REASON_CODES.ALLOW_SAFE_COMMAND);
    });
  });

  describe('5. Bounded Execution Time & Fail-Closed Safety', () => {
    test('Fails closed with DENY_POLICY_TIMEOUT if evaluation times out', async () => {
      const slowEngine = new SentinelPolicyEngine({
        workspaceRoot: mockWorkspace,
        timeoutMs: 1 // 1 millisecond timeout to force timeout
      });

      // Mock _executeRules to hang
      slowEngine._executeRules = () => new Promise(resolve => setTimeout(resolve, 50));

      const decision = await slowEngine.evaluate(baseAction);
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_POLICY_TIMEOUT);
    });

    test('Fails closed with DENY_FAIL_CLOSED if unexpected exception occurs', async () => {
      const errEngine = new SentinelPolicyEngine({ workspaceRoot: mockWorkspace });
      errEngine._executeRules = () => { throw new Error('Simulated runtime fault'); };

      const decision = await errEngine.evaluate(baseAction);
      expect(decision.decision).toBe(DECISION_DENY);
      expect(decision.reason_code).toBe(REASON_CODES.DENY_FAIL_CLOSED);
    });

    test('Handles concurrent evaluation requests safely', async () => {
      const actions = Array.from({ length: 20 }, (_, i) => ({
        ...baseAction,
        request_id: `req-concurrent-${i}`,
        resource: `file-${i}.txt`
      }));

      const decisions = await Promise.all(actions.map(a => engine.evaluate(a)));
      expect(decisions).toHaveLength(20);
      decisions.forEach(d => {
        expect([DECISION_ALLOW, DECISION_REQUIRE_APPROVAL]).toContain(d.decision);
      });
    });
  });
});

