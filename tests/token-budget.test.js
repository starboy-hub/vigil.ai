/**
 * Unit tests for VIGIL Blueprint #18: Token Budget Enforcement for Agentic AI
 */
const { TokenBudgetManager, estimateTokens } = require('../src/background/token-budget.js');

describe('VIGIL Blueprint #18: Token Budget Enforcement', () => {

  describe('Token Estimation Heuristic', () => {
    test('returns 0 for empty or null inputs', () => {
      expect(estimateTokens('')).toBe(0);
      expect(estimateTokens(null)).toBe(0);
      expect(estimateTokens(undefined)).toBe(0);
    });

    test('estimates token count for short prompt', () => {
      const prompt = 'Please summarize the quarterly earnings report.';
      const tokens = estimateTokens(prompt);
      expect(tokens).toBeGreaterThan(5);
      expect(tokens).toBeLessThan(25);
    });

    test('estimates token count for structured JSON / code payload', () => {
      const payload = {
        action: 'execute_command',
        command: 'git status',
        files: ['src/main.rs', 'src/lib.rs', 'package.json']
      };
      const tokens = estimateTokens(payload);
      expect(tokens).toBeGreaterThan(15);
    });
  });

  describe('Session Token Budget Enforcement (Hard Block)', () => {
    let manager;

    beforeEach(() => {
      manager = new TokenBudgetManager({
        sessionLimit: 1000,
        dailyLimit: 5000,
        enforcementMode: 'hard_block',
        alertThreshold: 0.8
      });
    });

    test('allows requests within session quota', () => {
      const verdict = manager.recordUsage('agent-alpha', 400);
      expect(verdict.allowed).toBe(true);
      expect(verdict.hardBlocked).toBe(false);
      expect(verdict.sessionTokens).toBe(400);
      expect(verdict.sessionRemaining).toBe(600);
      expect(verdict.sessionPercentage).toBe(40);
    });

    test('triggers near-limit warning when crossing alert threshold (80%)', () => {
      const v1 = manager.recordUsage('agent-alpha', 700);
      expect(v1.nearLimitWarning).toBe(false);

      const v2 = manager.recordUsage('agent-alpha', 150); // total 850 / 1000 = 85%
      expect(v2.allowed).toBe(true);
      expect(v2.nearLimitWarning).toBe(true);
    });

    test('hard blocks when request exceeds session limit', () => {
      manager.recordUsage('agent-alpha', 800);
      const blocked = manager.recordUsage('agent-alpha', 300); // 800 + 300 = 1100 > 1000

      expect(blocked.allowed).toBe(false);
      expect(blocked.hardBlocked).toBe(true);
      expect(blocked.committed).toBe(false);
      expect(blocked.reason).toContain('Session token limit reached');

      // Account usage should remain at 800, not corrupted
      const status = manager.getStatus('agent-alpha');
      expect(status.account.sessionTokens).toBe(800);
      expect(status.account.blockedRequests).toBe(1);
    });

    test('session reset allows new requests to proceed', () => {
      manager.recordUsage('agent-alpha', 1000);
      const blocked = manager.recordUsage('agent-alpha', 50);
      expect(blocked.allowed).toBe(false);

      // Reset agent session
      const resetOk = manager.resetSession('agent-alpha');
      expect(resetOk).toBe(true);

      const statusAfter = manager.getStatus('agent-alpha');
      expect(statusAfter.account.sessionTokens).toBe(0);

      const nextReq = manager.recordUsage('agent-alpha', 500);
      expect(nextReq.allowed).toBe(true);
      expect(nextReq.sessionTokens).toBe(500);
    });
  });

  describe('24-Hour Rolling Daily Quota', () => {
    let manager;

    beforeEach(() => {
      manager = new TokenBudgetManager({
        sessionLimit: 5000,
        dailyLimit: 3000,
        enforcementMode: 'hard_block'
      });
    });

    test('blocks when cumulative daily consumption exceeds daily limit', () => {
      // Session 1: 2000 tokens
      manager.recordUsage('agent-daily', 2000);
      manager.resetSession('agent-daily');

      // Session 2: 1500 tokens (Daily total would be 3500 > 3000)
      const verdict = manager.recordUsage('agent-daily', 1500);
      expect(verdict.allowed).toBe(false);
      expect(verdict.hardBlocked).toBe(true);
      expect(verdict.reason).toContain('24h rolling daily token limit reached');
    });

    test('automatically resets daily token count after 24 hours rollover', () => {
      manager.recordUsage('agent-daily', 2500);

      const acc = manager._getOrCreateAccount('agent-daily');
      expect(acc.dailyTokens).toBe(2500);

      // Simulate 25 hours elapsed
      acc.lastResetTimestamp = Date.now() - (25 * 3600 * 1000);

      // Next check triggers automatic rollover
      const preflight = manager.checkBudget('agent-daily', 500);
      expect(preflight.dailyTokens).toBe(0);
      expect(preflight.allowed).toBe(true);
    });
  });

  describe('Soft Alert Telemetry Mode', () => {
    let manager;

    beforeEach(() => {
      manager = new TokenBudgetManager({
        sessionLimit: 1000,
        dailyLimit: 2000,
        enforcementMode: 'soft_alert'
      });
    });

    test('permits execution but flags soft alert when budget exceeded', () => {
      const v1 = manager.recordUsage('agent-soft', 900);
      expect(v1.allowed).toBe(true);
      expect(v1.softAlert).toBe(false);

      const v2 = manager.recordUsage('agent-soft', 500); // 1400 > 1000
      expect(v2.allowed).toBe(true);
      expect(v2.hardBlocked).toBe(false);
      expect(v2.softAlert).toBe(true);
      expect(v2.committed).toBe(true);
      expect(v2.sessionTokens).toBe(1400);

      const status = manager.getStatus('agent-soft');
      expect(status.account.alertsCount).toBeGreaterThan(0);
    });
  });

  describe('Pre-flight Budget Inspection', () => {
    test('checkBudget tests feasibility without committing tokens', () => {
      const manager = new TokenBudgetManager({ sessionLimit: 500, dailyLimit: 1000 });
      manager.recordUsage('agent-pre', 200);

      const check = manager.checkBudget('agent-pre', 400);
      expect(check.allowed).toBe(false);
      expect(check.hardBlocked).toBe(true);

      // Verify that actual account was NOT modified by checkBudget
      const status = manager.getStatus('agent-pre');
      expect(status.account.sessionTokens).toBe(200);
      expect(status.account.totalRequests).toBe(1);
    });
  });

  describe('Runaway Agent Loop Detection', () => {
    test('detects high-frequency runaway recursion loops', () => {
      const manager = new TokenBudgetManager({
        sessionLimit: 50000,
        dailyLimit: 100000,
        loopThresholdCount: 5,
        loopWindowMs: 2000,
        enforcementMode: 'hard_block'
      });

      // Send 4 rapid requests (under threshold)
      for (let i = 0; i < 4; i++) {
        const v = manager.recordUsage('agent-loop', 10);
        expect(v.isRunawayLoop).toBe(false);
        expect(v.allowed).toBe(true);
      }

      // 5th request in the same instant should trigger runaway loop block
      const burstVerdict = manager.recordUsage('agent-loop', 10);
      expect(burstVerdict.isRunawayLoop).toBe(true);
      expect(burstVerdict.hardBlocked).toBe(true);
      expect(burstVerdict.reason).toContain('Runaway API loop detected');
    });
  });

  describe('Multi-Agent Isolation & Limits Customization', () => {
    test('maintains separate independent balances for multiple agents', () => {
      const manager = new TokenBudgetManager({ sessionLimit: 1000, dailyLimit: 5000 });

      manager.recordUsage('agent-writer', 800);
      manager.recordUsage('agent-coder', 300);

      const writerStatus = manager.getStatus('agent-writer');
      const coderStatus = manager.getStatus('agent-coder');

      expect(writerStatus.account.sessionTokens).toBe(800);
      expect(coderStatus.account.sessionTokens).toBe(300);

      // Resetting writer does not affect coder
      manager.resetSession('agent-writer');
      expect(manager.getStatus('agent-writer').account.sessionTokens).toBe(0);
      expect(manager.getStatus('agent-coder').account.sessionTokens).toBe(300);
    });

    test('setLimits dynamically modifies active policy limits', () => {
      const manager = new TokenBudgetManager({ sessionLimit: 1000 });
      manager.recordUsage('agent-flex', 1200); // Exceeded 1000 -> blocked

      manager.setLimits({ sessionLimit: 5000, enforcementMode: 'soft_alert' });
      expect(manager.config.sessionLimit).toBe(5000);
      expect(manager.config.enforcementMode).toBe('soft_alert');

      const v = manager.recordUsage('agent-flex', 1200);
      expect(v.allowed).toBe(true);
    });
  });
});
