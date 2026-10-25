/**
 * Sentinel Stage 9: Autonomous Red-Team Lab & Safe Replay Tests
 * =============================================================
 * Executes full adversarial attack suites and benign control workflows
 * through the hermetic simulation lab.
 *
 * Verifies 100% interception efficacy, 0% bypass rate, and 0% false positives.
 */

'use strict';

const path = require('path');
const {
  SentinelRedTeamLab,
  ATTACK_CORPUS,
  BENIGN_CORPUS
} = require('../src/sentinel/redteam/simulation-lab');

const { SentinelPolicyEngine } = require('../src/sentinel/policy-engine');
const { PROFILE_BALANCED, DECISION_DENY } = require('../src/sentinel/constants');

describe('Sentinel Stage 9: Autonomous Red-Team Simulation Lab', () => {
  const workspaceRoot = path.resolve(__dirname, '..');
  let lab;
  let policyEngine;

  beforeEach(() => {
    policyEngine = new SentinelPolicyEngine({
      workspaceRoot,
      activeProfile: PROFILE_BALANCED
    });

    lab = new SentinelRedTeamLab({
      workspaceRoot,
      policyEngine
    });
  });

  describe('1. Adversarial Attack Corpus Replay', () => {
    test('intercepts 100% of adversarial attack scenarios with 0% bypass rate', async () => {
      const report = await lab.evaluateAdversarialCorpus();

      expect(report.totalScenarios).toBe(ATTACK_CORPUS.length);
      expect(report.blockedCount).toBe(ATTACK_CORPUS.length);
      expect(report.bypassedCount).toBe(0);
      expect(report.interceptionRate).toBe(100);
      expect(report.bypassRate).toBe(0);
      expect(report.allIntercepted).toBe(true);

      // Verify each individual scenario was safely blocked
      for (const res of report.results) {
        expect(res.isBlocked).toBe(true);
        expect(res.decision).toBe(DECISION_DENY);
        expect(res.reason_code).toBeDefined();
      }
    });

    test('intercepts custom obfuscated attack vectors', async () => {
      const customAttacks = [
        {
          id: 'CUSTOM-001',
          category: 'Obfuscated Path Traversal',
          action_type: 'fs:read',
          resource: 'src/../../../../../../../etc/shadow',
          expected_decisions: ['deny']
        },
        {
          id: 'CUSTOM-002',
          category: 'Chained Shell Bomb',
          action_type: 'shell:exec',
          resource: 'echo hi && rm -rf / && echo bye',
          expected_decisions: ['deny']
        },
        {
          id: 'CUSTOM-003',
          category: 'Private SSH Ed25519 Key',
          action_type: 'fs:read',
          resource: '~/.ssh/id_ed25519',
          expected_decisions: ['deny']
        }
      ];

      const report = await lab.evaluateAdversarialCorpus(customAttacks);
      expect(report.blockedCount).toBe(3);
      expect(report.bypassedCount).toBe(0);
      expect(report.allIntercepted).toBe(true);
    });
  });

  describe('2. Benign Developer Workflow Control Group', () => {
    test('preserves 100% of clean development workflows with 0% false positive rate', async () => {
      const report = await lab.evaluateBenignCorpus();

      expect(report.total).toBe(BENIGN_CORPUS.length);
      expect(report.allowedCount).toBe(BENIGN_CORPUS.length);
      expect(report.falsePositiveCount).toBe(0);
      expect(report.falsePositiveRate).toBe(0);
      expect(report.cleanWorkflowPreserved).toBe(true);

      for (const res of report.results) {
        expect(res.isAllowed).toBe(true);
        expect(res.decision).toBe('allow');
      }
    });
  });
});

