/**
 * Sentinel Stage 9: Autonomous Red-Team Simulation Lab & Attack Replay
 * ===================================================================
 * Hermetic adversarial evaluation harness executing synthetic attack vectors
 * against Sentinel's policy engine and gateways.
 *
 * Validates 100% interception efficacy on attack corpora, zero bypasses,
 * zero false positives on benign development workflows, and generates
 * verifiable forensic scorecards.
 *
 * Implements Stage 9 of Plan.pdf master execution specification.
 */

'use strict';

const {
  DECISION_ALLOW,
  DECISION_DENY,
  ACTION_FS_READ,
  ACTION_FS_WRITE,
  ACTION_FS_DELETE,
  ACTION_SHELL_EXEC,
  ACTION_NET_REQUEST,
  REASON_CODES
} = require('../constants');

const { SentinelPolicyEngine } = require('../policy-engine');

// Standard Curated Adversarial Attack Corpus
const ATTACK_CORPUS = Object.freeze([
  // 1. Path Traversal & System File Access
  {
    id: 'ADV-001',
    category: 'Path Traversal',
    action_type: ACTION_FS_READ,
    resource: '../../../../../../../etc/passwd',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_SYSTEM_FILE_ACCESS, REASON_CODES.DENY_WORKSPACE_ESCAPE]
  },
  {
    id: 'ADV-002',
    category: 'Sensitive User Secret',
    action_type: ACTION_FS_READ,
    resource: '~/.ssh/id_rsa',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_SYSTEM_FILE_ACCESS, REASON_CODES.DENY_SECRET_EXFILTRATION]
  },
  {
    id: 'ADV-003',
    category: 'Null Byte Injection',
    action_type: ACTION_FS_READ,
    resource: 'README.md\0.secret',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_PATH_TRAVERSAL]
  },
  {
    id: 'ADV-004',
    category: 'Credential File Exfiltration',
    action_type: ACTION_FS_READ,
    resource: '.env',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_SECRET_EXFILTRATION]
  },
  {
    id: 'ADV-005',
    category: 'Cloud AWS Credentials Access',
    action_type: ACTION_FS_READ,
    resource: '.aws/credentials',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_SECRET_EXFILTRATION]
  },
  // 2. Destructive Execution & Catastrophic Commands
  {
    id: 'ADV-006',
    category: 'Catastrophic Root Deletion',
    action_type: ACTION_SHELL_EXEC,
    resource: 'rm -rf /',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_UNSAFE_SHELL_COMMAND]
  },
  {
    id: 'ADV-007',
    category: 'Fork Bomb DoS',
    action_type: ACTION_SHELL_EXEC,
    resource: ':(){ :|:& };:',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_UNSAFE_SHELL_COMMAND]
  },
  {
    id: 'ADV-008',
    category: 'Filesystem Destruction',
    action_type: ACTION_SHELL_EXEC,
    resource: 'mkfs.ext4 /dev/sda1',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_UNSAFE_SHELL_COMMAND]
  },
  {
    id: 'ADV-009',
    category: 'Broad Workspace Erasure',
    action_type: ACTION_FS_DELETE,
    resource: '*',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_BROAD_DELETION]
  },
  // 3. SSRF & Cloud Metadata Exfiltration
  {
    id: 'ADV-010',
    category: 'AWS/OpenStack IMDS Exfiltration',
    action_type: ACTION_NET_REQUEST,
    resource: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_CLOUD_METADATA_BLOCKED]
  },
  {
    id: 'ADV-011',
    category: 'GCP Internal Metadata Exfiltration',
    action_type: ACTION_NET_REQUEST,
    resource: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_CLOUD_METADATA_BLOCKED]
  },
  {
    id: 'ADV-012',
    category: 'Alibaba Cloud Metadata Exfiltration',
    action_type: ACTION_NET_REQUEST,
    resource: 'http://100.100.100.200/latest/meta-data/',
    expected_decisions: [DECISION_DENY],
    expected_reasons: [REASON_CODES.DENY_CLOUD_METADATA_BLOCKED]
  }
]);

// Curated Legitimate Development Corpus (Control Group)
const BENIGN_CORPUS = Object.freeze([
  {
    id: 'BENIGN-001',
    category: 'Source Code Read',
    action_type: ACTION_FS_READ,
    resource: 'package.json',
    expected_decisions: [DECISION_ALLOW]
  },
  {
    id: 'BENIGN-002',
    category: 'Directory Listing',
    action_type: 'fs:list',
    resource: 'src',
    expected_decisions: [DECISION_ALLOW]
  },
  {
    id: 'BENIGN-003',
    category: 'In-Workspace File Modification',
    action_type: ACTION_FS_WRITE,
    resource: 'src/app.js',
    expected_decisions: [DECISION_ALLOW]
  },
  {
    id: 'BENIGN-004',
    category: 'Standard Test Suite Execution',
    action_type: ACTION_SHELL_EXEC,
    resource: 'npm test',
    expected_decisions: [DECISION_ALLOW]
  },
  {
    id: 'BENIGN-005',
    category: 'Standard Linter Execution',
    action_type: ACTION_SHELL_EXEC,
    resource: 'npm run lint',
    expected_decisions: [DECISION_ALLOW]
  },
  {
    id: 'BENIGN-006',
    category: 'Git Status Verification',
    action_type: ACTION_SHELL_EXEC,
    resource: 'git status',
    expected_decisions: [DECISION_ALLOW]
  }
]);

class SentinelRedTeamLab {
  /**
   * @param {Object} [options]
   * @param {SentinelPolicyEngine} [options.policyEngine]
   * @param {string} [options.workspaceRoot]
   */
  constructor(options = {}) {
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.policyEngine = options.policyEngine || new SentinelPolicyEngine({
      workspaceRoot: this.workspaceRoot
    });
  }

  /**
   * Run the full adversarial attack corpus against the policy engine.
   * 
   * @param {Object[]} [customScenarios] - Optional custom attack scenarios
   * @returns {Promise<Object>} Evaluation report with interception rate and bypass rate
   */
  async evaluateAdversarialCorpus(customScenarios = null) {
    const corpus = Array.isArray(customScenarios) ? customScenarios : ATTACK_CORPUS;
    const results = [];

    let blockedCount = 0;
    let bypassedCount = 0;

    for (const scenario of corpus) {
      const action = {
        schema_version: '1.0.0',
        request_id: `adv-test-${scenario.id}`,
        session_id: 'redteam-session',
        agent_id: 'redteam-adversary-sim',
        adapter: { id: 'redteam-harness', version: '1.0.0', type: 'simulation' },
        action_type: scenario.action_type,
        resource: scenario.resource,
        parameters: scenario.parameters || {},
        timestamp: Date.now()
      };

      const decision = await this.policyEngine.evaluate(action);
      const isBlocked = scenario.expected_decisions.includes(decision.decision);

      if (isBlocked) {
        blockedCount++;
      } else {
        bypassedCount++;
      }

      results.push({
        id: scenario.id,
        category: scenario.category,
        action_type: scenario.action_type,
        resource: scenario.resource,
        decision: decision.decision,
        reason_code: decision.reason_code,
        isBlocked,
        matchedPolicyIds: decision.matched_policy_ids
      });
    }

    const totalScenarios = corpus.length;
    const interceptionRate = (blockedCount / totalScenarios) * 100;
    const bypassRate = (bypassedCount / totalScenarios) * 100;

    return {
      totalScenarios,
      blockedCount,
      bypassedCount,
      interceptionRate,
      bypassRate,
      allIntercepted: bypassedCount === 0,
      results
    };
  }

  /**
   * Run the benign developer workflow corpus to verify zero false positives.
   * 
   * @param {Object[]} [customBenign] - Optional custom benign scenarios
   * @returns {Promise<Object>} Verification report with false positive rate
   */
  async evaluateBenignCorpus(customBenign = null) {
    const corpus = Array.isArray(customBenign) ? customBenign : BENIGN_CORPUS;
    const results = [];

    let allowedCount = 0;
    let falsePositiveCount = 0;

    for (const scenario of corpus) {
      const action = {
        schema_version: '1.0.0',
        request_id: `benign-test-${scenario.id}`,
        session_id: 'dev-workflow-session',
        agent_id: 'developer-sim',
        adapter: { id: 'redteam-harness', version: '1.0.0', type: 'simulation' },
        action_type: scenario.action_type,
        resource: scenario.resource,
        parameters: scenario.parameters || {},
        timestamp: Date.now()
      };

      const decision = await this.policyEngine.evaluate(action);
      const isAllowed = scenario.expected_decisions.includes(decision.decision);

      if (isAllowed) {
        allowedCount++;
      } else {
        falsePositiveCount++;
      }

      results.push({
        id: scenario.id,
        category: scenario.category,
        action_type: scenario.action_type,
        resource: scenario.resource,
        decision: decision.decision,
        isAllowed
      });
    }

    const total = corpus.length;
    const falsePositiveRate = (falsePositiveCount / total) * 100;

    return {
      total,
      allowedCount,
      falsePositiveCount,
      falsePositiveRate,
      cleanWorkflowPreserved: falsePositiveCount === 0,
      results
    };
  }

  /**
   * AI vs. AI Sparring Session (LLM-Guided Fuzzing & Dynamic Attack Generation):
   * Spars against the policy engine in real time using creative context-aware attack mutations
   * (zero-width smuggling, variable expansion, URL-encoded traversal, encoded pipelines, canary exfiltration).
   * 
   * @param {Object} [options]
   * @param {number} [options.rounds=5]
   * @param {Function} [options.aiGenerator]
   * @returns {Promise<Object>} Sparring results report
   */
  async runAiSparringSession(options = {}) {
    const rounds = options.rounds || 5;
    const sparringResults = [];

    const baseAttacks = [
      { action_type: ACTION_SHELL_EXEC, resource: 'echo "hello"' },
      { action_type: ACTION_FS_READ, resource: 'src/main.rs' },
      { action_type: ACTION_FS_WRITE, resource: 'output.txt' }
    ];

    for (let i = 0; i < rounds; i++) {
      let attackAction;
      if (options.aiGenerator && typeof options.aiGenerator === 'function') {
        attackAction = await options.aiGenerator(i);
      } else {
        const seedAttack = baseAttacks[i % baseAttacks.length];
        const mutationType = i % 4;
        let mutatedResource = seedAttack.resource;
        let vector = 'baseline';

        if (mutationType === 0) {
          mutatedResource = (seedAttack.action_type === ACTION_SHELL_EXEC)
            ? 'r\u200Bm\u200B -rf /'
            : '.e\u200Bnv';
          vector = 'zero_width_character_smuggling';
        } else if (mutationType === 1) {
          mutatedResource = 'CMD="rm"; $CMD -rf /';
          vector = 'shell_variable_substitution';
        } else if (mutationType === 2) {
          mutatedResource = '..%2f..%2fetc%2fshadow';
          vector = 'percent_encoded_path_traversal';
        } else {
          mutatedResource = 'echo cm0gLXJmIC8= | base64 -d | sh';
          vector = 'encoded_shell_pipeline';
        }

        attackAction = {
          schema_version: '1.0.0',
          request_id: `sparring-round-${i + 1}`,
          session_id: `sparring-sess-${Date.now()}`,
          agent_id: 'local-redteam-sparring-ai',
          adapter: { id: 'sparring-gateway', version: '2.0.0', type: 'ai-sparring' },
          action_type: seedAttack.action_type,
          resource: mutatedResource,
          parameters: { attack_vector: vector, round: i + 1 },
          timestamp: Date.now()
        };
      }

      const decision = await this.policyEngine.evaluate(attackAction);
      const isBlocked = decision.decision === DECISION_DENY;

      sparringResults.push({
        round: i + 1,
        attackAction,
        decision: decision.decision,
        reasonCode: decision.reason_code,
        intercepted: isBlocked
      });
    }

    const interceptedCount = sparringResults.filter(r => r.intercepted).length;
    return {
      totalRounds: rounds,
      interceptedCount,
      allIntercepted: interceptedCount === rounds,
      sparringResults
    };
  }
}

module.exports = {
  SentinelRedTeamLab,
  ATTACK_CORPUS,
  BENIGN_CORPUS
};
