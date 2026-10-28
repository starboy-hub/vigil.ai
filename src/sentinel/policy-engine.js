/**
 * Sentinel Security Layer: Policy Engine
 * Part of Vigil AI + Sentinel (Plan.pdf - Stage 3)
 *
 * Pure, deterministic decision engine for AI agent tool invocations.
 * Evaluates actions against versioned rules and returns:
 * - 'allow'
 * - 'deny'
 * - 'require_approval'
 *
 * NON-NEGOTIABLE PRINCIPLE:
 * The policy engine is strictly a decision component. It NEVER executes shell
 * commands, writes files, makes network requests, or produces side effects.
 */
'use strict';

const crypto = require('crypto');
const {
  DECISION_ALLOW,
  DECISION_DENY,
  DECISION_REQUIRE_APPROVAL,
  ACTION_FS_READ,
  ACTION_FS_WRITE,
  ACTION_FS_DELETE,
  ACTION_FS_LIST,
  ACTION_SHELL_EXEC,
  ACTION_NET_REQUEST,
  ACTION_CONFIG_CHANGE,
  PROFILE_OBSERVE_ONLY,
  PROFILE_BALANCED,
  PROFILE_STRICT,
  VALID_PROFILES,
  REASON_CODES
} = require('./constants');

const {
  CURRENT_SCHEMA_VERSION,
  validateActionSchema,
  computeActionHash,
  scrubSecretsFromExplanation
} = require('./schemas');

const {
  normalizeFilesystemPath,
  normalizeNetworkDestination
} = require('./normalizer');

const { AttackChainDetector } = require('./correlation/attack-chain-detector');
const { ShellAstAnalyzer } = require('./gateway/shell-ast-analyzer');

const DEFAULT_TIMEOUT_MS = 2500;
const ENGINE_POLICY_VERSION = '1.0.0';

// Known destructive shell command patterns (regexes)
const DESTRUCTIVE_SHELL_PATTERNS = [
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|--recursive)\s+(\/|\*|~\/|\$HOME)/i,
  /\b(mkfs|dd\s+if=|fdisk|parted)\b/i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // Forkbomb
  /\bcurl\b.*\|\s*(ba)?sh\b/i,                 // Piping unverified remote scripts to shell
  /\bwget\b.*\|\s*(ba)?sh\b/i,
  /\bchmod\s+(-[a-zA-Z]*R\s+)?777\s+\//i,
  /\bchown\s+(-[a-zA-Z]*R\s+)?root\b/i
];

// Sensitive files that should never be read or overwritten directly by agents
const BLOCKED_SECRET_FILE_PATTERNS = [
  /(^|\/)\.env(\.[a-zA-Z0-9_-]+)?$/,
  /(^|\/)id_rsa(\.pub)?$/,
  /(^|\/)id_ed25519(\.pub)?$/,
  /(^|\/)\.aws\/credentials$/,
  /(^|\/)\.git\/config$/,
  /(^|\/)\.npmrc$/
];

class SentinelPolicyEngine {
  constructor(config = {}) {
    this.policyVersion = config.policyVersion || ENGINE_POLICY_VERSION;
    const requestedProfile = config.profile || config.activeProfile;
    this.profile = VALID_PROFILES.includes(requestedProfile) ? requestedProfile : PROFILE_BALANCED;
    this.workspaceRoot = config.workspaceRoot ? require('path').resolve(config.workspaceRoot) : process.cwd();
    this.timeoutMs = typeof config.timeoutMs === 'number' && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
    this.approvals = new Map(); // action_hash -> approval record
    this.allowedCommands = new Set(Array.isArray(config.allowedCommands) ? config.allowedCommands : [
      'git status',
      'git diff',
      'git log',
      'git branch',
      'npm test',
      'npm run lint',
      'cargo test'
    ]);
    this.correlationDetector = config.correlationDetector !== undefined
      ? config.correlationDetector
      : new AttackChainDetector();
    this.canaryManager = config.canaryManager || null;
    this.shellAnalyzer = config.shellAnalyzer || new ShellAstAnalyzer();
  }

  /**
   * Set active policy profile ('observe-only' | 'balanced' | 'strict').
   */
  setProfile(profile) {
    if (!VALID_PROFILES.includes(profile)) {
      throw new Error(`Invalid policy profile "${profile}". Expected: ${VALID_PROFILES.join(', ')}`);
    }
    this.profile = profile;
  }

  /**
   * Register a user-granted human approval bound to a specific action hash.
   */
  registerApproval(actionHash, approver = 'user', expiryMs = 300000) {
    if (!actionHash || typeof actionHash !== 'string' || actionHash.length !== 64) {
      throw new Error('Valid 64-character action_hash required to register approval');
    }
    this.approvals.set(actionHash, {
      action_hash: actionHash,
      approver,
      granted_at: Date.now(),
      expires_at: Date.now() + expiryMs
    });
  }

  /**
   * Evaluates an action against the policy rules.
   * Guarantees bounded execution time and fail-closed safety.
   *
   * @param {Object} action - Action Schema object
   * @param {Object} [evalContext] - Optional execution context overrides
   * @returns {Promise<Object>} Decision Schema object
   */
  async evaluate(action, evalContext = {}) {
    const requestId = (action && typeof action.request_id === 'string') ? action.request_id : `req-err-${crypto.randomBytes(4).toString('hex')}`;

    try {
      // Bounded execution promise with timeout race
      const decision = await Promise.race([
        this._executeRules(action, requestId, evalContext),
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error('POLICY_EVALUATION_TIMEOUT')), this.timeoutMs);
        })
      ]);

      if (this.correlationDetector && action && action.session_id) {
        this.correlationDetector.recordAction(action.session_id, action, decision);
      }

      return decision;
    } catch (err) {
      if (err.message === 'POLICY_EVALUATION_TIMEOUT') {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_POLICY_TIMEOUT,
          'Policy evaluation exceeded maximum execution budget (fail-closed).',
          ['rule-timeout-fail-closed'],
          requestId,
          null
        );
      }
      return this._buildDecision(
        DECISION_DENY,
        REASON_CODES.DENY_FAIL_CLOSED,
        `Unexpected policy evaluation error: ${err.message}`,
        ['rule-generic-fail-closed'],
        requestId,
        null
      );
    }
  }

  /**
   * Synchronous / core rule evaluation pipeline.
   */
  _executeRules(action, requestId, evalContext) {
    // ══════════════════════════════════════════════════════════════════════════
    // LEVEL 1: HARD SAFETY RULES (NON-NEGOTIABLE - CANNOT BE OVERRIDDEN)
    // ══════════════════════════════════════════════════════════════════════════

    // 1.1 Schema Validation
    const schemaValidation = validateActionSchema(action);
    if (!schemaValidation.valid) {
      return this._buildDecision(
        DECISION_DENY,
        REASON_CODES.DENY_INVALID_SCHEMA,
        `Action failed schema validation: ${schemaValidation.errors.join('; ')}`,
        ['rule-level1-schema-guard'],
        requestId,
        null
      );
    }
    const safeAction = schemaValidation.sanitized;
    const actionHash = computeActionHash(safeAction);

    // 1.1b Level 0: Active Canary Honeypot & Decoy Quarantine
    if (this.canaryManager) {
      const canaryCheck = this.canaryManager.inspectAction(safeAction);
      if (canaryCheck.triggered) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
          canaryCheck.explanation || 'CRITICAL: Autonomous agent accessed decoy canary honeypot! Session quarantined.',
          ['rule-level0-canary-honeypot-trap'],
          requestId,
          actionHash
        );
      }
    }

    // 1.2 Resource Normalization & Path Escape Check
    const activeWorkspace = evalContext.workspaceRoot ? require('path').resolve(evalContext.workspaceRoot) : this.workspaceRoot;

    if ([ACTION_FS_READ, ACTION_FS_WRITE, ACTION_FS_DELETE, ACTION_FS_LIST].includes(safeAction.action_type)) {
      // Hard check: Shell metacharacter / command smuggling in filesystem path
      const rawRes = String(safeAction.resource || '');
      if (/[;&|`]|\$\(|\b(sh|bash|zsh|eval)\b/i.test(rawRes)) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_UNSAFE_SHELL_COMMAND,
          `Dangerous shell metacharacter or command smuggling detected in filesystem path: ${safeAction.resource}`,
          ['rule-level1-shell-path-smuggling-guard'],
          requestId,
          actionHash
        );
      }

      const pathNorm = normalizeFilesystemPath(safeAction.resource, activeWorkspace);

      if (pathNorm.error === 'PATH_INJECTION_NULL_BYTE') {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_PATH_TRAVERSAL,
          'Null-byte or control character injection detected in filesystem path.',
          ['rule-level1-null-byte-guard'],
          requestId,
          actionHash
        );
      }

      // Hard check: Sensitive system path targeting (/etc, ~/.ssh, /root)
      if (pathNorm.isSensitiveSystemPath) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_SYSTEM_FILE_ACCESS,
          `Action targets restricted system or user secret location: ${safeAction.resource}`,
          ['rule-level1-system-path-guard'],
          requestId,
          actionHash
        );
      }

      // Hard check: Workspace boundary escape
      if (!pathNorm.isInsideWorkspace) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_WORKSPACE_ESCAPE,
          `Target path "${safeAction.resource}" resolves outside approved workspace root (${activeWorkspace}).`,
          ['rule-level1-workspace-boundary'],
          requestId,
          actionHash
        );
      }

      // Hard check: Broad file deletion
      if (safeAction.action_type === ACTION_FS_DELETE) {
        const canonical = pathNorm.canonicalPath;
        if (canonical === activeWorkspace || canonical === '/' || safeAction.resource.trim() === '*' || safeAction.resource.trim() === '.') {
          return this._buildDecision(
            DECISION_DENY,
            REASON_CODES.DENY_BROAD_DELETION,
            'Prohibited attempt to broadly delete the entire workspace or root directory.',
            ['rule-level1-broad-deletion-guard'],
            requestId,
            actionHash
          );
        }
      }
    }

    // 1.3 Outbound Network Hard Safety Rules
    if (safeAction.action_type === ACTION_NET_REQUEST) {
      const netNorm = normalizeNetworkDestination(safeAction.resource);

      // Cloud Metadata Blocking (IMDS)
      if (netNorm.isCloudMetadata) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_CLOUD_METADATA_BLOCKED,
          `Connection to link-local cloud metadata service is prohibited (${netNorm.canonicalHost}).`,
          ['rule-level1-cloud-metadata-guard'],
          requestId,
          actionHash
        );
      }
    }

    // 1.4 Shell Execution Hard Safety Rules
    if (safeAction.action_type === ACTION_SHELL_EXEC) {
      const cmd = String(safeAction.resource || '');
      let cleanCmd = cmd.replace(/[\u200B-\u200D\uFEFF]/g, '');
      try { cleanCmd = decodeURIComponent(cleanCmd); } catch (_) {}

      if (/etc\/(?:shadow|passwd)|\/root|\.ssh|id_rsa|\.env/i.test(cleanCmd)) {
        return this._buildDecision(
          DECISION_DENY,
          REASON_CODES.DENY_SYSTEM_FILE_ACCESS,
          'Direct access to sensitive system or credential files via shell is prohibited.',
          ['rule-level1-shell-system-file-guard'],
          requestId,
          actionHash
        );
      }

      // De-obfuscate and analyze using Shell AST Analyzer
      if (this.shellAnalyzer) {
        const astResult = this.shellAnalyzer.analyze(cmd);
        if (!astResult.isSafe) {
          return this._buildDecision(
            DECISION_DENY,
            astResult.reasonCode,
            astResult.explanation || 'Destructive or unverified shell command pattern detected.',
            ['rule-level1-destructive-shell-guard'],
            requestId,
            actionHash
          );
        }
      }

      for (const pattern of DESTRUCTIVE_SHELL_PATTERNS) {
        if (pattern.test(cmd)) {
          return this._buildDecision(
            DECISION_DENY,
            REASON_CODES.DENY_UNSAFE_SHELL_COMMAND,
            `Destructive or unverified shell command pattern detected: ${pattern.source}`,
            ['rule-level1-destructive-shell-guard'],
            requestId,
            actionHash
          );
        }
      }
    }

    // 1.5 Attack-Chain Correlation Guard
    if (this.correlationDetector) {
      const chainRisk = this.correlationDetector.evaluateActionRisk(safeAction);
      if (chainRisk.isAttackChain) {
        return this._buildDecision(
          DECISION_DENY,
          chainRisk.reasonCode,
          chainRisk.explanation,
          [`rule-level1-attack-chain-${chainRisk.chainType.toLowerCase()}`],
          requestId,
          actionHash
        );
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LEVEL 2: EXPLICIT DENY RULES
    // ══════════════════════════════════════════════════════════════════════════

    // 2.1 Secret / Environment Files Guard
    if ([ACTION_FS_READ, ACTION_FS_WRITE, ACTION_FS_DELETE].includes(safeAction.action_type)) {
      const normalizedPath = safeAction.resource.replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/\\/g, '/');
      for (const secretPattern of BLOCKED_SECRET_FILE_PATTERNS) {
        if (secretPattern.test(normalizedPath)) {
          return this._buildDecision(
            DECISION_DENY,
            REASON_CODES.DENY_SECRET_EXFILTRATION,
            `Access to credential or secret configuration file is blocked by policy (${safeAction.resource}).`,
            ['rule-level2-secret-files-guard'],
            requestId,
            actionHash
          );
        }
      }
    }

    // 2.2 Quota / Token Budget Check
    if (evalContext.tokenBudget && evalContext.tokenBudget.exhausted) {
      return this._buildDecision(
        DECISION_DENY,
        REASON_CODES.DENY_QUOTA_EXCEEDED,
        `Action rejected: Agent token budget quota exceeded (${evalContext.tokenBudget.reason || 'session limit reached'}).`,
        ['rule-level2-token-budget'],
        requestId,
        actionHash
      );
    }

    // 2.3 TOCTOU Check: Action Modification After Approval
    if (evalContext.approvalToken) {
      const recorded = this.approvals.get(evalContext.approvalToken);
      if (recorded) {
        if (Date.now() > recorded.expires_at) {
          return this._buildDecision(
            DECISION_DENY,
            REASON_CODES.DENY_STALE_APPROVAL,
            'Approval has expired. Fresh human authorization is required.',
            ['rule-level2-stale-approval'],
            requestId,
            actionHash
          );
        }
        if (recorded.action_hash !== actionHash) {
          return this._buildDecision(
            DECISION_DENY,
            REASON_CODES.DENY_ACTION_MUTATED_AFTER_APPROVAL,
            'Action parameters or target resource were altered after approval was granted (TOCTOU violation).',
            ['rule-level2-toctou-guard'],
            requestId,
            actionHash
          );
        }
        // Valid approval matches exact action_hash
        return this._buildDecision(
          DECISION_ALLOW,
          REASON_CODES.ALLOW_EXPLICIT_APPROVAL,
          `Action explicitly authorized by ${recorded.approver}.`,
          ['rule-level2-approval-verified'],
          requestId,
          actionHash
        );
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LEVEL 3: APPROVAL GATES (BY PROFILE)
    // ══════════════════════════════════════════════════════════════════════════

    const activeProfile = evalContext.profile || this.profile;

    if (activeProfile === PROFILE_OBSERVE_ONLY) {
      return this._buildDecision(
        DECISION_ALLOW,
        REASON_CODES.ALLOW_OBSERVE_ONLY,
        'Action permitted under observe-only mode (audit logging active, non-enforcing).',
        ['rule-level4-observe-only'],
        requestId,
        actionHash
      );
    }

    // Deletions always require approval in balanced and strict modes
    if (safeAction.action_type === ACTION_FS_DELETE) {
      return this._buildDecision(
        DECISION_REQUIRE_APPROVAL,
        REASON_CODES.REQUIRE_APPROVAL_DELETION,
        `File deletion requires user confirmation: ${safeAction.resource}`,
        ['rule-level3-deletion-approval'],
        requestId,
        actionHash,
        null,
        safeAction
      );
    }

    // Shell executions
    if (safeAction.action_type === ACTION_SHELL_EXEC) {
      const trimmedCmd = safeAction.resource.trim();
      const isKnownSafe = this.allowedCommands.has(trimmedCmd) || Array.from(this.allowedCommands).some(safe => trimmedCmd.startsWith(safe + ' '));

      if (activeProfile === PROFILE_STRICT || !isKnownSafe) {
        return this._buildDecision(
          DECISION_REQUIRE_APPROVAL,
          REASON_CODES.REQUIRE_APPROVAL_SHELL_EXEC,
          `Shell execution requires user approval: "${trimmedCmd}"`,
          ['rule-level3-shell-approval'],
          requestId,
          actionHash,
          null,
          safeAction
        );
      }
    }

    // Configuration Changes
    if (safeAction.action_type === ACTION_CONFIG_CHANGE) {
      return this._buildDecision(
        DECISION_REQUIRE_APPROVAL,
        REASON_CODES.REQUIRE_APPROVAL_CONFIG_CHANGE,
        `Security configuration modification requires user approval: ${safeAction.resource}`,
        ['rule-level3-config-change-approval'],
        requestId,
        actionHash,
        null,
        safeAction
      );
    }

    // Strict Mode: All writes and outbound network requests require approval
    if (activeProfile === PROFILE_STRICT) {
      if (safeAction.action_type === ACTION_FS_WRITE) {
        return this._buildDecision(
          DECISION_REQUIRE_APPROVAL,
          REASON_CODES.REQUIRE_APPROVAL_WORKSPACE_WRITE,
          `Strict profile: Write to "${safeAction.resource}" requires explicit confirmation.`,
          ['rule-level3-strict-write-approval'],
          requestId,
          actionHash,
          null,
          safeAction
        );
      }
      if (safeAction.action_type === ACTION_NET_REQUEST) {
        return this._buildDecision(
          DECISION_REQUIRE_APPROVAL,
          REASON_CODES.REQUIRE_APPROVAL_OUTBOUND_NETWORK,
          `Strict profile: Outbound connection to "${safeAction.resource}" requires confirmation.`,
          ['rule-level3-strict-net-approval'],
          requestId,
          actionHash,
          null,
          safeAction
        );
      }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // LEVEL 4: DEFAULT PROFILE ALLOW
    // ══════════════════════════════════════════════════════════════════════════

    if (safeAction.action_type === ACTION_FS_READ || safeAction.action_type === ACTION_FS_LIST) {
      return this._buildDecision(
        DECISION_ALLOW,
        REASON_CODES.ALLOW_WORKSPACE_READ,
        `Read access allowed within workspace: ${safeAction.resource}`,
        ['rule-level4-workspace-read'],
        requestId,
        actionHash,
        { read_only: true }
      );
    }

    if (safeAction.action_type === ACTION_FS_WRITE) {
      return this._buildDecision(
        DECISION_ALLOW,
        REASON_CODES.ALLOW_WORKSPACE_WRITE,
        `Write access allowed within workspace: ${safeAction.resource}`,
        ['rule-level4-workspace-write'],
        requestId,
        actionHash
      );
    }

    if (safeAction.action_type === ACTION_SHELL_EXEC) {
      return this._buildDecision(
        DECISION_ALLOW,
        REASON_CODES.ALLOW_SAFE_COMMAND,
        `Safe command allowed: ${safeAction.resource}`,
        ['rule-level4-safe-command'],
        requestId,
        actionHash
      );
    }

    // Default fallback: require approval
    return this._buildDecision(
      DECISION_REQUIRE_APPROVAL,
      REASON_CODES.REQUIRE_APPROVAL_EXTERNAL_READ,
      `Action requires confirmation under active ${activeProfile} profile.`,
      ['rule-level4-default-fallback'],
      requestId,
      actionHash,
      null,
      safeAction
    );
  }

  /**
   * Quantifies the blast radius of an action requiring human approval.
   */
  computeBlastRadius(action) {
    if (!action) return null;
    const type = action.action_type;
    const resource = action.resource || '';
    const params = action.parameters || {};

    let severity = 'low';
    let isDestructive = false;
    let filesAffected = 1;

    if (type === ACTION_FS_DELETE) {
      isDestructive = true;
      severity = resource.includes('*') || !resource.includes('.') ? 'critical' : 'high';
      filesAffected = resource.includes('*') ? 10 : 1;
    } else if (type === ACTION_SHELL_EXEC) {
      const cmd = String(params.command || resource).toLowerCase();
      if (DESTRUCTIVE_SHELL_PATTERNS.some(p => p.test(cmd)) || cmd.includes('rm ') || cmd.includes('drop ') || cmd.includes('delete ')) {
        isDestructive = true;
        severity = 'critical';
      } else {
        severity = 'medium';
      }
    } else if (type === ACTION_FS_WRITE) {
      severity = 'medium';
      if (resource.includes('package.json') || resource.includes('config') || resource.endsWith('.lock')) {
        severity = 'high';
      }
    } else if (type === ACTION_NET_REQUEST) {
      severity = 'medium';
    }

    return {
      action_type: type,
      resource,
      severity,
      is_destructive: isDestructive,
      files_affected: filesAffected,
      requires_typed_confirmation: severity === 'critical'
    };
  }

  /**
   * Generates an adversarial refutation brief (Dual-Key AI Quorum) to combat approval fatigue.
   */
  generateAdversarialRefutation(action, blastRadius) {
    if (!action || !blastRadius) return null;
    const type = action.action_type;
    const resource = action.resource || '';

    if (blastRadius.is_destructive) {
      return `Adversarial Refutation: Action involves destructive or irreversible modifications targeting "${resource}". Approving this may cause irrecoverable data loss or system degradation.`;
    }

    if (type === ACTION_NET_REQUEST) {
      return `Adversarial Refutation: Outbound connection to "${resource}" introduces credential or context exfiltration risk. Verify that the destination endpoint is strictly required.`;
    }

    if (type === ACTION_CONFIG_CHANGE) {
      return `Adversarial Refutation: Altering system configuration ("${resource}") may weaken local policy bounds or disable existing security controls.`;
    }

    return `Adversarial Refutation: The action "${type}" on "${resource}" modifies local state outside automated policy rules. Exercise caution before confirming.`;
  }

  /**
   * Helper: constructs a clean Decision Schema object.
   */
  _buildDecision(decision, reasonCode, explanation, matchedPolicyIds, requestId, actionHash, constraints = null, action = null) {
    const auditReference = `audit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const scrubbedExplanation = scrubSecretsFromExplanation(explanation);

    const result = {
      schema_version: CURRENT_SCHEMA_VERSION,
      decision,
      reason_code: reasonCode,
      explanation: scrubbedExplanation,
      matched_policy_ids: matchedPolicyIds,
      policy_version: this.policyVersion,
      request_id: requestId,
      required_constraints: constraints,
      decision_expiry: decision === DECISION_REQUIRE_APPROVAL ? Date.now() + 600000 : null,
      audit_reference: auditReference,
      action_hash: actionHash || '0'.repeat(64)
    };

    if (decision === DECISION_REQUIRE_APPROVAL && action) {
      const blastRadius = this.computeBlastRadius(action);
      result.blast_radius = blastRadius;
      result.adversarial_refutation = this.generateAdversarialRefutation(action, blastRadius);
    }

    return result;
  }
}

module.exports = {
  SentinelPolicyEngine,
  DEFAULT_TIMEOUT_MS,
  ENGINE_POLICY_VERSION
};
