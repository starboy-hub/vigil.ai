/**
 * Sentinel Stage 10: CLI Shim Enforcement Adapter
 * ===============================================
 * Intercepts command-line tool invocations, shell processes, and developer
 * commands. Normalizes CLI commands into Sentinel Action Schemas, evaluates
 * policy prior to execution, and blocks unsafe operations with standard exit codes.
 *
 * Implements Stage 10 of Plan.pdf master execution specification.
 */

'use strict';

const crypto = require('crypto');
const {
  DECISION_ALLOW,
  DECISION_DENY,
  DECISION_REQUIRE_APPROVAL,
  ACTION_SHELL_EXEC,
  REASON_CODES
} = require('../constants');

const { SentinelPolicyEngine } = require('../policy-engine');
const { scrubSecretsFromExplanation } = require('../schemas');

// Standard Exit Codes for Policy Denial
const EXIT_CODE_POLICY_DENIED = 126; // Command cannot be executed (POSIX 126)
const EXIT_CODE_SUCCESS = 0;

class SentinelCliShim {
  /**
   * @param {Object} [options]
   * @param {SentinelPolicyEngine} [options.policyEngine] - Sentinel policy engine instance
   * @param {string} [options.workspaceRoot] - Workspace root directory
   * @param {Function} [options.spawnFunction] - Injectable process executor: async (cmd, args, opts) => { exitCode, stdout, stderr }
   * @param {Function} [options.auditCallback] - Optional callback for audit logging
   */
  constructor(options = {}) {
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.policyEngine = options.policyEngine || new SentinelPolicyEngine({
      workspaceRoot: this.workspaceRoot
    });
    this.spawnFunction = typeof options.spawnFunction === 'function' ? options.spawnFunction : null;
    this.auditCallback = typeof options.auditCallback === 'function' ? options.auditCallback : null;
  }

  /**
   * Check policy for a command without executing it (dry-run mode).
   * 
   * @param {string} commandLine - Shell command string
   * @param {Object} [sessionContext]
   * @returns {Promise<Object>} Policy Decision object
   */
  async checkPolicy(commandLine, sessionContext = {}) {
    if (typeof commandLine !== 'string' || commandLine.trim().length === 0) {
      return {
        decision: DECISION_DENY,
        reason_code: REASON_CODES.DENY_INVALID_SCHEMA,
        explanation: 'Empty or invalid command string provided to CLI shim.'
      };
    }

    const action = this._mapCommandToAction(commandLine, sessionContext);
    return await this.policyEngine.evaluate(action, sessionContext);
  }

  /**
   * Execute command through Sentinel enforcement gate.
   * If allowed, executes via spawnFunction. If denied, halts without side effects.
   * 
   * @param {string} commandLine - Shell command string
   * @param {Object} [sessionContext]
   * @returns {Promise<{ exitCode: number, stdout: string, stderr: string, decision: Object }>}
   */
  async execute(commandLine, sessionContext = {}) {
    const decision = await this.checkPolicy(commandLine, sessionContext);

    // 1. ALLOW Path
    if (decision.decision === DECISION_ALLOW) {
      this._emitAuditEvent('cli:allowed', { commandLine, decision });

      if (this.spawnFunction) {
        try {
          const spawnResult = await this.spawnFunction(commandLine, sessionContext);
          return {
            exitCode: spawnResult.exitCode !== undefined ? spawnResult.exitCode : EXIT_CODE_SUCCESS,
            stdout: scrubSecretsFromExplanation(spawnResult.stdout || ''),
            stderr: scrubSecretsFromExplanation(spawnResult.stderr || ''),
            decision
          };
        } catch (execErr) {
          return {
            exitCode: 1,
            stdout: '',
            stderr: `Execution error: ${scrubSecretsFromExplanation(execErr.message)}`,
            decision
          };
        }
      }

      return {
        exitCode: EXIT_CODE_SUCCESS,
        stdout: `[SENTINEL_ALLOWED] Command approved for execution: ${commandLine}`,
        stderr: '',
        decision
      };
    }

    // 2. DENY Path
    if (decision.decision === DECISION_DENY) {
      this._emitAuditEvent('cli:blocked', { commandLine, decision });

      const safeExplanation = scrubSecretsFromExplanation(decision.explanation || 'Command execution blocked by Sentinel policy');
      const reasonCode = decision.reason_code || REASON_CODES.DENY_FAIL_CLOSED;

      return {
        exitCode: EXIT_CODE_POLICY_DENIED,
        stdout: '',
        stderr: `[SENTINEL_POLICY_DENIED] Error: ${reasonCode}\nDetails: ${safeExplanation}`,
        decision
      };
    }

    // 3. REQUIRE_APPROVAL Path
    if (decision.decision === DECISION_REQUIRE_APPROVAL) {
      this._emitAuditEvent('cli:approval_required', { commandLine, decision });

      return {
        exitCode: EXIT_CODE_POLICY_DENIED,
        stdout: '',
        stderr: `[SENTINEL_REQUIRE_APPROVAL] Command requires operator authorization: ${commandLine}\nReason: ${decision.reason_code}`,
        decision
      };
    }

    // Fallback: fail-closed
    return {
      exitCode: EXIT_CODE_POLICY_DENIED,
      stdout: '',
      stderr: '[SENTINEL_POLICY_DENIED] Fail-closed: unrecognized decision state.',
      decision
    };
  }

  /**
   * Helper: construct Action Schema from CLI command string
   */
  _mapCommandToAction(commandLine, sessionContext) {
    const requestId = `req-cli-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const trimmed = commandLine.trim();

    return {
      schema_version: '1.0.0',
      request_id: requestId,
      session_id: sessionContext.sessionId || 'cli-session-default',
      agent_id: sessionContext.agentId || 'developer-cli',
      adapter: {
        id: 'sentinel-cli-shim',
        version: '1.0.0',
        type: 'cli'
      },
      action_type: ACTION_SHELL_EXEC,
      resource: trimmed,
      parameters: {
        raw_command: trimmed
      },
      timestamp: Date.now(),
      approval_token: sessionContext.approvalToken || null
    };
  }

  /**
   * Helper: emit audit events
   */
  _emitAuditEvent(eventType, payload) {
    if (!this.auditCallback) return;
    try {
      this.auditCallback({
        event_type: eventType,
        timestamp: new Date().toISOString(),
        payload
      });
    } catch (_ignore) {
      // Non-fatal
    }
  }
}

module.exports = {
  SentinelCliShim,
  EXIT_CODE_POLICY_DENIED,
  EXIT_CODE_SUCCESS
};
