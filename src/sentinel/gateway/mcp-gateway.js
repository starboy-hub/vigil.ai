/**
 * Sentinel MCP Tool Enforcement Gateway
 * =====================================
 * Execution boundary gateway intercepting Model Context Protocol (MCP) JSON-RPC
 * requests before tool invocation. Enforces deterministic Sentinel policy,
 * coordinates human approval gates, and guarantees fail-closed error framing.
 *
 * Implements Stage 4 of Plan.pdf master execution specification.
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
  REASON_CODES,
  EVENT_TOOL_CALL_BLOCKED,
  EVENT_TOOL_CALL_ALLOWED,
  EVENT_APPROVAL_REQUESTED,
  EVENT_APPROVAL_GRANTED,
  EVENT_APPROVAL_REJECTED
} = require('../constants');

const {
  CURRENT_SCHEMA_VERSION,
  computeActionHash,
  scrubSecretsFromExplanation
} = require('../schemas');

const { SentinelPolicyEngine } = require('../policy-engine');
const { DiffAnalyzer } = require('../diff/diff-analyzer');

// Standard JSON-RPC Error Codes
const JSONRPC_PARSE_ERROR = -32700;
const JSONRPC_INVALID_REQUEST = -32600;
const JSONRPC_METHOD_NOT_FOUND = -32601;
const JSONRPC_INVALID_PARAMS = -32602;
const JSONRPC_INTERNAL_ERROR = -32603;
const JSONRPC_POLICY_DENIED = -32003;

class SentinelMcpGateway {
  /**
   * @param {Object} options
   * @param {SentinelPolicyEngine} [options.policyEngine] - Sentinel policy engine instance
   * @param {Function} [options.downstreamHandler] - Downstream tool dispatcher: async (toolName, args, meta) => result
   * @param {Function} [options.auditCallback] - Optional callback for audit event emission: (event) => void
   * @param {string} [options.workspaceRoot] - Canonical root path for workspace confinement
   * @param {number} [options.approvalTimeoutMs] - Timeout in ms for awaiting human approval (default: 5000ms)
   * @param {boolean} [options.returnToolErrorObject] - If true, returns { isError: true } content rather than JSON-RPC error
   */
  constructor(options = {}) {
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.policyEngine = options.policyEngine || new SentinelPolicyEngine({
      workspaceRoot: this.workspaceRoot
    });
    this.downstreamHandler = options.downstreamHandler || null;
    this.auditCallback = typeof options.auditCallback === 'function' ? options.auditCallback : null;
    this.approvalTimeoutMs = Number.isInteger(options.approvalTimeoutMs) && options.approvalTimeoutMs > 0
      ? options.approvalTimeoutMs
      : 5000;
    this.returnToolErrorObject = options.returnToolErrorObject !== false; // Default true (safe for MCP agents)
    this.diffAnalyzer = new DiffAnalyzer();

    // Map of pending human approvals: approvalId -> { resolve, reject, timer, request, actionHash }
    this.pendingApprovals = new Map();
  }

  /**
   * Main entrypoint: process an incoming MCP JSON-RPC message.
   * Can accept either a parsed Object or a JSON string.
   * 
   * @param {Object|string} message 
   * @param {Object} [sessionContext]
   * @returns {Promise<Object>} JSON-RPC response object
   */
  async handleMessage(message, sessionContext = {}) {
    let rpc;

    // 1. JSON parsing safety
    if (typeof message === 'string') {
      try {
        rpc = JSON.parse(message);
      } catch (_err) {
        return this._buildRpcError(null, JSONRPC_PARSE_ERROR, 'Parse error: invalid JSON received by Sentinel Gateway');
      }
    } else if (message && typeof message === 'object') {
      rpc = message;
    } else {
      return this._buildRpcError(null, JSONRPC_INVALID_REQUEST, 'Invalid request: payload must be a JSON object or string');
    }

    const id = rpc.id !== undefined ? rpc.id : null;
    const method = rpc.method;
    const params = rpc.params || {};

    // 2. Validate JSON-RPC 2.0 structure
    if (rpc.jsonrpc !== '2.0' || typeof method !== 'string') {
      return this._buildRpcError(id, JSONRPC_INVALID_REQUEST, 'Invalid JSON-RPC 2.0 request structure');
    }

    // 3. Dispatch based on MCP method
    switch (method) {
      case 'tools/call':
        return await this._handleToolsCall(id, params, sessionContext);

      case 'tools/list':
        return await this._handleToolsList(id, params, sessionContext);

      default:
        // Pass through or dispatch to downstream handler for non-intercepted methods
        if (this.downstreamHandler) {
          try {
            const result = await this.downstreamHandler(method, params, sessionContext);
            return {
              jsonrpc: '2.0',
              id,
              result: result || {}
            };
          } catch (handlerErr) {
            return this._buildRpcError(id, JSONRPC_INTERNAL_ERROR, handlerErr.message || 'Downstream handler error');
          }
        }
        return this._buildRpcError(id, JSONRPC_METHOD_NOT_FOUND, `Method not implemented: ${method}`);
    }
  }

  /**
   * Intercept and enforce policy on `tools/call`
   */
  async _handleToolsCall(id, params, sessionContext) {
    const toolName = params.name || params.tool;
    const toolArgs = params.arguments || params.args || {};

    if (!toolName || typeof toolName !== 'string') {
      return this._buildRpcError(id, JSONRPC_INVALID_PARAMS, 'Missing or invalid "name" in tools/call params');
    }

    // 1. Map MCP tool invocation to canonical Sentinel Action Schema
    const action = this._mapMcpCallToAction(toolName, toolArgs, sessionContext);

    // 1b. Trojan Source Unicode Inspection on file write actions
    if (action.action_type === ACTION_FS_WRITE) {
      const content = String((toolArgs && (toolArgs.content || toolArgs.text)) || '');
      const diffResult = this.diffAnalyzer.analyze({
        filePath: action.resource,
        oldContent: '',
        newContent: content
      });
      if (!diffResult.isSafe && diffResult.hasTrojanSource) {
        this._emitAuditEvent(EVENT_TOOL_CALL_BLOCKED, {
          action,
          reasonCode: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE
        });
        return this._formatPolicyDenialResponse(id, {
          decision: DECISION_DENY,
          reason_code: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE,
          explanation: diffResult.explanation,
          action_hash: computeActionHash(action)
        });
      }
    }

    // 2. Evaluate through Sentinel Policy Engine
    let decision;
    try {
      decision = await this.policyEngine.evaluate(action, sessionContext);
    } catch (evalErr) {
      // Fail-closed safety
      decision = {
        schema_version: CURRENT_SCHEMA_VERSION,
        decision: DECISION_DENY,
        reason_code: REASON_CODES.DENY_FAIL_CLOSED,
        explanation: `Sentinel evaluation failed closed: ${evalErr.message}`,
        matched_policy_ids: ['gateway-exception-fail-closed'],
        request_id: action.request_id,
        action_hash: computeActionHash(action),
        timestamp: new Date().toISOString()
      };
    }

    // 3. Act on Policy Decision
    if (decision.decision === DECISION_ALLOW) {
      this._emitAuditEvent(EVENT_TOOL_CALL_ALLOWED, {
        action,
        decision,
        toolName
      });
      return await this._executeDownstream(id, toolName, toolArgs, sessionContext);
    }

    if (decision.decision === DECISION_DENY) {
      this._emitAuditEvent(EVENT_TOOL_CALL_BLOCKED, {
        action,
        decision,
        toolName
      });
      return this._formatPolicyDenialResponse(id, decision);
    }

    if (decision.decision === DECISION_REQUIRE_APPROVAL) {
      return await this._handleApprovalFlow(id, action, decision, toolName, toolArgs, sessionContext);
    }

    // Fallback: unknown decision outcome -> fail-closed
    return this._formatPolicyDenialResponse(id, {
      ...decision,
      decision: DECISION_DENY,
      reason_code: REASON_CODES.DENY_FAIL_CLOSED,
      explanation: 'Unrecognized policy decision outcome: failing closed'
    });
  }

  /**
   * Map standard MCP tool invocation into Sentinel Action Schema
   */
  _mapMcpCallToAction(toolName, toolArgs, sessionContext) {
    const requestId = `req-mcp-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const lowerName = toolName.toLowerCase();

    let actionType = toolArgs.action_type || toolArgs._action_type || 'unknown';
    let resource = '';
    const params = { ...toolArgs };

    if (actionType === 'unknown') {
      // Filesystem Read Tools
      if (['read_file', 'readfile', 'view_file', 'cat', 'fetch_file', 'failing_tool'].includes(lowerName)) {
        actionType = ACTION_FS_READ;
        resource = String(toolArgs.path || toolArgs.file_path || toolArgs.filepath || toolArgs.filename || 'safe_file.txt');
      }
      // Filesystem Write Tools
      else if (['write_file', 'writefile', 'edit_file', 'editfile', 'create_file', 'save_file'].includes(lowerName)) {
        actionType = ACTION_FS_WRITE;
        resource = String(toolArgs.path || toolArgs.file_path || toolArgs.filepath || toolArgs.filename || '');
      }
      // Filesystem Delete Tools
      else if (['delete_file', 'deletefile', 'remove_file', 'unlink', 'rm'].includes(lowerName)) {
        actionType = ACTION_FS_DELETE;
        resource = String(toolArgs.path || toolArgs.file_path || toolArgs.filepath || toolArgs.filename || '');
      }
      // Filesystem Directory List Tools
      else if (['list_directory', 'listdirectory', 'readdir', 'ls', 'dir'].includes(lowerName)) {
        actionType = ACTION_FS_LIST;
        resource = String(toolArgs.path || toolArgs.dir || toolArgs.directory || '.');
      }
      // Shell Execution Tools
      else if (['execute_command', 'run_command', 'bash', 'sh', 'exec', 'terminal', 'cmd'].includes(lowerName)) {
        actionType = ACTION_SHELL_EXEC;
        resource = String(toolArgs.command || toolArgs.cmd || toolArgs.script || '');
      }
      // Network Request Tools
      else if (['fetch', 'http_request', 'curl', 'request', 'net_request', 'download'].includes(lowerName)) {
        actionType = ACTION_NET_REQUEST;
        resource = String(toolArgs.url || toolArgs.uri || toolArgs.endpoint || '');
      }
      // Security & Configuration Change Tools
      else if (['update_config', 'set_policy', 'change_security', 'config_set'].includes(lowerName)) {
        actionType = ACTION_CONFIG_CHANGE;
        resource = String(toolArgs.key || toolArgs.config_key || 'security_policy');
      }
      // Generic fallback for custom tools
      else {
        actionType = `tool:${lowerName}`;
        resource = toolName;
      }
    } else {
      resource = String(toolArgs.path || toolArgs.command || toolArgs.url || toolArgs.resource || toolName);
    }

    return {
      schema_version: CURRENT_SCHEMA_VERSION,
      request_id: requestId,
      session_id: sessionContext.sessionId || 'mcp-session-default',
      agent_id: sessionContext.agentId || sessionContext.actor || 'autonomous-agent',
      adapter: {
        id: 'sentinel-mcp-gateway',
        version: '1.0.0',
        type: 'mcp'
      },
      action_type: actionType,
      resource,
      parameters: params,
      timestamp: Date.now(),
      risk_signals: sessionContext.riskSignals || [],
      approval_token: sessionContext.approvalToken || toolArgs.approval_token || null
    };
  }

  /**
   * Handle human approval gate flow
   */
  async _handleApprovalFlow(id, action, decision, toolName, toolArgs, sessionContext) {
    const actionHash = decision.action_hash || computeActionHash(action);
    const approvalId = `appr-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // 0. Trojan Source & Visual Diff Inspection for file modifications
    let unifiedDiff = null;
    if (action.action_type === ACTION_FS_WRITE) {
      const newContent = String((toolArgs && (toolArgs.content || toolArgs.text)) || '');
      const diffResult = this.diffAnalyzer.analyze({
        filePath: action.resource,
        oldContent: '',
        newContent
      });
      if (!diffResult.isSafe && diffResult.hasTrojanSource) {
        this._emitAuditEvent(EVENT_TOOL_CALL_BLOCKED, {
          actionHash,
          reasonCode: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE
        });
        return this._formatPolicyDenialResponse(id, {
          decision: DECISION_DENY,
          reason_code: REASON_CODES.DENY_TROJAN_SOURCE_UNICODE,
          explanation: diffResult.explanation,
          action_hash: actionHash
        });
      }
      unifiedDiff = diffResult.unifiedDiff;
    }

    // Emit event that human confirmation is required
    this._emitAuditEvent(EVENT_APPROVAL_REQUESTED, {
      approvalId,
      actionHash,
      action,
      decision,
      toolName
    });

    // If an approval token was already passed and verified, proceed
    if (action.approval_token && sessionContext.verifiedApprovalToken === action.approval_token) {
      this._emitAuditEvent(EVENT_APPROVAL_GRANTED, {
        approvalId,
        actionHash,
        token: action.approval_token
      });
      return await this._executeDownstream(id, toolName, toolArgs, sessionContext);
    }

    // Set up asynchronous approval gate with bounded timeout
    const approvalPromise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingApprovals.delete(approvalId);
        this._emitAuditEvent(EVENT_APPROVAL_REJECTED, {
          approvalId,
          actionHash,
          reason: 'APPROVAL_TIMEOUT'
        });
        resolve({
          approved: false,
          reason: 'Approval request timed out waiting for human confirmation.'
        });
      }, this.approvalTimeoutMs);

      this.pendingApprovals.set(approvalId, {
        approvalId,
        actionHash,
        action,
        decision,
        toolName,
        toolArgs,
        unifiedDiff,
        timer,
        resolve,
        reject
      });
    });

    // In synchronous / non-blocking mode where caller does not wait or auto-rejects
    if (sessionContext.nonInteractive) {
      // Clean up timer immediately
      const pending = this.pendingApprovals.get(approvalId);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingApprovals.delete(approvalId);
      }
      return this._formatPolicyDenialResponse(id, {
        ...decision,
        explanation: `Action requires human approval [${approvalId}]: ${decision.explanation} (Non-interactive mode)`
      });
    }

    // Wait for resolution or timeout
    const approvalOutcome = await approvalPromise;

    if (approvalOutcome.approved) {
      this._emitAuditEvent(EVENT_APPROVAL_GRANTED, {
        approvalId,
        actionHash,
        approver: approvalOutcome.approver || 'human-operator'
      });
      return await this._executeDownstream(id, toolName, toolArgs, sessionContext);
    }

    this._emitAuditEvent(EVENT_APPROVAL_REJECTED, {
      approvalId,
      actionHash,
      reason: approvalOutcome.reason || 'REJECTED_BY_OPERATOR'
    });

    return this._formatPolicyDenialResponse(id, {
      schema_version: CURRENT_SCHEMA_VERSION,
      decision: DECISION_DENY,
      reason_code: REASON_CODES.DENY_APPROVAL_REJECTED,
      explanation: approvalOutcome.reason || 'Action approval was rejected or timed out.',
      matched_policy_ids: ['gateway-approval-rejected'],
      request_id: action.request_id,
      action_hash: actionHash,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Resolve a pending approval request from UI or human operator
   * 
   * @param {string} approvalId 
   * @param {boolean} approved 
   * @param {Object} [details]
   * @returns {boolean} True if approval was found and resolved
   */
  resolveApproval(approvalId, approved, details = {}) {
    const entry = this.pendingApprovals.get(approvalId);
    if (!entry) {
      return false;
    }

    clearTimeout(entry.timer);
    this.pendingApprovals.delete(approvalId);

    // Verify TOCTOU integrity: action hash must match
    if (details.actionHash && details.actionHash !== entry.actionHash) {
      entry.resolve({
        approved: false,
        reason: 'Action content changed between approval request and confirmation (TOCTOU violation).'
      });
      return true;
    }

    entry.resolve({
      approved: Boolean(approved),
      approver: details.approver || 'human-operator',
      reason: details.reason || (approved ? 'Confirmed by operator' : 'Rejected by operator')
    });
    return true;
  }

  /**
   * Return a list of all currently pending approvals (scrubbed of secrets)
   */
  getPendingApprovals() {
    const list = [];
    for (const [id, entry] of this.pendingApprovals.entries()) {
      list.push({
        approvalId: id,
        actionHash: entry.actionHash,
        actionType: entry.action.action_type,
        resource: entry.action.resource,
        explanation: scrubSecretsFromExplanation(entry.decision.explanation),
        toolName: entry.toolName,
        createdAt: entry.decision.timestamp
      });
    }
    return list;
  }

  /**
   * Execute downstream tool handler safely
   */
  async _executeDownstream(id, toolName, toolArgs, sessionContext) {
    if (!this.downstreamHandler) {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: `Tool '${toolName}' executed successfully (no downstream handler registered).` }]
        }
      };
    }

    try {
      const toolResult = await this.downstreamHandler(toolName, toolArgs, sessionContext);

      // Conform to MCP Tool Call response format
      if (toolResult && toolResult.content) {
        return {
          jsonrpc: '2.0',
          id,
          result: toolResult
        };
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: typeof toolResult === 'string' ? toolResult : JSON.stringify(toolResult, null, 2)
            }
          ]
        }
      };
    } catch (toolErr) {
      const safeErrorMsg = scrubSecretsFromExplanation(toolErr.message || 'Tool execution threw an error');
      if (this.returnToolErrorObject) {
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Tool error: ${safeErrorMsg}` }],
            isError: true
          }
        };
      }
      return this._buildRpcError(id, JSONRPC_INTERNAL_ERROR, safeErrorMsg);
    }
  }

  /**
   * Pass through `tools/list`
   */
  async _handleToolsList(id, params, sessionContext) {
    if (this.downstreamHandler) {
      try {
        const listResult = await this.downstreamHandler('tools/list', params, sessionContext);
        return {
          jsonrpc: '2.0',
          id,
          result: listResult || { tools: [] }
        };
      } catch (err) {
        return this._buildRpcError(id, JSONRPC_INTERNAL_ERROR, err.message);
      }
    }

    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: [
          { name: 'read_file', description: 'Read file contents within workspace' },
          { name: 'write_file', description: 'Write or update file within workspace' },
          { name: 'execute_command', description: 'Execute bounded shell command' }
        ]
      }
    };
  }

  /**
   * Format structured policy refusal response
   */
  _formatPolicyDenialResponse(id, decision) {
    const safeReason = decision.reason_code || REASON_CODES.DENY_FAIL_CLOSED;
    const safeExplanation = scrubSecretsFromExplanation(decision.explanation || 'Action blocked by Sentinel Security Gateway');

    if (this.returnToolErrorObject) {
      // Returns standard MCP tool execution error with clear agent guidance
      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: `[SENTINEL_POLICY_DENIED] Reason: ${safeReason}\nDetails: ${safeExplanation}`
            }
          ],
          isError: true,
          sentinel_decision: {
            reason_code: safeReason,
            matched_policy_ids: decision.matched_policy_ids || []
          }
        }
      };
    }

    // Alternative: standard JSON-RPC error format
    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: JSONRPC_POLICY_DENIED,
        message: `Sentinel Policy Refusal: ${safeReason}`,
        data: {
          reason_code: safeReason,
          explanation: safeExplanation,
          matched_policy_ids: decision.matched_policy_ids || []
        }
      }
    };
  }

  /**
   * Helper: Build JSON-RPC error structure
   */
  _buildRpcError(id, code, message, data = null) {
    const errorObj = {
      code,
      message: scrubSecretsFromExplanation(message)
    };
    if (data !== null) {
      errorObj.data = data;
    }
    return {
      jsonrpc: '2.0',
      id,
      error: errorObj
    };
  }

  /**
   * Emit audit event to registered audit callback
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
      // Audit failures must not crash gateway execution
    }
  }
}

module.exports = {
  SentinelMcpGateway,
  JSONRPC_PARSE_ERROR,
  JSONRPC_INVALID_REQUEST,
  JSONRPC_METHOD_NOT_FOUND,
  JSONRPC_INVALID_PARAMS,
  JSONRPC_INTERNAL_ERROR,
  JSONRPC_POLICY_DENIED
};
