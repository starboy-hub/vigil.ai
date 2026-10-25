/**
 * Sentinel Stage 8: Attack-Chain Correlation Engine
 * =================================================
 * Multi-event correlation engine tracking temporal sequences across
 * prompt injection, taint propagation, reconnaissance, and egress attempts.
 *
 * Catches multi-step attack chains that appear benign in isolation
 * but constitute composite exfiltration or privilege escalation over time.
 *
 * Implements Stage 8 of Plan.pdf master execution specification.
 */

'use strict';

const {
  REASON_CODES,
  ACTION_FS_READ,
  ACTION_FS_LIST,
  ACTION_NET_REQUEST,
  ACTION_CONFIG_CHANGE,
  ACTION_SHELL_EXEC
} = require('../constants');

class AttackChainDetector {
  /**
   * @param {Object} [options]
   * @param {number} [options.windowMs] - Sliding correlation window in ms (default: 600,000 / 10m)
   * @param {number} [options.reconBurstThreshold] - Max distinct reads in 60s before recon flag (default: 5)
   * @param {Function} [options.auditCallback] - Optional callback for attack chain alerts
   */
  constructor(options = {}) {
    this.windowMs = Number.isInteger(options.windowMs) && options.windowMs > 0
      ? options.windowMs
      : 600000;
    this.reconBurstThreshold = Number.isInteger(options.reconBurstThreshold) && options.reconBurstThreshold > 0
      ? options.reconBurstThreshold
      : 5;
    this.auditCallback = typeof options.auditCallback === 'function' ? options.auditCallback : null;

    // session_id -> { signals: [], history: [], tainted: boolean, taintSource: string }
    this.sessionState = new Map();
  }

  /**
   * Record a security risk signal for a session (e.g. prompt injection detection)
   * 
   * @param {string} sessionId
   * @param {string} signalType - e.g. 'INJECTION_DETECTED', 'UNTRUSTED_INPUT', 'SENSITIVE_LEAK'
   * @param {Object} [metadata]
   */
  recordSignal(sessionId, signalType, metadata = {}) {
    if (!sessionId || typeof sessionId !== 'string') return;

    const state = this._getOrCreateSessionState(sessionId);
    const now = Date.now();

    const signalRecord = {
      signalType,
      timestamp: now,
      metadata
    };

    state.signals.push(signalRecord);

    if (signalType === 'INJECTION_DETECTED' || signalType === 'UNTRUSTED_INPUT' || signalType === 'PROMPT_TAINT') {
      state.tainted = true;
      state.taintSource = metadata.source || signalType;
      state.taintedAt = now;
    }

    this._pruneSession(state, now);
  }

  /**
   * Record a proposed or executed action in the session's sliding history
   * 
   * @param {string} sessionId
   * @param {Object} action - Action Schema
   * @param {Object} [decision] - Decision Schema
   */
  recordAction(sessionId, action, decision = null) {
    if (!sessionId || typeof sessionId !== 'string' || !action) return;

    const state = this._getOrCreateSessionState(sessionId);
    const now = Date.now();

    // Check if the action itself carried risk signals
    if (Array.isArray(action.risk_signals) && action.risk_signals.length > 0) {
      for (const sig of action.risk_signals) {
        if (typeof sig === 'string' && (sig.includes('injection') || sig.includes('taint') || sig.includes('untrusted'))) {
          state.tainted = true;
          state.taintSource = sig;
          state.taintedAt = action.timestamp ? Number(action.timestamp) : now;
        }
      }
    }

    state.history.push({
      actionType: action.action_type,
      resource: action.resource,
      parameters: action.parameters || {},
      decision: decision ? decision.decision : null,
      reasonCode: decision ? decision.reason_code : null,
      timestamp: action.timestamp || now
    });

    this._pruneSession(state, now);
  }

  /**
   * Evaluate whether a candidate action completes an attack chain
   * 
   * @param {Object} action - Candidate Action Schema
   * @returns {{ isAttackChain: boolean, reasonCode?: string, explanation?: string, chainType?: string, chainEvents?: Object[] }}
   */
  evaluateActionRisk(action) {
    if (!action || !action.session_id) {
      return { isAttackChain: false };
    }

    const sessionId = action.session_id;
    const state = this.sessionState.get(sessionId);
    if (!state) {
      return { isAttackChain: false };
    }

    const now = Date.now();
    this._pruneSession(state, now);

    // ─────────────────────────────────────────────────────────────────────────
    // PATTERN 1: TAINTED EXFILTRATION ATTACK CHAIN
    // Sequence: Untrusted input / injection taint -> file read(s) -> outbound network request
    // ─────────────────────────────────────────────────────────────────────────
    if (state.tainted && action.action_type === ACTION_NET_REQUEST) {
      const recentReads = state.history.filter(
        (h) => (h.actionType === ACTION_FS_READ || h.actionType === ACTION_FS_LIST) && h.timestamp >= (state.taintedAt - 1000)
      );

      if (recentReads.length > 0) {
        const explanation = `Correlated exfiltration attack chain detected: Session was tainted by untrusted input (${state.taintSource}), accessed ${recentReads.length} file(s) [e.g. ${recentReads[0].resource}], and attempted outbound network connection to "${action.resource}".`;

        const chainEvents = [
          { type: 'taint_signal', source: state.taintSource, timestamp: state.taintedAt },
          ...recentReads.map((r) => ({ type: 'file_read', resource: r.resource, timestamp: r.timestamp })),
          { type: 'egress_attempt', destination: action.resource, timestamp: now }
        ];

        this._emitCorrelationAlert('exfiltration', sessionId, explanation, chainEvents);

        return {
          isAttackChain: true,
          chainType: 'EXFILTRATION_CHAIN',
          reasonCode: REASON_CODES.DENY_ATTACK_CHAIN_EXFILTRATION,
          explanation,
          chainEvents
        };
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PATTERN 2: RECONNAISSANCE BURST TO EGRESS ATTACK CHAIN
    // Sequence: Rapid burst of distinct file/dir enumerations within 60s -> network egress
    // ─────────────────────────────────────────────────────────────────────────
    if (action.action_type === ACTION_NET_REQUEST) {
      const oneMinuteAgo = now - 60000;
      const recentDistinctReads = new Set();

      for (const h of state.history) {
        if (h.timestamp >= oneMinuteAgo && (h.actionType === ACTION_FS_READ || h.actionType === ACTION_FS_LIST)) {
          recentDistinctReads.add(h.resource);
        }
      }

      if (recentDistinctReads.size >= this.reconBurstThreshold) {
        const explanation = `Correlated reconnaissance chain detected: Agent performed rapid enumeration across ${recentDistinctReads.size} distinct paths within 60 seconds followed by outbound network egress to "${action.resource}".`;

        const chainEvents = [
          { type: 'recon_burst', distinctCount: recentDistinctReads.size, paths: Array.from(recentDistinctReads) },
          { type: 'egress_attempt', destination: action.resource, timestamp: now }
        ];

        this._emitCorrelationAlert('reconnaissance', sessionId, explanation, chainEvents);

        return {
          isAttackChain: true,
          chainType: 'RECONNAISSANCE_BURST',
          reasonCode: REASON_CODES.DENY_ATTACK_CHAIN_RECONNAISSANCE,
          explanation,
          chainEvents
        };
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PATTERN 3: PRIVILEGE ESCALATION ATTACK CHAIN
    // Sequence: Multiple security denials -> attempt to modify security configuration
    // ─────────────────────────────────────────────────────────────────────────
    if (action.action_type === ACTION_CONFIG_CHANGE || (action.action_type === ACTION_SHELL_EXEC && String(action.resource).includes('chmod'))) {
      const recentDenials = state.history.filter(
        (h) => h.decision === 'deny' && h.timestamp >= now - 180000 // past 3 minutes
      );

      if (recentDenials.length >= 2) {
        const explanation = `Correlated privilege escalation chain detected: Agent received ${recentDenials.length} security policy denials and subsequently attempted to alter security configuration or permissions: "${action.resource}".`;

        const chainEvents = [
          ...recentDenials.map((d) => ({ type: 'policy_denial', reason: d.reasonCode, resource: d.resource })),
          { type: 'escalation_attempt', target: action.resource, timestamp: now }
        ];

        this._emitCorrelationAlert('privilege_escalation', sessionId, explanation, chainEvents);

        return {
          isAttackChain: true,
          chainType: 'PRIVILEGE_ESCALATION',
          reasonCode: REASON_CODES.DENY_ATTACK_CHAIN_PRIVILEGE_ESCALATION,
          explanation,
          chainEvents
        };
      }
    }

    return { isAttackChain: false };
  }

  /**
   * Helper: retrieve or create session record
   */
  _getOrCreateSessionState(sessionId) {
    let state = this.sessionState.get(sessionId);
    if (!state) {
      state = {
        signals: [],
        history: [],
        tainted: false,
        taintSource: null,
        taintedAt: 0
      };
      this.sessionState.set(sessionId, state);
    }
    return state;
  }

  /**
   * Helper: prune expired signals and history outside the sliding window
   */
  _pruneSession(state, now) {
    const cutoff = now - this.windowMs;
    state.signals = state.signals.filter((s) => s.timestamp >= cutoff);
    state.history = state.history.filter((h) => h.timestamp >= cutoff);

    // If taint signal expired, clear taint
    if (state.tainted && state.taintedAt < cutoff) {
      state.tainted = false;
      state.taintSource = null;
    }
  }

  /**
   * Emit correlation alert
   */
  _emitCorrelationAlert(chainType, sessionId, explanation, chainEvents) {
    if (!this.auditCallback) return;
    try {
      this.auditCallback({
        event_type: 'attack_chain:detected',
        chain_type: chainType,
        session_id: sessionId,
        explanation,
        chain_events: chainEvents,
        timestamp: new Date().toISOString()
      });
    } catch (_ignore) {
      // Non-fatal
    }
  }
}

module.exports = {
  AttackChainDetector
};
