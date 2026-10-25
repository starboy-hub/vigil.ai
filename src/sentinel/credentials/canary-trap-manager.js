/**
 * Sentinel Active Canary Honeypot & L0 Quarantine Manager
 * Part of Vigil AI + Sentinel
 *
 * Generates synthetic high-entropy decoy credentials and canary inodes.
 * Any attempt by an agent to read, parse, or transmit these values triggers
 * an immediate Level 0 fail-closed quarantine of the agent session.
 */
'use strict';

const crypto = require('crypto');
const { REASON_CODES } = require('../constants.js');

class CanaryTrapManager {
  constructor(options = {}) {
    // Generate deterministic yet unpredictable session canary tokens
    const randomHex = crypto.randomBytes(8).toString('hex').toUpperCase();
    const randomAlphanum = crypto.randomBytes(10).toString('hex');

    this.canaryAwsKey = options.canaryAwsKey || `AKIA_CANARY_${randomHex}`;
    this.canaryGithubPat = options.canaryGithubPat || `ghp_CanaryDecoy${randomAlphanum}`;
    this.canaryFiles = Object.freeze(['.env.canary', '.env.decoy']);

    this.activeTrapTokens = new Map();
    this.activeTrapTokens.set(this.canaryAwsKey, { type: 'AWS_KEY', createdAt: Date.now() });
    this.activeTrapTokens.set(this.canaryGithubPat, { type: 'GITHUB_PAT', createdAt: Date.now() });

    this.quarantinedSessions = new Set();
    this.forensicAlerts = [];
  }

  /**
   * Dynamically rotates trap keys, creating fresh unpredictable session decoys.
   */
  rotateTrapKeys(sessionId = null) {
    const randomHex = crypto.randomBytes(8).toString('hex').toUpperCase();
    const randomAlphanum = crypto.randomBytes(16).toString('hex');
    const newAws = `AKIA${randomHex}`;
    const newGh = `ghp_${randomAlphanum}`;

    this.activeTrapTokens.set(newAws, { type: 'AWS_KEY', sessionId, rotatedAt: Date.now() });
    this.activeTrapTokens.set(newGh, { type: 'GITHUB_PAT', sessionId, rotatedAt: Date.now() });
    this.canaryAwsKey = newAws;
    this.canaryGithubPat = newGh;

    return { awsKey: newAws, githubPat: newGh };
  }

  /**
   * Returns environment variables to inject into agent execution views.
   */
  getCanaryEnvironment() {
    return {
      VIGIL_CANARY_AWS_KEY: this.canaryAwsKey,
      VIGIL_CANARY_GITHUB_PAT: this.canaryGithubPat
    };
  }

  /**
   * Returns list of decoy canary filenames
   */
  getCanaryFilePaths() {
    return [...this.canaryFiles];
  }

  /**
   * Check if session is already permanently quarantined
   */
  isSessionQuarantined(sessionId) {
    if (!sessionId) return false;
    return this.quarantinedSessions.has(sessionId);
  }

  /**
   * Permanently quarantine a session
   */
  quarantineSession(sessionId) {
    if (sessionId) {
      this.quarantinedSessions.add(sessionId);
    }
  }

  /**
   * Inspect an incoming action schema for canary touches or exfiltration
   * @param {object} action
   * @returns {{ triggered: boolean, reasonCode?: string, explanation?: string }}
   */
  inspectAction(action) {
    if (!action) return { triggered: false };

    const sessionId = action.session_id;

    // 1. Check if session was already quarantined
    if (sessionId && this.isSessionQuarantined(sessionId)) {
      return {
        triggered: true,
        reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
        explanation: 'CRITICAL: Session is permanently quarantined due to prior canary trap activation.'
      };
    }

    const resource = String(action.resource || '');

    // 2. Direct Canary File Check
    const normalizedRes = resource.replace(/\\/g, '/');
    for (const canaryFile of this.canaryFiles) {
      if (normalizedRes === canaryFile || normalizedRes.endsWith('/' + canaryFile)) {
        this.quarantineSession(sessionId);
        return {
          triggered: true,
          reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
          explanation: `CRITICAL: Canary honeypot accessed (${canaryFile}). Potential indirect prompt injection.`
        };
      }
    }

    // 3. Canary Token Leakage in Resource or Parameters (including rotating tokens)
    const paramStr = (action.parameters && typeof action.parameters === 'object')
      ? JSON.stringify(action.parameters)
      : '';

    for (const [token, meta] of this.activeTrapTokens.entries()) {
      if (resource.includes(token) || paramStr.includes(token)) {
        this.quarantineSession(sessionId);
        const forensicAlert = {
          triggered: true,
          tokenType: meta.type,
          tokenSnippet: token.slice(0, 10) + '...',
          sessionId,
          requestId: action.request_id,
          agentId: action.agent_id,
          actionType: action.action_type,
          detectedIn: resource.includes(token) ? 'resource' : 'parameters',
          compromisedAt: Date.now()
        };
        this.forensicAlerts.push(forensicAlert);
        return {
          triggered: true,
          reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
          explanation: `CRITICAL: Injected decoy canary credential (${meta.type}) detected! Potential agent exfiltration.`,
          forensicAlert
        };
      }
    }

    return { triggered: false };
  }
}

module.exports = {
  CanaryTrapManager
};

