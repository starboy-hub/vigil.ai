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
    this.canaryFiles = Object.freeze(['.env.canary']);

    this.quarantinedSessions = new Set();
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

    // 3. Canary Token Leakage in Resource string
    if (resource.includes(this.canaryAwsKey) || resource.includes(this.canaryGithubPat)) {
      this.quarantineSession(sessionId);
      return {
        triggered: true,
        reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
        explanation: 'CRITICAL: Injected decoy canary credential detected in action resource!'
      };
    }

    // 4. Deep Inspection of Action Parameters for Canary Tokens
    if (action.parameters && typeof action.parameters === 'object') {
      const paramStr = JSON.stringify(action.parameters);
      if (paramStr.includes(this.canaryAwsKey) || paramStr.includes(this.canaryGithubPat)) {
        this.quarantineSession(sessionId);
        return {
          triggered: true,
          reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED,
          explanation: 'CRITICAL: Injected decoy canary credential detected in tool parameters!'
        };
      }
    }

    return { triggered: false };
  }
}

module.exports = {
  CanaryTrapManager
};

