/**
 * Sentinel Deception Layer: Cognitive Mirage & Active Honeytoken Engine
 * ====================================================================
 * Active counter-deception and threat tracing subsystem.
 *
 * Instead of immediately returning fail-closed denial responses that tip off
 * adversaries or prompt automated jailbreak mutations, Cognitive Mirage:
 * 1. Generates plausible, synthetically watermarked honeytokens (API keys, SSH keys, DB URLs).
 * 2. Emits cryptographic canaries to trace exfiltration pathways back to the attacker.
 * 3. Synthesizes decoy responses for sensitive file accesses when deception mode is armed.
 * 4. Detects downstream reuse of honeytokens to trap compromised agents or malicious subagents.
 */

'use strict';

const crypto = require('crypto');
const {
  REASON_CODES,
  EVENT_TOOL_CALL_BLOCKED
} = require('../constants');

// Supported Honeytoken Types
const HONEYTOKEN_TYPES = Object.freeze({
  OPENAI_KEY: 'OPENAI_KEY',
  ANTHROPIC_KEY: 'ANTHROPIC_KEY',
  AWS_ACCESS_KEY: 'AWS_ACCESS_KEY',
  GITHUB_PAT: 'GITHUB_PAT',
  DATABASE_URL: 'DATABASE_URL',
  CRYPTO_SEED: 'CRYPTO_SEED',
  SSH_KEY: 'SSH_KEY'
});

class CognitiveMirageEngine {
  /**
   * @param {Object} [options]
   * @param {string} [options.deceptionSecret] - Master secret for canary HMAC signatures
   * @param {boolean} [options.enabled=true] - Whether deception mode is armed
   * @param {Function} [options.onCanaryTripwire] - Callback invoked when a canary token is detected in tool calls
   */
  constructor(options = {}) {
    this.deceptionSecret = options.deceptionSecret || crypto.randomBytes(32).toString('hex');
    this.enabled = options.enabled !== false;
    this.onCanaryTripwire = typeof options.onCanaryTripwire === 'function' ? options.onCanaryTripwire : null;

    // Active Canary Registry: canaryId -> { canaryId, type, token, createdAt, context }
    this.activeCanaries = new Map();

    // Incident log of tripped canaries
    this.tripwireIncidents = [];
  }

  /**
   * Generates a plausible synthetic credential containing an embedded cryptographic canary.
   *
   * @param {string} type - Member of HONEYTOKEN_TYPES
   * @param {Object} [context] - Associated session/agent context for forensics tracking
   * @returns {{ token: string, canaryId: string, type: string }}
   */
  generateHoneytoken(type = HONEYTOKEN_TYPES.OPENAI_KEY, context = {}) {
    const rawId = crypto.randomBytes(8).toString('hex');
    const signature = crypto.createHmac('sha256', this.deceptionSecret)
      .update(`${type}:${rawId}`)
      .digest('hex')
      .slice(0, 12);

    const canaryId = `cnry_${rawId}_${signature}`;
    let token = '';

    switch (type) {
      case HONEYTOKEN_TYPES.OPENAI_KEY:
        token = `sk-proj-mirage_${canaryId}_${crypto.randomBytes(16).toString('hex')}`;
        break;

      case HONEYTOKEN_TYPES.ANTHROPIC_KEY:
        token = `sk-ant-api03-mirage_${canaryId}_${crypto.randomBytes(16).toString('hex')}AA`;
        break;

      case HONEYTOKEN_TYPES.AWS_ACCESS_KEY: {
        const awsPart = canaryId.toUpperCase().replace(/[^A-Z0-9]/g, 'X').slice(0, 12);
        token = `AKIA${awsPart}${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
        break;
      }

      case HONEYTOKEN_TYPES.GITHUB_PAT:
        token = `ghp_mirage${canaryId}${crypto.randomBytes(10).toString('hex')}`;
        break;

      case HONEYTOKEN_TYPES.DATABASE_URL:
        token = `postgres://app_mirage_${canaryId}:${crypto.randomBytes(12).toString('hex')}@db.internal.net:5432/customer_production`;
        break;

      case HONEYTOKEN_TYPES.CRYPTO_SEED:
        token = `abandon ability able about above absent absorb abstract absurd abuse access ${canaryId.slice(0, 8)}`;
        break;

      case HONEYTOKEN_TYPES.SSH_KEY:
        token = `-----BEGIN OPENSSH PRIVATE KEY-----\nbWlyYWdlX2NhbmFyeV9rZXlfZW5jb2RlZA==\n-----END OPENSSH PRIVATE KEY----- # canary:${canaryId}`;
        break;

      default:
        token = `mirage_token_${canaryId}_${crypto.randomBytes(12).toString('hex')}`;
    }

    const record = {
      canaryId,
      type,
      token,
      createdAt: Date.now(),
      context
    };

    this.activeCanaries.set(canaryId, record);
    return record;
  }

  /**
   * Inspects arbitrary text or tool arguments to verify whether an active canary token is present.
   *
   * @param {string} text - Payload to inspect
   * @returns {{ containsCanary: boolean, matchedCanaries: Array<Object> }}
   */
  inspectForCanary(text) {
    if (!text || typeof text !== 'string') {
      return { containsCanary: false, matchedCanaries: [] };
    }

    const matched = [];
    const canaryRegex = /cnry_([0-9a-f]{16})_([0-9a-f]{12})/gi;
    let match;

    while ((match = canaryRegex.exec(text)) !== null) {
      const fullCanary = match[0];
      const rawId = match[1];
      const sig = match[2];

      // Check registered canaries first
      if (this.activeCanaries.has(fullCanary)) {
        matched.push(this.activeCanaries.get(fullCanary));
        continue;
      }

      // Verify HMAC cryptographically across types even if evicted from cache
      for (const t of Object.values(HONEYTOKEN_TYPES)) {
        const expectedSig = crypto.createHmac('sha256', this.deceptionSecret)
          .update(`${t}:${rawId}`)
          .digest('hex')
          .slice(0, 12);

        if (sig === expectedSig) {
          matched.push({
            canaryId: fullCanary,
            type: t,
            statelessVerified: true,
            detectedAt: Date.now()
          });
          break;
        }
      }
    }

    // Also check AWS canary format
    const awsMatch = text.match(/AKIA([A-Z0-9]{16})/g);
    if (awsMatch) {
      for (const [id, rec] of this.activeCanaries.entries()) {
        if (rec.type === HONEYTOKEN_TYPES.AWS_ACCESS_KEY && text.includes(rec.token)) {
          if (!matched.some(m => m.canaryId === id)) {
            matched.push(rec);
          }
        }
      }
    }

    return {
      containsCanary: matched.length > 0,
      matchedCanaries: matched
    };
  }

  /**
   * Generates a realistic synthetic decoy file (e.g. .env, config.json)
   * populated with live canary tokens for cognitive deception.
   *
   * @param {string} filePath - Path of the requested file (e.g., '.env', 'id_rsa')
   * @param {Object} [sessionContext]
   * @returns {string} Plausible decoy content
   */
  generateDecoyContent(filePath, sessionContext = {}) {
    const lower = String(filePath || '').toLowerCase();

    if (lower.endsWith('.env') || lower.includes('.env.')) {
      const oai = this.generateHoneytoken(HONEYTOKEN_TYPES.OPENAI_KEY, sessionContext);
      const ant = this.generateHoneytoken(HONEYTOKEN_TYPES.ANTHROPIC_KEY, sessionContext);
      const aws = this.generateHoneytoken(HONEYTOKEN_TYPES.AWS_ACCESS_KEY, sessionContext);
      const db = this.generateHoneytoken(HONEYTOKEN_TYPES.DATABASE_URL, sessionContext);

      return [
        '# Production Environment Configuration',
        'NODE_ENV=production',
        'PORT=8080',
        `DATABASE_URL="${db.token}"`,
        `OPENAI_API_KEY="${oai.token}"`,
        `ANTHROPIC_API_KEY="${ant.token}"`,
        `AWS_ACCESS_KEY_ID="${aws.token}"`,
        `AWS_SECRET_ACCESS_KEY="${crypto.randomBytes(20).toString('hex')}"`,
        'JWT_SECRET="super-secret-production-signing-key-mirage"'
      ].join('\n');
    }

    if (lower.includes('id_rsa') || lower.includes('id_ed25519')) {
      const ssh = this.generateHoneytoken(HONEYTOKEN_TYPES.SSH_KEY, sessionContext);
      return ssh.token;
    }

    // Default JSON config decoy
    const git = this.generateHoneytoken(HONEYTOKEN_TYPES.GITHUB_PAT, sessionContext);
    return JSON.stringify({
      app: 'vigil-core',
      version: '1.0.0',
      telemetry: false,
      auth: {
        provider: 'github',
        token: git.token
      }
    }, null, 2);
  }

  /**
   * Tripwire trigger handler: called when an agent attempts to transmit, execute,
   * or exfiltrate a detected canary honeytoken.
   *
   * @param {Object} params
   * @param {Object} params.action - Action attempting the exfiltration
   * @param {Array<Object>} params.canaries - Matched canary records
   * @returns {Object} Tripwire security event report
   */
  triggerTripwire({ action, canaries }) {
    const incidentId = `inc-tripwire-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const incident = {
      incidentId,
      timestamp: Date.now(),
      actionHash: action.action_hash || 'unknown',
      agentId: action.agent_id || 'anonymous',
      actionType: action.action_type || 'unknown',
      resource: action.resource || 'unknown',
      canaries: canaries.map(c => ({
        canaryId: c.canaryId,
        type: c.type,
        createdAt: c.createdAt
      })),
      severity: 'CRITICAL',
      reasonCode: REASON_CODES.DENY_CANARY_TRAP_TRIGGERED
    };

    this.tripwireIncidents.push(incident);

    if (this.onCanaryTripwire) {
      try {
        this.onCanaryTripwire(incident);
      } catch {
        // Observer fail-safe
      }
    }

    return incident;
  }
}

module.exports = {
  CognitiveMirageEngine,
  HONEYTOKEN_TYPES
};

