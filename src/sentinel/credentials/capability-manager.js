/**
 * Sentinel Cryptographic Tool Capability Token Manager (MCP Hardening)
 * =====================================================================
 * Generates and verifies attenuated, ephemeral HMAC-SHA256 capability tokens
 * (Macaroon-style object capabilities) for Model Context Protocol (MCP) tool invocations.
 *
 * Prevents tool-chaining privilege escalation attacks by binding each tool execution
 * to single-use, cryptographically verified tokens with strict TTL and path attenuation.
 */
'use strict';

const crypto = require('node:crypto');

const DEFAULT_CAPABILITY_TTL_MS = 30000; // 30 seconds

class CapabilityManager {
  /**
   * @param {Object} [options]
   * @param {string} [options.masterSecret] - 32-byte master HMAC key (generated if omitted)
   * @param {number} [options.defaultTtlMs] - Default capability TTL in milliseconds
   */
  constructor(options = {}) {
    this.masterSecret = options.masterSecret || crypto.randomBytes(32).toString('hex');
    this.defaultTtlMs = options.defaultTtlMs || DEFAULT_CAPABILITY_TTL_MS;
    this.consumedNonces = new Set();
  }

  /**
   * Generates a signed, ephemeral capability token bound to a specific agent and resource.
   *
   * @param {Object} params
   * @param {string} params.agentId - Identity of the autonomous agent
   * @param {string} params.sessionId - Active session / conversation ID
   * @param {string} params.actionType - Action permitted (e.g. 'fs:read', 'fs:write')
   * @param {string} params.resource - Specific canonical resource path or pattern
   * @param {number} [params.ttlMs] - Custom TTL in milliseconds
   * @returns {string} Encoded capability token string
   */
  issueCapability({ agentId, sessionId, actionType, resource, ttlMs }) {
    if (!agentId || !sessionId || !actionType || !resource) {
      throw new Error('agentId, sessionId, actionType, and resource are required to issue a capability');
    }

    const nonce = crypto.randomBytes(16).toString('hex');
    const issuedAt = Date.now();
    const expiry = issuedAt + (ttlMs || this.defaultTtlMs);

    const payload = {
      v: 1,
      aid: String(agentId),
      sid: String(sessionId),
      act: String(actionType),
      res: String(resource),
      iat: issuedAt,
      exp: expiry,
      nce: nonce
    };

    const signature = this._signPayload(payload);
    const tokenObj = { ...payload, sig: signature };

    return Buffer.from(JSON.stringify(tokenObj), 'utf8').toString('base64url');
  }

  /**
   * Attenuates an existing capability token into a more restricted child token.
   *
   * @param {string} parentToken - Existing encoded capability token
   * @param {Object} restrictions - Additional restrictions to apply
   * @param {string} [restrictions.subResource] - More specific subpath
   * @param {number} [restrictions.shorterTtlMs] - Reduced TTL
   * @returns {string} Attenuated capability token
   */
  attenuate(parentToken, restrictions = {}) {
    const parent = this.decodeToken(parentToken);
    if (!parent || !this.verifyToken(parentToken).valid) {
      throw new Error('Cannot attenuate an invalid or expired capability token');
    }

    const subResource = restrictions.subResource || parent.res;
    // Sub-resource must stay within parent resource boundary
    if (!subResource.startsWith(parent.res)) {
      throw new Error(`Attenuated resource "${subResource}" must be a subpath of parent "${parent.res}"`);
    }

    const newExpiry = restrictions.shorterTtlMs
      ? Math.min(parent.exp, Date.now() + restrictions.shorterTtlMs)
      : parent.exp;

    const childNonce = crypto.randomBytes(16).toString('hex');
    const childPayload = {
      v: 1,
      aid: parent.aid,
      sid: parent.sid,
      act: parent.act,
      res: subResource,
      iat: Date.now(),
      exp: newExpiry,
      nce: childNonce,
      parent_sig: parent.sig
    };

    const signature = this._signPayload(childPayload);
    const childTokenObj = { ...childPayload, sig: signature };

    return Buffer.from(JSON.stringify(childTokenObj), 'utf8').toString('base64url');
  }

  /**
   * Decodes a base64url capability token into an object.
   * @param {string} tokenStr
   * @returns {Object|null}
   */
  decodeToken(tokenStr) {
    try {
      const json = Buffer.from(tokenStr, 'base64url').toString('utf8');
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  /**
   * Verifies the cryptographic authenticity and TTL of a capability token.
   *
   * @param {string} tokenStr - Capability token string
   * @param {boolean} [consumeNonce=false] - Whether to mark the nonce as consumed
   * @returns {{ valid: boolean, reason?: string, capability?: Object }}
   */
  verifyToken(tokenStr, consumeNonce = false) {
    const payload = this.decodeToken(tokenStr);
    if (!payload || typeof payload !== 'object') {
      return { valid: false, reason: 'MALFORMED_CAPABILITY_TOKEN' };
    }

    // 1. Verify schema and essential fields
    if (!payload.sig || !payload.aid || !payload.sid || !payload.act || !payload.res || !payload.exp || !payload.nce) {
      return { valid: false, reason: 'MISSING_CAPABILITY_FIELDS' };
    }

    // 2. Check replay consumption
    if (this.consumedNonces.has(payload.nce)) {
      return { valid: false, reason: 'REPLAYED_CAPABILITY_NONCE' };
    }

    // 3. Check expiration
    if (Date.now() > payload.exp) {
      return { valid: false, reason: 'EXPIRED_CAPABILITY_TOKEN' };
    }

    // 4. Verify HMAC signature
    const signature = payload.sig;
    const unsigned = { ...payload };
    delete unsigned.sig;

    const expectedSignature = this._signPayload(unsigned);
    const validSig = crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );

    if (!validSig) {
      return { valid: false, reason: 'INVALID_CAPABILITY_SIGNATURE' };
    }

    if (consumeNonce) {
      this.consumedNonces.add(payload.nce);
    }

    return { valid: true, capability: payload };
  }

  /**
   * Verifies that an incoming tool action is permitted by the supplied capability token.
   *
   * @param {string} tokenStr - Base64url token string
   * @param {Object} action - Action request object
   * @returns {{ allowed: boolean, reason?: string }}
   */
  authorizeAction(tokenStr, action) {
    if (!tokenStr) {
      return { allowed: false, reason: 'MISSING_CAPABILITY_TOKEN' };
    }

    const verification = this.verifyToken(tokenStr, false);
    if (!verification.valid) {
      return { allowed: false, reason: verification.reason };
    }

    const cap = verification.capability;

    // Check agent binding
    if (action.agent_id && action.agent_id !== cap.aid) {
      return { allowed: false, reason: 'AGENT_IDENTITY_MISMATCH' };
    }

    // Check action type binding
    if (action.action_type && action.action_type !== cap.act) {
      return { allowed: false, reason: 'ACTION_TYPE_MISMATCH' };
    }

    // Check resource path boundary
    const targetResource = action.resource || '';
    if (!targetResource.startsWith(cap.res)) {
      return { allowed: false, reason: 'RESOURCE_SCOPE_EXCEEDED' };
    }

    return { allowed: true };
  }

  /**
   * Computes HMAC-SHA256 signature over payload contents.
   * @private
   */
  _signPayload(payload) {
    const keys = Object.keys(payload).sort();
    const message = keys.map(k => `${k}=${payload[k]}`).join('&');
    return crypto.createHmac('sha256', this.masterSecret).update(message).digest('hex');
  }
}

module.exports = {
  CapabilityManager,
  DEFAULT_CAPABILITY_TTL_MS
};

