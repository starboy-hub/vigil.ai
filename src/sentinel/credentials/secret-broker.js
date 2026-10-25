/**
 * Sentinel Stage 6: Credentials & Capability Management
 * ====================================================
 * Mediates access to sensitive credentials and APIs using scoped,
 * short-lived, cryptographically-bound Capability Tokens.
 *
 * Prevents autonomous agents from ever receiving raw API keys or secrets.
 * Injects credentials strictly at the execution boundary and scrubs all
 * outbound responses and error frames.
 *
 * Implements Stage 6 of Plan.pdf master execution specification.
 */

'use strict';

const crypto = require('crypto');

const {
  scrubSecretsFromExplanation
} = require('../schemas');

// Capability Error Codes
const CAPABILITY_ERRORS = Object.freeze({
  TOKEN_INVALID_FORMAT: 'TOKEN_INVALID_FORMAT',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_REVOKED: 'TOKEN_REVOKED',
  TOKEN_SIGNATURE_INVALID: 'TOKEN_SIGNATURE_INVALID',
  AGENT_MISMATCH: 'AGENT_MISMATCH',
  SESSION_MISMATCH: 'SESSION_MISMATCH',
  INSUFFICIENT_SCOPE: 'INSUFFICIENT_SCOPE',
  SECRET_NOT_FOUND: 'SECRET_NOT_FOUND',
  SCOPE_NOT_PERMITTED_FOR_SECRET: 'SCOPE_NOT_PERMITTED_FOR_SECRET'
});

class CapabilityTokenManager {
  /**
   * @param {Object} [options]
   * @param {string} [options.signingKey] - HMAC-SHA256 signing secret (generated securely if omitted)
   * @param {number} [options.defaultTtlSecs] - Default token TTL in seconds (default: 900 / 15m)
   */
  constructor(options = {}) {
    this.signingKey = options.signingKey || crypto.randomBytes(32).toString('hex');
    this.defaultTtlSecs = Number.isInteger(options.defaultTtlSecs)
      ? options.defaultTtlSecs
      : 900;
    this.revokedTokenIds = new Set();
  }

  /**
   * Mint a new scoped capability token bound to an agent and session.
   * 
   * @param {Object} params
   * @param {string} params.agentId - Identity of the autonomous agent
   * @param {string} params.sessionId - Execution session ID
   * @param {string[]} params.scopes - Allowed operational scopes (e.g. ['api.github.com:read'])
   * @param {number} [params.ttlSecs] - Lifetime in seconds
   * @param {Object} [params.constraints] - Additional resource constraints
   * @returns {Object} Minted capability token object with compact token string
   */
  mintToken(params) {
    if (!params.agentId || typeof params.agentId !== 'string') {
      throw new Error('agentId is required to mint capability token');
    }
    if (!params.sessionId || typeof params.sessionId !== 'string') {
      throw new Error('sessionId is required to mint capability token');
    }
    if (!Array.isArray(params.scopes) || params.scopes.length === 0) {
      throw new Error('At least one scope is required');
    }

    const tokenId = `cap-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const ttlSecs = Number.isInteger(params.ttlSecs) ? params.ttlSecs : this.defaultTtlSecs;
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + ttlSecs;

    const payload = {
      tokenId,
      agentId: params.agentId,
      sessionId: params.sessionId,
      scopes: params.scopes.slice(),
      constraints: params.constraints || {},
      issuedAt: now,
      expiresAt
    };

    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', this.signingKey)
      .update(payloadB64)
      .digest('base64url');

    const tokenString = `${payloadB64}.${signature}`;

    return {
      tokenId,
      tokenString,
      agentId: params.agentId,
      sessionId: params.sessionId,
      scopes: params.scopes,
      expiresAt,
      issuedAt: now
    };
  }

  /**
   * Validate a capability token string against requested scope and caller context.
   * 
   * @param {string} tokenString
   * @param {string} requiredScope
   * @param {Object} [callerContext]
   * @returns {{ valid: boolean, error?: string, token?: Object }}
   */
  validateToken(tokenString, requiredScope, callerContext = {}) {
    if (!tokenString || typeof tokenString !== 'string') {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_INVALID_FORMAT };
    }

    const parts = tokenString.split('.');
    if (parts.length !== 2) {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_INVALID_FORMAT };
    }

    const [payloadB64, signature] = parts;

    // Verify cryptographic signature
    const expectedSig = crypto
      .createHmac('sha256', this.signingKey)
      .update(payloadB64)
      .digest('base64url');

    // Constant-time comparison
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_SIGNATURE_INVALID };
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch (_e) {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_INVALID_FORMAT };
    }

    // Check revocation
    if (this.revokedTokenIds.has(payload.tokenId)) {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_REVOKED };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.expiresAt) {
      return { valid: false, error: CAPABILITY_ERRORS.TOKEN_EXPIRED };
    }

    // Check agent identity binding
    if (callerContext.agentId && callerContext.agentId !== payload.agentId) {
      return { valid: false, error: CAPABILITY_ERRORS.AGENT_MISMATCH };
    }

    // Check session binding
    if (callerContext.sessionId && callerContext.sessionId !== payload.sessionId) {
      return { valid: false, error: CAPABILITY_ERRORS.SESSION_MISMATCH };
    }

    // Check scope authorization
    if (requiredScope) {
      const isAuthorized = payload.scopes.some((scope) => {
        if (scope === '*' || scope === requiredScope) return true;
        // Prefix wildcard check, e.g. "api.github.com:*" matches "api.github.com:read"
        if (scope.endsWith(':*')) {
          const prefix = scope.slice(0, -1);
          return requiredScope.startsWith(prefix);
        }
        return false;
      });

      if (!isAuthorized) {
        return { valid: false, error: CAPABILITY_ERRORS.INSUFFICIENT_SCOPE };
      }
    }

    return { valid: true, token: payload };
  }

  /**
   * Revoke an active capability token by ID
   */
  revokeToken(tokenId) {
    if (typeof tokenId === 'string') {
      this.revokedTokenIds.add(tokenId);
    }
  }
}

class SentinelSecretBroker {
  /**
   * @param {Object} [options]
   * @param {CapabilityTokenManager} [options.tokenManager]
   * @param {Function} [options.auditCallback]
   */
  constructor(options = {}) {
    this.tokenManager = options.tokenManager || new CapabilityTokenManager();
    this.auditCallback = typeof options.auditCallback === 'function' ? options.auditCallback : null;

    // Secure isolated vault: secretId -> { rawSecret, allowedScopes, registeredAt }
    this._secretStore = new Map();
  }

  /**
   * Register a raw credential in the isolated broker store.
   * Agents never receive this raw secret.
   * 
   * @param {string} secretId - Logical reference (e.g. 'github-read-token')
   * @param {string} rawSecret - Actual secret / API key
   * @param {string[]} allowedScopes - Permitted capability scopes
   */
  registerSecret(secretId, rawSecret, allowedScopes) {
    if (!secretId || typeof secretId !== 'string') {
      throw new Error('Valid secretId string required');
    }
    if (!rawSecret || typeof rawSecret !== 'string') {
      throw new Error('Valid rawSecret string required');
    }
    if (!Array.isArray(allowedScopes) || allowedScopes.length === 0) {
      throw new Error('allowedScopes array required');
    }

    this._secretStore.set(secretId, {
      rawSecret,
      allowedScopes: allowedScopes.slice(),
      registeredAt: Date.now()
    });
  }

  /**
   * Execute an operation requiring credentials on behalf of the agent.
   * The credential is injected at the boundary and scrubbed from all return paths.
   * 
   * @param {Object} options
   * @param {string} options.capabilityToken - Caller's capability token string
   * @param {string} options.requiredScope - Scope required for this execution
   * @param {string} options.secretId - Registered logical secret to inject
   * @param {Function} options.dispatcher - async (rawSecret) => Promise<any>
   * @param {Object} [options.callerContext] - Caller identity { agentId, sessionId }
   * @returns {Promise<Object>} Sanitized execution result
   */
  async executeBrokeredRequest(options) {
    const {
      capabilityToken,
      requiredScope,
      secretId,
      dispatcher,
      callerContext = {}
    } = options;

    // 1. Validate capability token
    const tokenValidation = this.tokenManager.validateToken(capabilityToken, requiredScope, callerContext);
    if (!tokenValidation.valid) {
      this._emitAuditEvent('capability:denied', {
        secretId,
        requiredScope,
        error: tokenValidation.error,
        callerContext
      });

      throw new Error(`Capability authorization failed: ${tokenValidation.error}`);
    }

    // 2. Lookup registered secret
    const secretEntry = this._secretStore.get(secretId);
    if (!secretEntry) {
      this._emitAuditEvent('capability:secret_not_found', { secretId, requiredScope });
      throw new Error(`Secret not found: ${secretId}`);
    }

    // 3. Verify secret supports the requested scope
    const isScopePermitted = secretEntry.allowedScopes.some((s) => {
      if (s === '*' || s === requiredScope) return true;
      if (s.endsWith(':*')) return requiredScope.startsWith(s.slice(0, -1));
      return false;
    });

    if (!isScopePermitted) {
      this._emitAuditEvent('capability:scope_disallowed_for_secret', { secretId, requiredScope });
      throw new Error(`Secret '${secretId}' is not authorized for requested scope '${requiredScope}'`);
    }

    // 4. Execute operation inside protected execution boundary
    let rawResult;
    try {
      rawResult = await dispatcher(secretEntry.rawSecret);
    } catch (dispatchErr) {
      // Scrub the raw secret from any error messages before bubbling
      const scrubbedErrMsg = this._sanitizeString(dispatchErr.message, secretEntry.rawSecret);
      this._emitAuditEvent('capability:dispatch_failed', {
        secretId,
        requiredScope,
        error: scrubbedErrMsg
      });
      throw new Error(`Brokered execution failed: ${scrubbedErrMsg}`);
    }

    // 5. Emit successful usage audit event (strictly zero secrets in event payload)
    this._emitAuditEvent('capability:executed', {
      secretId,
      requiredScope,
      tokenId: tokenValidation.token.tokenId,
      agentId: tokenValidation.token.agentId,
      sessionId: tokenValidation.token.sessionId
    });

    // 6. Deep sanitize the result object
    return this._deepSanitize(rawResult, secretEntry.rawSecret);
  }

  /**
   * Deep sanitize an object, string, or array to scrub all known secrets
   */
  _deepSanitize(value, rawSecret) {
    if (value === null || value === undefined) return value;

    if (typeof value === 'string') {
      return this._sanitizeString(value, rawSecret);
    }

    if (Array.isArray(value)) {
      return value.map((item) => this._deepSanitize(item, rawSecret));
    }

    if (typeof value === 'object') {
      const sanitized = {};
      for (const [k, v] of Object.entries(value)) {
        sanitized[k] = this._deepSanitize(v, rawSecret);
      }
      return sanitized;
    }

    return value;
  }

  /**
   * Scrub both the specific injected secret and generic secret patterns
   */
  _sanitizeString(str, rawSecret) {
    if (typeof str !== 'string') return str;

    let sanitized = str;
    if (rawSecret && rawSecret.length >= 4) {
      sanitized = sanitized.split(rawSecret).join('[REDACTED_BROKERED_SECRET]');
    }

    return scrubSecretsFromExplanation(sanitized);
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
      // Audit failure must not crash execution
    }
  }
}

module.exports = {
  CapabilityTokenManager,
  SentinelSecretBroker,
  CAPABILITY_ERRORS
};
