/**
 * Sentinel Stage 10: REST / HTTP Proxy Enforcement Adapter
 * ========================================================
 * Policy-enforcing HTTP proxy intercepting autonomous agent network egress,
 * cloud metadata requests, and external API calls. Mediates capability tokens
 * and injects brokered secrets at the network perimeter.
 *
 * Implements Stage 10 of Plan.pdf master execution specification.
 */

'use strict';

const crypto = require('crypto');
const {
  DECISION_DENY,
  DECISION_REQUIRE_APPROVAL,
  ACTION_NET_REQUEST
} = require('../constants');

const { SentinelPolicyEngine } = require('../policy-engine');
const { scrubSecretsFromExplanation } = require('../schemas');

class SentinelRestProxy {
  /**
   * @param {Object} [options]
   * @param {SentinelPolicyEngine} [options.policyEngine]
   * @param {Object} [options.secretBroker] - Optional SentinelSecretBroker
   * @param {Function} [options.forwardHandler] - Injectable forward dispatcher: async (url, method, headers, body) => { statusCode, headers, body }
   * @param {Function} [options.auditCallback]
   */
  constructor(options = {}) {
    this.policyEngine = options.policyEngine || new SentinelPolicyEngine();
    this.secretBroker = options.secretBroker || null;
    this.forwardHandler = typeof options.forwardHandler === 'function' ? options.forwardHandler : null;
    this.auditCallback = typeof options.auditCallback === 'function' ? options.auditCallback : null;
  }

  /**
   * Handle incoming HTTP/REST request from autonomous agent
   * 
   * @param {Object} request
   * @param {string} request.url - Full target URL
   * @param {string} [request.method='GET'] - HTTP Method
   * @param {Object} [request.headers] - HTTP Headers
   * @param {string|Object} [request.body] - Request body
   * @param {Object} [sessionContext]
   * @returns {Promise<{ statusCode: number, headers: Object, body: any }>}
   */
  async handleRequest(request, sessionContext = {}) {
    if (!request || !request.url || typeof request.url !== 'string') {
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: { error: 'BAD_REQUEST', message: 'Missing or invalid request URL' }
      };
    }

    const method = (request.method || 'GET').toUpperCase();
    const headers = request.headers || {};
    const capabilityToken = headers['x-sentinel-capability-token'] || headers['x-sentinel-capability'] || null;
    const secretId = headers['x-sentinel-secret-id'] || null;
    const requiredScope = headers['x-sentinel-required-scope'] || null;

    // 1. Map to Sentinel Action Schema
    const action = {
      schema_version: '1.0.0',
      request_id: `req-rest-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      session_id: sessionContext.sessionId || headers['x-sentinel-session-id'] || 'rest-session-default',
      agent_id: sessionContext.agentId || headers['x-sentinel-agent-id'] || 'rest-agent',
      adapter: { id: 'sentinel-rest-proxy', version: '1.0.0', type: 'rest' },
      action_type: ACTION_NET_REQUEST,
      resource: request.url,
      parameters: {
        method,
        headers: { ...headers }
      },
      timestamp: Date.now(),
      approval_token: sessionContext.approvalToken || null
    };

    // 2. Evaluate Policy
    const decision = await this.policyEngine.evaluate(action, sessionContext);

    // 3. DENY Path (Hard safety rules: e.g. IMDS 169.254.169.254)
    if (decision.decision === DECISION_DENY) {
      this._emitAuditEvent('rest:blocked', { url: request.url, decision });

      return {
        statusCode: 403,
        headers: {
          'content-type': 'application/json',
          'x-sentinel-decision': 'deny',
          'x-sentinel-reason': decision.reason_code
        },
        body: {
          error: 'SENTINEL_POLICY_DENIED',
          reason_code: decision.reason_code,
          explanation: scrubSecretsFromExplanation(decision.explanation)
        }
      };
    }

    // 4. Brokered Secret & Capability Token Path
    if (capabilityToken && this.secretBroker) {
      try {
        const brokeredResult = await this.secretBroker.executeBrokeredRequest({
          capabilityToken,
          requiredScope: requiredScope || `${new URL(request.url).hostname}:read`,
          secretId: secretId || 'default-secret',
          callerContext: { agentId: action.agent_id, sessionId: action.session_id },
          dispatcher: async (rawSecret) => {
            const injectedHeaders = { ...headers, authorization: `Bearer ${rawSecret}` };
            delete injectedHeaders['x-sentinel-capability-token'];
            delete injectedHeaders['x-sentinel-secret-id'];

            if (this.forwardHandler) {
              return await this.forwardHandler(request.url, method, injectedHeaders, request.body);
            }

            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: { message: `Brokered request to ${request.url} succeeded.` }
            };
          }
        });

        return brokeredResult;
      } catch (brokerErr) {
        return {
          statusCode: 401,
          headers: { 'content-type': 'application/json' },
          body: {
            error: 'BROKER_AUTHORIZATION_FAILED',
            message: scrubSecretsFromExplanation(brokerErr.message)
          }
        };
      }
    }

    // 5. REQUIRE_APPROVAL Path
    if (decision.decision === DECISION_REQUIRE_APPROVAL) {
      this._emitAuditEvent('rest:approval_required', { url: request.url, decision });

      return {
        statusCode: 403,
        headers: {
          'content-type': 'application/json',
          'x-sentinel-decision': 'require_approval',
          'x-sentinel-reason': decision.reason_code
        },
        body: {
          error: 'SENTINEL_REQUIRE_APPROVAL',
          reason_code: decision.reason_code,
          explanation: scrubSecretsFromExplanation(decision.explanation)
        }
      };
    }

    // 6. ALLOW Path - Standard Forwarding
    this._emitAuditEvent('rest:allowed', { url: request.url, decision });

    // Standard Forwarding
    if (this.forwardHandler) {
      try {
        const response = await this.forwardHandler(request.url, method, headers, request.body);
        return {
          statusCode: response.statusCode || 200,
          headers: response.headers || { 'content-type': 'application/json' },
          body: response.body
        };
      } catch (fwdErr) {
        return {
          statusCode: 502,
          headers: { 'content-type': 'application/json' },
          body: { error: 'BAD_GATEWAY', message: scrubSecretsFromExplanation(fwdErr.message) }
        };
      }
    }

    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: { message: `Request to ${request.url} permitted by Sentinel.` }
    };
  }

  _emitAuditEvent(eventType, payload) {
    if (!this.auditCallback) return;
    try {
      this.auditCallback({
        event_type: eventType,
        timestamp: new Date().toISOString(),
        payload
      });
    } catch (_ignore) {}
  }
}

module.exports = {
  SentinelRestProxy
};
