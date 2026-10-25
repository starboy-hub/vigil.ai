/**
 * Sentinel Security Layer: Versioned Schemas & Validators
 * Part of Vigil AI + Sentinel (Plan.pdf - Stage 2)
 *
 * Implements strict, defensive validation for Actions, Decisions, and Events.
 * Never trusts model-supplied paths, IDs, or risk scores without validation.
 */
'use strict';

const crypto = require('crypto');
const {
  VALID_DECISIONS,
  VALID_ACTION_TYPES,
  VALID_EVENT_TYPES,
  REASON_CODES
} = require('./constants');

const CURRENT_SCHEMA_VERSION = '1.0.0';

/**
 * Validates a versioned Action Schema object.
 * Returns { valid: true, sanitized: Object } or { valid: false, errors: Array<string> }
 */
function validateActionSchema(action) {
  const errors = [];
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    return { valid: false, errors: ['Action must be a non-null object'] };
  }

  // Schema version
  if (!action.schema_version || typeof action.schema_version !== 'string') {
    errors.push('Missing or invalid schema_version (expected string)');
  }

  // Request ID
  if (!action.request_id || typeof action.request_id !== 'string' || action.request_id.trim().length === 0) {
    errors.push('Missing or invalid request_id (non-empty string required)');
  }

  // Session ID
  if (!action.session_id || typeof action.session_id !== 'string' || action.session_id.trim().length === 0) {
    errors.push('Missing or invalid session_id (non-empty string required)');
  }

  // Authenticated Agent Identity
  if (!action.agent_id || typeof action.agent_id !== 'string' || action.agent_id.trim().length === 0) {
    errors.push('Missing or invalid agent_id (non-empty string required)');
  }

  // Adapter metadata
  if (!action.adapter || typeof action.adapter !== 'object' || Array.isArray(action.adapter)) {
    errors.push('Missing or invalid adapter object');
  } else {
    if (!action.adapter.id || typeof action.adapter.id !== 'string') {
      errors.push('Missing or invalid adapter.id');
    }
    if (!action.adapter.version || typeof action.adapter.version !== 'string') {
      errors.push('Missing or invalid adapter.version');
    }
    if (!action.adapter.type || typeof action.adapter.type !== 'string') {
      errors.push('Missing or invalid adapter.type');
    }
  }

  // Action type
  if (!action.action_type || !VALID_ACTION_TYPES.includes(action.action_type)) {
    errors.push(`Invalid action_type "${action.action_type}". Expected one of: ${VALID_ACTION_TYPES.join(', ')}`);
  }

  // Resource identifier
  if (typeof action.resource !== 'string' || action.resource.trim().length === 0) {
    errors.push('Missing or invalid resource identifier (non-empty string required)');
  }

  // Normalized parameters
  if (action.parameters !== undefined && (typeof action.parameters !== 'object' || action.parameters === null || Array.isArray(action.parameters))) {
    errors.push('parameters must be an object if supplied');
  }

  // Timestamp: supports epoch milliseconds or ISO 8601 string
  let ts = Number(action.timestamp);
  if ((!ts || isNaN(ts) || ts <= 0) && typeof action.timestamp === 'string') {
    const parsed = Date.parse(action.timestamp);
    if (!isNaN(parsed) && parsed > 0) ts = parsed;
  }
  if (!ts || isNaN(ts) || ts <= 0) {
    errors.push('Missing or invalid timestamp (positive integer epoch timestamp or valid ISO 8601 string required)');
  }

  // Optional Risk Signals
  if (action.risk_signals !== undefined && !Array.isArray(action.risk_signals)) {
    errors.push('risk_signals must be an array if supplied');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  // Return clean, normalized action structure
  const sanitized = {
    schema_version: action.schema_version,
    request_id: action.request_id.trim(),
    session_id: action.session_id.trim(),
    agent_id: action.agent_id.trim(),
    adapter: {
      id: action.adapter.id.trim(),
      version: action.adapter.version.trim(),
      type: action.adapter.type.trim()
    },
    action_type: action.action_type,
    resource: action.resource.trim(),
    parameters: action.parameters || {},
    requested_scope: typeof action.requested_scope === 'string' ? action.requested_scope.trim() : 'default',
    timestamp: ts,
    expiry: action.expiry ? Number(action.expiry) : null,
    risk_signals: Array.isArray(action.risk_signals) ? action.risk_signals : [],
    correlation_id: typeof action.correlation_id === 'string' ? action.correlation_id.trim() : action.request_id.trim(),
    idempotency_key: typeof action.idempotency_key === 'string' ? action.idempotency_key.trim() : null
  };

  return { valid: true, sanitized };
}

/**
 * Validates a Decision Schema object.
 */
function validateDecisionSchema(decision) {
  const errors = [];
  if (!decision || typeof decision !== 'object' || Array.isArray(decision)) {
    return { valid: false, errors: ['Decision must be a non-null object'] };
  }

  if (!decision.schema_version || typeof decision.schema_version !== 'string') {
    errors.push('Missing or invalid schema_version');
  }

  if (!decision.decision || !VALID_DECISIONS.includes(decision.decision)) {
    errors.push(`Invalid decision "${decision.decision}". Expected: ${VALID_DECISIONS.join(', ')}`);
  }

  if (!decision.reason_code || typeof decision.reason_code !== 'string' || !REASON_CODES[decision.reason_code]) {
    errors.push(`Invalid or unrecognized reason_code "${decision.reason_code}"`);
  }

  if (!decision.explanation || typeof decision.explanation !== 'string') {
    errors.push('explanation must be a non-empty string');
  }

  if (!Array.isArray(decision.matched_policy_ids)) {
    errors.push('matched_policy_ids must be an array of rule strings');
  }

  if (!decision.policy_version || typeof decision.policy_version !== 'string') {
    errors.push('Missing or invalid policy_version');
  }

  if (!decision.request_id || typeof decision.request_id !== 'string') {
    errors.push('Missing or invalid request_id');
  }

  if (!decision.audit_reference || typeof decision.audit_reference !== 'string') {
    errors.push('Missing or invalid audit_reference');
  }

  if (!decision.action_hash || typeof decision.action_hash !== 'string' || decision.action_hash.length !== 64) {
    errors.push('Missing or invalid action_hash (expected 64-char hex SHA-256 string for TOCTOU binding)');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, decision };
}

/**
 * Validates an Event Schema object.
 */
function validateEventSchema(event) {
  const errors = [];
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return { valid: false, errors: ['Event must be a non-null object'] };
  }

  if (!event.schema_version || typeof event.schema_version !== 'string') {
    errors.push('Missing or invalid schema_version');
  }

  if (!event.event_id || typeof event.event_id !== 'string') {
    errors.push('Missing or invalid event_id');
  }

  if (!event.event_type || !VALID_EVENT_TYPES.includes(event.event_type)) {
    errors.push(`Invalid event_type "${event.event_type}". Expected: ${VALID_EVENT_TYPES.join(', ')}`);
  }

  if (!event.timestamp || typeof event.timestamp !== 'string') {
    errors.push('timestamp must be a valid ISO-8601 string');
  }

  if (!event.request_id || typeof event.request_id !== 'string') {
    errors.push('Missing or invalid request_id');
  }

  if (!event.session_id || typeof event.session_id !== 'string') {
    errors.push('Missing or invalid session_id');
  }

  if (!event.agent_id || typeof event.agent_id !== 'string') {
    errors.push('Missing or invalid agent_id');
  }

  if (!event.action_type || !VALID_ACTION_TYPES.includes(event.action_type)) {
    errors.push('Missing or invalid action_type');
  }

  if (typeof event.canonical_resource !== 'string') {
    errors.push('canonical_resource must be a string');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true, event };
}

/**
 * Generates a deterministic canonical action hash for TOCTOU binding.
 * Binds the request_id, action_type, canonical resource, and sorted parameters.
 */
function computeActionHash(action) {
  const normResource = String(action.resource || '').trim();
  const sortedParams = action.parameters ? JSON.stringify(action.parameters, Object.keys(action.parameters).sort()) : '{}';
  const payload = [
    action.schema_version || CURRENT_SCHEMA_VERSION,
    action.request_id || '',
    action.agent_id || '',
    action.action_type || '',
    normResource,
    sortedParams
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Secret scrubber: guarantees that human-readable explanations and audit logs
 * never contain raw credentials, tokens, or private keys.
 */
function scrubSecretsFromExplanation(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]')
    .replace(/(?:ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,})/g, '[REDACTED_GITHUB_PAT]')
    .replace(/sk-[a-zA-Z0-9_-]{20,}/g, '[REDACTED_API_KEY]')
    .replace(/-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
}

module.exports = {
  CURRENT_SCHEMA_VERSION,
  validateActionSchema,
  validateDecisionSchema,
  validateEventSchema,
  computeActionHash,
  scrubSecretsFromExplanation
};
