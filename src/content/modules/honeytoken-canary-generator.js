/**
 * VIGIL AI — System 5: Active Counter-Surveillance & Dynamic Honeytoken Canary Generator
 *
 * Dynamically synthesizes zero-value high-fidelity decoy canaries (API keys,
 * cloud credentials, session JWTs, database URLs) tailored to user workflows.
 * Monitors DOM queries, clipboard exfiltration, and outbound transmissions to catch
 * rogue extensions, web scrapers, and malicious AI agents accessing decoy tripwires.
 *
 * 100% On-device deception technology.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_CANARY_GENERATOR = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Active canary registry: canaryValue -> metadata
  const activeCanaries = new Map();

  function fastHash(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
  }

  /**
   * Generates a realistic dummy canary token based on category and workflow seed
   */
  function generateCanary(category, domain = 'general', seed = '') {
    const s = seed || String(Date.now());
    const h = fastHash(`${category}|${domain}|${s}`);
    const h2 = fastHash(`${s}|${category}|${domain}`);

    let canary = null;
    let type = category.toUpperCase();

    switch (type) {
      case 'API_KEY':
        canary = `ak_live_vigil_sec_${h}${h2}`;
        break;
      case 'AWS_KEY':
        canary = `AKIA${h.toUpperCase()}${h2.toUpperCase()}`.slice(0, 20);
        break;
      case 'GITHUB_TOKEN':
        canary = `ghp_canary_${h}${h2}`.slice(0, 40);
        break;
      case 'OPENAI_KEY':
        canary = `sk-proj-canary-${h}-${h2}`;
        break;
      case 'JWT_SESSION':
        canary = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjYW5hcnkiOnRydWUsImlkIjoiY2FuYXJ5Xyke${h}In0.${h2}`;
        break;
      case 'DATABASE_URL':
        canary = `postgres://canary_admin:${h}@db-${domain.replace(/[^a-z0-9]/gi, '')}.internal:5432/production`;
        break;
      case 'EMAIL':
      default:
        canary = `canary.alert.${h}@sentinel-defense.invalid`;
        type = 'EMAIL';
        break;
    }

    const metadata = {
      value: canary,
      type,
      category,
      domain,
      createdAt: Date.now(),
      status: 'ARMED',
      hitCount: 0
    };

    activeCanaries.set(canary, metadata);
    return metadata;
  }

  /**
   * Generates a context-aware canary bundle for the target environment
   */
  function generateContextualBundle(domain = 'general', seed = '') {
    const bundle = {
      domain,
      generatedAt: Date.now(),
      canaries: []
    };

    const host = domain.toLowerCase();
    if (host.includes('github') || host.includes('gitlab')) {
      bundle.canaries.push(generateCanary('GITHUB_TOKEN', domain, seed));
      bundle.canaries.push(generateCanary('API_KEY', domain, seed));
    } else if (host.includes('aws') || host.includes('amazon') || host.includes('cloud')) {
      bundle.canaries.push(generateCanary('AWS_KEY', domain, seed));
      bundle.canaries.push(generateCanary('DATABASE_URL', domain, seed));
    } else if (host.includes('openai') || host.includes('anthropic') || host.includes('claude')) {
      bundle.canaries.push(generateCanary('OPENAI_KEY', domain, seed));
      bundle.canaries.push(generateCanary('JWT_SESSION', domain, seed));
    } else {
      bundle.canaries.push(generateCanary('API_KEY', domain, seed));
      bundle.canaries.push(generateCanary('EMAIL', domain, seed));
    }

    return bundle;
  }

  /**
   * Counter-Surveillance: Inspects payload to detect if any planted canary is present
   */
  function inspectPayloadForCanaries(payload) {
    if (!payload || typeof payload !== 'string' || activeCanaries.size === 0) {
      return { leakDetected: false, triggeredCanaries: [] };
    }

    const triggered = [];
    for (const [canary, meta] of activeCanaries.entries()) {
      if (payload.includes(canary)) {
        meta.hitCount += 1;
        meta.status = 'TRIGGERED';
        meta.lastTriggeredAt = Date.now();
        triggered.push(meta);
      }
    }

    return {
      leakDetected: triggered.length > 0,
      triggeredCanaries: triggered,
      warning: triggered.length > 0
        ? `🚨 Counter-Surveillance Alert: Decoy honeytoken (${triggered[0].type}) detected in data stream. Potential scraper or extension exfiltration!`
        : null
    };
  }

  /**
   * Registers an external canary (e.g. from service worker or vault)
   */
  function registerCanary(canaryValue, type = 'CUSTOM') {
    if (!canaryValue || typeof canaryValue !== 'string') return false;
    activeCanaries.set(canaryValue, {
      value: canaryValue,
      type,
      createdAt: Date.now(),
      status: 'ARMED',
      hitCount: 0
    });
    return true;
  }

  /**
   * Clears all registered canaries
   */
  function clearCanaries() {
    activeCanaries.clear();
  }

  /**
   * Lists all currently armed canaries
   */
  function listCanaries() {
    return Array.from(activeCanaries.values());
  }

  return {
    generateCanary,
    generateContextualBundle,
    inspectPayloadForCanaries,
    registerCanary,
    clearCanaries,
    listCanaries
  };
});

