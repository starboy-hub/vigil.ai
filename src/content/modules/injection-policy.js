/**
 * VIGIL - Sensitive Context Injection Policy
 * Blueprint #13: Enterprise Gatekeeper & Sensitive Surface Deny-List
 * Prevents content script execution on security-sensitive domains such as
 * identity providers, password managers, and payment gateways.
 */
(function (root) {
  'use strict';

  const DENY_PATTERNS = [
    // Browser internal schemes & protocols
    /^chrome:\/\//i,
    /^chrome-extension:\/\//i,
    /^moz-extension:\/\//i,
    /^edge:\/\//i,
    /^about:/i,
    /^data:/i,
    /^blob:/i,
    /^javascript:/i,

    // Identity Providers & Single Sign-On (SSO)
    /^https?:\/\/accounts\.google\.com/i,
    /^https?:\/\/login\.microsoftonline\.com/i,
    /^https?:\/\/login\.microsoft\.com/i,
    /^https?:\/\/login\.live\.com/i,
    /^https?:\/\/[a-z0-9-]+\.auth0\.com/i,
    /^https?:\/\/[a-z0-9-]+\.okta\.com/i,
    /^https?:\/\/appleid\.apple\.com/i,

    // Password Managers & Vault Portals
    /^https?:\/\/(?:[a-z0-9-]+\.)?1password\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?bitwarden\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?dashlane\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?lastpass\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?keepersecurity\.com/i,

    // Payment Processing Checkouts & Financial Portals
    /^https?:\/\/(?:[a-z0-9-]+\.)?paypal\.com\/(?:signin|auth)/i,
    /^https?:\/\/checkout\.stripe\.com/i,
    /^https?:\/\/pay\.google\.com/i
  ];

  /**
   * Evaluates if a given URL is permitted for content script execution.
   * @param {string} url - The URL to inspect (usually window.location.href)
   * @param {string[]} [customDenyList] - Optional user-configured blocked patterns
   * @returns {boolean} True if injection is permitted, false if denied.
   */
  function shouldInjectContentScript(url, customDenyList = []) {
    if (!url || typeof url !== 'string') return false;

    // Check built-in baseline deny-list
    for (const pattern of DENY_PATTERNS) {
      if (pattern.test(url)) {
        return false;
      }
    }

    // Check optional custom deny-list
    if (Array.isArray(customDenyList)) {
      for (const item of customDenyList) {
        if (!item || typeof item !== 'string') continue;
        const trimmed = item.trim().toLowerCase();
        if (!trimmed) continue;
        try {
          if (url.toLowerCase().includes(trimmed)) {
            return false;
          }
        } catch (_) {
          // Ignore invalid custom pattern match errors
        }
      }
    }

    return true;
  }

  const api = {
    DENY_PATTERNS,
    shouldInjectContentScript
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof root !== 'undefined') {
    root.VIGIL_INJECTION_POLICY = api;
  }
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));

