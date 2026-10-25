/**
 * VIGIL - Sensitive Context Injection Policy
 * Security Policy: Enterprise Gatekeeper & Sensitive Surface Deny-List
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

    // Identity Providers, Authentication & Single Sign-On (SSO)
    /^https?:\/\/accounts\.google\.com/i,
    /^https?:\/\/myaccount\.google\.com\/(?:security|signinoptions)/i,
    /^https?:\/\/login\.microsoftonline\.com/i,
    /^https?:\/\/login\.microsoft\.com/i,
    /^https?:\/\/login\.live\.com/i,
    /^https?:\/\/account\.live\.com/i,
    /^https?:\/\/[a-z0-9-]+\.auth0\.com/i,
    /^https?:\/\/[a-z0-9-]+\.okta\.com/i,
    /^https?:\/\/[a-z0-9-]+\.oktapreview\.com/i,
    /^https?:\/\/[a-z0-9-]+\.pingidentity\.com/i,
    /^https?:\/\/[a-z0-9-]+\.pingone\.com/i,
    /^https?:\/\/[a-z0-9-]+\.onelogin\.com/i,
    /^https?:\/\/[a-z0-9-]+\.duosecurity\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?login\.salesforce\.com/i,
    /^https?:\/\/appleid\.apple\.com/i,

    // Password Managers & Vault Portals
    /^https?:\/\/passwords\.google\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?1password\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?bitwarden\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?dashlane\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?lastpass\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?keepersecurity\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?nordpass\.com/i,
    /^https?:\/\/pass\.proton\.me/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?proton\.me\/pass/i,

    // Tier-1 Banking & Financial Portals
    /^https?:\/\/(?:[a-z0-9-]+\.)?chase\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?bankofamerica\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?wellsfargo\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?citi\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?fidelity\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?vanguard\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?schwab\.com/i,
    /^https?:\/\/(?:[a-z0-9-]+\.)?americanexpress\.com/i,

    // Payment Processing, Checkouts & Gateways
    /^https?:\/\/(?:[a-z0-9-]+\.)?paypal\.com/i,
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

