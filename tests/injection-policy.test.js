/**
 * Unit Tests for Blueprint #13: Enterprise Injection Policy & Deny-List
 * Validates sensitive domain exclusion, SSO guard, password manager denial,
 * and user-defined custom deny rules.
 */
const VIGIL_INJECTION_POLICY = require('../src/content/modules/injection-policy.js');
const { shouldInjectContentScript } = VIGIL_INJECTION_POLICY;

describe('Blueprint #13: Sensitive Context Injection Policy', () => {
  describe('Internal browser & special schemes', () => {
    test('blocks chrome:// internal URLs', () => {
      expect(shouldInjectContentScript('chrome://settings/passwords')).toBe(false);
      expect(shouldInjectContentScript('chrome://extensions')).toBe(false);
    });

    test('blocks extension schemes', () => {
      expect(shouldInjectContentScript('chrome-extension://xyz/options.html')).toBe(false);
      expect(shouldInjectContentScript('moz-extension://abc/popup.html')).toBe(false);
    });

    test('blocks about, data, and blob URLs', () => {
      expect(shouldInjectContentScript('about:blank')).toBe(false);
      expect(shouldInjectContentScript('data:text/html,<h1>test</h1>')).toBe(false);
      expect(shouldInjectContentScript('blob:https://example.com/uuid')).toBe(false);
    });
  });

  describe('Identity Providers & SSO', () => {
    test('blocks Google Accounts and Security management surfaces', () => {
      expect(shouldInjectContentScript('https://accounts.google.com/signin/v2/identifier')).toBe(false);
      expect(shouldInjectContentScript('https://accounts.google.com/ServiceLogin')).toBe(false);
      expect(shouldInjectContentScript('https://myaccount.google.com/security')).toBe(false);
      expect(shouldInjectContentScript('https://myaccount.google.com/signinoptions/two-step-verification')).toBe(false);
    });

    test('blocks Microsoft Identity and Azure AD', () => {
      expect(shouldInjectContentScript('https://login.microsoftonline.com/common/oauth2/authorize')).toBe(false);
      expect(shouldInjectContentScript('https://login.microsoft.com/')).toBe(false);
      expect(shouldInjectContentScript('https://login.live.com/login.srf')).toBe(false);
      expect(shouldInjectContentScript('https://account.live.com/proofs/manage/additional')).toBe(false);
    });

    test('blocks Auth0, Okta, Ping, OneLogin, and Duo enterprise tenants', () => {
      expect(shouldInjectContentScript('https://acme-corp.auth0.com/login')).toBe(false);
      expect(shouldInjectContentScript('https://company.okta.com/oauth2/v1/authorize')).toBe(false);
      expect(shouldInjectContentScript('https://company.oktapreview.com/login/default')).toBe(false);
      expect(shouldInjectContentScript('https://auth.pingidentity.com/as/authorization.oauth2')).toBe(false);
      expect(shouldInjectContentScript('https://apps.pingone.com/myapps')).toBe(false);
      expect(shouldInjectContentScript('https://company.onelogin.com/login')).toBe(false);
      expect(shouldInjectContentScript('https://api-12345.duosecurity.com/frame/prompt')).toBe(false);
    });

    test('blocks Salesforce login and Apple ID', () => {
      expect(shouldInjectContentScript('https://login.salesforce.com/')).toBe(false);
      expect(shouldInjectContentScript('https://mycompany.login.salesforce.com/')).toBe(false);
      expect(shouldInjectContentScript('https://appleid.apple.com/auth/authorize')).toBe(false);
    });
  });

  describe('Password Managers and Vault Portals', () => {
    test('blocks Google Passwords portal', () => {
      expect(shouldInjectContentScript('https://passwords.google.com/')).toBe(false);
      expect(shouldInjectContentScript('https://passwords.google.com/checkup')).toBe(false);
    });

    test('blocks 1Password web vaults', () => {
      expect(shouldInjectContentScript('https://my.1password.com/vaults/all')).toBe(false);
      expect(shouldInjectContentScript('https://start.1password.com/signin')).toBe(false);
    });

    test('blocks Bitwarden web vaults', () => {
      expect(shouldInjectContentScript('https://vault.bitwarden.com/#/vault')).toBe(false);
      expect(shouldInjectContentScript('https://bitwarden.com/')).toBe(false);
    });

    test('blocks Dashlane, LastPass, Keeper, NordPass, and Proton Pass portals', () => {
      expect(shouldInjectContentScript('https://app.dashlane.com/login')).toBe(false);
      expect(shouldInjectContentScript('https://lastpass.com/?ac=1')).toBe(false);
      expect(shouldInjectContentScript('https://keepersecurity.com/vault/')).toBe(false);
      expect(shouldInjectContentScript('https://nordpass.com/')).toBe(false);
      expect(shouldInjectContentScript('https://pass.proton.me/')).toBe(false);
      expect(shouldInjectContentScript('https://proton.me/pass')).toBe(false);
    });
  });

  describe('Tier-1 Banking & Financial Portals', () => {
    test('blocks tier-1 consumer banking and brokerage portals', () => {
      expect(shouldInjectContentScript('https://www.chase.com/')).toBe(false);
      expect(shouldInjectContentScript('https://secure01a.chase.com/web/auth/dashboard')).toBe(false);
      expect(shouldInjectContentScript('https://www.bankofamerica.com/')).toBe(false);
      expect(shouldInjectContentScript('https://www.wellsfargo.com/')).toBe(false);
      expect(shouldInjectContentScript('https://online.citi.com/US/login.do')).toBe(false);
      expect(shouldInjectContentScript('https://www.fidelity.com/')).toBe(false);
      expect(shouldInjectContentScript('https://investor.vanguard.com/')).toBe(false);
      expect(shouldInjectContentScript('https://client.schwab.com/Login/SignOn/CustomerCenterLogin.aspx')).toBe(false);
      expect(shouldInjectContentScript('https://www.americanexpress.com/')).toBe(false);
    });
  });

  describe('Financial and Payment Checkout Portals', () => {
    test('blocks PayPal checkout and authentication', () => {
      expect(shouldInjectContentScript('https://www.paypal.com/signin')).toBe(false);
      expect(shouldInjectContentScript('https://paypal.com/auth/flow')).toBe(false);
      expect(shouldInjectContentScript('https://www.paypal.com/checkoutnow')).toBe(false);
    });

    test('blocks Stripe Checkout and Google Pay', () => {
      expect(shouldInjectContentScript('https://checkout.stripe.com/pay/cs_test_123')).toBe(false);
      expect(shouldInjectContentScript('https://pay.google.com/payments/home')).toBe(false);
    });
  });

  describe('AI Web Applications and Standard Sites (Permitted)', () => {
    test('allows ChatGPT, Claude, and Gemini', () => {
      expect(shouldInjectContentScript('https://chatgpt.com/')).toBe(true);
      expect(shouldInjectContentScript('https://claude.ai/chat')).toBe(true);
      expect(shouldInjectContentScript('https://gemini.google.com/app')).toBe(true);
    });

    test('allows general web apps, GitHub, and docs', () => {
      expect(shouldInjectContentScript('https://github.com/starboy-hub/vigil.ai')).toBe(true);
      expect(shouldInjectContentScript('https://developer.mozilla.org/en-US/')).toBe(true);
    });
  });

  describe('User-Defined Custom Deny Patterns', () => {
    test('respects custom domain strings', () => {
      const customDeny = ['internal-bank.intranet', 'secret-portal.corp'];
      expect(shouldInjectContentScript('https://internal-bank.intranet/home', customDeny)).toBe(false);
      expect(shouldInjectContentScript('https://secret-portal.corp/dashboard', customDeny)).toBe(false);
      expect(shouldInjectContentScript('https://chatgpt.com/', customDeny)).toBe(true);
    });

    test('gracefully handles empty, null or invalid inputs', () => {
      expect(shouldInjectContentScript('')).toBe(false);
      expect(shouldInjectContentScript(null)).toBe(false);
      expect(shouldInjectContentScript(undefined)).toBe(false);
      expect(shouldInjectContentScript(12345)).toBe(false);
    });
  });
});

