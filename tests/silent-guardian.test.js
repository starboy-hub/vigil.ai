/**
 * Unit tests for Task 2: UI/UX Silent Guardian (Curing Alert Fatigue)
 * Tests SEVERITY_MAP, getSeverity, debounce, pure DOM UI components
 * (Yellow Banner, Green Shield, Toast, Red Pill), and routing logic.
 */

const fs = require('fs');
const path = require('path');

// Mock chrome extension APIs before loading scripts
if (!global.chrome) {
  global.chrome = {
    runtime: { sendMessage: jest.fn(), onMessage: { addListener: jest.fn() }, getURL: jest.fn(f => f) },
    storage: {
      local: { get: jest.fn((k, cb) => cb && cb({})), set: jest.fn() },
      sync: { get: jest.fn((k, cb) => cb && cb({})), set: jest.fn() },
      onChanged: { addListener: jest.fn() }
    }
  };
} else {
  if (!global.chrome.runtime) global.chrome.runtime = { sendMessage: jest.fn(), onMessage: { addListener: jest.fn() }, getURL: jest.fn(f => f) };
  if (!global.chrome.storage) global.chrome.storage = {
    local: { get: jest.fn((k, cb) => cb && cb({})), set: jest.fn() },
    sync: { get: jest.fn((k, cb) => cb && cb({})), set: jest.fn() },
    onChanged: { addListener: jest.fn() }
  };
}

// Load shared module and content script in jsdom environment
const VIGIL = require('../src/shared/vigil-shared.js');

// Evaluate content script to populate globalThis helpers
eval(fs.readFileSync(path.join(__dirname, '..', 'src', 'content', 'content.js'), 'utf8'));

const {
  renderComposerPill,
  removeComposerPill,
  renderYellowBanner,
  removeYellowBanner,
  renderGreenShield,
  removeGreenShield,
  showSilentToast,
  formatMaskedToastMessage,
  debounce
} = globalThis.__VIGIL_UI_HELPERS__;

describe('Task 2: Severity-Based Interruption Engine', () => {

  describe('SEVERITY_MAP & getSeverity', () => {
    test('SEVERITY_MAP contains CRITICAL, MEDIUM, and LOW tiers', () => {
      expect(VIGIL.SEVERITY_MAP).toBeDefined();
      expect(Array.isArray(VIGIL.SEVERITY_MAP.CRITICAL)).toBe(true);
      expect(Array.isArray(VIGIL.SEVERITY_MAP.MEDIUM)).toBe(true);
      expect(Array.isArray(VIGIL.SEVERITY_MAP.LOW)).toBe(true);
    });

    test('categorizes CRITICAL items correctly', () => {
      const criticalTypes = [
        'Credit Cards', 'Credit Card',
        'SSNs', 'SSN',
        'Passwords', 'Password',
        'API Keys', 'API Key', 'API_KEY',
        'Private Keys', 'Private Key', 'PRIVATE_KEY',
        'CREDENTIALS', 'DATABASE_URI', 'INJECTION', 'HONEYTOKEN', 'Vault Secret'
      ];
      criticalTypes.forEach(type => {
        expect(VIGIL.getSeverity(type)).toBe('CRITICAL');
      });
    });

    test('categorizes MEDIUM items correctly', () => {
      const mediumTypes = [
        'Financial data', 'FINANCIAL', 'Bank Account',
        'proprietary code snippets', 'CODE_SNIPPET', 'PROPRIETARY_CODE',
        'medical context', 'MEDICAL', 'CONDITION', 'MEDICATION', 'Medical Record',
        'LEGAL', 'EMPLOYMENT'
      ];
      mediumTypes.forEach(type => {
        expect(VIGIL.getSeverity(type)).toBe('MEDIUM');
      });
    });

    test('categorizes LOW items correctly', () => {
      const lowTypes = [
        'Names', 'Name',
        'Emails', 'Email',
        'Phone numbers', 'Phone',
        'generic addresses', 'Address',
        'IP Address', 'Date of Birth', 'Passport', 'Driver License', 'PERSONAL'
      ];
      lowTypes.forEach(type => {
        expect(VIGIL.getSeverity(type)).toBe('LOW');
      });
    });

    test('handles case-insensitivity and defaults safely', () => {
      expect(VIGIL.getSeverity('credit card')).toBe('CRITICAL');
      expect(VIGIL.getSeverity('api_key')).toBe('CRITICAL');
      expect(VIGIL.getSeverity('financial')).toBe('MEDIUM');
      expect(VIGIL.getSeverity('email')).toBe('LOW');
      expect(VIGIL.getSeverity(null)).toBe('LOW');
      expect(VIGIL.getSeverity('')).toBe('LOW');
      expect(VIGIL.getSeverity('unknown_custom_identifier')).toBe('LOW');
    });
  });

  describe('Debounce Utility Function', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    test('delays function execution by specified wait time (300ms)', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 300);

      debouncedFn('first');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(299);
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(2);
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('first');
    });

    test('debounces rapid sequential calls into a single invocation with last arguments', () => {
      const mockFn = jest.fn();
      const debouncedFn = debounce(mockFn, 300);

      debouncedFn('call 1');
      jest.advanceTimersByTime(100);
      debouncedFn('call 2');
      jest.advanceTimersByTime(100);
      debouncedFn('call 3');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(300);
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('call 3');
    });
  });

  describe('Pure DOM UI Elements: CRITICAL (Composer Pill)', () => {
    let inputEl;

    beforeEach(() => {
      document.body.innerHTML = '';
      inputEl = document.createElement('input');
      inputEl.type = 'text';
      inputEl.value = 'Secret: sk-test-12345';
      document.body.appendChild(inputEl);
      removeComposerPill();
    });

    test('renders red floating composer pill with accessible ARIA attributes', () => {
      renderComposerPill(inputEl, {
        alerts: [{ type: 'API_KEY' }],
        redactions: [{ text: 'sk-test-12345', type: 'API_KEY' }],
        element: inputEl,
        severity: 'CRITICAL'
      });

      const pill = document.querySelector('[data-vigil="composer-pill"]');
      expect(pill).not.toBeNull();
      expect(pill.getAttribute('role')).toBe('alert');
      expect(pill.getAttribute('aria-live')).toBe('assertive');

      // Styling must reflect red hard interrupt
      expect(pill.style.border).toContain('239, 68, 68');
      expect(pill.style.background).toContain('28, 10, 10');

      // Accessible buttons exist
      const maskBtn = pill.querySelector('[data-pill-action="sanitize"]');
      const allowBtn = pill.querySelector('[data-pill-action="allow"]');
      expect(maskBtn).not.toBeNull();
      expect(allowBtn).not.toBeNull();
      expect(maskBtn.textContent).toBe('Mask');
      expect(allowBtn.textContent).toBe('Allow');
    });

    test('allow button dismisses pill on deliberate user click', () => {
      renderComposerPill(inputEl, {
        alerts: [{ type: 'API_KEY' }],
        redactions: [{ text: 'sk-test-12345', type: 'API_KEY' }],
        element: inputEl
      });

      const pill = document.querySelector('[data-vigil="composer-pill"]');
      const allowBtn = pill.querySelector('[data-pill-action="allow"]');
      allowBtn.click();

      expect(document.querySelector('[data-vigil="composer-pill"]')).toBeNull();
    });
  });

  describe('Pure DOM UI Elements: MEDIUM (Yellow Banner)', () => {
    let inputEl;

    beforeEach(() => {
      document.body.innerHTML = '';
      inputEl = document.createElement('textarea');
      inputEl.value = 'My salary is $150,000';
      document.body.appendChild(inputEl);
      removeYellowBanner();
    });

    test('renders subtle non-blocking yellow banner below input with Review and Allow Once', () => {
      renderYellowBanner(inputEl, {
        alerts: [{ type: 'Financial data' }],
        redactions: [{ text: '$150,000', type: 'Financial data' }],
        element: inputEl
      });

      const banner = document.querySelector('[data-vigil="yellow-banner"]');
      expect(banner).not.toBeNull();
      expect(banner.getAttribute('role')).toBe('alert');
      expect(banner.getAttribute('aria-live')).toBe('polite');

      // Checks banner text format: "Vigil detected [Type]."
      expect(banner.textContent).toContain('Vigil detected Financial data.');

      // Buttons [Review] and [Allow Once]
      const buttons = banner.querySelectorAll('button');
      expect(buttons.length).toBe(2);
      expect(buttons[0].textContent).toBe('Review');
      expect(buttons[1].textContent).toBe('Allow Once');

      // Accessibility
      expect(buttons[0].getAttribute('aria-label')).toContain('Review detected');
      expect(buttons[1].getAttribute('aria-label')).toBe('Allow once for this input');

      // Clicking Allow Once dismisses the banner
      buttons[1].click();
      expect(document.querySelector('[data-vigil="yellow-banner"]')).toBeNull();
    });
  });

  describe('Pure DOM UI Elements: LOW (Silent Masking, Green Shield & Toast)', () => {
    let inputEl;

    beforeEach(() => {
      document.body.innerHTML = '';
      inputEl = document.createElement('input');
      inputEl.type = 'text';
      inputEl.value = 'alice@example.com';
      document.body.appendChild(inputEl);
      removeGreenShield();
    });

    test('renders tiny green shield icon with accessible status', () => {
      renderGreenShield(inputEl);

      const shield = document.querySelector('[data-vigil="green-shield"]');
      expect(shield).not.toBeNull();
      expect(shield.getAttribute('role')).toBe('status');
      expect(shield.getAttribute('aria-label')).toContain('Vigil');

      const svg = shield.querySelector('svg');
      expect(svg).not.toBeNull();
      expect(svg.getAttribute('fill')).toBe('#10b981');

      removeGreenShield();
      expect(document.querySelector('[data-vigil="green-shield"]')).toBeNull();
    });

    test('formatMaskedToastMessage formats correctly for email and phone', () => {
      expect(formatMaskedToastMessage([{ type: 'Email' }])).toBe('Masked 1 email address');
      expect(formatMaskedToastMessage([{ type: 'Email' }, { type: 'Email' }])).toBe('Masked 2 email addresses');
      expect(formatMaskedToastMessage([{ type: 'Phone' }])).toBe('Masked 1 phone number');
      expect(formatMaskedToastMessage([{ type: 'Name' }])).toBe('Masked 1 name');
    });

    test('renders auto-fading toast notification at bottom right', () => {
      jest.useFakeTimers();

      showSilentToast('Masked 1 email address');
      const toast = document.querySelector('[data-vigil="silent-toast"]');
      expect(toast).not.toBeNull();
      expect(toast.getAttribute('role')).toBe('status');
      expect(toast.textContent).toContain('Masked 1 email address');
      expect(toast.style.position).toBe('fixed');
      expect(toast.style.bottom).toBe('20px');
      expect(toast.style.right).toBe('20px');

      // Auto-fades after 2000ms
      jest.advanceTimersByTime(2000);
      expect(toast.style.opacity).toBe('0');

      jest.advanceTimersByTime(350);
      expect(document.querySelector('[data-vigil="silent-toast"]')).toBeNull();

      jest.useRealTimers();
    });
  });
});

