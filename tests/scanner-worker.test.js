/**
 * Tests for VIGIL AI Scanner Web Worker & Event Optimizations (Task 1)
 */
const {
  scanTextWorker,
  vaultExtractCandidates,
  vaultCandidateNorms,
  setWorkerSettings,
  setVaultState
} = require('../src/content/scanner-worker.js');

// Helper matching debounce implementation in content.js
function debounce(func, wait = 300) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

describe('Task 1: Scanner Worker & Event Performance Optimization', () => {

  describe('Debounce Functionality', () => {
    jest.useFakeTimers();

    test('delays function execution by specified wait time (300ms)', () => {
      const mockFn = jest.fn();
      const debounced = debounce(mockFn, 300);

      debounced('call 1');
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(200);
      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(100);
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('call 1');
    });

    test('batches rapid successive keystrokes and executes only once with the latest argument', () => {
      const mockFn = jest.fn();
      const debounced = debounce(mockFn, 300);

      debounced('h');
      jest.advanceTimersByTime(100);
      debounced('he');
      jest.advanceTimersByTime(100);
      debounced('hel');
      jest.advanceTimersByTime(100);
      debounced('hello');

      expect(mockFn).not.toHaveBeenCalled();

      jest.advanceTimersByTime(300);
      expect(mockFn).toHaveBeenCalledTimes(1);
      expect(mockFn).toHaveBeenCalledWith('hello');
    });
  });

  describe('Worker Candidate Extraction & Normalization', () => {
    test('extracts email and phone candidates correctly', () => {
      const sample = 'Please email john.doe@company.org or reach out at +1 (555) 234-5678 regarding the project';
      const cands = vaultExtractCandidates(sample);

      expect(cands.has('john.doe@company.org')).toBe(true);
      expect(cands.has('+1 (555) 234-5678')).toBe(true);
    });

    test('generates valid candidate norms across email, name, and phone', () => {
      const nameNorms = vaultCandidateNorms('Sarah   Mitchell');
      expect(nameNorms).toContain('sarah mitchell');

      const phoneNorms = vaultCandidateNorms('+1-555-0199');
      expect(phoneNorms).toContain('15550199');

      const emailNorms = vaultCandidateNorms('Test@Example.COM');
      expect(emailNorms).toContain('test@example.com');
    });

    test('skips short or empty texts gracefully', () => {
      expect(vaultExtractCandidates('').size).toBe(0);
      expect(vaultCandidateNorms('').length).toBe(0);
    });
  });

  describe('Worker Text Scanning & Serialization', () => {
    beforeEach(() => {
      setWorkerSettings({ regexEnabled: true, sensitivity: 'high', customPatterns: '' });
    });

    test('detects sensitive regex patterns (SSN, Email, API Keys) off the main thread', async () => {
      const payload = 'Here is the customer SSN: 123-45-6789 and email contact@example.com';
      const res = await scanTextWorker(payload, { sensitivity: 'high' });

      expect(res).toBeDefined();
      expect(Array.isArray(res.alerts)).toBe(true);
      expect(Array.isArray(res.redactions)).toBe(true);

      const types = res.alerts.map(a => a.type);
      expect(types).toContain('SSN');
      expect(types).toContain('Email');
    });

    test('returns empty results for text shorter than 5 characters', async () => {
      const res = await scanTextWorker('abc');
      expect(res.alerts).toEqual([]);
      expect(res.redactions).toEqual([]);
    });

    test('detects custom patterns when passed in options', async () => {
      const res = await scanTextWorker('Ticket ref: SEC-998812', {
        customPatterns: 'SEC_TICKET:/SEC-\\d{6}/g'
      });
      const types = res.alerts.map(a => a.type);
      expect(types).toContain('SEC_TICKET');
    });

    test('updates vault state and scans against trusted vault matchers', async () => {
      setVaultState('test-salt', [], [{ kind: 'name', value: 'Alice Wonderland' }]);
      const res = await scanTextWorker('Hello Alice Wonderland, welcome back!');
      const types = res.alerts.map(a => a.type);
      expect(types).toContain('Vault Name');
    });
  });
});

