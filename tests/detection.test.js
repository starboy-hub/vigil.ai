/**
 * Blueprint 11 Verification Contract:
 * Contextual Precision Engine (CPE) & Attribution Scopes
 * 
 * Enforces:
 * 1. Zero False Positives on academic, pedagogical, statistical, or precedent inquiries.
 * 2. Zero False Negatives on personal, 1st-person disclosures and high-entropy secrets.
 * 3. Payment gateway dummy test cards and test API keys are safely ignored.
 */

const engine = require('../src/content/modules/detection-engine.js');
const secrets = require('../src/content/modules/secret-engine.js');

describe('Blueprint 11: Contextual Precision Engine (CPE) Verification Contract', () => {
  describe('FP Guards (Academic, Pedagogical & Public Precedent — Must PASS)', () => {
    test('medical academic inquiry on antipyretics and fever produces zero alerts', () => {
      const text = 'What antipyretics treat fever?';
      const res = engine.scanWithContext(text);
      expect(res.alerts).toHaveLength(0);
      expect(res.redactions).toHaveLength(0);
    });

    test('pharmacological mechanism inquiry on metformin produces zero alerts', () => {
      const text = 'Explain mechanism of metformin';
      const res = engine.scanWithContext(text);
      expect(res.alerts).toHaveLength(0);
      expect(res.redactions).toHaveLength(0);
    });

    test('macro-economic median salary statistics produce zero alerts', () => {
      const text = 'National median salary is $145,000 in software engineering';
      const res = engine.scanWithContext(text);
      expect(res.alerts).toHaveLength(0);
      expect(res.redactions).toHaveLength(0);
    });

    test('historical antitrust lawsuit case-law precedent produces zero alerts', () => {
      const text = 'Analyze 1994 antitrust lawsuit precedent in federal court';
      const res = engine.scanWithContext(text);
      expect(res.alerts).toHaveLength(0);
      expect(res.redactions).toHaveLength(0);
    });

    test('mock/test API key prefix sk-test- produces zero alerts', () => {
      const text = 'sk-test-' + '4eC39HqLyjW7xK89MnBvAbCdEfGhIjKlMnOp';
      const res = secrets.scanSecrets(text);
      expect(res.alerts).toHaveLength(0);
      expect(res.redactions).toHaveLength(0);
    });

    test('Stripe and sandbox test card numbers bypass detection', () => {
      const stripeTest = 'Use test card 4242 4242 4242 4242 for stripe checkout';
      const visaTest = 'Use sandbox card 4000 0000 0000 0002 for visa testing';
      
      const r1 = engine.scanWithRegex(stripeTest);
      const r2 = engine.scanWithRegex(visaTest);
      
      expect(r1.alerts.filter(a => a.type === 'Credit Card')).toHaveLength(0);
      expect(r2.alerts.filter(a => a.type === 'Credit Card')).toHaveLength(0);
    });
  });

  describe('FN Guards (First-Person Disclosures & Live Secrets — Must REDACT)', () => {
    test('first-person symptom disclosure triggers medical redaction', () => {
      const text = 'I have had a high fever and headache since yesterday';
      const res = engine.scanWithContext(text);
      expect(res.alerts.some(a => a.type === 'MEDICAL')).toBe(true);
      expect(res.redactions.length).toBeGreaterThan(0);
    });

    test('first-person clinical diagnosis triggers medical redaction', () => {
      const text = 'I was diagnosed with leukemia earlier this year';
      const res = engine.scanWithContext(text);
      expect(res.alerts.some(a => a.type === 'MEDICAL')).toBe(true);
      expect(res.redactions.length).toBeGreaterThan(0);
    });

    test('first-person salary disclosure triggers financial redaction', () => {
      const text = 'My salary is $150,000 per year at my current job';
      const res = engine.scanWithContext(text);
      expect(res.alerts.some(a => a.type === 'FINANCIAL')).toBe(true);
      expect(res.redactions.some(r => r.text.includes('150,000'))).toBe(true);
    });

    test('live high-entropy API key triggers critical secret alert', () => {
      const text = 'export OPENAI_API_KEY=' + 'sk-proj-' + '7xK89MnBvAbCdEfGhIjKlMnOpQrStUvWxYz12';
      const res = secrets.scanSecrets(text);
      expect(res.alerts.some(a => a.type === 'API_KEY')).toBe(true);
      expect(res.redactions.length).toBeGreaterThan(0);
    });

    test('first-person lawsuit action triggers legal context alert', () => {
      const text = 'I am suing my former employer for breach of contract';
      const res = engine.scanWithContext(text);
      expect(res.alerts.some(a => a.type === 'LEGAL')).toBe(true);
      expect(res.redactions.length).toBeGreaterThan(0);
    });

    test('high-stigma conditions alert unconditionally', () => {
      const text = 'Recent patient status regarding HIV transmission';
      const res = engine.scanWithContext(text);
      expect(res.alerts.some(a => a.type === 'MEDICAL')).toBe(true);
    });
  });

  describe('Disambiguation & Obfuscation Guards (Order Numbers, SemVer, Obfuscated PII)', () => {
    test('order, invoice, and tracking numbers bypass SSN detection', () => {
      const t1 = 'Please check status for Order #123-45-6789';
      const t2 = 'Invoice #456-78-1234 has been processed';
      const t3 = 'Package Tracking number: 987-65-4321';
      const t4 = 'Replacement Part SKU 123-45-6789 in inventory';

      expect(engine.scanWithRegex(t1).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
      expect(engine.scanWithRegex(t2).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
      expect(engine.scanWithRegex(t3).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
      expect(engine.scanWithRegex(t4).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
    });

    test('invalid SSA area numbers bypass SSN detection', () => {
      const t1 = 'Code 000-12-3456 generated';
      const t2 = 'Sequence 666-12-3456 received';
      const t3 = 'Test ID 950-12-3456 rejected';

      expect(engine.scanWithRegex(t1).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
      expect(engine.scanWithRegex(t2).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
      expect(engine.scanWithRegex(t3).alerts.filter(a => a.type === 'SSN')).toHaveLength(0);
    });

    test('explicit first-person SSN disclosure alerts and redacts', () => {
      const text = 'My SSN is 123-45-6789 for tax filing';
      const res = engine.scanWithRegex(text);
      expect(res.alerts.some(a => a.type === 'SSN')).toBe(true);
      expect(res.redactions.some(r => r.text === '123-45-6789')).toBe(true);
    });

    test('software version numbers bypass IP address detection', () => {
      const t1 = 'Software Release Version 1.2.3.4 deployed to production';
      const t2 = 'Upgraded library to ver. 2.0.1.0 yesterday';
      const t3 = 'Target build 10.0.1.25-rc1 is ready';

      expect(engine.scanWithRegex(t1).alerts.filter(a => a.type === 'IP Address')).toHaveLength(0);
      expect(engine.scanWithRegex(t2).alerts.filter(a => a.type === 'IP Address')).toHaveLength(0);
      expect(engine.scanWithRegex(t3).alerts.filter(a => a.type === 'IP Address')).toHaveLength(0);
    });

    test('real network IP addresses alert and redact', () => {
      const text = 'Connect to gateway 192.168.1.1 on port 443';
      const res = engine.scanWithRegex(text);
      expect(res.alerts.some(a => a.type === 'IP Address')).toBe(true);
      expect(res.redactions.some(r => r.text === '192.168.1.1')).toBe(true);
    });

    test('obfuscated and bracketed email addresses alert and redact', () => {
      const t1 = 'Reach support at john [at] example [dot] com';
      const t2 = 'Contact alice(at)company(dot)org for billing';
      const t3 = 'Send inquiry to bob at acme dot co dot uk';

      const r1 = engine.scanWithRegex(t1);
      const r2 = engine.scanWithRegex(t2);
      const r3 = engine.scanWithRegex(t3);

      expect(r1.alerts.some(a => a.type === 'Email')).toBe(true);
      expect(r2.alerts.some(a => a.type === 'Email')).toBe(true);
      expect(r3.alerts.some(a => a.type === 'Email')).toBe(true);
      expect(r1.redactions.some(r => r.type === 'Email')).toBe(true);
    });
  });
});

