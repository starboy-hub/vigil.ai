/**
 * Test Suite: VIGIL Semantic Scenario Abstraction & Homomorphic Prompt Translator
 */
const abstractor = require('../src/content/modules/semantic-abstractor.js');
const engine = require('../src/content/modules/detection-engine.js');
const secrets = require('../src/content/modules/secret-engine.js');

// Equip globalThis with engine modules
global.VIGIL_ENGINE = engine;
global.VIGIL_SECRETS = secrets;

describe('VIGIL Semantic Scenario Abstraction Engine', () => {
  describe('Domain Detection', () => {
    test('detects CLINICAL domain from medical queries', () => {
      const d = abstractor.detectDomain('The patient has fever and asthma symptoms');
      expect(d).toBe(abstractor.DOMAINS.CLINICAL);
    });

    test('detects FINANCIAL domain from corporate revenue context', () => {
      const d = abstractor.detectDomain('Our Q4 revenue and ebitda margin dropped by 8%');
      expect(d).toBe(abstractor.DOMAINS.FINANCIAL);
    });

    test('detects INFRASTRUCTURE domain from technical cloud stack context', () => {
      const d = abstractor.detectDomain('Our Postgres database on AWS had an SSRF vulnerability');
      expect(d).toBe(abstractor.DOMAINS.INFRASTRUCTURE);
    });

    test('detects LEGAL domain from litigation phrasing', () => {
      const d = abstractor.detectDomain('Our attorney responded to the subpoena and lawsuit under CCPA');
      expect(d).toBe(abstractor.DOMAINS.LEGAL);
    });
  });

  describe('Perspective Generalization', () => {
    test('converts 1st-person medical statements into objective clinical scenarios', () => {
      const original = 'I was diagnosed with fever and my doctor prescribed medication';
      const generalized = abstractor.generalizePerspective(original, abstractor.DOMAINS.CLINICAL);
      expect(generalized).toContain('A patient presents with');
      expect(generalized).toContain('An attending specialist');
      expect(generalized).not.toContain('I was diagnosed with');
    });

    test('converts enterprise 1st-person statements into generic corporate scenarios', () => {
      const original = 'Our startup had our internal database accessed';
      const generalized = abstractor.generalizePerspective(original, abstractor.DOMAINS.INFRASTRUCTURE);
      expect(generalized).toContain('An enterprise organization');
      expect(generalized).toContain('The enterprise infrastructure');
    });
  });

  describe('Type-Consistent Abstraction & Rehydration', () => {
    test('replaces sensitive name and medical condition with type-consistent surrogates', () => {
      const prompt = 'My name is Sarah Mitchell and I have fever';
      const res = abstractor.abstractPrompt(prompt);

      expect(res.entityCount).toBeGreaterThan(0);
      expect(res.abstractedText).not.toContain('Sarah Mitchell');
      expect(res.substitutionMap['Sarah Mitchell']).toBeDefined();
      expect(res.reverseTree).toBeDefined();

      // Test reverse rehydration
      const cloudReply = `Hello ${res.substitutionMap['Sarah Mitchell']}, please take rest and monitor your symptoms.`;
      const rehydrated = abstractor.rehydrateResponse(cloudReply, res.reverseTree);

      expect(rehydrated).toBe('Hello Sarah Mitchell, please take rest and monitor your symptoms.');
    });

    test('replaces secrets with enterprise credential surrogate', () => {
      const prompt = 'Deploying with AWS key AKIAIOSFODNN7EXAMPLE to our cluster';
      const res = abstractor.abstractPrompt(prompt);

      expect(res.abstractedText).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(res.abstractedText).toContain('<ENTERPRISE_API_CREDENTIAL>');
    });

    test('disambiguates multiple secrets with distinct surrogate indices to prevent collisions', () => {
      const prompt = 'Key 1: AKIAIOSFODNN7EXAMPLE and Key 2: AKIAI44QH8DHBEXAMPLE';
      const res = abstractor.abstractPrompt(prompt);

      expect(res.abstractedText).toContain('<ENTERPRISE_API_CREDENTIAL>');
      expect(res.abstractedText).toContain('<ENTERPRISE_API_CREDENTIAL_2>');
      expect(res.reverseTree['<ENTERPRISE_API_CREDENTIAL>']).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(res.reverseTree['<ENTERPRISE_API_CREDENTIAL_2>']).toBe('AKIAI44QH8DHBEXAMPLE');

      const cloudReply = 'Processed <ENTERPRISE_API_CREDENTIAL> and <ENTERPRISE_API_CREDENTIAL_2>';
      const restored = abstractor.rehydrateResponse(cloudReply, res.reverseTree);
      expect(restored).toBe('Processed AKIAIOSFODNN7EXAMPLE and AKIAI44QH8DHBEXAMPLE');
    });

    test('handles empty or non-string inputs safely without throwing', () => {
      expect(abstractor.abstractPrompt('').abstractedText).toBe('');
      expect(abstractor.abstractPrompt(null).abstractedText).toBe('');
      expect(abstractor.rehydrateResponse('', {})).toBe('');
      expect(abstractor.rehydrateResponse(null, null)).toBe('');
    });
  });
});

