/**
 * Tests for VIGIL AI System 5: Active Counter-Surveillance & Dynamic Honeytoken Canary Generator
 */
const canaryGen = require('../src/content/modules/honeytoken-canary-generator.js');

describe('VIGIL Dynamic Honeytoken Canary Generator & Counter-Surveillance', () => {
  beforeEach(() => {
    canaryGen.clearCanaries();
  });

  test('generates realistic dummy canaries across key categories', () => {
    const apiKey = canaryGen.generateCanary('API_KEY', 'github.com', 'seed-1');
    const awsKey = canaryGen.generateCanary('AWS_KEY', 'aws.amazon.com', 'seed-1');
    const ghToken = canaryGen.generateCanary('GITHUB_TOKEN', 'github.com', 'seed-1');
    const jwt = canaryGen.generateCanary('JWT_SESSION', 'claude.ai', 'seed-1');
    const dbUrl = canaryGen.generateCanary('DATABASE_URL', 'internal-db', 'seed-1');

    expect(apiKey.value).toMatch(/^ak_live_vigil_sec_[a-f0-9]+$/);
    expect(awsKey.value).toMatch(/^AKIA[A-Z0-9]{16}$/);
    expect(ghToken.value).toMatch(/^ghp_canary_[a-f0-9]+$/);
    expect(jwt.value).toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(dbUrl.value).toContain('postgres://canary_admin:');
    expect(canaryGen.listCanaries()).toHaveLength(5);
  });

  test('contextual bundle creates domain-adaptive canaries', () => {
    const ghBundle = canaryGen.generateContextualBundle('github.com', 'session-123');
    const types = ghBundle.canaries.map(c => c.type);
    expect(types).toContain('GITHUB_TOKEN');
    expect(types).toContain('API_KEY');

    const awsBundle = canaryGen.generateContextualBundle('console.aws.amazon.com', 'session-456');
    const awsTypes = awsBundle.canaries.map(c => c.type);
    expect(awsTypes).toContain('AWS_KEY');
    expect(awsTypes).toContain('DATABASE_URL');
  });

  test('counter-surveillance inspects payload and detects canary exfiltration', () => {
    const canary = canaryGen.generateCanary('API_KEY', 'chatgpt.com', 'seed-test');
    
    // Clean payload -> no leak
    const cleanPayload = '{"action": "query", "text": "What is the capital of France?"}';
    const cleanResult = canaryGen.inspectPayloadForCanaries(cleanPayload);
    expect(cleanResult.leakDetected).toBe(false);
    expect(cleanResult.triggeredCanaries).toHaveLength(0);

    // Malicious scraper / rogue extension transmitting payload with canary -> DETECTED!
    const exfilPayload = `{"stolen_keys": "${canary.value}", "host": "chatgpt.com"}`;
    const leakResult = canaryGen.inspectPayloadForCanaries(exfilPayload);
    expect(leakResult.leakDetected).toBe(true);
    expect(leakResult.triggeredCanaries).toHaveLength(1);
    expect(leakResult.triggeredCanaries[0].value).toBe(canary.value);
    expect(leakResult.triggeredCanaries[0].status).toBe('TRIGGERED');
    expect(leakResult.warning).toContain('Counter-Surveillance Alert');
  });

  test('registerCanary registers external canaries successfully', () => {
    const success = canaryGen.registerCanary('VIGIL-CUSTOM-CANARY-XYZ123', 'CUSTOM_EXTERNAL');
    expect(success).toBe(true);

    const leak = canaryGen.inspectPayloadForCanaries('Found token: VIGIL-CUSTOM-CANARY-XYZ123 on page');
    expect(leak.leakDetected).toBe(true);
    expect(leak.triggeredCanaries[0].type).toBe('CUSTOM_EXTERNAL');
  });

  test('handles empty or invalid inputs safely without exceptions', () => {
    expect(canaryGen.inspectPayloadForCanaries(null).leakDetected).toBe(false);
    expect(canaryGen.inspectPayloadForCanaries('').leakDetected).toBe(false);
    expect(canaryGen.registerCanary(null)).toBe(false);
  });
});

