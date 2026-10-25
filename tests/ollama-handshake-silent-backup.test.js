/**
 * VIGIL AI - Ollama Cryptographic Handshake & Silent Backup Plan Tests
 * Verifies Part 5 Step 2:
 * 1. Cryptographic Handshake token (X-Vigil-Auth) is passed to local AI requests.
 * 2. Rogue server returning non-JSON or HTML is rejected safely.
 * 3. Silent Backup Plan gracefully degrades to on-device heuristics with 0 console errors.
 */
const VIGIL_ADAPTIVE_ROUTER = require('../src/background/adaptive-router.js');

describe('Part 5 Step 2: Ollama Cryptographic Handshake & Silent Backup Plan', () => {
  let originalConsoleError;
  let originalConsoleWarn;
  let consoleErrors = [];

  beforeEach(() => {
    consoleErrors = [];
    originalConsoleError = console.error;
    originalConsoleWarn = console.warn;
    console.error = (...args) => consoleErrors.push(args.join(' '));
    console.warn = (...args) => consoleErrors.push(args.join(' '));
  });

  afterEach(() => {
    console.error = originalConsoleError;
    console.warn = originalConsoleWarn;
  });

  test('Handshake token and security headers are included in outgoing inference calls', async () => {
    let capturedHeaders = null;
    let capturedBody = null;

    const mockFetch = async (url, options) => {
      capturedHeaders = options.headers;
      capturedBody = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({ response: 'Safely rewritten prompt' })
      };
    };

    const routeConfig = {
      selectedModel: 'llama3.2',
      tier: 'standard',
      taskType: 'FAST_PARAPHRASE',
      headers: { 'X-Vigil-Auth': 'mock-secret-token-12345' },
      options: { temperature: 0.1 }
    };

    const res = await VIGIL_ADAPTIVE_ROUTER.executeRoutedInference(routeConfig, 'My secret prompt', mockFetch);

    expect(res.ok).toBe(true);
    expect(res.text).toBe('Safely rewritten prompt');
    expect(capturedHeaders['X-Vigil-Auth']).toBe('mock-secret-token-12345');
    expect(capturedHeaders['X-Vigil-Origin']).toBe('chrome-extension://vigil-local');
    expect(capturedHeaders['X-Requested-With']).toBe('VigilAI');
    expect(capturedBody.model).toBe('llama3.2');
    expect(consoleErrors.length).toBe(0);
  });

  test('Rogue server returning HTML or invalid content-type is rejected silently', async () => {
    const mockRogueFetch = async () => {
      return {
        ok: true,
        status: 200,
        headers: { get: () => 'text/html' },
        json: async () => { throw new Error('HTML parsing failed'); }
      };
    };

    const routeConfig = {
      selectedModel: 'llama3.2',
      tier: 'standard',
      taskType: 'FAST_PARAPHRASE',
      headers: { 'X-Vigil-Auth': 'mock-token' }
    };

    const res = await VIGIL_ADAPTIVE_ROUTER.executeRoutedInference(routeConfig, 'Testing rogue server', mockRogueFetch);

    expect(res.ok).toBe(false);
    expect(res.fallback).toBe(true);
    expect(res.error).toBe('invalid_content_type');
    // Non-negotiable invariant: Zero console noise / network leak
    expect(consoleErrors.length).toBe(0);
  });

  test('Rogue server throwing network connection refused triggers Silent Backup with 0 console errors', async () => {
    const mockRefusedFetch = async () => {
      throw new Error('connect ECONNREFUSED 127.0.0.1:11434');
    };

    const routeConfig = {
      selectedModel: 'llama3.2',
      tier: 'standard',
      taskType: 'FAST_PARAPHRASE',
      headers: { 'X-Vigil-Auth': 'mock-token' }
    };

    const res = await VIGIL_ADAPTIVE_ROUTER.executeRoutedInference(routeConfig, 'Testing network refusal', mockRefusedFetch);

    expect(res.ok).toBe(false);
    expect(res.fallback).toBe(true);
    expect(res.error).toContain('ECONNREFUSED');
    expect(consoleErrors.length).toBe(0);
  });
});
