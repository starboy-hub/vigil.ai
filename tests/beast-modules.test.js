/**
 * VIGIL Beast Mode Modules Test Suite
 * Verifies secret scanner, vision firewall, swarm mesh, WebGPU engine, and voice spectral canary.
 */

const VIGIL_SECRETS = require('../src/content/modules/secret-engine.js');
const VIGIL_VISION = require('../src/content/modules/vision-firewall.js');
const VIGIL_SWARM_MESH = require('../src/background/swarm-mesh.js');
const VIGIL_WEBGPU = require('../src/background/webgpu-engine.js');
const VIGIL_VOICE_SPECTRAL = require('../companion/voice-spectral-canary.js');

describe('VIGIL Beast Mode Modules', () => {

  describe('Developer Secret & Code Sanitizer (VIGIL_SECRETS)', () => {
    test('detects AWS Access Key ID', () => {
      const res = VIGIL_SECRETS.scanSecrets('my aws key is FAKE_AWS_KEY in config');
      expect(res.alerts.some(a => a.type === 'API_KEY')).toBe(true);
      expect(res.redactions.some(r => r.text === 'FAKE_AWS_KEY')).toBe(true);
    });

    test('detects GitHub Personal Access Token', () => {
      const res = VIGIL_SECRETS.scanSecrets('token: FAKE_GITHUB_TOKEN');
      expect(res.alerts.some(a => a.type === 'API_KEY')).toBe(true);
      expect(res.redactions.some(r => r.text.startsWith('ghp_'))).toBe(true);
    });

    test('detects OpenAI / Anthropic API Key', () => {
      const res = VIGIL_SECRETS.scanSecrets('sk-proj-' + '1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef');
      expect(res.alerts.some(a => a.type === 'API_KEY')).toBe(true);
    });

    test('detects Stripe Live Key', () => {
      const res = VIGIL_SECRETS.scanSecrets('sk_' + 'live_000000000000000000000000');
      expect(res.alerts.some(a => a.type === 'API_KEY')).toBe(true);
    });

    test('detects Database Connection Strings', () => {
      const res = VIGIL_SECRETS.scanSecrets('mongodb://user:pass@localhost:27017/db');
      expect(res.alerts.some(a => a.type === 'DATABASE_URI')).toBe(true);
    });
  });

  describe('Multi-Modal Vision & Canvas Firewall (VIGIL_VISION)', () => {
    test('handles empty or non-canvas elements safely', () => {
      expect(VIGIL_VISION.inspectCanvasElement(null)).toBeNull();
    });
  });

  describe('P2P Swarm Threat Mesh (VIGIL_SWARM_MESH)', () => {
    test('broadcasts and receives threat signature hashes', () => {
      const ok = VIGIL_SWARM_MESH.broadcastThreat('hash-abc-123');
      expect(ok).toBe(true);
      expect(VIGIL_SWARM_MESH.knownHashes.has('hash-abc-123')).toBe(true);
    });
  });

  describe('WebGPU Neural Engine (VIGIL_WEBGPU)', () => {
    test('initializes and reports hardware status', async () => {
      const ok = await VIGIL_WEBGPU.init();
      expect(typeof ok).toBe('boolean');
    });
  });

  describe('Voice Clone Spectral Canary (VIGIL_VOICE_SPECTRAL)', () => {
    test('analyzes FFT frequency buffers without crashing', () => {
      const dummyFreq = new Uint8Array(256).fill(128);
      const res = VIGIL_VOICE_SPECTRAL.analyzeAudioSpectrum(dummyFreq);
      expect(res).toHaveProperty('isSynthetic');
      expect(res).toHaveProperty('score');
    });
  });

});
