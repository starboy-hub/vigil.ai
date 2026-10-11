/**
 * Tests for Blueprint #5: Cryptographic Native Messaging Channel
 * Verifies ephemeral ECDH (P-256) key exchange, AES-256-GCM authenticated encryption,
 * monotonic sequence counters, and replay attack rejection.
 */
const VIGIL_NATIVE_BRIDGE = require('../src/background/native-bridge.js');
const cryptoObj = require('crypto').webcrypto;

describe('Blueprint #5: Cryptographic Native Messaging Channel (ECDH + AES-GCM)', () => {
  let mockPort;

  beforeEach(() => {
    mockPort = {
      postMessage: jest.fn(),
      onMessage: { addListener: jest.fn() },
      onDisconnect: { addListener: jest.fn() }
    };

    global.chrome = {
      runtime: {
        connectNative: jest.fn().mockReturnValue(mockPort),
        id: 'emkokehejldjlfljlhhcimnfefcjcmon',
        lastError: null
      }
    };

    VIGIL_NATIVE_BRIDGE.port = null;
    VIGIL_NATIVE_BRIDGE.isConnected = false;
    VIGIL_NATIVE_BRIDGE.clearSession();
    VIGIL_NATIVE_BRIDGE.pendingRequests.clear();
  });

  afterEach(() => {
    delete global.chrome;
  });

  describe('1. Ephemeral ECDH Key Exchange & Shared Secret Derivation', () => {
    test('generateEcdhKeyPair creates P-256 keypair and export/import works roundtrip', async () => {
      const kp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      expect(kp.publicKey).toBeDefined();
      expect(kp.privateKey).toBeDefined();

      const exportedPub = await VIGIL_NATIVE_BRIDGE.exportPublicKey(kp.publicKey);
      expect(typeof exportedPub).toBe('string');
      expect(exportedPub.length).toBeGreaterThan(60);

      const importedPub = await VIGIL_NATIVE_BRIDGE.importPeerPublicKey(exportedPub);
      expect(importedPub.type).toBe('public');
      expect(importedPub.algorithm.name).toBe('ECDH');
    });

    test('Alice and Bob derive identical AES-256-GCM shared keys via ECDH', async () => {
      const aliceKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      const bobKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();

      const aliceKey = await VIGIL_NATIVE_BRIDGE.deriveSharedSecret(aliceKp.privateKey, bobKp.publicKey);
      const bobKey = await VIGIL_NATIVE_BRIDGE.deriveSharedSecret(bobKp.privateKey, aliceKp.publicKey);

      // Verify that data encrypted by Alice can be decrypted by Bob
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const plaintext = Buffer.from('hello-shared-secret');
      const ciphertext = await cryptoObj.subtle.encrypt({ name: 'AES-GCM', iv }, aliceKey, plaintext);
      const decrypted = await cryptoObj.subtle.decrypt({ name: 'AES-GCM', iv }, bobKey, ciphertext);

      expect(Buffer.from(decrypted).toString()).toBe('hello-shared-secret');
    });
  });

  describe('2. AES-256-GCM Framing & Anti-Replay Monotonic Sequence', () => {
    beforeEach(async () => {
      const clientKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      const serverKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();

      VIGIL_NATIVE_BRIDGE.sharedKey = await VIGIL_NATIVE_BRIDGE.deriveSharedSecret(clientKp.privateKey, serverKp.publicKey);
      VIGIL_NATIVE_BRIDGE.sequenceNumber = 0;
      VIGIL_NATIVE_BRIDGE.peerSequenceNumber = 0;
    });

    test('encryptFrame produces unique IV, ciphertext, and incrementing seq', async () => {
      const frame1 = await VIGIL_NATIVE_BRIDGE.encryptFrame({ test: 'hello' });
      const frame2 = await VIGIL_NATIVE_BRIDGE.encryptFrame({ test: 'world' });

      expect(frame1.seq).toBe(1);
      expect(frame2.seq).toBe(2);
      expect(frame1.iv).not.toBe(frame2.iv);
      expect(frame1.ciphertext).toBeDefined();
    });

    test('decryptFrame recovers plaintext payload when valid', async () => {
      const payload = { action: 'secure-read', data: [1, 2, 3] };
      const frame = await VIGIL_NATIVE_BRIDGE.encryptFrame(payload);

      const decrypted = await VIGIL_NATIVE_BRIDGE.decryptFrame(frame);
      expect(decrypted.action).toBe('secure-read');
      expect(decrypted.data).toEqual([1, 2, 3]);
      expect(decrypted.seq).toBe(1);
    });

    test('decryptFrame detects and rejects replay attacks (seq <= last_seq)', async () => {
      const frame1 = await VIGIL_NATIVE_BRIDGE.encryptFrame({ msg: 'first' });
      await VIGIL_NATIVE_BRIDGE.decryptFrame(frame1);

      // Attempt to replay frame 1
      await expect(VIGIL_NATIVE_BRIDGE.decryptFrame(frame1)).rejects.toThrow(/REPLAY_ATTACK_DETECTED/);
    });

    test('tampered ciphertext fails GCM authentication', async () => {
      const frame = await VIGIL_NATIVE_BRIDGE.encryptFrame({ msg: 'authentic' });
      // Corrupt the ciphertext
      const corruptBytes = Buffer.from(frame.ciphertext, 'base64');
      corruptBytes[0] ^= 0xff;
      frame.ciphertext = corruptBytes.toString('base64');

      await expect(VIGIL_NATIVE_BRIDGE.decryptFrame(frame)).rejects.toThrow();
    });
  });

  describe('3. Mutual Handshake & Encrypted Channel Negotiation', () => {
    test('handshake negotiates encrypted channel when host_pub_key is provided', async () => {
      VIGIL_NATIVE_BRIDGE.connect();

      const serverKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      const serverPubB64 = await VIGIL_NATIVE_BRIDGE.exportPublicKey(serverKp.publicKey);

      const handshakePromise = VIGIL_NATIVE_BRIDGE.performCryptoHandshake();
      await new Promise(resolve => setTimeout(resolve, 10));

      const sentPayload = mockPort.postMessage.mock.calls[0][0];
      expect(sentPayload.method).toBe('vigil.auth.handshake');
      expect(sentPayload.params.client_pub_key).toBeDefined();

      // Simulate native host responding with its public key
      const onMessageCallback = mockPort.onMessage.addListener.mock.calls[0][0];
      onMessageCallback({
        jsonrpc: '2.0',
        id: sentPayload.id,
        result: {
          authenticated: true,
          session_token: 'vigil_sess_enc_123',
          host_pub_key: serverPubB64
        }
      });

      const res = await handshakePromise;
      expect(res.authenticated).toBe(true);
      expect(VIGIL_NATIVE_BRIDGE.isEncryptedChannel).toBe(true);
      expect(VIGIL_NATIVE_BRIDGE.sharedKey).toBeDefined();
    });

    test('sendRequest transparently wraps RPC in vigil.encrypted_frame when channel is encrypted', async () => {
      VIGIL_NATIVE_BRIDGE.connect();

      // Establish encrypted channel
      const serverKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      const serverPubB64 = await VIGIL_NATIVE_BRIDGE.exportPublicKey(serverKp.publicKey);
      const handshakePromise = VIGIL_NATIVE_BRIDGE.performCryptoHandshake();
      await new Promise(resolve => setTimeout(resolve, 10));

      const hsPayload = mockPort.postMessage.mock.calls[0][0];
      mockPort.onMessage.addListener.mock.calls[0][0]({
        jsonrpc: '2.0',
        id: hsPayload.id,
        result: { authenticated: true, session_token: 'sess_123', host_pub_key: serverPubB64 }
      });
      await handshakePromise;

      // Now send privileged request
      const reqPromise = VIGIL_NATIVE_BRIDGE.sendRequest('vigil.keychainGet', { account: 'master' });
      await new Promise(resolve => setTimeout(resolve, 10));

      const encPayload = mockPort.postMessage.mock.calls[1][0];
      expect(encPayload.method).toBe('vigil.encrypted_frame');
      expect(encPayload.params.ciphertext).toBeDefined();
      expect(encPayload.params.iv).toBeDefined();
      expect(encPayload.params.seq).toBe(1);

      // Server responds with encrypted frame
      const serverDerivedKey = await VIGIL_NATIVE_BRIDGE.deriveSharedSecret(serverKp.privateKey, VIGIL_NATIVE_BRIDGE.clientKeyPair.publicKey);
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const respInner = JSON.stringify({ seq: 1, result: { secret: 'my-super-password' } });
      const cipherBytes = await cryptoObj.subtle.encrypt({ name: 'AES-GCM', iv }, serverDerivedKey, Buffer.from(respInner));

      mockPort.onMessage.addListener.mock.calls[0][0]({
        jsonrpc: '2.0',
        id: encPayload.id,
        result: {
          seq: 1,
          iv: Buffer.from(iv).toString('base64'),
          ciphertext: Buffer.from(cipherBytes).toString('base64')
        }
      });

      const res = await reqPromise;
      expect(res).toEqual({ secret: 'my-super-password' });
    });
  });

  describe('4. Fail-Closed Security & Roadmap Validation (Blueprints 01-03)', () => {
    test('failed ECDH setup fails closed without falling back to unkeyed traffic', async () => {
      VIGIL_NATIVE_BRIDGE.connect();
      VIGIL_NATIVE_BRIDGE.sessionEstablished = false;

      const spy = jest.spyOn(VIGIL_NATIVE_BRIDGE, 'performCryptoHandshake')
        .mockRejectedValue(new Error('ECDH_NEGOTIATION_FAILED'));

      await expect(VIGIL_NATIVE_BRIDGE.sendRequest('vigil.keychainGet', { account: 'test' }))
        .rejects.toThrow(/SECURITY_HANDSHAKE_FAILED/);

      const sentMethods = mockPort.postMessage.mock.calls.map(c => c[0].method);
      expect(sentMethods).not.toContain('vigil.keychainGet');
      spy.mockRestore();
    });

    test('failed key derivation rejects handshake loudly (fail closed)', async () => {
      VIGIL_NATIVE_BRIDGE.connect();
      VIGIL_NATIVE_BRIDGE.clientKeyPair = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();

      const spy = jest.spyOn(VIGIL_NATIVE_BRIDGE, 'importPeerPublicKey')
        .mockRejectedValue(new Error('INVALID_PEER_KEY'));

      const hsPromise = VIGIL_NATIVE_BRIDGE.performHandshake(null, null, 'VALID_PUB_KEY');
      await new Promise(resolve => setTimeout(resolve, 5));

      const hsCall = mockPort.postMessage.mock.calls[0][0];
      mockPort.onMessage.addListener.mock.calls[0][0]({
        jsonrpc: '2.0',
        id: hsCall.id,
        result: { authenticated: true, session_token: 'token123', host_pub_key: 'corrupt-host-key' }
      });

      await expect(hsPromise).rejects.toThrow(/CRYPTO_CHANNEL_ESTABLISHMENT_FAILED/);
      expect(VIGIL_NATIVE_BRIDGE.isEncryptedChannel).toBe(false);
      expect(VIGIL_NATIVE_BRIDGE.sharedKey).toBeNull();
      spy.mockRestore();
    });

    test('missing session token in handshake response is rejected', async () => {
      VIGIL_NATIVE_BRIDGE.connect();
      const hsPromise = VIGIL_NATIVE_BRIDGE.performHandshake();
      await new Promise(resolve => setTimeout(resolve, 5));

      const hsCall = mockPort.postMessage.mock.calls[0][0];
      mockPort.onMessage.addListener.mock.calls[0][0]({
        jsonrpc: '2.0',
        id: hsCall.id,
        result: { authenticated: true }
      });

      await expect(hsPromise).rejects.toThrow(/missing session token/);
    });

    test('malformed encrypted frame lacking sequence number is rejected', async () => {
      const clientKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      const serverKp = await VIGIL_NATIVE_BRIDGE.generateEcdhKeyPair();
      VIGIL_NATIVE_BRIDGE.sharedKey = await VIGIL_NATIVE_BRIDGE.deriveSharedSecret(clientKp.privateKey, serverKp.publicKey);

      const subtle = cryptoObj.subtle;
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const badFrameBytes = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        VIGIL_NATIVE_BRIDGE.sharedKey,
        Buffer.from(JSON.stringify({ result: 'no-seq' }))
      );

      const frameObj = {
        iv: Buffer.from(iv).toString('base64'),
        ciphertext: Buffer.from(badFrameBytes).toString('base64')
      };

      await expect(VIGIL_NATIVE_BRIDGE.decryptFrame(frameObj)).rejects.toThrow(/MALFORMED_FRAME/);
    });

    test('privileged operations fail if encrypted channel is not active', async () => {
      VIGIL_NATIVE_BRIDGE.connect();
      VIGIL_NATIVE_BRIDGE.sessionEstablished = true;
      VIGIL_NATIVE_BRIDGE.isEncryptedChannel = false;
      VIGIL_NATIVE_BRIDGE.sharedKey = null;

      await expect(VIGIL_NATIVE_BRIDGE.sendRequest('vigil.keychainGet', { account: 'test' }))
        .rejects.toThrow(/PRIVILEGED_OP_DENIED/);
    });
  });
});
