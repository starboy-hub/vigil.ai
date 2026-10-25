/**
 * VIGIL Native Messaging Bridge Module
 * Handles zero-network stdio IPC with the VIGIL Native Desktop Companion daemon (com.vigil.desktop).
 * Encapsulates JSON-RPC 2.0 message requests, heartbeat monitoring, and fallback routing.
 */
(function (root) {
  'use strict';

  const HOST_NAME = 'com.vigil.desktop';
  const TRUSTED_EXTENSION_IDS = [
    'emkokehejldjlfljlhhcimnfefcjcmon',
    'vigil-guardian-id'
  ];

  const TextEncoderCls = typeof TextEncoder !== 'undefined' ? TextEncoder : require('util').TextEncoder;
  const TextDecoderCls = typeof TextDecoder !== 'undefined' ? TextDecoder : require('util').TextDecoder;

  function toBase64(bytes) {
    let bin = '';
    new Uint8Array(bytes).forEach(b => { bin += String.fromCharCode(b); });
    return btoa(bin);
  }

  function fromBase64(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function getSubtleCrypto() {
    if (typeof crypto !== 'undefined') {
      if (crypto.subtle) return crypto.subtle;
      if (crypto.webcrypto && crypto.webcrypto.subtle) return crypto.webcrypto.subtle;
    }
    try {
      const nodeCrypto = require('crypto');
      return nodeCrypto.webcrypto ? nodeCrypto.webcrypto.subtle : null;
    } catch (e) {
      return null;
    }
  }

  function getRandomValues(arr) {
    if (typeof crypto !== 'undefined') {
      if (typeof crypto.getRandomValues === 'function') return crypto.getRandomValues(arr);
      if (crypto.webcrypto && typeof crypto.webcrypto.getRandomValues === 'function') return crypto.webcrypto.getRandomValues(arr);
    }
    try {
      const nodeCrypto = require('crypto');
      if (nodeCrypto.webcrypto && typeof nodeCrypto.webcrypto.getRandomValues === 'function') {
        return nodeCrypto.webcrypto.getRandomValues(arr);
      }
      if (typeof nodeCrypto.randomFillSync === 'function') {
        return nodeCrypto.randomFillSync(arr);
      }
    } catch (_e) {
      // ignore
    }
    throw new Error('Cryptographically secure randomness unavailable');
  }

  class VigilNativeBridge {
    constructor() {
      this.port = null;
      this.isConnected = false;
      this.pendingRequests = new Map();
      this.requestId = 0;
      this.listeners = new Set();
      this.sessionToken = null;
      this.handshakePromise = null;
      this.sessionEstablished = false;
      this.sharedKey = null;
      this.sequenceNumber = 0;
      this.peerSequenceNumber = 0;
      this.clientKeyPair = null;
      this.cachedClientPubKey = null;
      this.isEncryptedChannel = false;
    }

    /** Resolve current extension ID */
    getExtensionId() {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return chrome.runtime.id;
      }
      return 'emkokehejldjlfljlhhcimnfefcjcmon';
    }

    /** Resolve formatted extension origin */
    getOrigin() {
      return `chrome-extension://${this.getExtensionId()}/`;
    }

    /** Connect to Chrome Native Messaging host */
    connect() {
      if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.connectNative) {
        this.isConnected = false;
        return false;
      }

      try {
        this.port = chrome.runtime.connectNative(HOST_NAME);

        this.port.onMessage.addListener((response) => {
          this.handleIncomingMessage(response);
        });

        this.port.onDisconnect.addListener(() => {
          const err = chrome.runtime.lastError;
          if (err && this.sessionEstablished) {
            console.warn('[VIGIL] Native Daemon disconnected:', err.message);
          } else if (err) {
            console.debug('[VIGIL] Native Companion standby (daemon not running):', err.message);
          }
          this.isConnected = false;
          this.port = null;
          this.sessionToken = null;
          this.handshakePromise = null;
          this.sessionEstablished = false;
          this.sharedKey = null;
          this.sequenceNumber = 0;
          this.peerSequenceNumber = 0;
          this.clientKeyPair = null;
          this.cachedClientPubKey = null;
          this.isEncryptedChannel = false;
          this.rejectAllPending('Daemon disconnected');
          this.notifyStateChange(false);
        });

        this.isConnected = true;
        this.notifyStateChange(true);
        return true;
      } catch (e) {
        console.warn('[VIGIL] Native Messaging connection failed:', e.message);
        this.isConnected = false;
        this.sessionToken = null;
        this.handshakePromise = null;
        return false;
      }
    }

    /** Generate ephemeral ECDH P-256 keypair */
    async generateEcdhKeyPair() {
      const subtle = getSubtleCrypto();
      if (!subtle) throw new Error('SubtleCrypto unavailable for ECDH');
      return await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    }

    /** Export ECDH public key as raw base64 */
    async exportPublicKey(key) {
      const subtle = getSubtleCrypto();
      const raw = await subtle.exportKey('raw', key);
      return toBase64(raw);
    }

    /** Import peer ECDH public key from raw base64 */
    async importPeerPublicKey(rawBase64) {
      const subtle = getSubtleCrypto();
      return await subtle.importKey(
        'raw',
        fromBase64(rawBase64),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );
    }

    /** Derive shared AES-256-GCM symmetric key */
    async deriveSharedSecret(privateKey, peerPublicKey) {
      const subtle = getSubtleCrypto();
      return await subtle.deriveKey(
        { name: 'ECDH', public: peerPublicKey },
        privateKey,
        { name: 'AES-GCM', length: 256 },
        false, // non-extractable (Security Policy)
        ['encrypt', 'decrypt']
      );
    }

    /** Encrypt frame with AES-256-GCM and sequence counter */
    async encryptFrame(plainObj) {
      if (!this.sharedKey) throw new Error('Cannot encrypt frame: shared key not established');
      const subtle = getSubtleCrypto();
      const iv = getRandomValues(new Uint8Array(12));
      const seq = ++this.sequenceNumber;
      const plainJson = JSON.stringify({ ...plainObj, seq });
      const encoded = new TextEncoderCls().encode(plainJson);
      const cipherBytes = await subtle.encrypt({ name: 'AES-GCM', iv }, this.sharedKey, encoded);
      return {
        iv: toBase64(iv),
        ciphertext: toBase64(cipherBytes),
        seq
      };
    }

    /** Decrypt frame with AES-256-GCM and replay validation */
    async decryptFrame(frame) {
      if (!this.sharedKey) throw new Error('Cannot decrypt frame: shared key not established');
      const subtle = getSubtleCrypto();
      const iv = fromBase64(frame.iv);
      const cipherBytes = fromBase64(frame.ciphertext);
      const decryptedBuf = await subtle.decrypt({ name: 'AES-GCM', iv }, this.sharedKey, cipherBytes);
      const plainText = new TextDecoderCls().decode(decryptedBuf);
      const innerObj = JSON.parse(plainText);
      if (typeof innerObj.seq !== 'number') {
        throw new Error('MALFORMED_FRAME: Encrypted frame lacks a valid sequence number');
      }
      if (innerObj.seq <= this.peerSequenceNumber) {
        throw new Error(`REPLAY_ATTACK_DETECTED: Frame sequence ${innerObj.seq} <= last seen ${this.peerSequenceNumber}`);
      }
      this.peerSequenceNumber = innerObj.seq;
      return innerObj;
    }

    /** Perform mutual authentication handshake with Native Companion */
    performHandshake(customOrigin = null, customExtId = null, clientPubKey = null) {
      const extId = customExtId || this.getExtensionId();
      const origin = customOrigin || (customExtId ? `chrome-extension://${customExtId}/` : this.getOrigin());
      
      const nonceBytes = getRandomValues(new Uint8Array(16));
      const clientNonce = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, '0')).join('');

      const payload = {
        extension_id: extId,
        origin: origin,
        client_nonce: clientNonce,
        client_pub_key: clientPubKey || this.cachedClientPubKey || null,
        timestamp: Date.now()
      };

      return this.sendRawRequest('vigil.auth.handshake', payload).then(async (res) => {
        if (res && res.authenticated && res.session_token) {
          this.sessionToken = res.session_token;
          this.sessionEstablished = true;
          this.sequenceNumber = 0;
          this.peerSequenceNumber = 0;
          console.log('🚀 VIGIL Native Desktop Companion connected & authenticated');

          if (res.host_pub_key && this.clientKeyPair) {
            try {
              const peerKey = await this.importPeerPublicKey(res.host_pub_key);
              this.sharedKey = await this.deriveSharedSecret(this.clientKeyPair.privateKey, peerKey);
              this.isEncryptedChannel = true;
            } catch (err) {
              this.sharedKey = null;
              this.isEncryptedChannel = false;
              throw new Error(`CRYPTO_CHANNEL_ESTABLISHMENT_FAILED: ${err && err.message}`);
            }
          }
          return res;
        }
        throw new Error('Mutual authentication handshake failed: missing session token');
      });
    }

    /** Pre-generate ECDH keypair and perform handshake with public key attached */
    async performCryptoHandshake(customOrigin = null, customExtId = null) {
      try {
        this.clientKeyPair = await this.generateEcdhKeyPair();
        this.cachedClientPubKey = await this.exportPublicKey(this.clientKeyPair.publicKey);
      } catch (e) {
        this.clientKeyPair = null;
        this.cachedClientPubKey = null;
      }
      return this.performHandshake(customOrigin, customExtId, this.cachedClientPubKey);
    }

    /** Send raw JSON-RPC request without appending session authentication */
    sendRawRequest(method, params = {}, internalOptions = {}) {
      if (!this.isConnected || !this.port) {
        if (!this.connect()) {
          return Promise.reject(new Error('VIGIL Desktop Companion unavailable'));
        }
      }

      const isAuthMethod = method === 'vigil.auth.handshake' || method === 'vigil.auth.handshake';
      const skipSession = internalOptions.skipSession === true;

      // Establish the session exactly once before the first privileged
      // request. performCryptoHandshake establishes the E2E-encrypted channel.
      // If the cryptographic handshake fails, fail closed (Security Policy).
      if (!isAuthMethod && !skipSession && !this.sessionEstablished && !this.handshakePromise) {
        this.handshakePromise = this.performCryptoHandshake().catch((err) => {
          this.handshakePromise = null;
          console.warn('[VIGIL] Security handshake failed (fail-closed):', err && err.message);
          throw new Error(`SECURITY_HANDSHAKE_FAILED: ${err && err.message}`);
        });
      }

      const doSend = () => new Promise((resolve, reject) => {
        const id = ++this.requestId;
        const payload = {
          jsonrpc: '2.0',
          id,
          method,
          params
        };

        const timeoutId = setTimeout(() => {
          if (this.pendingRequests.has(id)) {
            this.pendingRequests.delete(id);
            reject(new Error(`Native Messaging request timed out: ${method}`));
          }
        }, 5000);

        this.pendingRequests.set(id, { resolve, reject, timeoutId });

        try {
          this.port.postMessage(payload);
        } catch (e) {
          clearTimeout(timeoutId);
          this.pendingRequests.delete(id);
          reject(e);
        }
      });

      if (!isAuthMethod && !skipSession && !this.sessionEstablished && this.handshakePromise) {
        return this.handshakePromise.then(() => doSend());
      }
      return doSend();
    }

    /** Send an authenticated JSON-RPC 2.0 request over Native Messaging pipe */
    sendRequest(method, params = {}, options = {}) {
      const isAuthMethod = method === 'vigil.auth.handshake' || method === 'vigil.auth.handshake';
      if (isAuthMethod) {
        return this.sendRawRequest(method, params);
      }

      // Auth metadata is built AFTER the session gate resolves, so the first
      // privileged request of a connection carries the fresh session token.
      if (!this.sessionEstablished && !this.handshakePromise) {
        this.handshakePromise = this.performCryptoHandshake().catch((err) => {
          this.handshakePromise = null;
          console.warn('[VIGIL] Security handshake failed (fail-closed):', err && err.message);
          throw new Error(`SECURITY_HANDSHAKE_FAILED: ${err && err.message}`);
        });
      }

      const buildAndSend = () => {
        const SENSITIVE_METHODS = new Set(['vigil.keychainGet', 'vigil.keychainSet', 'vigil.offloadMl', 'vigil.hardwareEnclave']);
        if (SENSITIVE_METHODS.has(method) && (!this.isEncryptedChannel || !this.sharedKey) && options.plain !== true) {
          return Promise.reject(new Error(`PRIVILEGED_OP_DENIED: Method ${method} requires an established encrypted channel`));
        }

        const mergedParams = Object.assign({}, params, {
          auth_token: options.overrideToken !== undefined ? options.overrideToken : (this.sessionToken || null),
          origin: options.overrideOrigin !== undefined ? options.overrideOrigin : this.getOrigin()
        });

        if (this.isEncryptedChannel && this.sharedKey && options.plain !== true) {
          return this.sendEncryptedRequest(method, params, options);
        }
        return this.sendRawRequest(method, mergedParams);
      };

      if (!this.sessionEstablished && this.handshakePromise) {
        return this.handshakePromise.then(buildAndSend);
      }
      return buildAndSend();
    }

    async sendEncryptedRequest(method, params = {}, options = {}) {
      const mergedParams = Object.assign({}, params, {
        auth_token: options.overrideToken !== undefined ? options.overrideToken : (this.sessionToken || null),
        origin: options.overrideOrigin !== undefined ? options.overrideOrigin : this.getOrigin()
      });
      const frame = await this.encryptFrame({ method, params: mergedParams });
      const envelope = {
        auth_token: mergedParams.auth_token,
        seq: frame.seq,
        iv: frame.iv,
        ciphertext: frame.ciphertext
      };
      const rawRes = await this.sendRawRequest('vigil.encrypted_frame', envelope);
      if (rawRes && rawRes.ciphertext && rawRes.iv) {
        const decrypted = await this.decryptFrame(rawRes);
        return decrypted.result !== undefined ? decrypted.result : decrypted;
      }
      return rawRes;
    }

    /** Simulate malicious origin handshake to verify origin lock enforcement */
    simulateMaliciousOrigin(maliciousExtensionId = 'malicious-attacker-extension-id') {
      return this.performHandshake(`chrome-extension://${maliciousExtensionId}/`, maliciousExtensionId);
    }

    /** Simulate unauthenticated request without session token */
    simulateUnauthenticatedRequest(method = 'vigil.keychainGet', params = {}) {
      // Deliberately bypasses the session-establishment gate: the point is to
      // observe how the daemon treats a request with no session token.
      return this.sendRawRequest(method, Object.assign({}, params, {
        auth_token: null,
        origin: this.getOrigin()
      }), { skipSession: true });
    }

    /** Check if an origin is permitted by whitelist */
    isOriginAllowed(origin) {
      if (!origin || typeof origin !== 'string') return false;
      const match = origin.match(/^chrome-extension:\/\/([a-z0-9_-]+)\/?$/i);
      if (!match) return false;
      const extId = match[1];
      return TRUSTED_EXTENSION_IDS.includes(extId);
    }

    /** Clear active authenticated session */
    clearSession() {
      this.sessionToken = null;
      this.sessionEstablished = false;
      this.sharedKey = null;
      this.sequenceNumber = 0;
      this.peerSequenceNumber = 0;
      this.clientKeyPair = null;
      this.isEncryptedChannel = false;
    }

    /** Handle response payload from stdin/stdout pipe */
    handleIncomingMessage(msg) {
      if (!msg) return;

      // Handle RPC response
      if (msg.id && this.pendingRequests.has(msg.id)) {
        const { resolve, reject, timeoutId } = this.pendingRequests.get(msg.id);
        clearTimeout(timeoutId);
        this.pendingRequests.delete(msg.id);

        if (msg.error) {
          reject(new Error(msg.error.message || 'Native Messaging Error'));
        } else if (msg.result && msg.result.ciphertext && msg.result.iv && this.sharedKey) {
          this.decryptFrame(msg.result)
            .then(dec => resolve(dec.result !== undefined ? dec.result : dec))
            .catch(err => reject(err));
        } else {
          resolve(msg.result);
        }
        return;
      }

      // Handle async pushed notifications from Desktop Daemon (e.g. VOICE_CANARY_ALERT, IDE_LEAK_ALERT)
      if (msg.method || msg.type) {
        this.notifyListeners(msg);
      }
    }

    rejectAllPending(reason) {
      this.pendingRequests.forEach(({ reject, timeoutId }) => {
        clearTimeout(timeoutId);
        reject(new Error(reason));
      });
      this.pendingRequests.clear();
    }

    addListener(fn) {
      this.listeners.add(fn);
    }

    removeListener(fn) {
      this.listeners.delete(fn);
    }

    notifyListeners(msg) {
      this.listeners.forEach((fn) => {
        try { fn(msg); } catch (e) {}
      });
    }

    /** Request audio spectrum FFT analysis from Desktop Daemon */
    analyzeAudioSpectrum(samples) {
      return this.sendRequest('vigil.analyzeAudioSpectrum', { samples });
    }

    /** Request IDE prompt inspection from Desktop Daemon */
    inspectIdePrompt(prompt) {
      return this.sendRequest('vigil.inspectIdePrompt', { prompt });
    }

    /** Request IDE proxy statistics from Desktop Daemon */
    getProxyStats() {
      return this.sendRequest('vigil.getProxyStats', {});
    }

    /** Request native GPU-accelerated text classification from Desktop Daemon */
    classifyTextNative(text) {
      return this.sendRequest('vigil.classifyTextNative', { text });
    }

    /** Request hardware-bound key sealing via TPM 2.0 / Apple Secure Enclave */
    sealMasterKeyNative(keyHex = null) {
      return this.sendRequest('vigil.hardwareSealKey', { key_hex: keyHex });
    }

    /** Request hardware-bound key unsealing via TPM 2.0 / Apple Secure Enclave */
    unsealMasterKeyNative(sealedRecord) {
      return this.sendRequest('vigil.hardwareUnsealKey', sealedRecord);
    }

    /** Request hardware security status and enclave capability */
    getHardwareSecurityStatus() {
      return this.sendRequest('vigil.getHardwareSecurityStatus', {});
    }

    /** Request Enterprise SIEM formatted log export from Desktop Daemon */
    exportSiemLog(eventData, format = 'json') {
      return this.sendRequest('vigil.exportSiemLog', Object.assign({}, eventData, { format }));
    }

    /** Request direct SIEM HTTP HEC log streaming from Desktop Daemon */
    streamSiemLog(endpoint, authHeader, payload) {
      return this.sendRequest('vigil.streamSiemLog', { endpoint, authHeader, payload });
    }

    /** Trigger Option B 1-Click Desktop & Extension Native Host Setup */
    setupInstaller(sourceExtensionDir = null) {
      return this.sendRequest('vigil.setupInstaller', { sourceExtensionDir });
    }

    /** Get 1-Click Desktop & Extension Setup Status */
    getSetupStatus() {
      return this.sendRequest('vigil.getSetupStatus', {});
    }

    /**
     * Sentinel Stage 5: Evaluate action policy via native companion
     */
    sentinelEvaluatePolicy(action, profile = null, workspaceRoot = null) {
      return this.sendRequest('vigil.sentinelEvaluatePolicy', {
        action,
        profile,
        workspace_root: workspaceRoot
      });
    }

    /**
     * Sentinel Stage 5: Query status of human approval from native anchor
     */
    sentinelGetApprovalStatus(target) {
      return this.sendRequest('vigil.sentinelGetApprovalStatus', { target });
    }

    /**
     * Sentinel Stage 5: Submit human approval decision to native anchor
     */
    sentinelSubmitApproval(target, decision = 'approve', details = {}) {
      return this.sendRequest('vigil.sentinelSubmitApproval', {
        target,
        action_hash: details.actionHash || target,
        decision,
        approver: details.approver || 'operator',
        token: details.token || null,
        ttl_secs: details.ttlSecs || 300
      });
    }

    /**
     * Sentinel Stage 5: Register active enforcement adapter
     */
    sentinelRegisterEnforcementPoint(adapterInfo) {
      return this.sendRequest('vigil.sentinelRegisterEnforcementPoint', adapterInfo);
    }

    notifyStateChange(state) {
      this.notifyListeners({ type: 'NATIVE_DAEMON_STATUS', connected: state });
    }
  }

  const VIGIL_NATIVE_BRIDGE = new VigilNativeBridge();

  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_NATIVE_BRIDGE;
  else root.VIGIL_NATIVE_BRIDGE = VIGIL_NATIVE_BRIDGE;
})(typeof self !== 'undefined' ? self : this);
