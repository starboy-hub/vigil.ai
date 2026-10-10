/**
 * VIGIL Signing Engine
 * Device-local ECDSA P-256 signing keys (stored as JWK in chrome.storage).
 * Sign arbitrary text into a portable VIGIL signed block; verify blocks
 * from any VIGIL user. This is the foundation for provenance verification:
 * AI-forged content claiming a signature fails verification loudly.
 */
(function (root) {
  'use strict';

  const TextEncoderCls = typeof TextEncoder !== 'undefined' ? TextEncoder : require('util').TextEncoder;

  function b64urlEncode(bytes) {
    let bin = '';
    new Uint8Array(bytes).forEach(b => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(str) {
    const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
    const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  const BEGIN_MSG = '-----BEGIN VIGIL SIGNED MESSAGE-----';
  const BEGIN_SIG = '-----BEGIN VIGIL SIGNATURE-----';
  const END_SIG = '-----END VIGIL SIGNATURE-----';

  // Zero-width 2-bit steganography alphabet
  const ZW_CHARS = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
  const ZW_MAP = {
    '\u200B': 0,
    '\u200C': 1,
    '\u200D': 2,
    '\uFEFF': 3
  };
  const ZW_DELIM = '\u2060';

  // The zero-width classes below enumerate code points as ALTERNATIVES —
  // no-misleading-character-class cannot see that they never join, so the
  // false positive is suppressed explicitly on each line.
  // eslint-disable-next-line no-misleading-character-class
  const ZW_STRIP_RE = new RegExp('[' + ZW_CHARS.join('') + ZW_DELIM + ']', 'gu');
  // eslint-disable-next-line no-misleading-character-class
  const ZW_RUN_RE = new RegExp('[' + ZW_CHARS.join('') + ']{16,}', 'u');

  /** Encode a buffer or array of bytes into zero-width character stream */
  function bytesToZeroWidth(bytes) {
    let out = ZW_DELIM;
    const u8 = new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) {
      const b = u8[i];
      out += ZW_CHARS[(b >> 6) & 3];
      out += ZW_CHARS[(b >> 4) & 3];
      out += ZW_CHARS[(b >> 2) & 3];
      out += ZW_CHARS[b & 3];
    }
    out += ZW_DELIM;
    return out;
  }

  /** Decode a zero-width character stream back into byte array */
  function zeroWidthToBytes(str) {
    const bits = [];
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      if (ZW_MAP[ch] !== undefined) {
        bits.push(ZW_MAP[ch]);
      }
    }
    const byteCount = Math.floor(bits.length / 4);
    const bytes = new Uint8Array(byteCount);
    for (let i = 0; i < byteCount; i++) {
      const b0 = bits[i * 4];
      const b1 = bits[i * 4 + 1];
      const b2 = bits[i * 4 + 2];
      const b3 = bits[i * 4 + 3];
      bytes[i] = (b0 << 6) | (b1 << 4) | (b2 << 2) | b3;
    }
    return bytes;
  }

  /** Strip all zero-width watermark characters to recover visible plaintext */
  function cleanVisibleText(text) {
    if (typeof text !== 'string') return '';
    return text.replace(ZW_STRIP_RE, '');
  }

  /** Extract watermark payload and visible text from watermarked string */
  function extractInvisibleWatermark(text) {
    if (typeof text !== 'string') return null;
    const delimStart = text.indexOf(ZW_DELIM);
    let zwContent = '';
    if (delimStart !== -1) {
      const delimEnd = text.indexOf(ZW_DELIM, delimStart + 1);
      if (delimEnd !== -1) {
        zwContent = text.slice(delimStart + 1, delimEnd);
      }
    }
    if (!zwContent) {
      const match = text.match(ZW_RUN_RE);
      if (match) zwContent = match[0];
    }
    if (!zwContent) return null;
    try {
      const bytes = zeroWidthToBytes(zwContent);
      const TextDec = typeof TextDecoder !== 'undefined' ? TextDecoder : require('util').TextDecoder;
      const jsonStr = new TextDec().decode(bytes);
      const watermark = JSON.parse(jsonStr);
      if (!watermark || !watermark.alg || !watermark.sig || !watermark.pub) return null;
      return { watermark, visibleText: cleanVisibleText(text) };
    } catch (e) {
      return null;
    }
  }

  /** Embed zero-width watermark into visible text non-destructively */
  function embedInvisibleWatermark(visibleText, block) {
    const clean = cleanVisibleText(visibleText);
    const jsonStr = JSON.stringify(block);
    const bytes = new TextEncoderCls().encode(jsonStr);
    const zw = bytesToZeroWidth(bytes);
    if (clean.includes(' ')) {
      return clean.replace(/^(\S+\s+)/, '$1' + zw);
    }
    return clean + zw;
  }

  /** Format a signed message as a portable text block. */
  function formatSignedMessage(text, block) {
    return BEGIN_MSG + '\n' + text + '\n' + BEGIN_SIG + '\n' + JSON.stringify(block) + '\n' + END_SIG;
  }

  /** Parse a portable block; returns {text, block} or null. */
  function parseSignedMessage(blockText) {
    if (typeof blockText !== 'string') return null;

    if (blockText.indexOf(BEGIN_MSG) === -1 || blockText.indexOf(BEGIN_SIG) === -1) return null;
    const bodyStart = blockText.indexOf(BEGIN_MSG) + BEGIN_MSG.length;
    const sigStart = blockText.indexOf(BEGIN_SIG, bodyStart);
    const end = blockText.indexOf(END_SIG, sigStart);
    if (sigStart === -1 || end === -1) return null;
    const text = blockText.slice(bodyStart, sigStart).replace(/^\r?\n/, '').replace(/\r?\n$/, '');
    let block;
    try { block = JSON.parse(blockText.slice(sigStart + BEGIN_SIG.length, end).trim()); } catch (e) { return null; }
    return { text, block };
  }

  function createSigner(storage, cryptoObj) {
    const KEYS = root.VIGIL ? root.VIGIL.KEYS : require('../shared/vigil-shared.js').KEYS;
    const subtle = cryptoObj.subtle;
    let cached = null;

    async function ensureKeys() {
      if (cached) return cached;
      const stored = await storage.get(KEYS.SIGNING_KEY);
      if (stored[KEYS.SIGNING_KEY]) {
        const jwk = stored[KEYS.SIGNING_KEY];
        cached = {
          privateKey: await subtle.importKey('jwk', jwk.privateKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']),
          publicKey: await subtle.importKey('jwk', jwk.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
        };
      } else {
        const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        await storage.set({
          [KEYS.SIGNING_KEY]: {
            privateKey: await subtle.exportKey('jwk', kp.privateKey),
            publicKey: await subtle.exportKey('jwk', kp.publicKey)
          }
        });
        cached = kp;
      }
      return cached;
    }

    /** Sign text; returns a portable signature block object. */
    async function signText(text) {
      const keys = await ensureKeys();
      const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoderCls().encode(text));
      const rawPub = new Uint8Array(await subtle.exportKey('raw', keys.publicKey));
      return { alg: 'ES256', ts: new Date().toISOString(), pub: b64urlEncode(rawPub), sig: b64urlEncode(sig) };
    }

    /** Verify raw text against a signature block object. */
    async function verifySignature(text, block) {
      try {
        if (!block || block.alg !== 'ES256' || !block.pub || !block.sig) return false;
        const pub = await subtle.importKey('raw', b64urlDecode(block.pub), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
        return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, b64urlDecode(block.sig), new TextEncoderCls().encode(text));
      } catch (e) {
        return false;
      }
    }

    /** Verify a full portable block (as produced by formatSignedMessage). */
    async function verifySignedMessage(blockText) {
      const parsed = parseSignedMessage(blockText);
      if (!parsed) return { valid: false, reason: 'no valid signature block' };
      const valid = await verifySignature(parsed.text, parsed.block);
      return { valid, text: parsed.text, ts: parsed.block.ts, reason: valid ? '' : 'signature does not match content' };
    }

    /** Sign text invisibly using zero-width Unicode steganography */
    async function signInvisible(text) {
      const clean = cleanVisibleText(text);
      const block = await signText(clean);
      return embedInvisibleWatermark(clean, block);
    }

    /** Raw base64url of this device's public key (for publisher trust checks) */
    async function devicePubB64() {
      const keys = await ensureKeys();
      const rawPub = new Uint8Array(await subtle.exportKey('raw', keys.publicKey));
      return b64urlEncode(rawPub);
    }

    /** Verify invisible watermark extracted from text.
     * `trusted` is true only when the watermark was produced by THIS device's
     * signing key. A watermark signed by a foreign key is cryptographically
     * intact but self-attested — any page can watermark itself. */
    async function verifyInvisible(text) {
      const extracted = extractInvisibleWatermark(text);
      if (!extracted) return { valid: false, hasWatermark: false, reason: 'no invisible watermark found' };
      const valid = await verifySignature(extracted.visibleText, extracted.watermark);
      let trusted = false;
      if (valid) {
        try {
          trusted = extracted.watermark.pub === await devicePubB64();
        } catch (e) { trusted = false; }
      }
      return {
        valid,
        trusted,
        hasWatermark: true,
        text: extracted.visibleText,
        ts: extracted.watermark.ts,
        pub: extracted.watermark.pub,
        reason: !valid
          ? 'signature does not match visible content (tampered)'
          : (trusted ? '' : 'signature intact but publisher key is not this device (self-attested provenance)')
      };
    }

    return {
      ensureKeys, signText, verifySignature, verifySignedMessage, formatSignedMessage, parseSignedMessage,
      signInvisible, verifyInvisible, devicePubB64
    };
  }

  const VIGIL_SIGNING = {
    createSigner,
    formatSignedMessage,
    parseSignedMessage,
    cleanVisibleText,
    bytesToZeroWidth,
    zeroWidthToBytes,
    embedInvisibleWatermark,
    extractInvisibleWatermark
  };
  root.VIGIL_SIGNING = VIGIL_SIGNING;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_SIGNING;
})(typeof self !== 'undefined' ? self : globalThis);
