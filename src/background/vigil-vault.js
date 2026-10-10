/**
 * VIGIL Identity Vault
 * Stores the user's own identity values encrypted at rest (AES-256-GCM with a
 * device-local key) and manages per-site pseudonym mappings so the same real
 * value always becomes the same fake on the same site — conversations stay
 * coherent, and the mapping lets VIGIL restore real values in AI responses.
 *
 * Threat model: the key lives in chrome.storage.local on this device. This
 * protects the vault from being read as plaintext (sync leakage, casual
 * inspection, other extensions reading storage) — not from an attacker with
 * full disk access. A passphrase-hardened mode is future work.
 *
 * Runs in the background service worker; tests drive it via createVault()
 * with an in-memory storage adapter.
 */
(function (root) {
  'use strict';

  function b64encode(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64decode(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  // TextEncoder/TextDecoder exist in service workers and browsers; Node
  // exposes them via util (needed for jest jsdom runs)
  const TextEncoderCls = typeof TextEncoder !== 'undefined' ? TextEncoder : require('util').TextEncoder;
  const TextDecoderCls = typeof TextDecoder !== 'undefined' ? TextDecoder : require('util').TextDecoder;

  function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let diff = a.length ^ b.length;
    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
      const cA = i < a.length ? a.charCodeAt(i) : 0;
      const cB = i < b.length ? b.charCodeAt(i) : 0;
      diff |= (cA ^ cB);
    }
    return diff === 0;
  }

  function normalizeVaultValue(kind, value) {
    const s = String(value || '').trim();
    if (kind === 'phone') {
      return s.replace(/\D/g, '');
    }
    if (kind === 'email') {
      return s.toLowerCase();
    }
    return s.toLowerCase().replace(/\s+/g, ' ');
  }

  async function computeBlindHash(salt, normalizedValue, subtleInstance) {
    const subtle = subtleInstance || (typeof crypto !== 'undefined' && crypto.subtle ? crypto.subtle : (typeof require === 'function' ? require('crypto').webcrypto.subtle : null));
    if (!subtle) throw new Error('SubtleCrypto unavailable for blind hash');
    const input = salt + ':' + normalizedValue;
    const buf = await subtle.digest('SHA-256', new TextEncoderCls().encode(input));
    const bytes = new Uint8Array(buf);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function createVault(storage, cryptoObj) {
    const KEYS = root.VIGIL ? root.VIGIL.KEYS : require('../shared/vigil-shared.js').KEYS;
    const subtle = cryptoObj.subtle;
    let cachedKey = null;
    let cachedVault = null;

    async function deriveKeyFromPassphrase(passphrase, saltBytes) {
      const enc = new TextEncoderCls();
      const baseKey = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
      const salt = saltBytes || cryptoObj.getRandomValues(new Uint8Array(16));
      const derivedKey = await subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      cachedKey = derivedKey;
      return { key: derivedKey, salt: b64encode(salt) };
    }

    async function ensureKey() {
      if (cachedKey) return cachedKey;
      const stored = await storage.get(KEYS.VAULT_KEY);
      if (stored[KEYS.VAULT_KEY]) {
        cachedKey = await subtle.importKey('raw', b64decode(stored[KEYS.VAULT_KEY]), 'AES-GCM', true, ['encrypt', 'decrypt']);
      } else {
        cachedKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const raw = await subtle.exportKey('raw', cachedKey);
        await storage.set({ [KEYS.VAULT_KEY]: b64encode(raw) });
      }
      return cachedKey;
    }

    async function encryptJson(obj) {
      const key = await ensureKey();
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const data = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoderCls().encode(JSON.stringify(obj)));
      return { iv: b64encode(iv), data: b64encode(data) };
    }

    async function decryptJson(blob) {
      try {
        const key = await ensureKey();
        const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64decode(blob.iv) }, key, b64decode(blob.data));
        return JSON.parse(new TextDecoderCls().decode(plain));
      } catch (_err) {
        return { error: 'DECRYPTION_FAILED', message: 'Vault data is corrupted or key is invalid' };
      }
    }

    async function loadVault() {
      if (cachedVault) return cachedVault;
      const stored = await storage.get(KEYS.VAULT_DATA);
      const blob = stored[KEYS.VAULT_DATA] ? await decryptJson(stored[KEYS.VAULT_DATA]) : { entries: [], trusted: [] };
      // Backward compatibility: blobs from before the trust graph lack `trusted`
      cachedVault = { entries: blob.entries || [], trusted: blob.trusted || [] };
      return cachedVault;
    }

    async function saveVault(v) {
      cachedVault = v;
      await storage.set({ [KEYS.VAULT_DATA]: await encryptJson(v), [KEYS.VAULT_VERSION]: Date.now() });
    }

    async function listEntries() {
      return (await loadVault()).entries;
    }

    async function addEntry(kind, value) {
      const v = String(value || '').trim();
      if (!v) return null;
      const vlt = await loadVault();
      const existing = vlt.entries.find(e => e.kind === kind && e.value.toLowerCase() === v.toLowerCase());
      if (existing) return existing;
      const entry = { id: b64encode(cryptoObj.getRandomValues(new Uint8Array(6))), kind, value: v };
      await saveVault({ entries: [...vlt.entries, entry], trusted: vlt.trusted });
      return entry;
    }

    async function removeEntry(id) {
      const vlt = await loadVault();
      await saveVault({ entries: vlt.entries.filter(e => e.id !== id), trusted: vlt.trusted });
    }

    // ---- trusted organizations / contacts (matched, never masked) ----

    async function listTrusted() {
      return (await loadVault()).trusted;
    }

    async function addTrusted(kind, value) {
      const v = String(value || '').trim();
      if (!v) return null;
      const vlt = await loadVault();
      const existing = vlt.trusted.find(e => e.value.toLowerCase() === v.toLowerCase());
      if (existing) return existing;
      const entry = { id: b64encode(cryptoObj.getRandomValues(new Uint8Array(6))), kind, value: v };
      await saveVault({ entries: vlt.entries, trusted: [...vlt.trusted, entry] });
      return entry;
    }

    async function removeTrusted(id) {
      const vlt = await loadVault();
      await saveVault({ entries: vlt.entries, trusted: vlt.trusted.filter(e => e.id !== id) });
    }

    async function clearAll() {
      cachedVault = null;
      await storage.remove([KEYS.VAULT_DATA, KEYS.PSEUDO_MAP]);
      await storage.set({ [KEYS.VAULT_VERSION]: Date.now() });
    }

    // ---- pseudonym map (plaintext: fakes are not secrets) ----

    async function getPseudoMap() {
      const stored = await storage.get(KEYS.PSEUDO_MAP);
      return stored[KEYS.PSEUDO_MAP] || {};
    }

    async function recordPseudo(entryId, site, fake) {
      const map = await getPseudoMap();
      (map[site] = map[site] || {})[entryId] = fake;
      await storage.set({ [KEYS.PSEUDO_MAP]: map });
    }

    async function getPseudoFor(entryId, site) {
      const map = await getPseudoMap();
      return (map[site] || {})[entryId] || null;
    }

    async function getBlindIndices(salt) {
      const vlt = await loadVault();
      const s = salt || b64encode(cryptoObj.getRandomValues(new Uint8Array(16)));
      const indices = [];
      for (const entry of vlt.entries) {
        const norm = normalizeVaultValue(entry.kind, entry.value);
        if (!norm) continue;
        const blindHash = await computeBlindHash(s, norm, subtle);
        indices.push({
          id: entry.id,
          kind: entry.kind,
          blindHash,
          minLen: norm.length
        });
      }
      return { salt: s, indices };
    }

    // ---- Blueprint #15: Burner Identity Mode (Ephemeral 24h Session Pseudonyms) ----
    const BURNER_TTL_MS = 86400000; // 24 hours

    async function getBurnerPseudoMap() {
      const storageKey = KEYS.BURNER_PSEUDO_MAP || 'vigil_burner_pseudo_map';
      const stored = await storage.get(storageKey);
      const rawMap = stored[storageKey] || {};
      const now = Date.now();
      let changed = false;
      const pruned = {};

      for (const [site, siteEntries] of Object.entries(rawMap)) {
        if (!siteEntries || typeof siteEntries !== 'object') continue;
        const validEntries = {};
        for (const [entryId, data] of Object.entries(siteEntries)) {
          if (data && data.expiresAt && data.expiresAt > now) {
            validEntries[entryId] = data;
          } else {
            changed = true;
          }
        }
        if (Object.keys(validEntries).length > 0) {
          pruned[site] = validEntries;
        }
      }

      if (changed) {
        await storage.set({ [storageKey]: pruned });
      }
      return pruned;
    }

    async function recordBurnerPseudo(entryId, site, fake, ttlMs = BURNER_TTL_MS, sessionId = null) {
      const map = await getBurnerPseudoMap();
      const now = Date.now();
      const expiresAt = now + (ttlMs || BURNER_TTL_MS);
      (map[site] = map[site] || {})[entryId] = {
        fake,
        createdAt: now,
        expiresAt,
        sessionId: sessionId || null
      };
      await storage.set({ [KEYS.BURNER_PSEUDO_MAP || 'vigil_burner_pseudo_map']: map });
      return map[site][entryId];
    }

    async function getBurnerPseudoFor(entryId, site, sessionId = null) {
      const map = await getBurnerPseudoMap();
      const siteEntries = map[site] || {};
      const entry = siteEntries[entryId];
      if (!entry) return null;
      if (sessionId && entry.sessionId && entry.sessionId !== sessionId) {
        return null;
      }
      return entry.fake;
    }

    async function rotateBurnerIdentity(site = null, entryId = null) {
      const map = await getBurnerPseudoMap();
      if (site && entryId) {
        if (map[site]) delete map[site][entryId];
      } else if (site) {
        delete map[site];
      } else {
        await storage.set({ [KEYS.BURNER_PSEUDO_MAP || 'vigil_burner_pseudo_map']: {} });
        return true;
      }
      await storage.set({ [KEYS.BURNER_PSEUDO_MAP || 'vigil_burner_pseudo_map']: map });
      return true;
    }

    async function getBurnerStatus(site = null) {
      const map = await getBurnerPseudoMap();
      const now = Date.now();
      const active = [];
      for (const [s, siteEntries] of Object.entries(map)) {
        if (site && s !== site) continue;
        for (const [id, data] of Object.entries(siteEntries)) {
          active.push({
            site: s,
            entryId: id,
            fake: data.fake,
            createdAt: data.createdAt,
            expiresAt: data.expiresAt,
            ttlRemainingMs: Math.max(0, data.expiresAt - now),
            sessionId: data.sessionId
          });
        }
      }
      return { activeBurners: active, totalActive: active.length };
    }

    async function verifyCandidateMatch(candidate, site, options = {}) {
      if (typeof candidate !== 'string' || !candidate.trim()) return { match: false };
      const vlt = await loadVault();
      const trimmed = candidate.trim();
      for (const entry of vlt.entries) {
        const normCandidate = normalizeVaultValue(entry.kind, trimmed);
        const normEntry = normalizeVaultValue(entry.kind, entry.value);
        if (normCandidate && normEntry && constantTimeEqual(normCandidate, normEntry)) {
          let fake = null;
          const isBurner = !!options.burnerMode;
          if (site) {
            if (isBurner) {
              fake = await getBurnerPseudoFor(entry.id, site, options.sessionId);
              if (!fake) {
                const pools = { name: 'names', email: 'emails', phone: 'phones' };
                const fakeModule = root.VIGIL_FAKE || (typeof require === 'function' ? require('../content/modules/fake-data.js') : null);
                const fakeData = fakeModule ? fakeModule.FAKE_DATA : (root.VIGIL ? root.VIGIL.FAKE_DATA : null);
                const pool = fakeData && pools[entry.kind] ? fakeData[pools[entry.kind]] : null;
                const randArr = new Uint32Array(1);
                cryptoObj.getRandomValues(randArr);
                const randSeed = randArr[0];
                fake = (pool && pool.length) ? pool[randSeed % pool.length] : ('[Burner-' + randSeed.toString(36) + ']');
                await recordBurnerPseudo(entry.id, site, fake, options.ttlMs, options.sessionId);
              }
            } else {
              fake = await getPseudoFor(entry.id, site);
              if (!fake) {
                const pools = { name: 'names', email: 'emails', phone: 'phones' };
                const fakeModule = root.VIGIL_FAKE || (typeof require === 'function' ? require('../content/modules/fake-data.js') : null);
                const fakeData = fakeModule ? fakeModule.FAKE_DATA : (root.VIGIL ? root.VIGIL.FAKE_DATA : null);
                const pool = fakeData && pools[entry.kind] ? fakeData[pools[entry.kind]] : null;
                const shared = root.VIGIL || (typeof require === 'function' ? require('../shared/vigil-shared.js') : null);
                const seed = shared ? shared.strHash(normEntry + '|' + site) : 42;
                fake = (pool && pool.length) ? pool[Math.abs(seed) % pool.length] : ('[Private-' + Math.abs(seed).toString(36) + ']');
                await recordPseudo(entry.id, site, fake);
              }
            }
          }
          return {
            match: true,
            entryId: entry.id,
            kind: entry.kind,
            opaquePointer: '{{VAULT:' + entry.id + '}}',
            fake,
            isBurner
          };
        }
      }
      return { match: false };
    }

    async function resolveOpaquePointer(entryId, site, options = {}) {
      if (!entryId) return null;
      const vlt = await loadVault();
      const entry = vlt.entries.find(e => e.id === entryId);
      if (!entry) return null;
      let fake = null;
      const isBurner = !!options.burnerMode;
      if (site) {
        if (isBurner) {
          fake = await getBurnerPseudoFor(entry.id, site, options.sessionId);
          if (!fake) {
            const pools = { name: 'names', email: 'emails', phone: 'phones' };
            const fakeModule = root.VIGIL_FAKE || (typeof require === 'function' ? require('../content/modules/fake-data.js') : null);
            const fakeData = fakeModule ? fakeModule.FAKE_DATA : (root.VIGIL ? root.VIGIL.FAKE_DATA : null);
            const pool = fakeData && pools[entry.kind] ? fakeData[pools[entry.kind]] : null;
            const randArr = new Uint32Array(1);
            cryptoObj.getRandomValues(randArr);
            const randSeed = randArr[0];
            fake = (pool && pool.length) ? pool[randSeed % pool.length] : ('[Burner-' + randSeed.toString(36) + ']');
            await recordBurnerPseudo(entry.id, site, fake, options.ttlMs, options.sessionId);
          }
        } else {
          fake = await getPseudoFor(entry.id, site);
          if (!fake) {
            const pools = { name: 'names', email: 'emails', phone: 'phones' };
            const fakeModule = root.VIGIL_FAKE || (typeof require === 'function' ? require('../content/modules/fake-data.js') : null);
            const fakeData = fakeModule ? fakeModule.FAKE_DATA : (root.VIGIL ? root.VIGIL.FAKE_DATA : null);
            const pool = fakeData && pools[entry.kind] ? fakeData[pools[entry.kind]] : null;
            const shared = root.VIGIL || (typeof require === 'function' ? require('../shared/vigil-shared.js') : null);
            const normEntry = normalizeVaultValue(entry.kind, entry.value);
            const seed = shared ? shared.strHash(normEntry + '|' + site) : 42;
            fake = (pool && pool.length) ? pool[Math.abs(seed) % pool.length] : ('[Private-' + Math.abs(seed).toString(36) + ']');
            await recordPseudo(entry.id, site, fake);
          }
        }
      }
      return {
        id: entry.id,
        kind: entry.kind,
        opaquePointer: '{{VAULT:' + entry.id + '}}',
        fake,
        isBurner
      };
    }

    async function restoreText(text, site) {
      if (typeof text !== 'string' || !text || !site) return { text };
      const vlt = await loadVault();
      let restored = text;

      // 1. Unmask burner pseudonyms first
      const burnerMap = await getBurnerPseudoMap();
      const burnerSiteMap = burnerMap[site] || {};
      for (const entry of vlt.entries) {
        const burnerItem = burnerSiteMap[entry.id];
        if (burnerItem && burnerItem.fake && restored.includes(burnerItem.fake)) {
          restored = restored.split(burnerItem.fake).join(entry.value);
        }
      }

      // 2. Unmask persistent pseudonyms
      const map = (await getPseudoMap())[site] || {};
      for (const entry of vlt.entries) {
        const fake = map[entry.id];
        if (fake && restored.includes(fake)) {
          restored = restored.split(fake).join(entry.value);
        }
      }

      // 3. Resolve opaque pointer tokens (Blueprint #1). When a redaction
      // shipped a provenance token instead of a pseudonym, the AI echoes the
      // token back; restore it for display the same way pseudonyms are.
      restored = restored.replace(/\{\{(?:PTR:[A-Z0-9]+_|VAULT:)([A-Za-z0-9+/]{8})\}\}/g, (token, id) => {
        const entry = vlt.entries.find(e => e.id === id);
        return entry ? entry.value : token;
      });
      return { text: restored };
    }

    // ---- Blueprint 5: Vault Key Rotation Mechanism ----
    async function rotateMasterKey() {
      // 1. Load current plaintext vault and trusted entries with existing key
      const currentVault = await loadVault();

      // 2. Generate a fresh, uncompromised AES-256-GCM master key
      const newKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const newRawKey = await subtle.exportKey('raw', newKey);

      // 3. Encrypt the vault data under the new key
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const encryptedData = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        newKey,
        new TextEncoderCls().encode(JSON.stringify(currentVault))
      );
      const newBlob = { iv: b64encode(iv), data: b64encode(encryptedData) };

      // 4. Atomically commit both the new key and the re-encrypted data in a single storage transaction
      await storage.set({
        [KEYS.VAULT_KEY]: b64encode(newRawKey),
        [KEYS.VAULT_DATA]: newBlob,
        [KEYS.VAULT_VERSION]: Date.now()
      });

      // 5. Update cached key and vault state
      cachedKey = newKey;
      cachedVault = currentVault;
      return { success: true, version: Date.now() };
    }

    // ---- Blueprint 6: Encrypted Backup & Recovery Protocol ----
    async function exportVaultEncrypted(passphrase) {
      if (!passphrase || typeof passphrase !== 'string' || passphrase.length < 8) {
        throw new Error('Passphrase must be at least 8 characters');
      }
      const vlt = await loadVault();
      const salt = cryptoObj.getRandomValues(new Uint8Array(16));
      const iv = cryptoObj.getRandomValues(new Uint8Array(12));
      const enc = new TextEncoderCls();

      // Derive key using PBKDF2-SHA256 with 600,000 iterations
      const baseKey = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
      const exportKey = await subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      const payload = JSON.stringify({
        version: 1,
        exportedAt: new Date().toISOString(),
        entries: vlt.entries,
        trusted: vlt.trusted
      });

      const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, exportKey, enc.encode(payload));

      return JSON.stringify({
        format: 'VIGIL_ENCRYPTED_VAULT_BACKUP',
        kdf: 'PBKDF2-SHA256',
        iterations: 600000,
        cipher: 'AES-256-GCM',
        salt: b64encode(salt),
        iv: b64encode(iv),
        ciphertext: b64encode(encrypted)
      }, null, 2);
    }

    async function importVaultEncrypted(backupJsonString, passphrase) {
      if (!passphrase || typeof passphrase !== 'string') {
        throw new Error('Passphrase required');
      }
      let backup;
      try {
        backup = typeof backupJsonString === 'string' ? JSON.parse(backupJsonString) : backupJsonString;
      } catch (e) {
        throw new Error('Invalid backup file JSON');
      }

      if (backup.format !== 'VIGIL_ENCRYPTED_VAULT_BACKUP' || !backup.salt || !backup.iv || !backup.ciphertext) {
        throw new Error('Unrecognized or corrupt backup envelope');
      }

      const enc = new TextEncoderCls();
      const salt = b64decode(backup.salt);
      const iv = b64decode(backup.iv);
      const ciphertext = b64decode(backup.ciphertext);

      const baseKey = await subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
      const importKey = await subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: backup.iterations || 600000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, importKey, ciphertext);
      const restored = JSON.parse(new TextDecoderCls().decode(decrypted));

      // Merge into current vault
      const vlt = await loadVault();
      const existingIds = new Set(vlt.entries.map(e => e.id));
      const newEntries = [...vlt.entries];

      for (const ent of (restored.entries || [])) {
        if (!existingIds.has(ent.id)) {
          newEntries.push(ent);
          existingIds.add(ent.id);
        }
      }

      const merged = {
        entries: newEntries,
        trusted: [...(vlt.trusted || []), ...(restored.trusted || [])]
      };

      await saveVault(merged);
      return { success: true, importedEntriesCount: (restored.entries || []).length };
    }

    return {
      addEntry, removeEntry, listEntries, listTrusted, addTrusted, removeTrusted, clearAll,
      encryptJson, decryptJson, deriveKeyFromPassphrase, getPseudoMap, recordPseudo, getPseudoFor,
      getBlindIndices, verifyCandidateMatch, resolveOpaquePointer, restoreText,
      getBurnerPseudoMap, recordBurnerPseudo, getBurnerPseudoFor, rotateBurnerIdentity, getBurnerStatus,
      rotateMasterKey, exportVaultEncrypted, importVaultEncrypted
    };
  }

  /**
   * Build case-insensitive matchers for vault entries. Names and custom
   * values match with word boundaries and flexible inner whitespace; phone
   * numbers match in any common formatting (digits joined by optional
   * separators); emails match literally.
   */
  function buildMatchers(entries) {
    return (entries || []).filter(e => e && typeof e.value === 'string' && e.value.trim()).map(e => {
      let re;
      if (e.kind === 'phone') {
        const digits = e.value.replace(/\D/g, '');
        if (digits.length < 7) return null;
        re = new RegExp('(?<!\\d)' + digits.split('').join('[-.\\s()]*') + '(?!\\d)', 'gi');
      } else if (e.kind === 'email') {
        re = new RegExp('\\b' + escapeRe(e.value) + '\\b', 'gi');
      } else {
        re = new RegExp('\\b' + escapeRe(e.value).replace(/ /g, '\\s+') + '\\b', 'gi');
      }
      return { entryId: e.id, kind: e.kind, value: e.value, regex: re };
    }).filter(Boolean);
  }

  const VIGIL_VAULT = {
    createVault,
    buildMatchers,
    normalizeVaultValue,
    constantTimeEqual,
    computeBlindHash
  };
  root.VIGIL_VAULT = VIGIL_VAULT;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_VAULT;
})(typeof self !== 'undefined' ? self : globalThis);
