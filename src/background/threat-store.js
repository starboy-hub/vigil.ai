/**
 * VIGIL Swarm Defense — local threat-signature node.
 * Stores anonymized signatures (normalized text hashes) of detected scams;
 * Sentinel checks every message against them first. Packs are export/import
 * files: privacy-safe by construction (hashes only, never message text),
 * shareable between VIGIL installs today, federatable via a relay later.
 */
(function (root) {
  'use strict';

  function createThreatStore(storage, VIGIL) {
    const KEYS = VIGIL.KEYS;
    const MAX = 10000;

    async function load() {
      const stored = await storage.get(KEYS.THREAT_SIGS);
      return stored[KEYS.THREAT_SIGS] || { version: 1, signatures: [] };
    }

    async function save(data) {
      await storage.set({ [KEYS.THREAT_SIGS]: data, [KEYS.VAULT_VERSION]: Date.now() });
    }

    /** Is this normalized hash a known threat? */
    async function isKnown(hash) {
      const data = await load();
      return data.signatures.some(s => s.value === hash);
    }

    /** Record a locally detected threat signature. */
    async function record(hash) {
      if (!hash) return false;
      const data = await load();
      if (data.signatures.some(s => s.value === hash)) return false;
      data.signatures.push({ value: hash, addedAt: new Date().toISOString(), source: 'local' });
      if (data.signatures.length > MAX) data.signatures.splice(0, data.signatures.length - MAX);
      await save(data);
      return true;
    }

    /** Privacy-safe pack: hashes only, never message text. */
    async function exportPack() {
      const data = await load();
      return { vigilThreatPack: true, version: 1, exported: new Date().toISOString(), count: data.signatures.length, signatures: data.signatures.map(s => ({ value: s.value, addedAt: s.addedAt })) };
    }

    /** Merge an imported pack; returns how many new signatures were added. */
    async function importPack(pack) {
      if (!pack || pack.vigilThreatPack !== true || !Array.isArray(pack.signatures)) {
        return { added: 0, error: 'not a valid VIGIL threat pack' };
      }
      const data = await load();
      const known = new Set(data.signatures.map(s => s.value));
      let added = 0;
      for (const s of pack.signatures) {
        if (!s || typeof s.value !== 'string' || known.has(s.value)) continue;
        data.signatures.push({ value: s.value, addedAt: s.addedAt || new Date().toISOString(), source: 'pack' });
        known.add(s.value);
        added++;
      }
      if (added) await save(data);
      return { added };
    }

    async function count() {
      return (await load()).signatures.length;
    }

    return { isKnown, record, exportPack, importPack, count };
  }

  const VIGIL_THREATS = { createThreatStore };
  root.VIGIL_THREATS = VIGIL_THREATS;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_THREATS;
})(typeof self !== 'undefined' ? self : globalThis);
