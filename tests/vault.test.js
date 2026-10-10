/**
 * Tests for the VIGIL Identity Vault (crypto, persistence, matchers, pseudonyms)
 */
require('../src/shared/vigil-shared.js');
const { createVault, buildMatchers } = require('../src/background/vigil-vault.js');
const VIGIL = require('../src/shared/vigil-shared.js');

const cryptoObj = require('crypto').webcrypto;

function makeStorage() {
  const mem = new Map();
  return {
    mem,
    async get(keys) {
      const out = {};
      (Array.isArray(keys) ? keys : [keys]).forEach(k => { if (mem.has(k)) out[k] = mem.get(k); });
      return out;
    },
    async set(obj) { Object.entries(obj).forEach(([k, v]) => mem.set(k, v)); },
    async remove(keys) { (Array.isArray(keys) ? keys : [keys]).forEach(k => mem.delete(k)); }
  };
}

function makeVault() { return createVault(makeStorage(), cryptoObj); }

describe('VIGIL Identity Vault', () => {
  test('add + list roundtrip; values are encrypted at rest', async () => {
    const storage = makeStorage();
    const vault = createVault(storage, cryptoObj);
    const entry = await vault.addEntry('name', 'Sarah Mitchell');
    expect(entry.kind).toBe('name');
    expect(entry.value).toBe('Sarah Mitchell');

    const list = await vault.listEntries();
    expect(list).toHaveLength(1);

    // The raw storage must not contain plaintext
    const raw = JSON.stringify([...storage.mem.values()]);
    expect(raw).not.toContain('Sarah Mitchell');
  });

  test('add is idempotent per kind+value', async () => {
    const vault = makeVault();
    await vault.addEntry('email', 'me@x.com');
    await vault.addEntry('email', 'ME@X.com');
    expect(await vault.listEntries()).toHaveLength(1);
  });

  test('remove and clearAll wipe the vault', async () => {
    const vault = makeVault();
    const a = await vault.addEntry('name', 'Sarah Mitchell');
    await vault.addEntry('phone', '555 123 4567');
    await vault.removeEntry(a.id);
    expect(await vault.listEntries()).toHaveLength(1);
    await vault.clearAll();
    expect(await vault.listEntries()).toHaveLength(0);
  });

  test('encryptJson/decryptJson roundtrip', async () => {
    const vault = makeVault();
    const secret = { entries: [{ id: 'x', value: 'top secret' }] };
    const blob = await vault.encryptJson(secret);
    expect(JSON.stringify(blob)).not.toContain('top secret');
    expect(await vault.decryptJson(blob)).toEqual(secret);
  });

  test('decryptJson handles corrupted data gracefully without throwing', async () => {
    const vault = makeVault();
    const corruptedBlob = { iv: 'invalid-iv-base64', data: 'invalid-data-base64' };
    const res = await vault.decryptJson(corruptedBlob);
    expect(res).toEqual({ error: 'DECRYPTION_FAILED', message: 'Vault data is corrupted or key is invalid' });
  });

  test('deriveKeyFromPassphrase derives AES key via PBKDF2 (600,000 iterations)', async () => {
    const vault = makeVault();
    const { key, salt } = await vault.deriveKeyFromPassphrase('my-master-password-123');
    expect(key).toBeDefined();
    expect(salt).toBeDefined();
    const secret = { entries: [{ id: 'pbkdf2', value: 'master secret' }] };
    const blob = await vault.encryptJson(secret);
    expect(await vault.decryptJson(blob)).toEqual(secret);
  });

  test('pseudonym map is per-site and persistent', async () => {
    const vault = makeVault();
    await vault.recordPseudo('entry1', 'chat.openai.com', 'James Wilson');
    await vault.recordPseudo('entry1', 'claude.ai', 'Ana Costa');
    expect(await vault.getPseudoFor('entry1', 'chat.openai.com')).toBe('James Wilson');
    expect(await vault.getPseudoFor('entry1', 'claude.ai')).toBe('Ana Costa');
    expect(await vault.getPseudoFor('entry1', 'gemini.google.com')).toBeNull();
  });

  test('trusted entities: roundtrip, encrypted at rest, independent of identity entries', async () => {
    const storage = makeStorage();
    const vault = createVault(storage, cryptoObj);
    await vault.addEntry('name', 'Sarah Mitchell');
    await vault.addTrusted('org', 'Global Bank');
    await vault.addTrusted('contact', 'john@family.com');

    const trusted = await vault.listTrusted();
    expect(trusted).toHaveLength(2);
    expect(trusted.map(t => t.kind).sort()).toEqual(['contact', 'org']);
    expect((await vault.listEntries())).toHaveLength(1); // identity entries untouched

    // encrypted at rest
    const raw = JSON.stringify([...storage.mem.values()]);
    expect(raw).not.toContain('Global Bank');

    // dedup by value
    await vault.addTrusted('org', 'global bank');
    expect(await vault.listTrusted()).toHaveLength(2);

    await vault.removeTrusted(trusted[0].id);
    expect((await vault.listTrusted()).some(t => t.value === 'Global Bank')).toBe(false);
  });
});

describe('Vault matchers', () => {
  test('names match case-insensitively with word bounds and flexible spaces', () => {
    const [m] = buildMatchers([{ id: '1', kind: 'name', value: 'Sarah Mitchell' }]);
    expect('hi, I am sarah mitchell!'.match(m.regex)).toBeTruthy();
    expect('sarah  mitchell'.match(m.regex)).toBeTruthy();
    expect('SarahMitchell'.match(m.regex)).toBe(null);
    expect('Sarah Mitchellson'.match(m.regex)).toBe(null);
  });

  test('phone matcher accepts any common formatting', () => {
    const [m] = buildMatchers([{ id: '2', kind: 'phone', value: '555-123-4567' }]);
    expect('call 555-123-4567 now'.match(m.regex)).toBeTruthy();
    expect('call (555) 123 4567 now'.match(m.regex)).toBeTruthy();
    expect('call 5551234567 now'.match(m.regex)).toBeTruthy();
    expect('call 15551234567 now'.match(m.regex)).toBe(null); // different number
  });

  test('email and custom matchers work literally and case-insensitively', () => {
    const [email] = buildMatchers([{ id: '3', kind: 'email', value: 'sarah@work.com' }]);
    expect('write to SARAH@WORK.COM ok'.match(email.regex)).toBeTruthy();
    const [custom] = buildMatchers([{ id: '4', kind: 'custom', value: '12 Ocean Avenue' }]);
    expect('I live at 12  ocean avenue now'.match(custom.regex)).toBeTruthy();
  });

  test('short phone values are rejected (too noisy)', () => {
    expect(buildMatchers([{ id: '5', kind: 'phone', value: '123' }])).toHaveLength(0);
  });
});

describe('deterministic pseudonym picking (shared.strHash)', () => {
  test('same seed -> same index, different seed -> (almost surely) different', () => {
    const pool = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
    const h1 = VIGIL.strHash('entry1|chat.openai.com');
    expect(pool[h1 % pool.length]).toBe(pool[h1 % pool.length]);
    let differing = 0;
    for (let i = 1; i <= 20; i++) {
      if (VIGIL.strHash('entry1|site' + i) !== h1) differing++;
    }
    expect(differing).toBeGreaterThan(15);
  });
});

describe('Blueprint 5: Vault Master Key Rotation', () => {
  test('rotateMasterKey re-encrypts vault atomically under a new master key', async () => {
    const storage = makeStorage();
    const vault = createVault(storage, cryptoObj);
    await vault.addEntry('name', 'Alice Architect');
    await vault.addEntry('email', 'alice@example.com');

    const initialKey = storage.mem.get('vault_key');
    const initialData = storage.mem.get('vault_data');
    expect(initialKey).toBeDefined();
    expect(initialData).toBeDefined();

    const rotationResult = await vault.rotateMasterKey();
    expect(rotationResult.success).toBe(true);
    expect(rotationResult.version).toBeDefined();

    const rotatedKey = storage.mem.get('vault_key');
    const rotatedData = storage.mem.get('vault_data');

    // Key and ciphertext IV/data must change
    expect(rotatedKey).not.toBe(initialKey);
    expect(rotatedData.iv).not.toBe(initialData.iv);

    // Entries must remain identical when decrypted with the new key
    const entries = await vault.listEntries();
    expect(entries).toHaveLength(2);
    expect(entries.map(e => e.value).sort()).toEqual(['Alice Architect', 'alice@example.com'].sort());
  });
});

describe('Blueprint 6: Encrypted Backup & Recovery Protocol', () => {
  test('exportVaultEncrypted produces a valid PBKDF2/AES-GCM envelope', async () => {
    const vault = makeVault();
    await vault.addEntry('name', 'Bob Builder');
    await vault.addEntry('phone', '555-987-6543');

    const backupJson = await vault.exportVaultEncrypted('SuperSecretPassphrase123!');
    const envelope = JSON.parse(backupJson);

    expect(envelope.format).toBe('VIGIL_ENCRYPTED_VAULT_BACKUP');
    expect(envelope.cipher).toBe('AES-256-GCM');
    expect(envelope.kdf).toBe('PBKDF2-SHA256');
    expect(envelope.iterations).toBe(600000);
    expect(envelope.salt).toBeDefined();
    expect(envelope.iv).toBeDefined();
    expect(envelope.ciphertext).toBeDefined();

    // Plaintext values must not appear anywhere in the backup envelope
    expect(backupJson).not.toContain('Bob Builder');
    expect(backupJson).not.toContain('555-987-6543');
  });

  test('importVaultEncrypted restores entries into a fresh vault instance', async () => {
    const originalVault = makeVault();
    await originalVault.addEntry('name', 'Carol Danvers');
    await originalVault.addEntry('email', 'carol@marvel.com');

    const backupJson = await originalVault.exportVaultEncrypted('RestoreKey2026!');

    // Create a fresh, empty vault
    const newStorage = makeStorage();
    const freshVault = createVault(newStorage, cryptoObj);
    expect(await freshVault.listEntries()).toHaveLength(0);

    const restoreRes = await freshVault.importVaultEncrypted(backupJson, 'RestoreKey2026!');
    expect(restoreRes.success).toBe(true);
    expect(restoreRes.importedEntriesCount).toBe(2);

    const restoredEntries = await freshVault.listEntries();
    expect(restoredEntries).toHaveLength(2);
    expect(restoredEntries.map(e => e.value).sort()).toEqual(['Carol Danvers', 'carol@marvel.com'].sort());
  });

  test('importVaultEncrypted rejects incorrect passphrase', async () => {
    const vault = makeVault();
    await vault.addEntry('name', 'Dave Bowman');
    const backupJson = await vault.exportVaultEncrypted('CorrectPass123!');

    const freshVault = makeVault();
    await expect(freshVault.importVaultEncrypted(backupJson, 'WrongPassphrase!')).rejects.toThrow();
  });
});
