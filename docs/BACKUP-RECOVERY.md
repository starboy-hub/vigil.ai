# VIGIL IDENTITY VAULT — BACKUP & RECOVERY PROTOCOL

**Document Version:** 1.0  
**Classification:** User & Administrator Guide  
**Security Model:** Zero-Trust, Self-Custodial, Client-Encrypted  

---

## 1. Overview

The Vigil Identity Vault stores personal identity markers (names, emails, phone numbers, addresses, custom secrets) locally in encrypted form. 

To ensure resilience against operating system reinstallations, machine migrations, or keychain corruption, Vigil provides an **Encrypted Backup & Recovery Protocol** decoupled from third-party cloud sync services.

---

## 2. Cryptographic Architecture of Backups

Every backup export produces a standalone JSON envelope structured as follows:

```json
{
  "format": "VIGIL_ENCRYPTED_VAULT_BACKUP",
  "kdf": "PBKDF2-SHA256",
  "iterations": 600000,
  "cipher": "AES-256-GCM",
  "salt": "<base64 16 bytes>",
  "iv": "<base64 12 bytes>",
  "ciphertext": "<base64 encrypted payload>"
}
```

### Key Derivation & Encryption Parameters
- **KDF**: PBKDF2 with SHA-256 and **600,000 iterations** (OWASP-recommended standard).
- **Salt**: 16 cryptographically secure random bytes generated via `crypto.getRandomValues()`.
- **Cipher**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Zero-Knowledge Guarantee**: The backup file contains no plaintext identity entries or unencrypted hashes. Only individuals possessing the exact passphrase can decrypt and restore the envelope.

---

## 3. Step-by-Step User Instructions

### Exporting an Encrypted Backup
1. Open the **Vigil Settings / Options** page (`chrome-extension://<id>/options/options.html`).
2. Navigate to the **Identity Vault** tab.
3. Click **Export Encrypted Backup**.
4. Enter a strong backup passphrase (minimum 8 characters, recommended 16+ characters).
5. Confirm the passphrase. Vigil derives the key, re-encrypts the vault data, and downloads `vigil-vault-backup-<YYYYMMDD>.json` to your local drive.
6. Store this backup file in a secure location (e.g., an encrypted USB drive, password manager attachment, or offline cold storage).

### Restoring from an Encrypted Backup
1. On your new or refreshed machine, install the Vigil extension.
2. Open the **Vigil Settings / Options** page and go to the **Identity Vault** tab.
3. Click **Import Encrypted Backup**.
4. Select your `vigil-vault-backup-<YYYYMMDD>.json` file.
5. Enter the backup passphrase used during export.
6. Click **Restore Vault**.
7. Vigil verifies the AES-GCM authentication tag and restores all identity markers and trusted organization entities into the local vault.
