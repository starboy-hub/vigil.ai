# Vigil AI Privacy Policy

_Last updated: 2026-10-04_

**The short version: Vigil AI does not collect, transmit, or sell any of your data. All processing happens 100% locally on your machine. There is zero cloud transmission, no mandatory account, zero telemetry, and zero third-party analytics.**

## What Vigil AI Stores on Your Device

- **Settings** (toggles, sensitivity, theme) — stored in `chrome.storage.sync`, synced by your browser across your own signed-in browsers. Contains no personal data.
- **Identity Vault** — the identity values, secrets, and trusted organizations/contacts you choose to save. Encrypted at rest with AES-256-GCM using PBKDF2 (600,000 iterations) using keys generated solely on your device and never uploaded. Stored in `chrome.storage.local`.
- **Audit history** — a local record of protection events (type, site, timestamp). Original sensitive values are stored only so you can undo a redaction; exports mask them by design.
- **Pseudonym map** — synthetic fake values assigned per site.
- **Signing key & threat signatures** — a device-local Ed25519/ECDSA keypair for content signing, and anonymized SHA-256 hashes of flagged threat signatures.

## What Vigil AI Does NOT Do

- It does not send your browsing history, page content, vault contents, or audit data to any external server.
- It does not include analytics, tracking, or third-party advertising scripts.
- It does not modify or transmit anything to AI services without your explicit confirmation; it operates inside client-side input buffers on your screen.

## Optional Local-First Network Connections

- **Local Ollama Inference:** If enabled in settings, Vigil AI sends flagged text to **localhost:11434** (your own local machine) for deep reasoning. This never leaves your device.
- **Native Companion Daemon:** Communicates over local loopback (`127.0.0.1:8765`) or Chrome Native Messaging with the on-device desktop application.

## Data Deletion

Removing the extension deletes all stored local data. You can also purge the Identity Vault and audit history from the settings page at any time with 1 click.

## Contact & Governance

Open an issue or security report at https://github.com/starboy-hub/vigil.ai/issues
