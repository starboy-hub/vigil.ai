# Vigil AI Guardian Security Model

Overview of cryptographic lifecycles, guarantees, and trust boundaries.

---

## 1. Cryptographic Lifecycles

### Identity Vault Key (AES-256-GCM + PBKDF2)
1. **Key Derivation:** On initialization, `crypto.subtle.deriveKey` generates a 256-bit AES-GCM key using **PBKDF2-SHA256 (600,000 iterations)** with a unique 16-byte cryptographically secure random salt.
2. **Encryption at Rest:** Plaintext entries are encrypted using AES-256-GCM with a fresh 12-byte initialization vector (IV) generated per save.
3. **Memory Isolation:** Decrypted values are held strictly in memory in the background service worker or content script isolated world and never serialized to plain disk.

### Content Signing Key (ECDSA P-256 / Ed25519)
1. Generated on first use and persisted securely in `chrome.storage.local`.
2. Signs outbound messages with ES256 / SHA-256; the public key is embedded in the signed message payload so any Vigil AI client can verify integrity without shared secrets.
3. Private key never leaves the user's host machine.

---

## 2. Trust Boundaries

| Boundary | Guarantee |
|---|---|
| **Web page → Content script** | Isolated worlds: Host page scripts cannot access extension variables, DOM overlays, or `chrome.storage`. |
| **Web page → Background worker** | Untrusted web pages cannot send messages (`externally_connectable` disabled). Inbound messages undergo strict schema validation (`validateMessage`). |
| **Extension ↔ Native Desktop App** | Chrome Native Messaging / Loopback IPC (`127.0.0.1`): Only the local user on the host OS can communicate with the native companion. |
| **Loopback AI Engine** | Ollama requests communicate strictly with `http://127.0.0.1:11434`. Zero external network egress. |

---

## 3. Known Limitations & Threat Boundaries

- Physical access or root-level host compromise defeats client-side memory protection.
- Heuristic and WebGPU neural classifications provide probabilistic signals with transparent confidence scores rather than absolute deterministic truths.
