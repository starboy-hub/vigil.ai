# Vigil AI Security Threat Matrix & Decision Records

**Version:** 1.0.0  
**Framework:** STRIDE + PASTA (Process for Attack Simulation and Threat Analysis)  
**Living Document:** Updated and verified across every release gate.

---

## 1. Comprehensive Asset Threat Matrix

| Asset | Threat Actor | Entry Point | Trust Boundary | Threat Category | Mitigating Control | Residual Risk | Automated Test Suite |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Vault Master Key** | Malicious Local Process | OS Keychain / Filesystem | Host OS ↔ Desktop Companion | Information Disclosure | AES-256-GCM sealed under OS Keychain with zeroize memory wiping | Host root/kernel compromise | `tests/vault.test.js`, `desktop/src/main.rs` |
| **Native IPC Channel** | Rogue Local Extension | Chrome Native Messaging pipe | Extension ↔ Native Host | Spoofing / Tampering | Ephemeral ECDH (P-256) + AES-256-GCM + Origin Lock allowlist | Uncompromised Chrome process assumption | `tests/native-crypto-channel.test.js`, `e2e/native-messaging.spec.js` |
| **Authentication Credentials** | Malicious Script on Web Page | Input fields on Banking / SSO | Content Script ↔ Host Page DOM | Tampering / Snooping | Sensitive Context Deny-List (`injection-policy.js`) unloads content script on login pages | Zero-day on non-listed auth domain | `tests/injection-policy.test.js` |
| **Content Script UI** | Malicious Third-Party Page | DOM Nodes / Injected Banners | Content Script Isolated World ↔ Page DOM | Elevation of Privilege (DOM-XSS) | 100% pure DOM construction (`createElement`, `textContent`); zero `.innerHTML` | Browser layout engine memory corruption | `tests/adversarial-normalizer.test.js`, ESLint rules |
| **Regex Detection Engine** | Hostile AI Prompts | User Input / Webhook | Web Page ↔ Regex Evaluator | Denial of Service (ReDoS) | Linear-time regex patterns + ReDoS watchdog AST scanner | Edge-case non-polynomial backtracking | `tests/redos-protection.test.js`, `tests/fuzz-detection.test.js` |
| **Prompt Pipeline** | Adversarial Attacker | Hidden Web Text / Zero-Width Chars | Web DOM ↔ Sentinel Engine | Tampering (Evasion) | Adversarial Normalizer folds homoglyphs, strips zero-width runs, unfolds leet | Novel zero-day Unicode steganography | `tests/adversarial-normalizer.test.js` |
| **Storage History** | Untrusted Script / Extension | `chrome.storage.local` | Extension Storage ↔ Local Host | Repudiation / Leakage | Storage Audit Proxy logs operations with sensitive values masked | Storage quota limits | `tests/storage-audit.test.js` |

---

## 2. Security Decision Records (SDRs)

### SDR-001: Preservation of Ambient `<all_urls>` with Sensitive Context Deny-List
* **Context:** An external proposal suggested reducing host permissions to `optional_host_permissions` requiring manual per-site user consent.
* **Decision:** Rejected. VIGIL is an ambient real-time Data Loss Prevention sentinel. Requiring manual approvals breaks prompt interception on ChatGPT, Claude, and internal tools.
* **Mitigation:** Implemented a pre-execution deny-list (`injection-policy.js`) that immediately unloads VIGIL on Google Accounts, Microsoft Identity, Auth0, Okta, 1Password, Bitwarden, and payment gateways.

### SDR-002: Ephemeral ECDH P-256 over Native Messaging Pipe
* **Context:** Chrome Native Messaging operates over stdin/stdout, which can theoretically be intercepted if a rogue process swaps manifests.
* **Decision:** Enforce mandatory ephemeral ECDH key exchange deriving an AES-256-GCM session key with monotonic sequence numbers, rejecting plaintext fallbacks fail-closed for production extensions.

### SDR-003: Software OS Keychain Fallback with Explicit Reduced-Trust Labeling
* **Context:** Full hardware-rooted TPM 2.0 / Apple Secure Enclave is platform-dependent and unavailable in headless/CI environments.
* **Decision:** Implement honest capability reporting: classify software keychain sealing as `TIER_2_REDUCED_TRUST_KEYCHAIN`, while supporting a strict fail-closed option (`require_hardware: true`) for enterprise deployments.

### SDR-004: In-Memory Ring Buffer for Storage Audit Logging
* **Context:** Compliance auditors require verification of storage reads/writes without creating an infinite storage leak.
* **Decision:** Deploy an in-memory 500-entry ring buffer recording timestamps, operations, and key names while strictly redacting all data payloads.

### SDR-005: Elimination of `.innerHTML` in Extension UI
* **Context:** String interpolation in `.innerHTML` within content script DOM overlays creates residual DOM-based XSS surface.
* **Decision:** Mandate pure DOM creation (`createElement`, `textContent`, `setAttribute`) across all alert cards, banners, and toasts.

