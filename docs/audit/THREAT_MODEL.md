# VIGIL AI — Comprehensive Threat Model

> **Document:** `docs/audit/THREAT_MODEL.md`  
> **Repository:** [starboy-hub/vigil.ai](https://github.com/starboy-hub/vigil.ai.git)  
> **Specification Reference:** [Roadmap.md](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/Roadmap.md) — Section 14

---

## 1. Scope & System Architecture Overview

Vigil AI is a privacy-first, zero-cloud browser extension and native companion designed to intercept, detect, redact, and monitor sensitive information (PII, credentials, proprietary data) before it is transmitted to external generative AI services (e.g., OpenAI ChatGPT, Anthropic Claude, Google Gemini, local Ollama).

The system spans four distinct execution tiers:
1. **In-Page Content Context (`src/content/`):** Executes in an isolated world within user browser tabs, monitoring DOM inputs, injecting defensive overlays (Composer Pill), and sanitizing outbound text.
2. **Background Service Worker (`src/background/`):** The orchestration kernel managing cryptographic vaults, multi-engine consensus firewalls, local on-device neural training, and message dispatching.
3. **Offscreen Compute Context (`src/background/offscreen.js`):** Isolated DOM document for WebGPU/WASM accelerated model inference without service worker termination constraints.
4. **Native Desktop Companion (`desktop/`, `companion/`):** Rust and Node.js daemons running on the local host providing hardware enclave key sealing, IDE transparent proxying (port 8383), and agent firewall proxying (port 8765).

---

## 2. Trust Boundaries & Security Zones

```
+---------------------------------------------------------------------------------------+
| ZONE 0: Untrusted External Cloud Services                                            |
| - OpenAI / Anthropic / Google Cloud AI APIs                                           |
| - Swarm Mesh Relay Servers                                                            |
+---------------------------------------------------------------------------------------+
                                        ▲ Outbound Sanitized Prompts
                                        │ (Zero Raw PII / Surrogates Only)
+---------------------------------------------------------------------------------------+
| ZONE 1: Untrusted Web Applications & Browser DOM                                      |
| - Arbitrary Web Pages / Malicious Third-Party Scripts                                  |
| - AI Chat Web UIs (DOM Mutation, Event Listeners)                                     |
| - Webmail Inboxes (Potential Phishing / Prompt Smuggling)                             |
+---------------------------------------------------------------------------------------+
           │ DOM Events                                 ▲ Intercepted & Sanitized
           ▼                                            │
+---------------------------------------------------------------------------------------+
| ZONE 2: Browser Content Script (Isolated World)                                       |
| - `injection-policy.js` (Domain Gatekeeper: Blocks execution on banking/SSO)          |
| - `adversarial-normalizer.js` (Unicode & Steganography Unpacker)                      |
| - `detection-engine.js`, `secret-engine.js`, `injection-engine.js`                    |
| - `semantic-abstractor.js` & `rehydration-engine.js`                                   |
+---------------------------------------------------------------------------------------+
           │ `chrome.runtime.sendMessage` (Extension IPC Channel)
           ▼
+---------------------------------------------------------------------------------------+
| ZONE 3: Extension Background Service Worker (Trusted Extension Core)                  |
| - `vigil-vault.js` (AES-256-GCM Vault, HMAC Blind Index, Non-extractable CryptoKey)   |
| - `consensus-firewall.js` (2-of-3 Byzantine Quorum & Strict Fail-Closed Arbiter)      |
| - `local-lora.js` (On-Device SGD Adapter Training with Gradient Clipping)             |
| - `redteam-agent.js` (Adversarial Mutation Generator)                                 |
+---------------------------------------------------------------------------------------+
           │ Native Messaging Bridge (P-256 ECDH + AES-256-GCM Stdio Stream)
           ▼
+---------------------------------------------------------------------------------------+
| ZONE 4: Local Host OS & Native Companion Services                                     |
| - Native Rust Bridge (`desktop/src/main.rs`)                                          |
| - Hardware Enclave Key Sealer (`desktop/src/hardware_enclave.rs` - TPM / Keyring)     |
| - IDE Forward Proxy (`127.0.0.1:8383`)                                                 |
| - Agent Firewall Loopback Daemon (`127.0.0.1:8765`)                                   |
+---------------------------------------------------------------------------------------+
```

### Trust Boundary Definitions
1. **TB-01: Untrusted DOM to Content Script:** Content scripts share the DOM with untrusted page JavaScript. Although isolated worlds prevent direct JS object pollution, attackers can manipulate DOM attributes, insert mutation traps, or spoof inputs.
2. **TB-02: Content Script to Extension Background:** Internal message passing (`chrome.runtime.sendMessage`). Must validate sender origin, message structure, and prevent arbitrary invocation of privileged APIs.
3. **TB-03: Webpage to Companion Loopback Listeners:** Web pages executing in standard browser tabs may attempt `fetch('http://127.0.0.1:8383')` or `fetch('http://127.0.0.1:8765')` (CSRF / DNS rebinding / port scanning).
4. **TB-04: Extension to Native OS Process:** Chrome Native Messaging channel over stdio. Boundary between browser sandbox and unrestricted OS execution privileges.
5. **TB-05: Client to External AI Provider:** Network boundary over TLS. Unsanitized prompts must never cross this boundary.

---

## 3. Threat Actors & Adversarial Capabilities

| Actor | Description | Capabilities | Motivation |
|---|---|---|---|
| **A-1: Malicious Remote Prompter** | Web attacker crafting indirect prompt injections in web pages, emails, or documents consumed by AI. | Can embed zero-width characters, homoglyphs, markdown exfiltration links, base64 payloads, or jailbreak delimiters. | Exfiltrate user context, override system instructions, steal PII. |
| **A-2: Malicious Web Application** | Website running in user browser attempting to access local daemons or extract extension state. | Can attempt loopback HTTP requests (`localhost:8383`, `localhost:8765`), timing attacks, or DNS rebinding. | Bypass firewall, compromise local files, probe installed extensions. |
| **A-3: Untrusted / Compromised Model** | Upstream or local LLM returning poisoned or manipulative responses. | Can emit malicious script payloads, prompt rehydration traps, or attempt model inversion. | Evade detection, leak real identities via echoed surrogates. |
| **A-4: Local Multi-User / Co-located Process** | Unprivileged process running on the same workstation as the user. | Can inspect network loopback if unauthenticated, monitor shared temporary directories, or probe memory. | Steal encrypted vault keys, intercept native messaging. |
| **A-5: Poisoned Training Adversary** | Adversary feeding adversarial samples into continuous self-play learning. | Can attempt gradient explosion, loss corruption, or catastrophic forgetting of security rules. | Weaken consensus firewall over time. |

---

## 4. Security Invariants

The following security invariants are non-negotiable and enforced on runtime execution paths:

### Invariant 1: Zero Cloud Data Egress (PII / Secrets)
* **Guarantee:** Plaintext PII (credit cards, SSNs, phone numbers, email addresses), cryptographic secrets (AWS keys, GitHub tokens, private keys), and user credentials MUST NEVER be emitted over external network sockets.
* **Enforcement:** Dual-stage scanning (regex, Shannon entropy, semantic NER) and isomorphic surrogate substitution (`src/content/modules/semantic-abstractor.js`).

### Invariant 2: Injective Surrogate Mapping & Scope Isolation
* **Guarantee:** In a given session and prompt context, every distinct sensitive entity $E_i$ maps to a unique surrogate $S_i$ ($E_i \neq E_j \iff S_i \neq S_j$).
* **Enforcement:** Tracked in `usedSurrogates` map with fallback indexing (`<SURROGATE_2>`), preventing surrogate collision and entity mixup.

### Invariant 3: Rehydration Origin & Temporal Boundary
* **Guarantee:** Surrogate tokens can only be rehydrated back to real values if:
  1. The response originated from the exact web origin where the prompt was submitted (`boundOrigin === targetOrigin`).
  2. The substitution was created within the valid TTL window ($T \le 60\text{ minutes}$).
  3. The rehydration payload does not match dangerous code execution or script injection vectors.
* **Enforcement:** Enforced in `src/content/modules/rehydration-engine.js`.

### Invariant 4: Byzantine Fail-Closed Consensus Under Strict Policy
* **Guarantee:** When strict protection mode is active (`protectionPreset === 'strict'` or `failClosedOnTimeout: true`), inputs lacking consensus quorum (e.g. 2+ abstentions, engine timeouts, malformed votes) MUST NOT fail open.
* **Enforcement:** Evaluated in `src/background/consensus-firewall.js` returning `strict_quorum_unmet` with `decision: 'block'`.

### Invariant 5: Local Companion Origin & Rebinding Immunization
* **Guarantee:** Local HTTP/WebSocket companion endpoints on `127.0.0.1:8383` and `127.0.0.1:8765` reject cross-origin browser requests, enforce valid `Host: localhost` or `127.0.0.1` headers, and reject remote DNS rebinding domains.
* **Enforcement:** `companion/vigil-agent-firewall.js` (`isAuthorizedControlRequest`) and `desktop/src/ide_proxy.rs`.

### Invariant 6: Non-Extractable Cryptographic Isolation
* **Guarantee:** Vault encryption keys cannot be read by page scripts or exported in plaintext from WebCrypto.
* **Enforcement:** Derived with PBKDF2 (100,000 iterations SHA-256) into non-extractable AES-256-GCM CryptoKey objects, backed optionally by TPM / OS hardware security enclaves.

### Invariant 7: Bounded Self-Play & Gradient Finiteness
* **Guarantee:** On-device LoRA adapter updates during continuous self-play or red-teaming cannot cause NaN weight poisoning or explode gradient norms.
* **Enforcement:** Gradient clipping (`MAX_GRAD_NORM = 5.0`) and weight sanitization (`Number.isFinite`) in `src/background/local-lora.js`.

---

## 5. STRIDE Threat Analysis Matrix

| Threat Category | Target Component | Threat Scenario | Mitigation Status | Evidence Reference |
|---|---|---|---|---|
| **Spoofing** | Background Message Bus | Untrusted tab spoofing internal background messages (`VAULT_UNLOCK`). | ✅ Mitigated | Sender validation via `sender.id === chrome.runtime.id` in `background.js`. |
| **Spoofing** | Companion Control API | Web page spoofing administrative requests to Agent Firewall (8765). | ✅ Mitigated | Origin and Host validation (`isAuthorizedControlRequest`). |
| **Tampering** | Extension File Integrity | Local disk modification of extension source files by malicious script. | ✅ Mitigated | `src/background/file-integrity.js` verifies SHA-256 checksums against signed manifest. |
| **Tampering** | LoRA Adapter Weights | Adversarial inputs causing gradient explosion or infinite loss. | ✅ Mitigated | Gradient norm clipping ($L_2 \le 5.0$) and weight validation in `local-lora.js`. |
| **Repudiation** | Forensics Log | User or attacker denies prompt transmission or injection attempt. | ✅ Mitigated | Append-only `forensics-replay.js` and local SHA-256 hashed ledger in `prompt-git.js`. |
| **Information Disclosure** | Cloud AI Outbound Request | Raw PII/Credentials transmitted to LLM API. | ✅ Mitigated | Injective surrogate abstraction in `semantic-abstractor.js` and regex/entropy scanning. |
| **Information Disclosure** | Cross-Origin Rehydration | Domain B rehydrating surrogate tokens generated on Domain A. | ✅ Mitigated | `targetOrigin` origin-binding verification in `rehydration-engine.js`. |
| **Denial of Service** | Consensus Firewall Engine | Extremely long adversarial prompts causing regex ReDoS or memory leak. | ✅ Mitigated | Timeout guarantees (4000ms), bounded input lengths, strict quorum fallback. |
| **Denial of Service** | Substitution Store | Endless generation of surrogates filling browser memory. | ✅ Mitigated | `MAX_SUBSTITUTIONS = 500` eviction limit and 60-minute TTL cleanup. |
| **Elevation of Privilege** | Stdio Native Host | Untrusted process invoking native companion commands. | ✅ Mitigated | Stdio stream only accessible to browser parent process launched via Chrome Native Messaging manifest. |

