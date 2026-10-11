# VIGIL AI — End-to-End Data Flow & Lifecycle Specification

> **Document:** `docs/audit/DATA_FLOW.md`  
> **Repository:** [starboy-hub/vigil.ai](https://github.com/starboy-hub/vigil.ai.git)  
> **Specification Reference:** [Roadmap.md](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/Roadmap.md) — Section 14

---

## 1. Data Classification Taxonomy

| Sensitivity Tier | Data Types | Permitted Contexts | Storage Mechanism | Transmission Policy |
|---|---|---|---|---|
| **Tier 1: High Sensitivity (PII & Secrets)** | Credit cards, SSNs, phone numbers, email addresses, AWS/OpenAI API keys, private keys, passwords. | In-memory DOM capture; Encrypted Vault (`vigil-vault.js`). | WebCrypto AES-256-GCM in `chrome.storage.local` (keys non-extractable) or OS Enclave/TPM. | **STRICT PROHIBITION:** Never transmitted over external network. Replaced with synthetic surrogates before network egress. |
| **Tier 2: Pseudonymous Surrogates** | Isomorphic surrogates (`<CREDIT_CARD_1>`, `<ENTERPRISE_API_CREDENTIAL>`, `<US_SSN_1>`). | Client DOM, Outbound HTTP payload to Cloud AI, Inbound AI response. | In-memory ephemeral map in `semantic-abstractor.js` & `rehydration-engine.js`. | Permitted to cross external network boundary to AI providers (ChatGPT, Claude, etc.). |
| **Tier 3: Sanitized Prompt Text** | User instructions, non-sensitive queries, redacted code blocks. | Content scripts, background consensus firewall, local LLMs, cloud AI. | In-memory; optionally local append-only hashed ledger (`prompt-git.js`). | Permitted to egress to external AI services after passing consensus firewall. |
| **Tier 4: Security Telemetry & Fingerprints** | SHA-256 threat hashes, rule trigger counts, consensus decision logs, latency timings. | Extension storage; Swarm mesh relay (`swarm-mesh.js`). | `chrome.storage.local`. | Signatures and hashes permitted over local or swarm relays; zero raw prompt text included. |
| **Tier 5: Adapter Weights & Models** | Rank-4 LoRA SGD weight matrices ($W_A, W_B$), continuous red-team mutation logs. | Extension background worker. | In-memory Float32Array; local IndexedDB. | Strictly local; never shared or uploaded. |

---

## 2. Ingestion Points & Interception Architecture

Vigil AI intercepts data across three primary ingress vectors:

### Vector 1: Web Browser DOM Input
* **Source:** Content script listeners attached to input fields, textareas, and contenteditable elements on supported domains (ChatGPT, Claude, Gemini, Copilot, Perplexity, etc.).
* **Gatekeeping:** Before attaching listeners, `injection-policy.js` evaluates the current `window.location.origin`. If the domain matches banking, SSO, or credential manager allowlists, execution is aborted immediately.

### Vector 2: Local IDE & Desktop Proxy (Port 8383)
* **Source:** Outbound HTTP/HTTPS requests from IDE extensions (Cursor, VS Code GitHub Copilot, Ollama CLI) redirected through local proxy `127.0.0.1:8383`.
* **Interception:** `desktop/src/ide_proxy.rs` parses HTTP request bodies, runs Rust regex and entropy classifiers, substitutes credentials, and forwards sanitized payloads upstream.

### Vector 3: Autonomous Agent Proxy (Port 8765)
* **Source:** Local agent frameworks (AutoGPT, LangChain, CrewAI) sending tool execution payloads and LLM prompts through `127.0.0.1:8765`.
* **Interception:** `companion/vigil-agent-firewall.js` intercepts outbound prompt chunks and inbound Server-Sent Events (SSE), dynamically rewriting surrogate tokens.

---

## 3. End-to-End Data Transformation Pipeline

The data lifecycle follows an 8-stage transformation pipeline:

```
[User Input in DOM]
        │
        ▼ (Stage 1: Domain Gating)
[injection-policy.js] ── (Deny) ──► [Halt Execution]
        │ (Permit)
        ▼ (Stage 2: Adversarial Normalization)
[adversarial-normalizer.js] ──► Strip Zero-Width, Unify Homoglyphs, Decrypt Leet-Speak
        │
        ▼ (Stage 3: Multi-Engine Detection)
[detection-engine.js]  ──► Regex & Heuristics (PII: CC, SSN, Emails, Phones)
[secret-engine.js]     ──► Shannon Entropy & Prefixes (AWS, GitHub PAT, Private Keys)
[injection-engine.js]  ──► Jailbreaks & Delimiter Overrides
[sentinel-engine.js]   ──► Scam & Phishing Urgency
        │
        ▼ (Stage 4: Vault & Blind Indexing)
[vigil-vault.js] ──► HMAC-SHA256 Blind Index Query (Detects enrolled identities)
        │
        ▼ (Stage 5: Consensus Firewall Arbitration)
[consensus-firewall.js] ──► 2-of-3 Byzantine Quorum (Heuristics, Neural Head, Local LLM)
        │ (Evaluates Decision: ALLOW / WARN / BLOCK)
        ▼ (Stage 6: Injective Surrogate Substitution)
[semantic-abstractor.js] ──► Replaces RAW secrets with Unique Surrogates (<SECRET_1>)
        │
        ▼ (Stage 7: Network Egress)
[External AI Cloud] ──► Cloud receives ONLY sanitized text + surrogates
        │
        ▼ (Stage 8: Origin-Bound Rehydration)
[rehydration-engine.js] ──► Inspects streaming AI tokens; restores RAW values IF:
                             • Response origin === Submission origin
                             • TTL <= 60 minutes
                             • No executable script injection in payload
```

---

## 4. Injective Surrogate Substitution & Rehydration Lifecycle

### A. Injective Mapping Specification
To prevent surrogate collisions and maintain semantic integrity across multi-entity prompts:
1. When an entity of category $C$ (e.g. `ENTERPRISE_API_CREDENTIAL`) is encountered:
2. The engine checks if the exact raw value has already been assigned a surrogate in the active session. If yes, it reuses that surrogate.
3. If it is a new raw value, the base surrogate `<C>` is generated. If `<C>` is already claimed by another value, an incremented index `<C_2>`, `<C_3>` is allocated.
4. The injective invariant guarantees:
   $$\forall \text{raw}_1, \text{raw}_2 : \text{raw}_1 \neq \text{raw}_2 \implies \text{surrogate}(\text{raw}_1) \neq \text{surrogate}(\text{raw}_2)$$

### B. Response Rehydration Boundaries
1. **Origin Isolation:** Every substitution entry records `boundOrigin: window.location.origin`. When response chunks are scanned for surrogates, rehydration will only execute if `boundOrigin === targetOrigin`. Cross-domain rehydration is strictly rejected.
2. **Temporal Window (TTL):** Each substitution entry is stamped with `createdAt = Date.now()`. Entries expire after $3,600,000\text{ ms}$ (60 minutes).
3. **Memory Bounding:** The substitution cache is bounded by `MAX_SUBSTITUTIONS = 500`. Exceeding this triggers LRU eviction of the oldest entries.
4. **Injection Sanitation:** Before substituting original text into the DOM, `isSafeToRehydrate()` validates that the response fragment does not contain malicious script tags (`<script>`, `javascript:`, `onerror=`).

---

## 5. Storage Boundaries & Cryptographic Key Management

```
+-------------------------------------------------------------------------------+
| BROWSER MEMORY (RAM)                                                          |
| - Unencrypted plaintexts (active during prompt processing only, GC collected) |
| - Injective surrogate substitution table (TTL: 60 min, Max: 500 entries)      |
| - Fast-path LRU cache of consensus decisions (Max: 500 entries)               |
+-------------------------------------------------------------------------------+
                                        │ Encrypt with WebCrypto AES-256-GCM
                                        ▼
+-------------------------------------------------------------------------------+
| PERSISTENT BROWSER STORAGE (`chrome.storage.local`)                          |
| - `vigil_vault_db`: AES-256-GCM encrypted ciphertext + IV + Auth Tag           |
| - `vigil_vault_blind_index`: HMAC-SHA256 hashes of known sensitive entities   |
| - `vigil_settings`: Protection presets (Strict / Standard / Balanced)         |
| - `vigil_threat_signatures`: SHA-256 hashes of known prompt injection patterns|
+-------------------------------------------------------------------------------+
                                        │ Ephemeral P-256 ECDH Handshake
                                        ▼
+-------------------------------------------------------------------------------+
| NATIVE OS SECURE ENCLAVE / HARDWARE ROOT                                      |
| - Hardware Enclave / TPM / OS Keyring (`desktop/src/hardware_enclave.rs`)     |
| - Hardware-sealed master encryption key                                       |
+-------------------------------------------------------------------------------+
```

---

## 6. Zero External Leakage Invariant Verification

| Network Target | Data Transmitted | Privacy Safeguards |
|---|---|---|
| **Cloud AI APIs** (`api.openai.com`, etc.) | Sanitized prompts, synthetic surrogates | All raw credentials, PII, and secrets stripped prior to dispatch. |
| **Local Inference** (`127.0.0.1:11434` Ollama) | Plaintext or redacted prompt chunks | Bound to loopback interface; zero external network egress. |
| **Local Proxies** (`127.0.0.1:8383`, `:8765`) | In-flight developer and agent traffic | Bound strictly to loopback; origin and host headers validated. |
| **Swarm Mesh Relay** | Threat rule SHA-256 hashes only | Zero prompt content, zero PII, zero tokens transmitted. |
| **External Analytics / Telemetry** | **NONE** | No external tracking, telemetry, or analytics beacons exist in the codebase. |

