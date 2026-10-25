# Sentinel Stage 1: Current Architecture & Source-Level Audit

**Document Version**: 1.0.0  
**Specification**: `Plan.pdf` (Stage 1: Source-Level Architecture Audit)  
**Date**: 2026-10-25  
**Audit Target**: `Vigil AI Guardian` Repository  

---

## 1. Source Tree Map (Section 3.1)

```text
vigil.ai/
├── src/                               # Browser Extension Source (MV3)
│   ├── manifest.json                  # Manifest V3 configuration & strict CSP
│   ├── background/                    # Background Service Worker & Core Subsystems
│   │   ├── background.js              # Central extension coordinator, alarm handlers
│   │   ├── compute-boundary.js        # WebGPU / WASM execution isolation
│   │   ├── consensus-firewall.js      # 2-of-3 multi-model consensus voting engine
│   │   ├── file-integrity.js          # Self-audit & SHA-256 manifest verifier
│   │   ├── forensics-replay.js        # Prompt & event replay timeline logger
│   │   ├── local-lora.js              # On-device fine-tuned weight adapter
│   │   ├── native-bridge.js           # Native Messaging IPC (ECDH + AES-GCM)
│   │   ├── offscreen.js               # Offscreen document for DOM / audio / ML tasks
│   │   ├── prompt-git.js              # Micro-git prompt versioning system
│   │   ├── redteam-agent.js           # Local adversarial generator & probe
│   │   ├── semantic-drift.js          # Embedding drift & context divergence monitor
│   │   ├── shopping-detector.js       # Financial checkout / cart fraud monitor
│   │   ├── token-budget.js            # Agent session & daily token quota manager
│   │   ├── vigil-vault.js             # AES-256-GCM encrypted pseudonym vault
│   │   └── webgpu-engine.js           # WebGPU hardware acceleration wrapper
│   ├── content/                       # Content Scripts & Interception Hooks
│   │   ├── content.js                 # DOM input/textarea/contenteditable hooks & UI toasts
│   │   ├── scanner-worker.js          # Off-thread Web Worker for high-throughput regex
│   │   └── modules/                   # Individual Detection & Analysis Engines
│   │       ├── adversarial-normalizer.js # Unicode homoglyph, zero-width, invisible char cleaner
│   │       ├── detection-engine.js    # Regex PII, Luhn credit card, SSN, phone, address
│   │       ├── honeytoken-canary-generator.js # Decoy credential injector
│   │       ├── injection-engine.js    # Prompt injection syntax heuristics & indicators
│   │       ├── injection-policy.js    # Sensitive banking/credential domain denial rules
│   │       ├── k-anonymity-auditor.js  # Quasi-identifier re-identification scorer
│   │       ├── leakage-detector.js    # Outbound prompt exfiltration classifier
│   │       ├── redos-engine.js        # Safe regex parser preventing catastrophic backtracking
│   │       ├── rehydration-engine.js  # Replaces synthetic tokens with real user text
│   │       ├── secret-engine.js       # AWS, GitHub PAT, OpenAI, SSH/RSA private keys
│   │       ├── semantic-abstractor.js # Generates semantic summaries of masked entities
│   │       ├── vision-canary.js       # Micro-canvas, steganography, opacity detector
│   │       └── wasm-simd-fft.js       # WASM SIMD Fast Fourier Transform audio engine
│   ├── options/                       # Extension settings UI
│   ├── popup/                         # Extension popup interface & status badge
│   └── shared/                        # Shared Utilities
│       ├── phash.js                   # Perceptual image hashing
│       ├── siem-exporter.js           # CEF, OCSF v1.1.0, JSON telemetry formatters
│       ├── storage-audit.js           # Chrome storage access auditor
│       ├── vigil-shared.js            # Configuration merging, validation, defaults
│       └── zk-compliance.js           # Zero-knowledge proof attestation generator
├── companion/                         # Native Node.js Tools & Setup
│   ├── vigil-agent-firewall.js        # Loopback HTTP forward proxy (port 8765)
│   ├── hardware-enclave.js            # Node native hardware enclave fallback
│   ├── sse-rewrite.js                 # Server-Sent Events stream chunk rewriter
│   ├── vigil-canary.js                # Honeytoken challenge generator
│   ├── vigil-wrap.js                  # CLI wrapper setting HTTP_PROXY / HTTPS_PROXY
│   └── installer/                     # Native messaging host registration scripts
├── desktop/                           # Rust Native Desktop Companion (`com.vigil.desktop`)
│   ├── Cargo.toml / Cargo.lock        # Rust dependency manifests (serde, aes-gcm, p256, sha2)
│   └── src/                           # Rust Subsystems
│       ├── main.rs                    # Stdio JSON-RPC 2.0 loop, mutual auth, message router
│       ├── ide_proxy.rs               # In-memory prompt inspection & TokenBudgetEngine
│       ├── file_integrity.rs          # Native filesystem hash auditor with path traversal defense
│       ├── hardware_enclave.rs        # OS Keychain / TPM / Secure Enclave binding
│       ├── ml_offload.rs              # Local GPU/CPU ML inference dispatcher
│       └── phash.rs                   # Rust SIMD pHash implementation
├── docs/                              # Architecture, Incident Response, Compliance Specs
│   └── sentinel/                      # Sentinel Evolution Specifications (Plan.pdf)
├── tests/                             # 60 Jest Unit & Integration Test Suites
├── e2e/                               # Playwright End-to-End Browser Tests
├── evaluation/                        # Adversarial benchmarks, latency suites, optimizer
├── playground/                        # Isolated local cyber range test app
├── relay/                             # Local peer threat hash synchronization
└── tools/                             # Automated online evaluation harnesses
```

---

## 2. Component Tracing & Technical Realities (Sections 3.2 – 3.3)

### 2.1 Browser Extension Manifest & Interception Plane
* **File**: [`src/manifest.json`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/manifest.json)
* **Entry Point**: `document_end` on all frames across `<all_urls>` via `content_scripts`.
* **Inputs & Scope**: All DOM keyboard inputs, pastes, form submissions, and in-page `window.fetch` / `window.XMLHttpRequest` requests.
* **Side Effects**: In-DOM sanitization (replacing sensitive substrings with `[VIGIL-N]` tokens before submission), display of warning pills / banners.
* **Network Boundary**: Enforced by strict MV3 `content_security_policy`:
  ```text
  connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:* http://localhost:* ws://localhost:*;
  ```
  Zero remote network calls are permitted from extension pages.

### 2.2 Content Script Scanner & Web Worker
* **Files**: [`src/content/content.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/content/content.js), [`src/content/scanner-worker.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/content/scanner-worker.js)
* **Enforcement Behavior**: 
  * Captures `keydown` (Enter) and form `submit` events.
  * Pauses submission, invokes regex heuristics via `scanner-worker.js` or in-thread engines.
  * If critical secrets (PEM keys, high-entropy API tokens) are found, the submission is halted (`event.preventDefault()`, `event.stopImmediatePropagation()`).
* **Test Coverage**: Tested comprehensively in [`tests/outbound-private-key-and-submission-guard.test.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/tests/outbound-private-key-and-submission-guard.test.js) and `tests/silent-guardian.test.js`.

### 2.3 Native Messaging Bridge & Crypto Handshake
* **Files**: [`src/background/native-bridge.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/background/native-bridge.js), [`desktop/src/main.rs`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/desktop/src/main.rs)
* **Entry Point**: `chrome.runtime.connectNative("com.vigil.desktop")` communicating over 32-bit length-prefixed stdio JSON-RPC 2.0.
* **Authentication & Authorization**:
  * Step 1: Extension ID check (`emkokehejldjlfljlhhcimnfefcjcmon` verified by native host).
  * Step 2: `vigil.auth.handshake` establishes an authenticated `session_token` and performs an ECDH (P-256) key exchange.
  * Step 3: All subsequent privileged RPCs must be wrapped in `vigil.encrypted_frame` (AES-256-GCM) with strictly incrementing sequence numbers (`seq`), rejecting replayed or out-of-order frames.
* **Exposed RPC Methods**:
  * `vigil.inspectIdePrompt`: Inspects and redacts secrets in developer prompts.
  * `vigil.tokenBudgetRecord` / `vigil.tokenBudgetStatus`: Tracks agent token consumption.
  * `vigil.hardwareSealKey` / `vigil.hardwareUnsealKey`: TPM / Keychain master key sealing.
  * `vigil.verifyFileIntegrity` / `vigil.restoreFileIntegrity`: SHA-256 self-audit against tampering.
  * `vigil.exportSiemLog` / `vigil.streamSiemLog`: Enterprise logging.
* **Test Coverage**: Tested in [`tests/native-bridge.test.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/tests/native-bridge.test.js) and Rust unit tests in `desktop/src/main.rs`.

### 2.4 Agent Firewall & IDE Proxy (The Pre-Sentinel Implementation)
* **Files**: [`companion/vigil-agent-firewall.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/companion/vigil-agent-firewall.js), [`desktop/src/ide_proxy.rs`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/desktop/src/ide_proxy.rs)
* **Entry Point**: Node.js HTTP Proxy on `127.0.0.1:8765`.
* **Modes**:
  * `monitor`: Scans bodies, logs findings, forwards untouched.
  * `guard`: Scans bodies, replaces configured sensitive values with stable `[VIGIL-N]` tokens, and forwards to upstream.
  * `lock`: Blocks requests if dangerous injections, unmasked PII, or raw secrets are detected.
* **Test Coverage**: Tested in [`tests/companion.test.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/tests/companion.test.js).

---

## 3. Enforcement Reality & Critical Blind Spots (Section 3.4)

Answering the exact enforcement questions mandated by Section 3.4 of `Plan.pdf`:

### 1. Does the current proxy inspect, decide, block, or only log?
* **For Cleartext HTTP**: In `lock` mode it **blocks** (returns HTTP 403); in `guard` mode it **mutates** (redacts sensitive tokens); in `monitor` mode it **only logs**.
* **For HTTPS CONNECT Tunnels**: It **CANNOT inspect payload bodies**. The code in [`companion/vigil-agent-firewall.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/companion/vigil-agent-firewall.js#L905-L943) explicitly tunnels TLS traffic directly via `net.connect()` without MITM certificate inspection:
  ```javascript
  // CONNECT tunnels are end-to-end TLS encrypted and CANNOT inspect payload bodies
  // without a trusted local CA root certificate (TLS MITM). Destination validation
  // is strictly enforced, and uninspected status is explicitly audited.
  ```
  It validates only the target `host:port` (blocking metadata services and private IPs unless `--allow-private` is passed), but the actual prompt and response remain an **uninspected blind spot**.

### 2. What exact operation reaches it?
* Only HTTP/HTTPS requests originating from tools explicitly configured to use `HTTP_PROXY=http://127.0.0.1:8765`.

### 3. Can the caller bypass it?
* **YES**. Any agent process can simply unset `HTTP_PROXY`, make direct socket connections, call native shell binaries (`curl`, `git`, `ssh`), or make filesystem mutations directly on the OS.
* **Crucial Finding**: The existing `vigil-agent-firewall.js` is an HTTP transport proxy, **not an execution-boundary tool gateway**. It has **zero visibility or control** over:
  * File reads and writes on disk.
  * Bash/terminal executions.
  * MCP (Model Context Protocol) tool invocations.
  * Subprocess spawning.

### 4. What happens if the component is stopped, disconnected, or times out?
* If `vigil-agent-firewall.js` stops: Any client with `HTTP_PROXY` configured receives connection refused (`ECONNREFUSED`) and fails.
* If `com.vigil.desktop` stops: The extension falls back gracefully to in-browser heuristics and software crypto (`tests/native-bridge.test.js`).

---

## 4. The Zero-Cloud Promise Audit (Section 3.5)

* **Audit Search**: Scanned `src/`, `companion/`, `desktop/` for remote domains, telemetry beacons, analytics trackers, and external cloud APIs.
* **Findings**:
  * **External Telemetry**: **ZERO**. No Google Analytics, Sentry, Mixpanel, or third-party telemetry libraries exist in the repository.
  * **Local Host Access**:
    * `http://localhost:11434` is queried conditionally if the user has a local Ollama instance running.
    * `http://127.0.0.1:8765` is the local companion proxy.
  * **Model Weights**: Transformers models are loaded from local extension storage or offscreen documents (`onnxruntime-web`). If models are missing, the runtime falls back locally to regex/WASM heuristics without making remote downloads.
* **Verdict**: The repository is **100% compliant** with the Zero-Cloud promise.

---

## 5. Architectural Implications for Sentinel

To fulfill `Plan.pdf`, Sentinel must **NOT** merely be another HTTP proxy. Sentinel must introduce:
1. **Direct Execution-Boundary Interception**: Intercepting tools at the agent's actual operational boundary (e.g. MCP proxy/gateway or Claude Code hook).
2. **Deterministic Shared Policy Engine**: Deciding `allow`, `deny`, or `require_approval` on normalized actions (`fs:read`, `fs:write`, `shell:exec`, `net:request`) before any side effect occurs.
3. **Audit Correlation**: Linking prompt findings to tool execution requests.

