<div align="center">

<img src="src/icons/icon128.png" width="96" alt="Vigil AI Guardian + Sentinel" />

# Vigil AI Guardian & Sentinel

**The Open-Source AI Security Architecture — Browser Privacy Shield & Policy-Enforced Agent Enforcement Gateway.**  
*100% local, zero-trust, fail-closed, zero-cloud.*

[![Version](https://img.shields.io/badge/version-1.1.0-6366f1?style=flat-square)](https://github.com/starboy-hub/vigil.ai)
[![License](https://img.shields.io/badge/license-MIT-10b981?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-926%20unit%20%7C%2027%20rust%20%7C%20105%20e2e%20passing-10b981?style=flat-square)](#testing)
[![Adversarial Catch Rate](https://img.shields.io/badge/adversarial%20catch%20rate-100%25-10b981?style=flat-square)](#security-score)
[![False Positives](https://img.shields.io/badge/false%20positive%20rate-0.00%25-10b981?style=flat-square)](#security-score)
[![Chrome](https://img.shields.io/badge/Chrome-MV3-4285F4?style=flat-square&logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/)
[![Firefox](https://img.shields.io/badge/Firefox-MV3-FF7139?style=flat-square&logo=firefox&logoColor=white)](#installation)

*Vigil AI intercepts and neutralizes AI-era threats — prompt injections, data leaks, credential scraping, malicious MCP tools, destructive agent shell commands, and phishing — before they leave your machine.*

[**Install**](#installation) · [**Features**](#features) · [**Sentinel Agent Gateway**](#-sentinel-ai-agent-security-gateway) · [**Architecture**](#architecture) · [**Testing**](#testing) · [**Contributing**](#contributing)

</div>

---

## What is Vigil AI + Sentinel?

As artificial intelligence evolves from text chatbots into autonomous desktop agents (Claude Code, Cursor, Devin, custom MCP clients), the attack surface expands dramatically:

1. **In the Browser**: Typing into ChatGPT, Claude, or webmail risks silently exposing credit card numbers, passwords, health disclosures, API keys, and corporate source code.
2. **On the Host**: Autonomous coding agents running in your terminal can be hijacked via indirect prompt injection to execute destructive shell scripts (`rm -rf /`), exfiltrate cloud metadata (`169.254.169.254`), escape workspaces, or smuggle Trojan Source Unicode vulnerabilities into your codebase.

**Vigil AI + Sentinel solves both sides of this security boundary entirely on-device**:
* **Vigil Browser Shield**: Real-time outbound DLP, anti-injection firewall, and non-intrusive pre-submission privacy protection across Chrome, Brave, Edge, and Firefox.
* **Sentinel Agent Gateway**: A deterministic, fail-closed policy enforcement layer and tool proxy intercepting autonomous AI agent actions (MCP JSON-RPC, shell execution, file I/O, network requests) before any side effect occurs on your operating system.

> **Zero-cloud guarantee:** All scanning, AST normalization, honeypot traps, cryptographic ledger chaining, and policy evaluations execute locally on your hardware. Vigil never sends your code, prompts, or credentials to any remote server.

---

## 🛡️ Sentinel: AI Agent Security Gateway

Built in accordance with the *Developer Agent Master Execution Specification* ([`Plan.pdf`](Plan.pdf)), **Sentinel** acts as an unbreakable policy firewall between autonomous AI agents and your local operating system.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      AUTONOMOUS AGENT RUNTIME                          │
│          (Cursor, Claude Code, Terminal CLI, Custom MCP Agents)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Tool Invocations / Shell / Network
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     SENTINEL ENFORCEMENT GATEWAY                       │
│                                                                        │
│  ┌───────────────────────┐          ┌───────────────────────────────┐  │
│  │  Model Context Proto  │          │  Shell AST De-Obfuscator      │  │
│  │  (MCP) Gateway        │          │  · Quote unrolling: r'm' -rf  │  │
│  │  · JSON-RPC validator │          │  · Pipeline base64 decode     │  │
│  │  · TOCTOU action hash │          │  · Dynamic eval/process sub   │  │
│  └───────────┬───────────┘          └───────────────┬───────────────┘  │
│              │                                      │                  │
│              ▼                                      ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │             DETERMINISTIC POLICY ENGINE (4 TIERS)                │  │
│  │  Tier 1: Non-Negotiable Hard Safety Rules (Path escape, IMDS)     │  │
│  │  Tier 2: Explicit Deny Rules (.env, secrets, quota breach)       │  │
│  │  Tier 3: Human Approval Gates (Destructive ops, config edits)     │  │
│  │  Tier 4: Explicit Allow (Scoped workspace read/write)            │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│              ┌──────────────────────┴──────────────────────┐           │
│              ▼                                             ▼           │
│  ┌───────────────────────────────┐          ┌───────────────────────┐  │
│  │  Active Canary Honeypots      │          │  Scoped Secret Broker │  │
│  │  · .env.canary tripwires      │          │  · HMAC-SHA256 tokens │  │
│  │  · L0 session quarantine      │          │  · Boundary injection │  │
│  └───────────┬───────────────────┘          └───────────────┬───────┘  │
│              │                                              │          │
│              ▼                                              ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │          CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT LEDGER               │  │
│  │     SHA-256 Hash Chaining from Genesis · CEF / JSON Export       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Safe, Verified Execution
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        LOCAL OPERATING SYSTEM                          │
│                   Filesystem · Shell · Network Sockets                 │
└────────────────────────────────────────────────────────────────────────┘
```

### Sentinel Core Capabilities

| Capability | How It Protects You | Specification Reference |
|---|---|---|
| **MCP Tool Enforcement Gateway** | Intercepts all Model Context Protocol `tools/call` invocations. Validates JSON-RPC schemas, binds human approvals to cryptographic action hashes (TOCTOU defense), and deep-scrubs secrets from agent outputs. | Stage 4 ([`src/sentinel/gateway/mcp-gateway.js`](src/sentinel/gateway/mcp-gateway.js)) |
| **Shell AST De-Obfuscation** | Normalizes quote-splitting (e.g. `r'm' -rf /`), unrolls variable concatenations, and decodes base64-piped payloads (`echo cm0... \| base64 -d \| sh`) before shell dispatch. | Stage 4 ([`src/sentinel/gateway/shell-ast-analyzer.js`](src/sentinel/gateway/shell-ast-analyzer.js)) |
| **Trojan Source & Diff Analyzer** | Scans proposed code modifications for CVE-2021-42574 bidirectional Unicode override characters (`\u202E`, zero-width spaces) used to disguise malicious logic in benign-looking code. | Stage 4 ([`src/sentinel/diff/diff-analyzer.js`](src/sentinel/diff/diff-analyzer.js)) |
| **Deterministic Policy Engine** | Evaluates actions across 4 strict precedence tiers: Hard Safety Rules &rarr; Explicit Deny &rarr; Human Approval Gates &rarr; Explicit Allow. Fails closed with bounded timeouts. | Stage 3 ([`src/sentinel/policy-engine.js`](src/sentinel/policy-engine.js)) |
| **Active Canary Honeypots & L0 Quarantine** | Deploys decoy canary credentials (`.env.canary`). If an agent attempts to harvest or exfiltrate a canary token, Sentinel trips an instant L0 Kill Switch, permanently quarantining the session. | Stage 6 ([`src/sentinel/credentials/canary-trap-manager.js`](src/sentinel/credentials/canary-trap-manager.js)) |
| **Capability Token Secret Broker** | Agents never receive raw API keys or private keys. Sentinel mints short-lived, HMAC-SHA256-signed capability tokens, injecting credentials at the execution boundary and redacting output. | Stage 6 ([`src/sentinel/credentials/secret-broker.js`](src/sentinel/credentials/secret-broker.js)) |
| **Tamper-Evident Audit Ledger** | Cryptographic hash chaining from genesis records every action proposal, policy verdict, approval, and execution. Detects any retrofitted log tampering, entry deletion, or timestamp modification. | Stage 7 ([`src/sentinel/ledger/audit-ledger.js`](src/sentinel/ledger/audit-ledger.js)) |
| **Attack-Chain Correlation** | Correlates multi-step threat progressions (e.g., prompt injection &rarr; credential reconnaissance &rarr; unauthorized egress) using temporal sliding windows and taint propagation. | Stage 8 ([`src/sentinel/correlation/chain-detector.js`](src/sentinel/correlation/chain-detector.js)) |
| **Autonomous Red-Team Lab** | Hermetic simulation engine replaying 12 real-world attack vectors with a verified **100% block rate** and **0% false-positive rate** on benign developer commands. | Stage 9 ([`src/sentinel/redteam/simulation-lab.js`](src/sentinel/redteam/simulation-lab.js)) |

---

## 🌐 Browser Protection & Ergonomic Silent Guardian

Vigil’s browser extension delivers enterprise-grade DLP without disrupting your typing flow:

### 🔒 Sovereign Input Protection (Zero Mid-Typing Mutation)
* **Pristine Keystrokes**: Vigil **never** overwrites your active textarea while you are typing. Keystrokes remain 100% sovereign.
* **Non-Intrusive Indicators**: A subtle green shield appears in the corner of the input to confirm silent protection is active.
* **Pre-Submission Interception**: Real protection occurs at the boundary. When you click **Send** or hit **Enter**, Vigil's `submissionGuard` intercepts any unprotected secrets or credentials and displays a clean confirmation bar asking whether to mask before network egress.

### 🚦 Strict UI Mutex (Zero Alert Clutter)
Vigil enforces strict mutual exclusion across all on-screen overlays:
* **No Triple-Siren Collisions**: Only **one** primary alert ever renders at any time. Displaying a banner or pill immediately dismisses all other overlays.
* **Minimized by Default**: The 360px side card stays tucked away as a subtle bottom-right pill (`1 Protected ▾`) during passive typing, only expanding when you explicitly click **[Review]** or click the pill.

### Outbound Data Loss Prevention Coverage

| Data Category | Detection Mechanism | Enforcement Action |
|---|---|---|
| **Credit Cards & Banking** | Luhn checksum algorithm + context-aware scoring | Pre-submission mask / block |
| **Social Security & Tax IDs** | Format matching + Area/Group valid range check | Pre-submission mask / block |
| **Medical PHI & Records** | Clinical regex + Contextual Precision Engine (CPE) | Yellow non-blocking banner & pre-submission review |
| **API Keys & Cloud Tokens** | Shannon entropy validation + vendor signature regex (AWS, GitHub, Stripe, OpenAI, PKCS#8) | Instant red warning capsule + submission hold |
| **Passwords & SSH Keys** | PEM header parsing + credential assignment regex | Critical interrupt |
| **Names, Emails, and Phone Numbers** | Heuristic name extractor + E.164 phone classifier | Quiet green indicator + optional submission mask |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    BROWSER EXTENSION                         │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │  Silent      │    │   Detection Pipeline              │   │
│  │  Guardian UI │───▶│   ① Evasion Normalizer           │   │
│  │  Engine      │    │   ② ReDoS-Hardened Engine        │   │
│  └──────────────┘    │   ③ Secret & PII Scanner          │   │
│                      │   ④ Injection Defense Engine       │   │
│  ┌──────────────┐    │   ⑤ Sentinel (Phishing/Scams)     │   │
│  │  Webmail     │    │   ⑥ Conversation Drift Guard      │   │
│  │  Shield      │    │   ⑦ Decoy Credential System       │   │
│  └──────────────┘    └──────────────────────────────────┘   │
│                                      │                       │
│  ┌──────────────┐    ┌───────────────▼──────────────────┐   │
│  │  Vision      │    │   Multi-Tier Detection Engine    │   │
│  │  Firewall    │    │   Tier 1: Fast Rule Engine        │   │
│  └──────────────┘    │   Tier 2: WebGPU Neural (ONNX)   │   │
│                      │   Tier 3: Local SLM / Heuristics  │   │
│  ┌──────────────┐    └──────────────────────────────────┘   │
│  │  Identity    │                    │                       │
│  │  Vault       │    ┌───────────────▼──────────────────┐   │
│  │  (AES-GCM)   │    │   Local Processing Engine         │   │
│  └──────────────┘    │   On-Device Preferences           │   │
│                      │   Private Workflow Adaptation     │   │
│                      └──────────────────────────────────┘   │
└──────────────────────────────────┬──────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│               NATIVE DESKTOP COMPANION (RUST)                │
│                                                              │
│  · Chrome Native Messaging Host (stdin/stdout)               │
│  · Hardware Enclave (AES-256-GCM sealed keys)               │
│  · OS Keychain Integration                                   │
│  · High-Speed Sentinel Rust Policy Evaluator                 │
│  · Voice Spectral FFT Canary (Acoustic anti-deepfake)        │
└──────────────────────────────────┬──────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────┐
│              AGENT FIREWALL & SENTINEL PROXY                 │
│                 http://127.0.0.1:8765                        │
│                                                              │
│  · MCP Gateway & JSON-RPC Interceptor                        │
│  · Shell AST De-Obfuscator & CLI Shim                        │
│  · Link-Local Cloud Metadata (IMDS) Blocker                  │
│  · Active Canary Honeypot & L0 Kill Switch                   │
│  · Cryptographic Tamper-Evident Audit Ledger (CEF / JSON)    │
│  · Single-Window Management Console                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation & Quick Start

### 1. Browser Extension (Chrome / Brave / Edge)

```bash
git clone https://github.com/starboy-hub/vigil.ai.git
cd vigil.ai
npm install
npm run build
```

1. Navigate to `chrome://extensions` in your browser.
2. Toggle on **Developer Mode** (top-right).
3. Click **Load unpacked** and select the `/dist` directory.

### 2. Firefox Add-on

```bash
npm run build:firefox
```
Open `about:debugging` &rarr; **This Firefox** &rarr; **Load Temporary Add-on** &rarr; select any file inside `dist-firefox/`.

### 3. Native Desktop Companion (Rust)

```bash
cd desktop
cargo build --release
```

To register the native messaging host for your browser:
```bash
node companion/installer/register-native-hosts.js
```

### 4. Running the Sentinel Agent Firewall

Start the local loopback proxy to protect CLI tools and autonomous agents:

```bash
node companion/vigil-agent-firewall.js --mode=guard
```
* **Interactive Dashboard**: Open [`http://127.0.0.1:8765/vigil-dashboard`](http://127.0.0.1:8765/vigil-dashboard)
* **Single-Window Operations Console**: Open [`sentinel-unified-console.html`](sentinel-unified-console.html) in any browser.

---

## Testing & Quality Assurance

Vigil and Sentinel enforce multi-tier test automation and strict supply-chain verification before any release:

```bash
# Run full Jest test suite (71 test suites, 926 tests, 100% pass)
npm test

# Run all 11 Sentinel Agent Security test suites
npx jest tests/sentinel-*.test.js

# Run native Rust companion tests (27 unit tests)
cd desktop && cargo test

# Run ESLint (zero errors, zero warnings enforced)
npm run lint

# Run automated 7-Gate Security Release Pipeline
npm run release:gate
```

### The 7-Gate Security Release Pipeline (`npm run release:gate`)
Every build must pass 7 automated verification gates before distribution:
1. **Gate 1: Extension Key Pinning** — Manifest public key mathematically verified (`emkokehejldjlfljlhhcimnfefcjcmon`).
2. **Gate 2: Package Completeness** — Manifest and asset completeness validation.
3. **Gate 3: Deterministic Reproducibility** — Build tree SHA-256 composite hash verification against committed baseline.
4. **Gate 4: Security Audit Dossier** — Automated generation of `dist/audit-dossier.json`.
5. **Gate 5: Strict CSP Lockdown** — `default-src 'none'`, `object-src 'none'` enforced.
6. **Gate 6: Injection Policy Integrity** — Sensitive auth/vault injection denial verified.
7. **Gate 7: RFC 9116 Policy & Disclosures** — Security policy and vulnerability guidelines verified.

---

## Privacy Guarantee

| Data Surface | Privacy Policy Guarantee |
|---|---|
| **Prompts & Keystrokes** | Evaluated locally in-memory only. Never logged, never transmitted to any external server. |
| **Agent Tool Calls** | Processed through local policy engine. Secrets are scrubbed at execution boundaries. |
| **Identity Vault** | Encrypted locally with AES-256-GCM and bound to your OS Keychain. |
| **Canary Tokens** | High-entropy synthetic decoy strings generated on-device. No telemetry. |
| **Audit Ledger** | Append-only SHA-256 hash-chained log stored purely on your local machine. |
| **Telemetry & Analytics** | Zero analytics, zero phone-home pings, zero cloud dependencies. |

---

## Contributing

Vigil AI & Sentinel are open-source and MIT-licensed. Contributions are welcome!

```bash
git clone https://github.com/starboy-hub/vigil.ai.git
cd vigil.ai
npm install
npm test
```

Please ensure:
1. All changes include automated unit tests alongside implementation.
2. Code passes `npm run lint` with **0 errors and 0 warnings**.
3. All 7 release gates pass: `npm run release:gate`.
4. User keystrokes are treated as sovereign—no mid-typing DOM mutation.

Security vulnerabilities should be reported privately in accordance with our [Security Policy](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).

<div align="center">

Built with ❤️ for privacy, sovereignty, and safe AI autonomy.  
*No cloud. No telemetry. No compromise.*

</div>
