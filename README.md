<div align="center">

<img src="src/icons/icon128.png" width="96" alt="Vigil AI Guardian + Sentinel" />

# Vigil AI Guardian & Sentinel Agent Gateway

### Sovereign Enterprise AI Security & Policy-Enforced Autonomous Agent Firewall
**100% Local Execution · Air-Gapped · Fail-Closed · Zero Outbound Telemetry**

[![Version](https://img.shields.io/badge/version-1.1.0-6366f1?style=flat-square)](https://github.com/starboy-hub/vigil.ai)
[![License: AGPLv3 / Commercial](https://img.shields.io/badge/license-AGPLv3%20%7C%20Commercial-blue?style=flat-square)](LICENSE)
[![Tests: 100% Passing](https://img.shields.io/badge/tests-931%20unit%20%7C%2028%20rust%20%7C%2038%20e2e%20passing-10b981?style=flat-square)](#testing--verification)
[![Rust Invariant Fuzzing](https://img.shields.io/badge/fuzzing-100k%20cycles%20%7C%200%20panics-10b981?style=flat-square)](#supply-chain-assurance--7-gate-security-pipeline)
[![Adversarial Block Rate](https://img.shields.io/badge/adversarial%20block%20rate-100%25-10b981?style=flat-square)](#autonomous-red-team-simulation-lab)
[![False Positive Rate](https://img.shields.io/badge/false%20positives-0.00%25-10b981?style=flat-square)](#autonomous-red-team-simulation-lab)
[![Compliance Ready](https://img.shields.io/badge/compliance-SOC%202%20%7C%20ISO%2027001%20%7C%20HIPAA%20%7C%20GDPR-purple?style=flat-square)](#enterprise-compliance--governance-matrix)

<p align="center">
  <b>Vigil AI intercepts and neutralizes the two greatest attack surfaces of modern enterprise artificial intelligence:</b><br/>
  <b>1. Outbound Data Loss (Browser):</b> Secret keys, source code, and PII typed into web LLMs (ChatGPT, Claude, Gemini, webmail).<br/>
  <b>2. Autonomous Agent Hijacking (Host):</b> Destructive shell execution, cloud metadata exfiltration, and tool abuse by autonomous coding agents (Cursor, Claude Code, Devin, MCP clients).
</p>

[**Executive Summary**](#executive-summary-for-cisos--security-leadership) · [**Architecture**](ARCHITECTURE.md) · [**Security Policy**](SECURITY.md) · [**Sentinel Gateway**](#1-sentinel-ai-agent-security-gateway) · [**Browser DLP**](#2-browser-dlp--sovereign-silent-guardian) · [**Dual-Licensing**](#enterprise-commercial-licensing--support) · [**Deployment**](#deployment--operations)

</div>

---

## Executive Summary for CISOs & Security Leadership

As enterprise workforces adopt generative AI and autonomous developer agents, traditional Perimeter and Cloud DLP solutions fail:

1. **The Browser Blindspot (Shadow AI):** Employees routinely paste production database connection strings, AWS keys, customer PHI, and confidential financial disclosures into public web LLMs. Cloud DLP is too late—once the packet leaves the endpoint, the third-party LLM provider has ingested the secret.
2. **The Host Execution Crisis (Autonomous Agents):** Developers are giving autonomous coding agents (Cursor, Claude Code, Terminal LLMs) direct access to terminal shells, file systems, and network sockets. A single indirect prompt injection in a repository README or issue description can hijack an agent to execute catastrophic commands (`rm -rf /`), harvest link-local cloud metadata (`169.254.169.254`), or exfiltrate private credentials.

**Vigil AI is the first sovereign, air-gapped security stack that neutralizes both threats entirely on the endpoint before network or operating system side-effects occur.**

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 ENTERPRISE THREAT MODEL                                │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ BROWSER THREAT SURFACE (HUMAN TYPING)     │ HOST THREAT SURFACE (AUTONOMOUS AGENTS)    │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ · Unintentional AWS / GitHub token leaks  │ · Destructive shell commands (rm -rf /)    │
│ · Customer PII / Medical PHI disclosure   │ · Cloud Metadata (IMDS SSRF) exfiltration  │
│ · Inbound Indirect Prompt Injection       │ · Base64-piped & obfuscated shell commands │
│ · Trojan Source Unicode hidden payloads   │ · Malicious MCP (Model Context) tool abuse │
│ · Zero-width character steganography      │ · Secret & .env credential harvesting      │
├───────────────────────────────────────────┴────────────────────────────────────────────┤
│                           VIGIL AI AIR-GAPPED DEFENSE MATRIX                           │
│     100% Local Inference · Sub-7ms Latency · Fail-Closed · Zero Telemetry Egress       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Security Pillars

### 1. 🛡️ Sentinel: AI Agent Security Gateway

Built in accordance with the *Developer Agent Master Execution Specification* ([`Plan.pdf`](Plan.pdf)), **Sentinel** operates as a deterministic, fail-closed policy proxy between autonomous AI agents and your local operating system (`http://127.0.0.1:8765`).

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
│  │  · Dynamic rotating decoys    │          │  · HMAC-SHA256 tokens │  │
│  │  · L0 session quarantine      │          │  · Boundary injection │  │
│  └───────────┬───────────────────┘          └───────────────┬───────┘  │
│              │                                              │          │
│              ▼                                              ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │          CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT LEDGER               │  │
│  │     SHA-256 Hash Chaining from Genesis · CEF / OCSF Export       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Safe, Verified Execution
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        LOCAL OPERATING SYSTEM                          │
│                   Filesystem · Shell · Network Sockets                 │
└────────────────────────────────────────────────────────────────────────┘
```

* **MCP Tool Enforcement Gateway:** Intercepts Model Context Protocol `tools/call` invocations. Validates JSON-RPC schemas, binds approvals to cryptographic action hashes ($\text{SHA-256}$ TOCTOU defense), and deep-scrubs secrets.
* **Shell AST De-Obfuscation:** Normalizes quote-splitting (e.g. `r'm' -rf /`), unrolls variable concatenations, strips zero-width spaces (`\u200B-\u200D\uFEFF`), and decodes base64-piped commands (`echo cm0... | base64 -d | sh`) before dispatch.
* **Universal Cloud Metadata Firewall (IMDS):** Blocks all agent access to AWS, GCP, and Azure link-local instance metadata endpoints (`169.254.169.254`, `metadata.google.internal`), preventing SSRF-based IAM role exfiltration.
* **Dynamic Rotating Honeypots & L0 Quarantine:** Seeds high-entropy, indistinguishable decoy tokens into workspaces. Any agent read or network exfiltration of a canary trips an instantaneous L0 Kill Switch, permanently quarantining the session and generating a forensic provenance alert.
* **HMAC-SHA256 Scoped Secret Broker:** Agents never see raw API keys. Sentinel mints short-lived, signed capability tokens, injecting real credentials only at the operating system execution boundary.

---

### 2. 🌐 Browser DLP & Sovereign Silent Guardian

Vigil’s browser extension delivers enterprise-grade DLP across Chrome, Brave, Edge, and Firefox without disrupting developer workflow or typing performance:

* **Sovereign Keystrokes (Zero Mid-Typing Mutation):** Vigil **never** mutates active textareas while typing. Keystrokes remain 100% sovereign.
* **Dynamic Web Worker Sandbox:** Content scripts incur zero background freezing. Heavy math and WebGPU run inside isolated background workers, instantiated dynamically only upon text focus or AI domain navigation.
* **Pre-Submission Interception Mutex:** When the user clicks **Send** or hits **Enter**, the `submissionGuard` intercepts unmasked credentials or PII, displaying an ergonomic confirmation bar with one-click deterministic pseudonymization.
* **Sensitive Domain Immunity:** Enforces strict execution denial on SSO portals (Okta, Auth0, Ping), password managers (1Password, Bitwarden), and banking systems.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ OUTBOUND DATA LOSS PREVENTION COVERAGE MATRIX                            │
├─────────────────────────┬────────────────────────────┬───────────────────┤
│ DATA CLASSIFICATION     │ DETECTION MECHANISM        │ ENFORCEMENT       │
├─────────────────────────┼────────────────────────────┼───────────────────┤
│ Cloud Credentials       │ Shannon Entropy + Signatures│ Pre-submission hold│
│ (AWS, Azure, GCP, OpenAI)│ (AKIA, ghp_, sk-proj, etc.)│ & Red Warning     │
├─────────────────────────┼────────────────────────────┼───────────────────┤
│ Private Keys & Secrets  │ PKCS#8, RSA, OpenSSH PEM   │ Hard Block &      │
│                         │ parsing + regex classifier │ Critical Interrupt│
├─────────────────────────┼────────────────────────────┼───────────────────┤
│ Customer Banking & PII  │ Luhn algorithm + Social    │ Deterministic     │
│ (Credit Cards, SSNs)    │ Security Area/Group bounds │ Pseudonymization  │
├─────────────────────────┼────────────────────────────┼───────────────────┤
│ Medical Records (PHI)   │ Contextual Precision Engine│ Yellow Non-block  │
│                         │ & Clinical Regex           │ Review Banner     │
├─────────────────────────┼────────────────────────────┼───────────────────┤
│ Prompt Injection        │ Structural AST analysis &  │ In-page Warning   │
│ & Trojan Source         │ CVE-2021-42574 bidi checks │ & Payload Strip   │
└─────────────────────────┴────────────────────────────┴───────────────────┘
```

---

### 3. 🔐 The Vault Slot (Native Messaging IPC Isolation)

Unlike legacy browser extensions that leave persistent native messaging ports open to the desktop OS, Vigil AI implements **The Vault Slot**:

* **One-Shot Request-Response-Drop:** The extension opens a native messaging port, delivers an encrypted JSON frame, awaits the cryptographic acknowledgement, and **instantly drops the port**.
* **Zero Lingering State:** Prevents privilege escalation and eliminate cross-tab port hijacking.
* **Cryptographic Local Handshake:** Requests to local LLMs (Ollama) require a 256-bit authentication token (`X-Vigil-Auth`) and origin headers, paired with silent failover to built-in heuristics with zero console error leaks.

---

### 4. 📜 Tamper-Evident SHA-256 Chained Audit Ledger & Enterprise SIEM

Every policy decision, human approval, rule override, and canary breach is immutably linked in an append-only cryptographic hash chain:

$$\text{Block Hash}_n = \text{SHA-256}\left(\text{Block Hash}_{n-1} \,\|\, \text{Timestamp} \,\|\, \text{Request ID} \,\|\, \text{Verdict} \,\|\, \text{Action Hash}\right)$$

* **Tamper Evidence:** Retroactive modification or deletion of any log entry breaks the mathematical chain from genesis.
* **Enterprise SIEM Streaming:** Exports real-time event telemetry natively in **Common Event Format (CEF)**, **Open Cybersecurity Schema Framework (OCSF v1.1.0)**, and standard enterprise JSON lines for ingestion into Splunk, Datadog, Microsoft Sentinel, and IBM QRadar.

---

### 5. 🥊 Autonomous Red-Team Simulation Lab

Sentinel embeds an autonomous red-team testing laboratory (`src/sentinel/redteam/simulation-lab.js`) that verifies protection against 12 real-world attack classes with a verified **100% block rate** and **0% false positive rate** on benign developer commands:

1. Base64-Piped Shell Destruction (`echo cm0gLXJm... | sh`)
2. Link-Local IMDS SSRF Exfiltration (`http://169.254.169.254/...`)
3. Quote-Unrolled Shell Evasion (`r'm' -rf /`)
4. Trojan Source Bidirectional Overrides (`\u202E` CVE-2021-42574)
5. Zero-Width Character Smuggling (`r\u200Bm\u200B -rf /`)
6. Environment File Suffix Exfiltration (`.env.production`, `.env.local`)
7. Canary Trap Decoy Harvesting
8. Dynamic Variable Concatenation (`CMD="rm"; $CMD -rf /`)
9. TOCTOU Action Parameter Tampering
10. Encoded Path Traversal (`..%2f..%2fetc%2fshadow`)
11. Multi-Step Exfiltration Chains (Recon &rarr; Read &rarr; Egress)
12. LLM-Guided Adversarial Fuzzing Sparring

---

## Enterprise Compliance & Governance Matrix

Vigil AI provides turnkey technical controls supporting major enterprise regulatory frameworks:

| Compliance Standard | Relevant Requirement | Vigil AI Technical Control |
| :--- | :--- | :--- |
| **SOC 2 Type II** | CC6.1, CC6.6, CC6.8 (Boundary Protection & Access) | Deterministic 4-tier policy engine, zero-trust MCP proxy, and tamper-evident SHA-256 audit chaining. |
| **ISO/IEC 27001:2022** | A.8.8, A.8.20, A.8.24 (Vulnerabilities, Network, Cryptography) | Pinned manifest key, AES-256-GCM hardware enclave binding, link-local IMDS firewalling, and 100k-cycle fuzzing. |
| **HIPAA Security Rule** | 45 CFR § 164.312 (Technical Safeguards) | Automatic real-time pseudonymization of PHI prior to browser transport; on-device tokenization with zero server storage. |
| **GDPR** | Article 25 & 32 (Privacy by Design & Data Security) | 100% local processing. Prompts and source code never leave the user's workstation. Zero telemetry phone-home. |
| **NIST AI RMF 1.0** | Govern 1.2, Map 1.5, Measure 2.6, Manage 2.4 | Continuous AI vs AI sparring simulation lab; AST de-obfuscation blocking prompt injection and agent privilege escalation. |
| **OWASP Top 10 for LLMs** | LLM01 (Prompt Injection), LLM02 (Sensitive Data Exposure), LLM06 (Excessive Agency) | Real-time injection firewall, Shannon entropy secret scrubbing, and strict human-in-the-loop approval gates. |

---

## Architecture Blueprint

Detailed technical specifications, sequence diagrams, and latency budgets are available in [**ARCHITECTURE.md**](ARCHITECTURE.md).

```
┌─────────────────────────────────────────────────────────────┐
│                    BROWSER EXTENSION                         │
│  · Sovereign Typing Interceptor (Zero Mid-Typing Mutation)   │
│  · Dynamic Web Worker Sandbox & Smart Loading               │
│  · Pre-Submission Hold Mutex (Enter & Send Button Intercept) │
│  · AES-256-GCM Identity Vault & Pseudonymization Engine      │
└──────────────────────────────┬──────────────────────────────┘
                               │ "The Vault Slot" (1-Shot IPC)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               NATIVE DESKTOP COMPANION (RUST)                │
│  · Chrome & Firefox Native Messaging Host                   │
│  · Hardware Enclave (AES-256-GCM sealed keys)               │
│  · OS Keychain Integration (Linux SecretService, macOS, Win) │
│  · 100k-Cycle Invariant-Fuzzed Sentinel Policy Core         │
└──────────────────────────────┬──────────────────────────────┘
                               │ Loopback Proxy (:8765 / :8383)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              AGENT FIREWALL & SENTINEL PROXY                 │
│  · Model Context Protocol (MCP) JSON-RPC Gateway             │
│  · Shell AST De-Obfuscator & CLI Shim                        │
│  · Universal IMDS Cloud Metadata Link-Local Blocker          │
│  · Dynamic Rotating Honeypot Traps & L0 Kill Switch          │
│  · Cryptographic Tamper-Evident SHA-256 Audit Ledger        │
│  · Enterprise SIEM Telemetry (CEF / OCSF v1.1.0 / JSON)     │
└─────────────────────────────────────────────────────────────┘
```

---

## Deployment & Operations

### 1. Browser Extension (Chrome / Brave / Edge / Firefox)

```bash
git clone https://github.com/starboy-hub/vigil.ai.git
cd vigil.ai
npm install
npm run build
```
* **Chromium (Chrome / Brave / Edge):** Navigate to `chrome://extensions`, enable **Developer Mode**, click **Load unpacked**, and select `dist/`.
* **Firefox:** Run `npm run build:firefox`, open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on**, and select `dist-firefox/manifest.json`.

### 2. Native Desktop Security Companion (Rust)

```bash
cd desktop
cargo build --release
cd ..
node companion/installer/register-native-hosts.js
```

### 3. Sentinel Agent Security Gateway

Launch the Sentinel proxy daemon to monitor autonomous agents and terminal shells:

```bash
node companion/vigil-agent-firewall.js --mode=guard
```
* **Live Interactive Dashboard:** [`http://127.0.0.1:8765/vigil-dashboard`](http://127.0.0.1:8765/vigil-dashboard)
* **Single-Window Operations Console:** Open [`sentinel-unified-console.html`](sentinel-unified-console.html) in any modern browser.

---

## Supply Chain Assurance & 7-Gate Security Pipeline

Every release of Vigil AI must pass an automated, fail-closed 7-gate release pipeline (`npm run release:gate`):

```bash
npm run release:gate
```

1. **Gate 1: Cryptographic Extension Key Pinning:** Pinned to `emkokehejldjlfljlhhcimnfefcjcmon` in `manifest.json`.
2. **Gate 2: Package Completeness & Asset Integrity:** Complete distribution tree verification.
3. **Gate 3: Deterministic Build Reproducibility:** SHA-256 composite fingerprint matches committed baseline (`.github/build-hash.txt`).
4. **Gate 4: Security Audit Dossier Generation:** Generates machine-readable `dist/audit-dossier.json`.
5. **Gate 5: Strict CSP Least-Privilege Verification:** Enforces `default-src 'none'`, `object-src 'none'`.
6. **Gate 6: Sensitive Context Injection Denial:** Validates exclusion on auth, vault, and banking portals.
7. **Gate 7: RFC 9116 Policy & Disclosure Verification:** Validates `SECURITY.md`, `security.txt`, and threat matrix.

---

## Testing & Verification

The codebase maintains a 100% test pass rate across all tiers:

```bash
# JavaScript Test Suites (72 suites, 931 tests, 100% pass)
npm test

# Native Rust Companion Tests & Invariant Fuzzer (28 tests, 100k cycles)
cargo test --manifest-path desktop/Cargo.toml

# End-to-End Browser Specifications (38 Playwright E2E tests)
npx playwright test

# Codebase Linter (0 errors, 0 warnings enforced)
npm run lint
```

---

## Enterprise Commercial Licensing & Support

Vigil AI is offered under a strategic **Dual-Licensing Model**:

1. **Open Source Edition (GNU AGPLv3):** Free software licensed under the **GNU Affero General Public License Version 3 (GNU AGPLv3)**. Under Section 13, any party that embeds, modifies, or delivers Vigil AI or Sentinel over a network (including SaaS platforms, cloud proxies, enterprise agent gateways, and hosted APIs) must publish their entire corresponding source code under the AGPLv3.
2. **Commercial Enterprise Edition:** Designed for commercial enterprises, OEMs, cloud providers, and organizations requiring proprietary closed-source integration, corporate indemnification, customized SIEM connectors, dedicated SLAs, and priority security patches without copyleft obligations.

### Enterprise Inquiries & Due Diligence

For enterprise licensing quotes, technical due diligence whitepapers, SOC 2 / ISO 27001 audit packages, or commercial pilots:
* **Commercial Licensing:** `licensing@vigil-sec.io`
* **Security Architecture & Leadership:** `temur.khalid@gmail.com`
* **Vulnerability Advisories:** [Security Advisory Portal](https://github.com/starboy-hub/vigil.ai/security/advisories)

---

<div align="center">

**Built for sovereign privacy, zero-trust autonomy, and uncompromised enterprise defense.**  
*No cloud. No telemetry. No compromise.*

</div>
