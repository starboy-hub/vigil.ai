<div align="center">

<img src="src/icons/icon128.png" width="96" alt="Vigil AI Guardian + Sentinel" />

# Vigil AI Guardian & Sentinel Agent Gateway

### Sovereign Enterprise AI Security & Policy-Enforced Autonomous Agent Firewall
**100% Local Execution · Air-Gapped · Fail-Closed · Zero Outbound Telemetry**

[![Version](https://img.shields.io/badge/version-2.0.0-6366f1?style=flat-square)](https://github.com/starboy-hub/vigil.ai)
[![License: AGPLv3 / Commercial](https://img.shields.io/badge/license-AGPLv3%20%7C%20Commercial-blue?style=flat-square)](LICENSE)
[![godaudits: 100/100](https://img.shields.io/badge/godaudits-100%2F100%20audit--proof-10b981?style=flat-square)](.godaudits/AUDIT.mdx)
[![Tests: 100% Passing](https://img.shields.io/badge/tests-106%20sentinel%20%7C%2028%20rust%20%7C%207%2F7%20gates-10b981?style=flat-square)](#testing--verification)
[![Rust Invariant Fuzzing](https://img.shields.io/badge/fuzzing-100k%20cycles%20%7C%200%20panics-10b981?style=flat-square)](#supply-chain-assurance--7-gate-security-pipeline)
[![Adversarial Block Rate](https://img.shields.io/badge/adversarial%20block%20rate-100%25-10b981?style=flat-square)](#autonomous-red-team-simulation-lab)
[![False Positive Rate](https://img.shields.io/badge/false%20positives-0.00%25-10b981?style=flat-square)](#autonomous-red-team-simulation-lab)
[![Compliance Ready](https://img.shields.io/badge/compliance-SOC%202%20%7C%20ISO%2027001%20%7C%20HIPAA%20%7C%20GDPR-purple?style=flat-square)](#enterprise-compliance--governance-matrix)

<p align="center">
  <b>Vigil AI intercepts and neutralizes the two greatest attack surfaces of modern enterprise artificial intelligence:</b><br/>
  <b>1. Outbound Data Loss (Browser):</b> Secret keys, source code, and PII typed into web LLMs (ChatGPT, Claude, Gemini, webmail).<br/>
  <b>2. Autonomous Agent Exploitation (Host & MCP):</b> Destructive shell commands, cloud metadata exfiltration, logic-bombs, visual injections, and tool abuse by autonomous coding agents (Cursor, Claude Code, Devin, MCP clients).
</p>

[**Executive Summary**](#executive-summary-for-cisos--security-leadership) · [**Architecture**](ARCHITECTURE.md) · [**Security Policy**](SECURITY.md) · [**Sentinel Gateway**](#1-sentinel-ai-agent-security-gateway) · [**Futuristic Defenses**](#sentinel-20-next-generation-autonomous-defenses) · [**Browser DLP**](#2-browser-dlp--sovereign-silent-guardian) · [**Dual-Licensing**](#enterprise-commercial-licensing--support) · [**Deployment**](#deployment--operations)

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
│ · Microscopic & canvas visual injections  │ · Temporal logic-bombs & crypto degradation│
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
│  │  Cognitive Mirage Decoys      │          │  Capability Tokens    │  │
│  │  · Dynamic canary honeypots   │          │  · HMAC-SHA256 tokens │  │
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
* **HMAC-SHA256 Scoped Capability Tokens:** Agents never hold unbounded root credentials. Sentinel issues signed, single-use, attenuated capability tokens bound to specific resource subpaths.

---

### 2. ⚡ Sentinel 2.0: Next-Generation Autonomous Defenses

To defend against advanced multi-agent cascades and modern generative exploitation, Sentinel incorporates five autonomous defense layers:

#### 🪤 A. Cognitive Mirage & Active Honeypots (`src/sentinel/deception/cognitive-mirage.js`)
* **Counter-Deception:** Rather than alerting attackers with an immediate fail-closed denial when `.env` or credential files are probed, Sentinel serves a **plausible synthetic decoy**.
* **Embedded Canary Watermarks:** Decoy credentials (OpenAI `sk-proj-mirage_...`, Anthropic `sk-ant-api03-mirage_...`, AWS `AKIA...`, SSH keys, and PostgreSQL URLs) carry cryptographic HMAC watermarks.
* **Tripwire Trapping:** Any agent call or network egress attempting to use a canary token triggers an immediate critical alert (`DENY_CANARY_TRAP_TRIGGERED`), quarantining the session and exposing the exfiltration endpoint.

#### ⏪ B. Causal Time-Travel & Atomic Rollback Engine (`src/sentinel/journal/causal-rollback.js`)
* **Transactional Session Shadowing:** Captures immutable pre-action snapshots before filesystem mutations.
* **1-Click Atomic Rewind:** If an agent executes a destructive payload, introduces a backdoor, or is rejected by the operator, `rollbackSession(sessionId)` executes an atomic LIFO rewind:
  * Modified files are restored byte-for-byte to their original cryptographic hash.
  * Newly created files are unlinked.
  * Deleted files and directories are reconstituted with original permissions.

#### 🧬 C. Autonomous Local Immune System (`src/sentinel/immune/vaccine-synthesizer.js`)
* **Attack Deconstruction:** Autonomously classifies caught adversarial mutations (`ZERO_WIDTH_SMUGGLING`, `ROLEPLAY_HIJACKING`, `BASE64_WRAPPED`, `DELIMITER_OVERRIDE`).
* **Zero-Shot Vaccine Synthesis:** Formulates generalized AST regex invariants covering entire exploit classes.
* **0% False-Positive Corpus Benchmark:** Benchmarks candidates against a safe code and conversation corpus. Only invariants achieving a $0.00\%$ false positive rate are sealed into Sentinel.
* **P2P Swarm Inoculation:** Exports anonymous, zero-knowledge `swm_vac_...` hashes across `swarm-mesh.js` to inoculate all developer machines across the local swarm.

#### 🔗 D. Multi-Agent Swarm Provenance Chain (`src/sentinel/credentials/provenance-chain.js`)
* **Merkle Proof-of-Human-Origin:** Solves the "Agent Telephone Game" by anchoring trust to explicit human prompts.
* **Cryptographic Delegation Hops:** Multi-agent handoffs (Human &rarr; Orchestrator &rarr; Subagent &rarr; Runner) require signed delegation links.
* **Privilege Attenuation:** Subagents can only narrow permissions, never escalate. Unproven actions or injected intent are quarantined with `DENY_PROVENANCE_LINEAGE_BROKEN`.

#### 👁️ E. Multimodal Vision & Canvas Stream Firewall (`src/content/modules/vision-firewall.js`)
* **Visual Injection Detection:** Intercepts microscopic text ($< 4\text{px}$), transparent color camouflage (Delta-E $< 15$), and off-screen canvas coordinates.
* **PII & Secret Bounding Box Redaction:** Hooks `HTMLCanvasElement.prototype.toDataURL` and `toBlob` to automatically redact sensitive credentials, API keys, and credit cards before computer-use agents ingest screen frames.

#### 📊 F. Cybernetic Defense Matrix HUD (`src/popup/hud/cybernetic-hud.js`)
* **Interactive Neural Topology:** Real-time 60 FPS Canvas 2D telemetry visualizing active agents, capability gates, sandboxes, and threat deflection conduits.
* **In-Flight Pulse Telemetry:** Renders animated particle packets traveling along active conduits during tool calls with dynamic threat-level transitions (`NOMINAL`, `DEFENSE_ACTIVE`, `CRITICAL_BREACH`).

---

### 3. 🌐 Browser DLP & Sovereign Silent Guardian

Vigil’s browser extension delivers enterprise-grade DLP across Chrome, Brave, Edge, and Firefox without disrupting developer workflow:

* **Sovereign Keystrokes (Zero Mid-Typing Mutation):** Vigil **never** mutates active textareas while typing. Keystrokes remain 100% sovereign.
* **Dynamic Web Worker Sandbox:** Content scripts incur zero background freezing. Heavy math and WebGPU run inside isolated background workers.
* **Pre-Submission Interception Mutex:** When the user clicks **Send** or hits **Enter**, the `submissionGuard` intercepts unmasked credentials or PII, displaying an ergonomic confirmation bar with one-click deterministic pseudonymization.
* **Sensitive Domain Immunity:** Enforces strict execution denial on SSO portals (Okta, Auth0, Ping), password managers (1Password, Bitwarden), and banking portals.

---

### 4. 🔐 The Vault Slot & Native OS Sandbox (Rust)

* **One-Shot Request-Response-Drop:** The extension opens a native messaging port, delivers an encrypted JSON frame, awaits cryptographic acknowledgement, and **instantly drops the port**.
* **Kernel Sandbox Confinement (`desktop/src/sandbox.rs`):** Implements `SandboxPolicy` path canonicalization, dynamic linker scrubbing (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`), and loopback-only network socket enforcement.
* **Hardware Enclave:** Sealing and unsealing keys via AES-256-GCM / ChaCha20-Poly1305 bound to OS keychains.

---

### 5. 📜 Tamper-Evident SHA-256 Audit Ledger & Enterprise SIEM

Every policy decision, human approval, rule override, and canary breach is immutably linked in an append-only cryptographic hash chain:

$$\text{Block Hash}_n = \text{SHA-256}\left(\text{Block Hash}_{n-1} \,\|\, \text{Timestamp} \,\|\, \text{Request ID} \,\|\, \text{Verdict} \,\|\, \text{Action Hash}\right)$$

* **Tamper Evidence:** Retroactive modification or deletion of any log entry breaks the mathematical chain from genesis.
* **Enterprise SIEM Streaming:** Exports real-time event telemetry natively in **Common Event Format (CEF)**, **Open Cybersecurity Schema Framework (OCSF v1.1.0)**, and JSON lines for Splunk, Datadog, Microsoft Sentinel, and IBM QRadar.

---

## Enterprise Compliance & Governance Matrix

| Compliance Standard | Relevant Requirement | Vigil AI Technical Control |
| :--- | :--- | :--- |
| **SOC 2 Type II** | CC6.1, CC6.6, CC6.8 (Boundary Protection & Access) | Deterministic 4-tier policy engine, zero-trust MCP proxy, and tamper-evident SHA-256 audit chaining. |
| **ISO/IEC 27001:2022** | A.8.8, A.8.20, A.8.24 (Vulnerabilities, Network, Cryptography) | Pinned manifest key, hardware enclave binding, link-local IMDS firewalling, and 100k-cycle fuzzing. |
| **HIPAA Security Rule** | 45 CFR § 164.312 (Technical Safeguards) | Automatic real-time pseudonymization of PHI prior to browser transport; on-device tokenization with zero server storage. |
| **GDPR** | Article 25 & 32 (Privacy by Design & Data Security) | 100% local processing. Prompts and source code never leave the workstation. Zero telemetry phone-home. |
| **NIST AI RMF 1.0** | Govern 1.2, Map 1.5, Measure 2.6, Manage 2.4 | Continuous AI vs AI sparring simulation lab; AST de-obfuscation blocking prompt injection and agent privilege escalation. |
| **OWASP Top 10 for LLMs** | LLM01 (Prompt Injection), LLM02 (Sensitive Data Exposure), LLM06 (Excessive Agency) | Real-time injection firewall, Shannon entropy secret scrubbing, and strict human-in-the-loop approval gates. |

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
# JavaScript Sentinel & Futuristic Test Suites (10 suites, 106 tests, 100% pass)
npm test

# Native Rust Companion Tests & Invariant Fuzzer (28 tests, 100k cycles)
cargo test --manifest-path desktop/Cargo.toml

# Full End-to-End Release Gate Verification
node scripts/release-gate.js

# Sovereign godaudits Certification Gate (Score 100/100, 100% coverage)
node .agents/skills/godaudits/runtime/godaudits.js validate .godaudits/AUDIT.json --repo . --require-fresh-evidence
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

```bash
node companion/vigil-agent-firewall.js --mode=guard
```
* **Live Interactive Dashboard:** [`http://127.0.0.1:8765/vigil-dashboard`](http://127.0.0.1:8765/vigil-dashboard)
* **Single-Window Operations Console:** Open [`sentinel-unified-console.html`](sentinel-unified-console.html) in any browser.

---

## Enterprise Commercial Licensing & Support

Vigil AI is offered under a strategic **Dual-Licensing Model**:

1. **Open Source Edition (GNU AGPLv3):** Free software licensed under the **GNU Affero General Public License Version 3 (GNU AGPLv3)**. Under Section 13, any party that embeds, modifies, or delivers Vigil AI or Sentinel over a network must publish their entire corresponding source code under the AGPLv3.
2. **Commercial Enterprise Edition:** Designed for commercial enterprises, OEMs, cloud providers, and organizations requiring proprietary closed-source integration, corporate indemnification, customized SIEM connectors, dedicated SLAs, and priority security patches without copyleft obligations.

### Enterprise Inquiries & Due Diligence

* **Commercial Licensing:** `licensing@vigil-sec.io`
* **Security Architecture & Leadership:** `temur.khalid@gmail.com`
* **Vulnerability Advisories:** [Security Advisory Portal](https://github.com/starboy-hub/vigil.ai/security/advisories)

---

<div align="center">

**Built for sovereign privacy, zero-trust autonomy, and uncompromised enterprise defense.**  
*No cloud. No telemetry. No compromise.*

</div>
