# Enterprise Security Policy & Vulnerability Management Framework

Vigil AI and Sentinel Agent Gateway are engineered for defense-in-depth, zero-trust enterprise environments. This document outlines our vulnerability disclosure policy, service level agreements (SLAs), enterprise compliance posture, supply chain attestations, and security architecture boundaries.

---

## 1. Coordinated Vulnerability Disclosure (CVD)

**Do NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**

We adhere to strict Coordinated Vulnerability Disclosure (RFC 9116) principles to protect production deployments and our user community:

* **Primary Disclosure Portal:** [GitHub Private Security Advisories](https://github.com/starboy-hub/vigil.ai/security/advisories/new)
* **Direct Security Team Escalation:** `temur.khalid@gmail.com`
* **PGP / Encrypted Escalation:** Request PGP public key via email before sending sensitive proof-of-concept material.
* **RFC 9116 Policy Document:** Hosted at [`.well-known/security.txt`](.well-known/security.txt)

### Incident Response SLAs

Our dedicated security response team enforces the following response and remediation commitments:

| Severity (CVSS v3.1) | Initial Response | Triage & Reproduction | Remediation / Patch SLA | Public Disclosure Notice |
| :--- | :--- | :--- | :--- | :--- |
| **Critical (9.0 – 10.0)** | < **24 Hours** | < **48 Hours** | < **7 Business Days** | Coordinated post-patch release |
| **High (7.0 – 8.9)** | < **24 Hours** | < **48 Hours** | < **14 Business Days** | Coordinated post-patch release |
| **Medium (4.0 – 6.9)** | < **48 Hours** | < **5 Business Days** | Next Minor Release (< 30 days) | Release notes advisory |
| **Low (0.1 – 3.9)** | < **72 Hours** | < **7 Business Days** | Backlog / Next Sprint | Release notes advisory |

### Safe Harbor Commitment

We consider security research conducted under this policy to be authorized, and we will not initiate legal action against researchers who:
1. Make a good-faith effort to avoid privacy violations, destruction of data, and interruption or degradation of service.
2. Maintain confidentiality until a patch is released and the disclosure timeframe has elapsed.
3. Do not exploit vulnerabilities beyond the minimum necessary to establish a proof of concept.

Valid, responsible disclosures are publicly credited in release advisories and permanently enshrined in our [Security Hall of Fame](HALL_OF_FAME.md).

---

## 2. Enterprise Compliance & Security Baseline

Vigil AI provides technical safeguards aligned with international enterprise compliance standards:

| Standard / Framework | Regulatory Scope | Vigil AI Technical Safeguard Implementation |
| :--- | :--- | :--- |
| **SOC 2 Type II** | Security & Confidentiality (CC6.1, CC6.6, CC6.8) | Deterministic policy evaluation, zero outbound telemetry, client-side cryptographic key vaulting, and tamper-evident SHA-256 audit logs. |
| **ISO/IEC 27001:2022** | A.8.8 (Vulnerabilities), A.8.20 (Network), A.8.24 (Cryptography) | Pinned manifest public keys, AES-256-GCM hardware enclave binding, link-local IMDS firewalling, and continuous invariant fuzzing in CI. |
| **HIPAA Security Rule** | 45 CFR § 164.312 (Technical Safeguards) | Automatic real-time pseudonymization of Protected Health Information (PHI) prior to browser transport; on-device deterministic tokenization. |
| **GDPR** | Article 25 (Privacy by Design) & Article 32 (Security) | 100% on-device heuristic and neural inference. Zero cloud phone-home, zero remote prompt logging, sovereign user input preservation. |
| **NIST AI RMF 1.0** | Govern 1.2, Map 1.5, Measure 2.6, Manage 2.4 | Autonomous red-team lab with 12 verified attack vectors; AST de-obfuscation blocking prompt injection and agent privilege escalation. |

---

## 3. Cryptographic Provenance & Supply Chain Assurance

Every production release of Vigil AI is governed by an automated, fail-closed 7-Gate Security Pipeline (`npm run release:gate`):

```
┌────────────────────────────────────────────────────────────────────────┐
|                   7-GATE SECURITY RELEASE PIPELINE                     |
├────────────────────────────────────────────────────────────────────────┤
| Gate 1: Cryptographic Extension Key Pinning (emkokehejldjlfljlhhcimn)  |
| Gate 2: Distribution Package Completeness & Integrity Attestation      |
| Gate 3: Deterministic Build Reproducibility (Composite SHA-256 Hash)   |
| Gate 4: Security Audit Dossier Generation (dist/audit-dossier.json)    |
| Gate 5: Strict CSP Least-Privilege Verification (default-src 'none')   |
| Gate 6: Sensitive Context Injection Denial (Auth, Vault, Banking)       |
| Gate 7: RFC 9116 Policy & Disclosure Verification (.well-known/sec.txt)|
└────────────────────────────────────────────────────────────────────────┘
```

1. **Cryptographic Key Pinning:** The Chrome/Edge Extension ID is cryptographically pinned to `emkokehejldjlfljlhhcimnfefcjcmon` via the hardcoded public key in `manifest.json`. Tampering with the extension binary invalidates the cryptographic signature.
2. **Deterministic Build Reproducibility:** Every build computes a composite SHA-256 digest across all build artifacts. Any discrepancy against `.github/build-hash.txt` halts the CI pipeline.
3. **Strict Content Security Policy (CSP):** The extension runtime enforces `script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; default-src 'none'`, preventing remote script execution, cross-site scripting, and unauthorized object embedding.
4. **Automated Continuous Invariant Fuzzing:** The Rust Sentinel core is continuously fuzzed in GitHub Actions (`.github/workflows/sentinel-fuzz.yml`) across 100,000+ randomized mutation cycles per commit to guarantee zero memory panics and zero policy escapes.

---

## 4. Multi-Layer Security Boundaries & Invariants

```
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 1: IN-PAGE DOM INTERCEPTOR & WORKER SANDBOX                     │
│ · Dynamic worker instantiation on user interaction                     │
│ · Zero keystroke mutation during active typing                         │
│ · Pre-submission hold on unmasked PII or credentials                   │
│ · Sensitive domain injection denial (SSO, Banks, Password Vaults)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ WebCrypto AES-GCM
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 2: BACKGROUND SERVICE WORKER & LOCAL INFERENCE                   │
│ · 256-bit cryptographic auth token (X-Vigil-Auth) for local Ollama     │
│ · Silent failover on connection refusal (zero network error leaks)     │
│ · Offscreen WebGPU acceleration for neural classification               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Native Messaging "Vault Slot"
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 3: THE VAULT SLOT (1-SHOT ISOLATION IPC)                         │
│ · Strict request-response-drop IPC lifecycle                           │
│ · Zero lingering open ports or long-lived native handles               │
│ · Ephemeral ECDH P-256 handshake + AES-256-GCM framing                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Memory IPC
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 4: DESKTOP SENTINEL ENGINE (RUST NATIVE DAEMON)                  │
│ · Hard safety invariants: link-local IMDS (169.254.169.254) blocked   │
│ · Universal .env / SSH key / private credential exfiltration blocked   │
│ · Shell AST normalization (quote unrolling, base64 decode, variable sub│
│ · Trojan Source Unicode (CVE-2021-42574) & zero-width smuggling denied│
│ · OS Keychain & Hardware Key Enclave integration                       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Audit Chaining
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 5: TAMPER-EVIDENT LEDGER & ENTERPRISE SIEM EXPORT                │
│ · SHA-256 hash-chained immutable audit ledger                          │
│ · Common Event Format (CEF) & OCSF v1.1.0 data security events         │
│ · Dynamic rotating canary traps with forensic provenance tracking      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Integration Coverage & Traffic Inspection Matrix

| Integration Surface | Protocol / Channel | Inspection & Redaction Coverage | Explicit Security Boundaries & Policy |
| :--- | :--- | :--- | :--- |
| **Browser Extension** (`src/`) | DOM Content Scripts / Web Workers | **Full Pre-Encryption Inspection**<br>Scans all DOM submissions (buttons, Enter key, forms, quarantine buffer) for PII, secrets, and prompt injection before transport. | Deny-list excludes banking, password managers, and payment flows. Context isolation prevents content scripts from accessing privileged vault keys. |
| **Native IDE Proxy** (`desktop/`, Port 8383) | Loopback HTTP / IPC | **Full Prompt Inspection**<br>Inspects prompts from Cursor, Copilot, and Ollama. Redacts AWS keys, GitHub PATs, API keys, and RSA/PKCS#8 keys. Enforces token budgets. | Bound to `127.0.0.1`. Plaintext prompts only; token budget engine enforces hard block / soft alert thresholds. |
| **Agent Firewall — Plain HTTP** (`companion/`, Port 8765) | HTTP/1.1 Forward Proxy | **Full Streaming DLP Inspection**<br>Redacts request and response streams. Rewrites tokens in SSE streams with bounded memory. | Drops recursive proxy loops (400) and cloud metadata IMDS SSRF (403). Validates actual connected socket IP and blocks prohibited redirects. |
| **Agent Firewall — HTTPS Tunnels** (`companion/`, Port 8765) | HTTP `CONNECT` Tunneling | **Uninspected Traffic (`tunnel_uninspected`)**<br>TCP byte stream is end-to-end TLS encrypted between client and upstream host. | **Fundamental TLS Limitation:** Vigil does NOT install an OS root CA certificate (TLS MITM) to decrypt HTTPS payloads. Destination safety (blocking IMDS SSRF and recursive loops) is enforced, but encrypted payload bodies are strictly audited as `tunnel_uninspected`. |

---

## 6. Supported Versions & Lifecycle

| Release Track | Current Version | Status | Security Support | Maintenance SLA |
| :--- | :--- | :--- | :--- | :--- |
| **v1.x (Production)** | **v1.1.0** | Active / Stable | Full Security Support | Patches & Backports |
| **v1.0.x** | v1.0.0 | Superseded | Critical CVEs Only | Upgrade Recommended |
| **< v1.0.0** | Pre-release | End of Life | Unsupported | None |

---

## 7. Licensing & Enterprise Inquiries

Vigil AI is dual-licensed:
* **Open Source Edition:** Free software licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**. Any networked or SaaS service embedding modified code must publish its source under AGPLv3.
* **Commercial Enterprise Edition:** Closed-source enterprise licensing, dedicated SLAs, custom compliance adapters, and corporate indemnification are available for commercial organizations.

For enterprise security questionnaires, SOC 2 / ISO 27001 audit dossiers, or commercial licensing agreements:
* **Email:** `licensing@vigil-sec.io` / `temur.khalid@gmail.com`
* **Security Advisories:** [https://github.com/starboy-hub/vigil.ai/security/advisories](https://github.com/starboy-hub/vigil.ai/security/advisories)
