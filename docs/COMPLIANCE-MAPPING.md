# VIGIL AI GUARDIAN — COMPLIANCE FRAMEWORK MAPPING

**Document Version:** 1.0  
**Classification:** Public Security Documentation  
**Audience:** Security Engineers, CISOs, Compliance Auditors, Procurement Teams  
**Governing Philosophy:** Zero-Telemetry, On-Device Enforcement, Cryptographic Proof  

---

## Executive Summary

Vigil AI Guardian is a local-first, zero-telemetry cognitive firewall and data loss prevention (DLP) solution for AI interactions (browsers, IDEs, and local agents). Rather than shipping prompts to third-party cloud scrubbers, Vigil executes all detection, pseudonymization, consensus arbitration, and cryptographic sealing strictly within device memory.

This document formally maps Vigil’s technical controls to major regulatory and cybersecurity standards:
- **ISO/IEC 27001:2022** (Information Security Management)
- **SOC 2 Type II** (Trust Services Criteria: Security, Confidentiality, Privacy)
- **GDPR** (Regulation (EU) 2016/679 — Data Protection)
- **HIPAA Security & Privacy Rules** (45 CFR Part 160 & Part 164)

---

## 1. ISO/IEC 27001:2022 Mapping

| ISO 27001 Control | Control Objective | Vigil Technical Implementation |
| :--- | :--- | :--- |
| **A.5.15 Access control** | Enforce policy-based access to information. | Role-scoped Identity Vault with per-site session pseudonymization. |
| **A.8.7 Protection against malware** | Prevent malicious software execution. | Native Agentic Firewall (`HTTP_PROXY=127.0.0.1:8765`) and IDE proxy intercept runaway shell and code execution loops. |
| **A.8.11 Data masking** | Mask sensitive data in accordance with policies. | Real-time PII, secret, and PHI replacement with deterministic cryptographic pseudonyms before prompts reach the LLM network boundary. |
| **A.8.12 Data leakage prevention** | Apply DLP measures to prevent unauthorized exfiltration. | Contextual Precision Engine (CPE) + Shannon entropy scanner intercepts API keys, credentials, PII, and copyleft code. |
| **A.8.24 Use of cryptography** | Effective use of cryptography to protect confidentiality and integrity. | AES-256-GCM vault encryption, PBKDF2-SHA256 (600k iterations), ECDH P-256 native messaging frames, Ed25519 steganographic watermarking. |
| **A.8.28 Secure coding** | Protect software from tampering and vulnerabilities. | Automated adversarial CI benchmarking (`scripts/adversarial-benchmark.js`), strict ReDoS protection, fail-closed consensus architecture. |

---

## 2. SOC 2 Type II (Trust Services Criteria)

| SOC 2 Criteria | Requirement | Vigil Technical Control |
| :--- | :--- | :--- |
| **CC6.1 (Logical Access)** | Protect assets from unauthorized access. | Identity Vault encrypted at rest; master keys isolated in OS Keychain / memory; zero cloud access. |
| **CC6.6 (Boundary Protection)** | Protect against unauthorized data transmission. | MV3 compute boundary isolates WebGPU/Wasm models in Offscreen documents; content scripts only hold opaque tokens (`[VAULT_ID:token]`). |
| **CC6.7 (Transmission Security)** | Protect data during transmission. | Native messaging channels use ECDH P-256 authenticated key exchange with per-frame AES-256-GCM encryption and replay counters. |
| **CC7.2 (Monitoring)** | Monitor infrastructure for vulnerabilities. | Real-time Forensics Replay logs all tier verdicts locally; CEF/OCSF SIEM real-time syslog and HTTPS streaming for enterprise SOCs. |
| **P1.1 – P4.3 (Privacy)** | Minimize collection, retain only necessary PII. | **Zero Telemetry by Architecture**: No telemetry servers exist. No analytics endpoints. Prompts never leave device memory unmasked. |

---

## 3. GDPR (General Data Protection Regulation)

| GDPR Article | Legal Mandate | Vigil Compliance Mechanism |
| :--- | :--- | :--- |
| **Art. 5(1)(c) Data Minimization** | Personal data shall be adequate, relevant, and limited. | PII stripped at prompt boundary; only synthetic pseudonyms sent to AI providers (OpenAI, Anthropic, Google). |
| **Art. 25 Data Protection by Design and by Default** | Technical measures implemented at design time. | Local-first architecture; all model weights (Wasm/ONNX) and vault storage reside on client hardware. |
| **Art. 32 Security of Processing** | Pseudonymisation and encryption of personal data. | Deterministic thread-coherent pseudonyms cached in `chrome.storage.session`; unmasked for display only via local DOM MutationObserver. |
| **Art. 33 / 34 Breach Notification** | Minimize exposure in case of upstream breaches. | If an upstream LLM provider suffers a data breach, user logs only reveal synthetic pseudonyms and blind hashes, preventing identity linkage. |

---

## 4. HIPAA Security & Privacy Rules

| HIPAA Specification | Regulatory Objective | Vigil Technical Implementation |
| :--- | :--- | :--- |
| **164.312(a)(2)(iv) Encryption & Decryption** | Implement mechanism to encrypt and decrypt ePHI. | Sensitive medical conditions and medications encrypted with AES-256-GCM. Contextual Precision Engine distinguishes medical disclosures from clinical research queries. |
| **164.312(b) Audit Controls** | Record and examine activity in systems containing ePHI. | Keyed Merkle accumulator with HMAC-SHA256 DLP attestation; tamper-evident event logging without recording cleartext patient names. |
| **164.312(c)(1) Integrity** | Protect ePHI from improper alteration or destruction. | Cryptographic watermarks and Self-Healing File Integrity Monitor (`file_integrity.rs`) verify application binaries and configuration state. |
| **164.514 Safe Harbor De-Identification** | Remove 18 designated PII/PHI identifiers. | Regex, named-entity heuristics, and context engines target all 18 identifiers (Names, Dates, Phones, SSN, MRN, IP, Account Numbers, Geographic data). |

---

## Summary Matrix for Security Auditors

```
+-------------------------------------------------------------------------+
|                  VIGIL AI GUARDIAN COMPLIANCE BOUNDARY                  |
+-------------------------------------------------------------------------+
| [Client Application / Browser / IDE]                                  |
|   |                                                                     |
|   v (Cleartext Input)                                                   |
| +---------------------------------------------------------------------+ |
| | VIGIL CONTEXTUAL PRECISION ENGINE & CRYPTOGRAPHIC VAULT (ON-DEVICE) | |
| | - AES-256-GCM / PBKDF2-SHA256 Key Sealing                           | |
| | - Zero Telemetry / Local Memory Isolation                           | |
| | - ISO 27001 / SOC 2 / GDPR Art. 25 Compliant By Design              | |
| +---------------------------------------------------------------------+ |
|   |                                                                     |
|   v (Sanitized Pseudonyms / Redacted Cleartext)                         |
| [External LLM API / Cloud Model Providers]                              |
+-------------------------------------------------------------------------+
```
