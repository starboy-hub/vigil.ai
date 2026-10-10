# Vigil AI Threat Model & Security Boundaries (STRIDE Framework)

> **Document Version:** 10.0.0  
> **Target System:** Vigil AI Universal AI Privacy Shield & Zero-Trust Desktop Guardian  
> **Security Philosophy:** Local-first, zero-telemetry, client-side cryptographic isolation.

---

## 1. System Overview & Security Perimeter

**Vigil AI** is an open-source endpoint Data Loss Prevention (DLP) and threat protection system operating across web browsers (Chrome, Brave, Edge, Firefox) and native desktop operating systems (macOS, Windows, Linux).

### Security Perimeter Architecture:
```
┌────────────────────────────────────────────────────────────────────────┐
│ USER BROWSER CONTEXT                                                   │
│                                                                        │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │ Web Page / DOM        │             │ Vigil AI MV3 Context       │  │
│  │ (ChatGPT / AI Models) │             │                            │  │
│  │                       │             │  ┌──────────────────────┐  │  │
│  │  [Content Scripts] ───┼──(Runtime)──┼─►│ Service Worker SW       │  │  │
│  │  - DOM TreeWalker     │             │  │ - PBKDF2 / AES-GCM Vault │  │  │
│  │  - Smart Paste        │             │  │ - Native Bridge IPC      │  │  │
│  │  - RTE Adapter        │             │  └──────────┬───────────┘  │  │
│  │  └───────────────────────┘                        │             │  │
│  │                                                   ▼             │  │
│  │                                        ┌─────────────────────┐  │  │
│  │                                        │ WebGPU Neural Engine│  │  │
│  │                                        │ - Local BERT Model  │  │  │
│  │                                        │ - WebGPU / WASM     │  │  │
│  │                                        └─────────────────────┘  │  │
│  └───────────────────────────────────────────────────┬────────────────┘
│                                                      ▼
│                                           ┌─────────────────────┐
│                                           │ Vigil Native Desktop│
│                                           │ - Menu Bar System   │
│                                           │ - Voice FFT Canary  │
│                                           └─────────────────────┘
```

---

## 2. STRIDE Threat Analysis

### S — Spoofing (Identity & Message Authenticity)
- **Threat:** Malicious web pages impersonating Vigil AI UI or forging signed message blocks.
- **Mitigation:**
  - Vigil AI signed messages use Web Crypto ECDSA (P-256) / Ed25519 signatures with device-unique private keys stored in `chrome.storage.local`.
  - Content scripts render UI inside isolated containers preventing host page styling overrides.
  - Webmail profile engine analyzes display names vs sender domains to detect free-provider spoofing (e.g. `PayPal Support <alert@gmail.com>`).

### T — Tampering (Data Alteration)
- **Threat:** Page scripts modifying Vigil AI redaction placeholders before network transmission.
- **Mitigation:**
  - Vigil AI intercepts native form submit and `Enter` key events at the capture phase (`addEventListener(..., { capture: true })`).
  - Redaction replacements are applied directly to DOM node values (`HTMLInputElement.value`, `HTMLTextAreaElement.value`, or RTE Range selections).

### R — Repudiation (Disavowal of Actions)
- **Threat:** Users or admins questioning whether a sensitive secret was sanitized.
- **Mitigation:**
  - Local audit history is stored in `chrome.storage.local` with timestamps, domain names, and masked incident types (zero raw PII).
  - Telemetry exports support standard B2B SIEM formats (**CEF**, **OCSF v1.1.0**, **JSON**).

### I — Information Disclosure (Data Leakage)
- **Threat:** Unencrypted exposure of Vault identities on disk or via sync storage.
- **Mitigation:**
  - AES-256-GCM encryption with **PBKDF2-SHA256 (600,000 iterations)**.
  - Zero cloud network transmission: all scanning and inference occur 100% on the local device.

### D — Denial of Service (Algorithmic / ReDoS)
- **Threat:** Malicious web pages containing pathological strings designed to lock up the browser's regex engine (Catastrophic Backtracking).
- **Mitigation:**
  - All detection patterns are linear-time regular expressions audited against ReDoS vulnerabilities.
  - 1,000-pass fuzz test suite (`tests/fuzz-detection.test.js`) verifies sub-millisecond execution even on massive repeated input strings.

### E — Elevation of Privilege (Agent Hijacking)
- **Threat:** Indirect prompt injection embedded in web pages attempting to control autonomous AI agents.
- **Mitigation:**
  - Vigil AI Injection Engine scans incoming LLM context and web inputs for system prompt overrides, safety bypasses, and data exfiltration markers.
