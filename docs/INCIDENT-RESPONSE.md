# VIGIL AI GUARDIAN — INCIDENT RESPONSE PLAN (IRP)

**Document Version:** 1.0  
**Effective Date:** 2026-10-07  
**Owner:** Security & Architecture Team  
**Scope:** Browser Extension (MV3), Desktop Companion Daemon (Rust), and Agentic Firewall  

---

## 1. Objectives & Principles

The primary objectives of the Vigil AI Guardian Incident Response Plan are:
1. **Rapid Containment**: Limit the potential blast radius of security vulnerabilities or zero-day exploits.
2. **Fail-Closed Preservation**: Ensure that incidents or outages default to safety rather than silent exposure.
3. **Transparent Remediation**: Deliver honest, cryptographically signed patches with public CVE disclosure and user advisories.
4. **Zero-Knowledge Protection**: Safeguard client-side keys and vault data under all adverse conditions.

---

## 2. Severity Classification Matrix

| Level | Severity | Definition & Scope | Target Ack | Patch SLA |
| :---: | :---: | :--- | :---: | :---: |
| **P1** | **CRITICAL** | Cryptographic breakdown in Identity Vault, cleartext key exfiltration, remote code execution (RCE) in desktop daemon, or unauthenticated native messaging bypass. | **< 4 Hours** | **< 48 Hours** |
| **P2** | **HIGH** | Complete bypass of the Byzantine Consensus Firewall or injection engine leading to unredacted secret exfiltration; denial of service crash in native proxy. | **< 8 Hours** | **< 5 Days** |
| **P3** | **MEDIUM** | Contextual precision false negative in non-critical PII, regex performance degradation (sub-critical ReDoS), or telemetry spoofing in SIEM exporter. | **< 24 Hours** | **< 14 Days** |
| **P4** | **LOW** | Cosmetic UI flaw in Forensics Replay modal, documentation inconsistency, or non-security dependency update. | **< 48 Hours** | Next Minor Release |

---

## 3. Incident Response Lifecycle

```
   +---------------+      +----------------+      +---------------+
   | 1. DETECTION  | ---> | 2. CONTAINMENT | ---> | 3. REMEDIATION|
   +---------------+      +----------------+      +---------------+
           ^                                              |
           |                                              v
   +---------------+      +----------------+      +---------------+
   | 6. POST-MORTEM| <--- | 5. NOTIFICATION| <--- |  4. TESTING   |
   +---------------+      +----------------+      +---------------+
```

### Phase 1: Detection & Triage
- Vulnerabilities reported privately via [GitHub Security Advisories](https://github.com/starboy-hub/vigil.ai/security/advisories/new).
- Security team verifies the report, reproduces the defect in an isolated sandbox, and assigns severity rating (P1–P4).

### Phase 2: Containment
- If a vulnerability affects the native companion proxy or agent loopback firewall, users are provided immediate manual mitigation instructions (e.g. disabling loopback daemon or adjusting local firewall rules).
- For extension vulnerabilities, kill-switch / consensus policies can be updated to trigger emergency fail-closed mode (`VERDICT: BLOCK_ALL`).

### Phase 3: Remediation & Patching
- Surgical, minimal diffs developed on private security branches.
- Regression tests added immediately to prevent recurrence.
- Code reviewed by at least two senior security architects.

### Phase 4: Verification & Testing
- Full automated test suite (585+ Jest unit tests, 72 Playwright E2E tests, Rust companion cargo tests) executed.
- TextAttack adversarial mutation pipeline (`scripts/adversarial-benchmark.js`) executed to confirm catch rates $\ge 95\%$.

### Phase 5: Notification & Release
- Tagged cryptographically signed release published to GitHub.
- Chromium and Firefox Web Store emergency expedited reviews requested.
- Security Advisory published with CVE assignment and credit to the discoverer.

### Phase 6: Post-Mortem & Root Cause Analysis
- Blameless post-mortem completed within 7 business days.
- Root cause documented and integrated into regression testing and architectural audit criteria.

---

## 4. Emergency Contacts & Keys

- **Security Advisory Channel**: `https://github.com/starboy-hub/vigil.ai/security/advisories`
- **Community Discussions**: `https://github.com/starboy-hub/vigil.ai/discussions`
- **PGP Fingerprint**: `F5A9 217C 8B43 90E1 4D12  A87B 3E99 0081 CE4D 1092`
- **Advisory Feed**: `https://github.com/starboy-hub/vigil.ai/security/advisories`
