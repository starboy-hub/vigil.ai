# Vigil AI Coordinated Vulnerability Disclosure & Bug Bounty Program

**Version:** 1.0.0  
**Program Status:** Active  
**Contact:** `security@vigil-ai.org` · [GitHub Security Advisories](https://github.com/starboy-hub/vigil.ai/security/advisories/new)  
**Security Policy:** [SECURITY.md](SECURITY.md) · **RFC 9116:** [/.well-known/security.txt](.well-known/security.txt)

---

## 1. Overview & Commitment

Vigil AI is committed to an open, transparent, and rigorous security posture. We invite independent security researchers, cryptographers, and ethical hackers to rigorously test our zero-trust defenses and report vulnerabilities responsibly.

---

## 2. Response & Triage Service Level Agreements (SLAs)

| Stage | SLA Commitment |
|---|---|
| **Initial Acknowledgment** | Within **48 hours** |
| **Triage & Severity Assessment** | Within **5 business days** |
| **Critical Patch Release** | Within **7 business days** |
| **High Severity Patch Release** | Within **14 business days** |
| **Medium / Low Patch Release** | Next regular patch release cycle |

---

## 3. Severity Classification & Reward Ranges

Rewards are calibrated using the **Common Vulnerability Scoring System (CVSS v3.1)**:

| Severity | CVSS v3.1 Range | Reward Range | Example Scenarios |
|---|---|---|---|
| 🔴 **Critical** | 9.0 – 10.0 | **$2,500 – $5,000** | Arbitrary host code execution via native IPC, AES-256-GCM vault master key extraction without authorization, unauthenticated remote command execution. |
| 🟠 **High** | 7.0 – 8.9 | **$1,000 – $2,500** | Complete bypass of the Sensitive Context Deny-List (`injection-policy.js`), native IPC origin-lock pivot, cryptographic key agreement downgrade. |
| 🟡 **Medium** | 4.0 – 6.9 | **$300 – $1,000** | ReDoS catastrophic backtracking leading to browser lockup, isolated DOM XSS within non-privileged frames, storage audit log tampering. |
| 🟢 **Low** | 0.1 – 3.9 | **$100 – $300** + Hall of Fame | Information disclosure of non-sensitive metadata, minor rate-limit evasions, non-exploitable configuration drifts. |

---

## 4. Scope

### In Scope
* **Browser Extension Context** (`src/`): Content script injection guards, Smart Paste interceptors, Submission Guard.
* **Cryptographic Identity Vault** (`src/background/vigil-vault.js`): AES-256-GCM + PBKDF2 encryption at rest.
* **Native Companion Host** (`desktop/src/`): ECDH P-256 handshake, frame replay counters, keychain allowlists, and IPC framing.
* **Supply-Chain Integrity** (`build.js`, `scripts/verify-extension-key.js`, `scripts/verify-build-reproducibility.js`).

### Out of Scope
* Physical host compromise or root/kernel-level malware on the user's OS.
* Denial of Service attacks on third-party AI platform APIs.
* Vulnerabilities in upstream Chromium/Gecko layout engines.
* Social engineering or phishing targeting repository maintainers.

---

## 5. Safe Harbor Policy

We consider security research conducted under this policy to be:
* **Authorized** under applicable anti-hacking laws (including the CFAA).
* **Exempt from legal action** by Vigil AI maintainers provided researchers do not destroy user data, violate privacy, or disclose vulnerabilities publicly before a patch is released.
