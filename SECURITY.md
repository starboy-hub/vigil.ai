# Security Policy

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Report privately through GitHub's **Security Advisories** (Repository → Security → Report a vulnerability) or by contacting the repository maintainers (`security@vigil-ai.org` / GitHub: `starboy-hub`).

- **Acknowledgment SLA:** Within **48 hours**.
- **Triage & Patch SLA:** Critical within **7 business days**; High within **14 business days**.
- **Credit & Responsible Disclosure:** Valid vulnerability reports are credited in release advisories upon patch release.

## Severity & Scope

### In Scope
- Core extension context (`src/`): DOM content scripts, event interceptors, smart paste, submission guard.
- Cryptographic identity vault (`src/background/vigil-vault.js`): AES-256-GCM encryption, PBKDF2-SHA256 key derivation.
- Native messaging bridge (`src/background/native-bridge.js` & `desktop/src/main.rs`): ECDH P-256 key exchange, AES-256-GCM framing, replay sequence verification, origin locks.
- Neural offscreen and local ML execution (`src/background/webgpu-engine.js`, `src/background/local-lora.js`).
- Supply chain and build reproducibility (`build.js`, `scripts/verify-dist.js`, `scripts/verify-extension-key.js`).

### Out of Scope
- Compromise of the host OS root/kernel or hardware keylogger/enclave tampering.
- Upstream browser zero-days in the underlying Chromium or Firefox layout engines.
- Third-party model weights hosted externally.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| **v1.0.0 (Latest)** | Yes |
| < v1.0.0 | No |

Only the latest release on `main` receives security fixes.

## Security Controls Overview
Vigil AI implements an uncompromising local-first, zero-telemetry defense model:
1. **Pinned Manifest Key:** Extension origin is locked to `emkokehejldjlfljlhhcimnfefcjcmon`.
2. **Encrypted Native Messaging:** AES-256-GCM channel negotiated via ephemeral ECDH with replay counters.
3. **Sensitive Surface Isolation:** Pre-execution deny-list prevents injection on SSO, password managers, and payment flows.
4. **Zero Outbound Egress:** Telemetry is strictly zero; all AI models and regex heuristics run 100% on localhost.
