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

## Integration Coverage & Traffic Inspection Matrix

| Integration Surface | Protocol / Channel | Inspection & Redaction Coverage | Explicit Security Boundaries & Policy |
| :--- | :--- | :--- | :--- |
| **Browser Extension** (`src/`) | DOM Content Scripts / In-Memory Interceptors | **Full Pre-Encryption Inspection**<br>Scans all DOM submissions (buttons, Enter key, forms, quarantine buffer) for PII, secrets, and prompt injection before transport. | Deny-list excludes banking, password managers, and payment flows. Context isolation prevents content scripts from accessing privileged vault keys. |
| **Native IDE Proxy** (`desktop/`, Port 8383) | Loopback HTTP / IPC | **Full Prompt Inspection**<br>Inspects prompts from Cursor, Copilot, and Ollama. Redacts AWS keys, GitHub PATs, API keys, and RSA/PKCS#8 keys. Enforces token budgets. | Bound to `127.0.0.1`. Plaintext prompts only; token budget engine enforces hard block / soft alert thresholds. |
| **Agent Firewall — Plain HTTP** (`companion/`, Port 8765) | HTTP/1.1 Forward Proxy | **Full Streaming DLP Inspection**<br>Redacts request and response streams. Rewrites tokens in SSE streams with bounded memory. | Drops recursive proxy loops (400) and cloud metadata IMDS SSRF (403). Validates actual connected socket IP and blocks prohibited redirects. |
| **Agent Firewall — HTTPS Tunnels** (`companion/`, Port 8765) | HTTP `CONNECT` Tunneling | **Uninspected Traffic (`tunnel_uninspected`)**<br>TCP byte stream is end-to-end TLS encrypted between client and upstream host. | **Fundamental TLS Limitation:** Vigil does NOT install an OS root CA certificate (TLS MITM) to decrypt HTTPS payloads. Destination safety (blocking IMDS SSRF and recursive loops) is enforced, but encrypted payload bodies are strictly audited as `tunnel_uninspected`. |

