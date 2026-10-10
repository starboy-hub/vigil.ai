# Security Policy

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Report privately through GitHub's **Security Advisories** (Repository → Security → Report a vulnerability) or by contacting the repository maintainers (**starboy-hub**) directly.

- You will receive an acknowledgment within **48 to 72 hours**.
- Fixes for confirmed vulnerabilities ship in the next patch release, and you will be credited in the release notes if you wish.

## Scope

- **In scope:** The core extension and companion code in this repository (`src/`, `companion/`, `build.js`, `scripts/`, `evaluation/`) — including the Identity Vault's AES-256-GCM encryption, native messaging bridge, WebGPU neural engine, detection pipelines, and build integrity.
- **Out of scope:** Third-party dependencies (e.g. the Ollama project itself, browser-level engine exploits), attacks requiring physical possession of an unlocked machine, or compromise of the host operating system keychain (these are documented limitations in our threat model — see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md)).

## Supported Versions

| Version | Supported |
| :--- | :--- |
| **v10.0.0 (Latest)** | Yes |
| < v10.0.0 | No |

Only the latest release on `main` receives security fixes.
