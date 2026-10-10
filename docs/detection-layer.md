# Vigil AI Detection Layer — Developer & Architecture Reference

Technical reference for the zero-trust local detection stack. Everything executes client-side with zero external cloud transmission.

---

## 1. Module Map

| Module | Path | Loads In | Purpose |
|---|---|---|---|
| `vigil-shared.js` | `src/shared/` | popup, options, content, background, tests | Storage keys, settings defaults, `strHash`, `flexiblePattern`, `maskSensitive`, `normalizeForSignature` |
| `detection-engine.js` | `src/content/modules/` | content, tests | Regex PII + context patterns, name heuristics, custom patterns, Luhn check, `cleanText` |
| `secret-engine.js` | `src/content/modules/` | content, tests | Developer secret shield (AWS, GitHub, OpenAI, Stripe, SSH, DB URIs) |
| `sentinel-engine.js` | `src/content/modules/` | content, tests | Inbound scam scoring: signals → level + advice, trust escalation, `shouldWarn` |
| `injection-engine.js` | `src/content/modules/` | content, tests | Direct, indirect, and second-order prompt injection pattern scoring |
| `vision-canary.js` | `src/content/modules/` | content, tests | Multimodal canvas steganography & micro-overlay inspection |
| `webgpu-engine.js` | `src/background/` | background, offscreen, tests | On-device hardware-accelerated WebGPU neural classification |
| `fake-data.js` | `src/content/modules/` | content, tests | `FAKE_DATA` pools, `getFakeData`, `redactText` (the Protect path) |
| `vigil-vault.js` | `src/background/` | background, tests | PBKDF2 (600k rounds) / AES-256-GCM encrypted Identity Vault + trust list |
| `signing-engine.js` | `src/background/` | background, tests | ECDSA P-256 / Ed25519 content signing and verification |
| `threat-store.js` | `src/background/` | background, tests | P2P Swarm threat mesh signature store, pack export/import |
| `reality-engine.js` | `src/background/` | background, tests | Image-byte C2PA provenance & generative media forensics |
| `enterprise-policy.js`| `src/background/` | background, tests | Enterprise Group Policy / Google Admin Console governance |

---

## 2. Core Design Rules

1. **Universal Module Definition (UMD):** Each module assigns to `self` in the browser and `module.exports` in Node.js, ensuring 100% test coverage without build steps.
2. **Pure Functional Engines:** Scoring and regex analysis are decoupled from DOM mutations, making them isolated and unit-testable.
3. **Value-Only Redaction:** Captures the sensitive sub-string while preserving structural labels (e.g. `Date of birth: 01/01/1990` -> `Date of birth: 04/12/1988`).
4. **Whitespace & Linebreak Tolerant:** Uses `flexiblePattern` to match formatted text even across multiline pastes.
