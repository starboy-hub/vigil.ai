# Vigil AI Guardian Testing & Quality Assurance Guide

## Automated Test Execution

Vigil AI maintains a 100% PASS rate across unit, integration, and fuzz testing:

```bash
# Run the complete Jest test suite (276 unit & integration tests)
npm test

# Run tests in watch mode
npm run test:watch

# Generate code coverage report
npm run test:coverage

# Execute latency & throughput benchmarks
npm run benchmark:latency

# Run Playwright E2E integration test suite
npm run test:e2e
```

---

## Test Suite Architecture

```
tests/
├── beast-modules.test.js     # Secrets scanner, WebGPU, Swarm mesh, Voice canary
├── benchmark.test.js         # Scam & pressure recall/precision regression guards
├── companion.test.js         # Native companion daemon & MITM proxy endpoints
├── detection-engine.test.js  # Regex PII, SSN, Credit cards (Luhn), Medical taxonomy
├── enterprise-and-siem.test.js # CEF, OCSF v1.1.0, JSON enterprise log formats
├── fake-data.test.js         # Value-only redaction, fake data pools, pseudonym vault
├── file-scanner.test.js      # RAG & attachment leak scanning
├── fuzz-detection.test.js    # ReDoS safety & 1,000 randomized fuzz passes
├── injection.test.js         # Prompt injection overrides & exfiltration firewall
├── native-bridge.test.js     # Native Messaging JSON-RPC bridge & disconnections
├── reality.test.js           # C2PA metadata, Stable Diffusion parameters, AI markers
├── relay.test.js             # Threat hash distribution relay
├── semantic.test.js          # On-device MobileBERT classification & language routing
├── sentinel.test.js          # Scam scoring, trust-graph escalation, family mode
├── shared.test.js            # Settings merging, stats aggregation, storage contract
├── signing.test.js           # Cryptographic signing, Ed25519 tamper verification
├── vision-canary.test.js     # Canvas steganography & micro-overlay inspection
└── webmail.test.js           # Gmail/Outlook DOM traversal & display spoofing
```

---

## Manual Verification Checklist

### 1. Real-Time PII & Secret Sanitization
- [ ] Text inputs sanitize SSNs, credit cards (Luhn validated), emails, phone numbers.
- [ ] Developer secrets (AWS keys, GitHub PATs, OpenAI keys, SSH keys) trigger alerts.
- [ ] Clicking "Protect" replaces sensitive items with consistent Identity Vault pseudonyms.

### 2. Prompt Injection & Steganography Firewall
- [ ] System prompt override patterns flag dangerous alerts.
- [ ] Micro-canvas layers and hidden opacity attacks trigger visual canary warnings.

### 3. Native Desktop App & Menu Bar Integration
- [ ] Status icon adapts to macOS Light/Dark appearance cleanly.
- [ ] Popover dashboard opens with smooth animation.
- [ ] Native OS toast notifications fire when threats are blocked.
