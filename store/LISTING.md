# Chrome Web Store & Browser Marketplace Listing

Everything needed for Chrome Web Store, Microsoft Edge Add-ons, and Firefox Add-ons submission.

---

## Store Listing Details

**Name:** Vigil AI: Universal AI Privacy Shield

**Summary (132 chars max):**
> Zero-trust local guardian against AI threats: sanitizes PII/secrets, blocks prompt injections, and intercepts scams. 100% offline.

**Category:** Privacy & Security
**Language:** English (9 interface & detection languages supported)

---

## Detailed Description

Every day, millions of users and autonomous agents leak confidential data, developer secrets, and personal identity into AI platforms — while prompt injections, scams, and synthetic deepfakes attack them. 

**Vigil AI Guardian** is a zero-trust, local-first security enclave protecting both outbound data privacy and inbound AI threat surfaces. 100% on-device — zero cloud transmission.

### 🛡️ OUTBOUND PRIVACY & SECRET SHIELD
• Real-time sanitization of SSNs, credit cards (Luhn validated), emails, phones, and compensation.
• Developer secret shield: Intercepts AWS keys, GitHub PATs, OpenAI keys, Stripe tokens, and SSH keys.
• Identity Vault: Encrypted locally (AES-256-GCM via PBKDF2 600,000 rounds). Replaces sensitive entities with coherent per-site pseudonyms.
• Automatic un-masking: When an AI replies using a pseudonym, Vigil AI restores real values on your screen dynamically.

### 🛑 PROMPT INJECTION & AGENT FIREWALL
• Scans incoming LLM streams and web inputs for system prompt overrides, exfiltration instructions, and safety bypasses.
• Multimodal Canvas Steganography: Inspects canvas elements and micro-text layers designed to hijack vision-capable AI agents.

### 🧠 3-TIER ZERO-TRUST DEFENSE MATRIX
• Tier 1: Sub-millisecond (<1ms) deterministic regex, secret, and Luhn engine.
• Tier 2: Offline on-device WebGPU neural classification (10ms).
• Tier 3: Local AI reasoning enclave via local Ollama models (`deepseek-r1`).

### 🗣️ VOICE SPECTRAL CANARY
• Anti-clone challenge-response generator to verify identity and defeat deepfake voice clone attacks.

### 🏢 B2B ENTERPRISE & SIEM GOVERNANCE
• Centralized enterprise policy enforcement via `chrome.storage.managed`.
• 1-Click SOC exports in Common Event Format (CEF), OCSF v1.1.0, and Enterprise JSON.

---

## Permissions Justification

- `storage` — Settings, encrypted Identity Vault, and local audit history stored in isolated browser storage.
- `activeTab` — Displays current domain safety score and active protection mode.
- `nativeMessaging` — Loopback IPC with on-device native desktop companion and system tray.
- `host_permissions (<all_urls>)` — Operates client-side across web applications and AI platforms. Zero telemetry or external network calls.

---

## Privacy Policy
See [store/PRIVACY-POLICY.md](PRIVACY-POLICY.md).
