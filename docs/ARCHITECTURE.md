# Vigil AI Guardian Architecture

Technical breakdown of entry points, message flow, storage model, and security boundaries.

---

## 1. Entry Points

| Context | File(s) | Runs When | Responsibilities |
|---|---|---|---|
| **Background Service Worker** | `background.js` (imports `vigil-vault.js`, `enterprise-policy.js`, `native-bridge.js`, `reality-engine.js`, `signing-engine.js`, `threat-store.js`, `vigil-shared.js`) | Extension events; wakes on message | Settings source of truth, Vault PBKDF2/AES encryption, Native Bridge RPC, Ollama bridge, SIEM export, WebGPU offscreen manager |
| **Content Script** | `content.js` + detection modules | Injected at `document_end` on `<all_urls>` | All DOM-facing work: regex scanner, secret detector, inline popup UI, submission/attachment guards, pseudonym restore pass |
| **Popup UI** | `popup.html/.js/.css` | Toolbar icon click | Guardian dashboard: real-time status, layer toggles, presets, telemetry, activity log |
| **Settings UI** | `options.html/.js/.css` | Options page | Vault/Trust management, custom regex patterns, WebGPU/Ollama toggles, SIEM log exports, Swarm packs |
| **Native Companion & Tray** | `companion/native-app/` (`Vigil Desktop.app`) | macOS login / autostart | Native system tray popover, OS notifications, local proxy firewall, audio FFT canary |

---

## 2. Message Flow & Boundaries

```
Content Script ──runtime.sendMessage──► Background Service Worker ──Native Messaging──► Vigil Native Desktop
      ▲                                        │
      └────────tabs.sendMessage────────────────┘
```

Pages never participate: `chrome.runtime.onMessage` only accepts messages from this extension's own isolated world contexts (`externally_connectable` is not declared).

---

## 3. Storage Model

| Area | Key | Contents | Sensitivity |
|---|---|---|---|
| `sync` | `settings` | Toggles, sensitivity, trusted sites, family mode | Public preferences |
| `sync` | `theme`, `manualLanguage` | UI preferences | Public preferences |
| `local` | `vault_data`, `vault_salt` | PBKDF2 (600k rounds) / AES-256-GCM encrypted PII and secrets | **High** (Encrypted at rest) |
| `local` | `history`, `history_summary` | Redaction audit log (masked on export) | Medium |
| `local` | `pseudo_map` | Site-specific deterministic pseudonyms | Low |
| `local` | `signing_key` | Local ECDSA P-256 / Ed25519 signing keypair | High (Isolated to device) |
| `managed` | Enterprise Policy | Organizational policy presets via Google Admin / MDM | High (Read-only) |
