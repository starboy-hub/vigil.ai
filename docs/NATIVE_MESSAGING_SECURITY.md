# Native Messaging Hardening & Strict Mutual Authentication

## 1. Threat Model & Overview

Native Messaging provides zero-network standard I/O (stdio) inter-process communication between the Vigil AI browser extension and the local native desktop companion app (`com.vigil.desktop` / `com.vigil.desktop`). 

Without strict controls, standard native messaging implementations face three major vulnerabilities:
1. **Malicious Extension Hijacking / Origin Spoofing**: A rogue third-party extension installed in the browser could attempt to connect to the native messaging host to execute privileged commands (such as OS Keychain reads, ML model queries, or filesystem operations).
2. **Wildcard Origin Exploitation**: Permissive manifest definitions such as `chrome-extension://*` permit arbitrary extensions to connect.
3. **Unauthenticated Session Execution**: Executing privileged RPC functions without establishing a cryptographic challenge-response session.

To completely mitigate these threat vectors, Vigil AI enforces a **3-Tier Defense-in-Depth Architecture**.

---

## 2. 3-Tier Defense-in-Depth Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Tier 1: OS Host Manifest Origin Whitelist                   │
│ - Strict extension IDs only (Zero Wildcards)                │
│ - Verified by Browser Kernel before launching process       │
└──────────────────────────────┬──────────────────────────────┘
                               │ (stdio launch)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 2: Cryptographic Handshake & Origin Lock Validation     │
│ - vigil.auth.handshake (client nonce, timestamp, origin)    │
│ - Native Host verifies extension_id against ALLOWED_ORIGINS │
│ - Unauthorized origins rejected with FORBIDDEN_ORIGIN_LOCK  │
└──────────────────────────────┬──────────────────────────────┘
                               │ (session token generated)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Tier 3: Authenticated RPC Session Guard                      │
│ - Every privileged method requires valid active auth_token  │
│ - Missing/invalid token -> UNAUTHORIZED (-32401)            │
│ - Origin mismatch -> FORBIDDEN_ORIGIN_LOCK (-32403)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Protocol Specification

### 3.1 Mutual Authentication Handshake (`vigil.auth.handshake`)

When the extension initiates communication via `chrome.runtime.connectNative`, it executes an initial mutual authentication handshake before issuing any privileged commands.

**Client Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "vigil.auth.handshake",
  "params": {
    "extension_id": "emkokehejldjlfljlhhcimnfefcjcmon",
    "origin": "chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/",
    "client_nonce": "9a8b7c6d5e4f3a2b1029384756abcdef",
    "timestamp": 1791128400000
  }
}
```

**Host Verification & Response (Success):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "authenticated": true,
    "session_token": "vigil_sess_1791128400a1b2c3d4",
    "host_name": "com.vigil.desktop",
    "origin_locked": true,
    "extension_id": "emkokehejldjlfljlhhcimnfefcjcmon"
  }
}
```

**Host Response (Forbidden Origin):**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32403,
    "message": "FORBIDDEN_ORIGIN_LOCK: Origin 'chrome-extension://malicious-attacker-extension-id/' is not authorized by the native host manifest policy"
  }
}
```

### 3.2 Privileged RPC Requests

Subsequent operations (such as `keychainGet`, `keychainSet`, `inspectIdePrompt`, `classifyTextNative`, `exportSiemLog`, etc.) must provide the active `auth_token` and matching `origin`:

**Client Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "vigil.keychainGet",
  "params": {
    "service": "vigil-identity-vault",
    "account": "master-key",
    "auth_token": "vigil_sess_1791128400a1b2c3d4",
    "origin": "chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/"
  }
}
```

If an unauthenticated request is received without a valid session token:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32401,
    "message": "UNAUTHORIZED: Mutual authentication handshake required. Missing or invalid session token."
  }
}
```

---

## 4. Manifest Security Policies

### Chromium Host Manifest (`com.vigil.desktop.json` / `com.vigil.desktop.json`)
```json
{
  "name": "com.vigil.desktop",
  "description": "Vigil / VIGIL Native Desktop Security Companion Daemon",
  "path": "/Applications/VIGIL.app/Contents/MacOS/vigil-native-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/",
    "chrome-extension://vigil-guardian-id/",
    "chrome-extension://vigil-guardian-id/"
  ]
}
```

### Firefox Host Manifest
```json
{
  "name": "com.vigil.desktop",
  "description": "Vigil / VIGIL Local Security Sentinel & Local AI Enclave Bridge (Firefox)",
  "path": "/Applications/VIGIL.app/Contents/MacOS/vigil-native-host",
  "type": "stdio",
  "allowed_extensions": [
    "vigil@starboy-hub.github.io",
    "vigil@starboy-hub.github.io"
  ]
}
```

---

## 5. Automated Verification & E2E Testing

The native messaging security hardening is verified continuously across both unit and end-to-end test suites:

| Test Suite | File | Coverage |
| :--- | :--- | :--- |
| **Jest Unit Test** | `tests/native-bridge.test.js` | Handshake resolution, session token attachment, disconnected session cleanup, manifest generator zero-wildcard enforcement, and `isOriginAllowed` whitelist matching. |
| **Playwright E2E Test** | `e2e/native-messaging.spec.js` | Live browser environment validation, manifest schema compliance, simulated malicious origin attack rejection (`FORBIDDEN_ORIGIN_LOCK`), and unauthenticated request rejection (`UNAUTHORIZED`). |
| **Extension E2E Test** | `e2e/extension.spec.js` | Live browser context validation of `VIGIL_NATIVE_BRIDGE` origin lock and whitelist enforcement. |
