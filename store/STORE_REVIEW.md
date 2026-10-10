# 📋 VIGIL Chrome Web Store Reviewer Guide & Permission Justification

> **Extension Name:** Vigil AI Guardian  
> **Manifest Version:** MV3 (v11.0.0)  
> **Privacy Model:** 100% On-Device / Zero Telemetry / Zero Remote Network Calls

---

## 1. Single-Purpose Statement

VIGIL is an open-source endpoint Data Loss Prevention (DLP) and threat shield extension designed to automatically detect, redact, and pseudonymize sensitive data (PII, developer secrets, credentials) before submission to web-based AI platforms, and to analyze inbound content for prompt injections and scams.

---

## 2. Justification for Broad Permissions

### 🌐 `<all_urls>` (Host Permission)
- **Why Required:**  
  AI chat interfaces, prompt fields, and Rich Text Editors (Notion, ChatGPT, Claude, Google Gemini, custom internal corporate AI portals, Slack, webmail) reside across arbitrary web domains.
- **Scope of Use:**  
  Content scripts read text strictly inside active input/textarea elements when typed or pasted by the user to perform local regex and heuristic PII redaction.
- **Privacy Assurance:**  
  No DOM text or user input is ever recorded, logged remotely, or transmitted to any external server.

### 📄 `offscreen` Permission
- **Why Required:**  
  Manifest V3 background service workers cannot initialize DOM/WASM environments required for local ONNX tensor execution.
- **Scope of Use:**  
  The `offscreen.html` document runs a bundled, fine-tuned multilingual AI sequence classification model (`src/offscreen-model/onnx/model_quantized.onnx`) locally via WebGPU/WASM.
- **Privacy Assurance:**  
  All AI inference occurs 100% on-device within the extension's isolated offscreen document origin.

### 🔒 `storage` Permission
- **Why Required:**  
  Used to store encrypted Identity Vault records (via Web Crypto AES-256-GCM) and user preferences locally on the device (`chrome.storage.local`).

### 🖱️ `contextMenus` Permission
- **Why Required:**  
  Adds optional user-invoked right-click shortcuts:
  - `🛡️ VIGIL: Sanitize Selected Code/Text` (sanitizes highlighted text in 1 click).
  - `🔍 VIGIL: Check Image Provenance (C2PA/AI)` (inspects image metadata for C2PA/AI provenance).

---

## 3. Reviewer Verification Steps

To verify the extension during Chrome Web Store review:

1. Load unpacked `dist/` in Chrome (`chrome://extensions/`).
2. Open any web page with an input box (e.g., `https://chatgpt.com` or a local HTML page).
3. Type `my email is john.doe@gmail.com and my secret is AKIAIOSFODNN7EXAMPLE`.
4. Observe the VIGIL inline shield notification detecting **Email** and **AWS Access Key ID**.
5. Click **Protect** to verify local redaction with fake placeholders.
6. Open DevTools Network tab to confirm **0 network requests** are sent by VIGIL.
