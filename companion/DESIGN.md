# Vigil AI Companion & Desktop Architecture

> **Status:** Production Architecture (Implemented in v11.0.0)  
> **Components:** Native macOS Menu Bar App (`Vigil Desktop.app`), Cross-Platform Agent Firewall Proxy (`companion/vigil-agent-firewall.js`), Native Messaging Bridge (`src/background/native-bridge.js`), and Voice Spectral Canary.

---

## 1. Why a Desktop Companion?

While browser extensions protect against web-based data loss, modern AI security requires defenses across the host operating system:

1. **System-Wide Agent-Traffic Firewall:** Intercepts traffic from desktop AI coding tools (Cursor, Windsurf, Claude Code, CLI agents) outside the browser.
2. **Audio FFT Spectral Canary:** Analyzes voice streams and anti-clone challenges to detect synthetic deepfake vishing attacks.
3. **OS-Level Notifications:** Delivers native system notifications via macOS `UNUserNotificationCenter` and Windows Toast when threats are blocked in background agent runs.

---

## 2. Implemented Architecture

### A. Native macOS Menu Bar Desktop App (`Vigil Desktop.app`)
- Built in Objective-C / Cocoa running under `LSUIElement = true` (zero Dock clutter).
- Dynamic light/dark template status bar icon with glassmorphic webview popover.
- Manages the local loopback firewall lifecycle automatically.

### B. Agent-Traffic Security Firewall Proxy
- High-performance local loopback proxy (`http://127.0.0.1:8765`).
- Parses agent streaming payloads (JSON, raw HTTP, SSE).
- Modes:
  - `Monitor`: Logs all payload inspections.
  - `Guard`: Tokenizes sensitive identity values with coherent per-session pseudonyms before outbound dispatch.
  - `Lock`: Strict air-gap mode blocking prompt injection patterns or untrusted payloads.

### C. Voice Clone Spectral Canary
- Generates dynamic challenge-response questions to defeat voice cloning.
- Performs real-time audio FFT frequency buffer analysis.

---

## 3. Universal 1-Click Installers

All components are packaged into turnkey native installers:
- **macOS:** `releases/macOS/Vigil-AI-macOS-v11.0.0.dmg`
- **Linux:** `releases/Linux/vigil-ai_11.0.0_amd64.deb` & `vigil-ai-v11.0.0-linux-x64.tar.gz`
- **Windows:** `companion/installer/vigil-windows-setup.iss`
