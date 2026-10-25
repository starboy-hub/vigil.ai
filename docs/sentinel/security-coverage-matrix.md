# Sentinel Stage 1: Security Coverage Matrix

**Document Version**: 1.0.0  
**Specification**: `Plan.pdf` (Section 3.6)  
**Date**: 2026-10-25  
**Governing Principle**: "Repository truth beats assumptions. Never claim universal host visibility when only some events are observed."

---

## Component Security Coverage Matrix

| Component | Entry Point | Observed Behavior | Enforces? | Tested? | Blind Spots | Planned Sentinel Evolution |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **DOM Input Interceptor** | `src/content/content.js` (`keydown`, `input`, `submit`) | Intercepts keyboard input in browser web pages, scans for PII/secrets, replaces sensitive values with pseudonyms. | **YES** (In-DOM) | **YES** (`tests/outbound-private-key...`, `tests/silent-guardian...`) | Only operates inside web pages loaded in Chrome/Firefox. Zero visibility into terminal CLIs or desktop IDEs. | Retain as the browser-tier defense; feed detection events into Sentinel correlation engine. |
| **Web Scanner Worker** | `src/content/scanner-worker.js` (Web Worker) | Runs regex and heuristic scanning off the main thread to maintain <50ms typing responsiveness. | **YES** (Analysis) | **YES** (`tests/scanner-worker.test.js`) | Scans only string text chunks dispatched from `content.js`. | Keep worker for high-throughput regex evaluation in browser contexts. |
| **Consensus Firewall** | `src/background/consensus-firewall.js` | Runs 2-of-3 multi-model consensus voting across Heuristics, Neural head, and Semantic reasoner. | **YES** (Voting decision) | **YES** (`tests/beast-modules.test.js`) | Only evaluates text passed to it. Cannot prevent execution of actions on the OS. | Adapt voting logic into Sentinel's higher-level risk scoring layer. |
| **Identity Vault** | `src/background/vigil-vault.js` | AES-GCM-256 encrypted storage for synthetic pseudonym mappings with key derivation. | **YES** (At Rest) | **YES** (`tests/fake-data.test.js`) | Plaintext keys are in extension process memory when unlocked; susceptible to full-disk host compromise without hardware enclave. | Connect to Sentinel capability manager for narrow, time-limited secret access tokens. |
| **Native Messaging Bridge** | `src/background/native-bridge.js` | Connects browser extension to `com.vigil.desktop` over stdio IPC with ECDH P-256 and AES-GCM encrypted frames. | **YES** (Channel Crypto) | **YES** (`tests/native-bridge.test.js`) | Rejects unauthorized extension IDs, but relies on browser's native messaging host registration. | Reuse the secure bridge to allow extension UI to view Sentinel agent audit events and approve actions. |
| **Rust Desktop Companion** | `desktop/src/main.rs` | JSON-RPC 2.0 host handling hardware key sealing, integrity audits, and IDE prompt inspection. | **YES** (RPC boundary) | **YES** (`cargo test` 20 tests) | Only executes RPC methods explicitly called by authorized callers. | Host Sentinel daemon or companion policy evaluation endpoints safely on loopback. |
| **Rust IDE Prompt Inspector** | `desktop/src/ide_proxy.rs` (`inspect_prompt`) | Scans developer prompt strings for AWS, GitHub, OpenAI, and PEM private keys using lazy regexes. | **PARTIAL** (Redacts in memory) | **YES** (`desktop/src/ide_proxy.rs` tests) | Only inspects prompt strings submitted via RPC. Does **NOT** intercept tool executions, file operations, or shell commands. | Evolve from text inspection into a true execution-boundary tool gateway. |
| **Token Budget Engine** | `desktop/src/ide_proxy.rs` & `src/background/token-budget.js` | Tracks session and daily token usage per `agent_id`; flags runaway loops or returns `hard_block`. | **YES** (Budget decision) | **YES** (`tests/token-budget.test.js` & `cargo test`) | Relies on callers reporting accurate token numbers; no kernel-level process throttling. | Integrate token budget consumption directly into Sentinel policy evaluation (`quota_exceeded` rule). |
| **Agent HTTP Firewall** | `companion/vigil-agent-firewall.js` (Port 8765) | Node.js forward HTTP proxy that redacts PII or blocks requests in `lock` mode based on request body. | **PARTIAL** (HTTP bodies only) | **YES** (`tests/companion.test.js`) | **CRITICAL BLIND SPOT**: HTTPS CONNECT tunnels are passed through with payload uninspected (end-to-end TLS). Ignores non-HTTP traffic, direct sockets, and shell commands. | Supplement HTTP proxy with an execution-boundary Gateway (MCP / Agent Hook) that intercepts operations directly. |
| **File Integrity Auditor** | `src/background/file-integrity.js` & `desktop/src/file_integrity.rs` | Computes SHA-256 hashes of extension files and system manifests to detect tampering or unauthorized modifications. | **YES** (Tamper detection) | **YES** (`tests/file-integrity.test.js` & `cargo test`) | Only verifies files listed in reference manifest; cannot protect unmonitored directories. | Use file integrity auditor to verify Sentinel policy definitions and rule configuration files. |
| **Replay & Forensics** | `src/background/forensics-replay.js` & `src/background/prompt-git.js` | Tracks prompt mutation trees and provides an append-only timeline log of intercepted events. | **NO** (Audit/Log only) | **YES** (`tests/forensics-replay.test.js`) | In-memory / storage log; does not guarantee Byzantine tamper resistance against privileged root. | Evolve into the official Sentinel Audit Ledger (Stage 7). |
| **Sentinel Policy Engine** | *To be built in Stage 3* | Shared, deterministic, versioned rule engine evaluating canonical action schemas (`allow`/`deny`/`require_approval`). | **PLANNED** | *Stage 3* | Must not execute side effects itself; must fail closed on timeout or invalid config. | **New core module** (`sentinel/policy-engine.js`). |
| **Sentinel Tool Gateway** | *To be built in Stage 4* | Intercepts agent tool executions (MCP or agent CLI hooks) before disk, network, or terminal side effects happen. | **PLANNED** | *Stage 4* | Only intercepts tools routed through the gateway adapter; unsupported tools must be documented. | **New core gateway** (`sentinel/gateway/`). |

---

## Summary of Critical Coverage Gaps Identified

1. **HTTPS Traffic Blindness in Proxy**: `vigil-agent-firewall.js` passes HTTPS CONNECT tunnels without body inspection. Any agent using `https://api.openai.com` or `https://api.anthropic.com` cannot have its payload inspected or sanitized by the HTTP proxy alone unless TLS MITM is used.
2. **Tool Execution Bypass**: The current architecture monitors prompts and HTTP egress, but has **zero control over tools that execute on the local OS** (such as reading `/etc/passwd`, executing `rm -rf`, modifying `.git`, or accessing environment variables).
3. **Execution-Time Enforcement**: Sentinel's primary mission must be to establish enforcement at the **tool invocation layer** (e.g. MCP Server Gateway or Claude Code hook) before the OS side effect executes.

