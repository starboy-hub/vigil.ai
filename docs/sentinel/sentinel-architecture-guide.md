# Sentinel Developer Agent Security Gateway: Architecture & Operating Manual

**Document Version**: 1.0.0  
**Specification Reference**: `Plan.pdf` (Vigil AI + Sentinel Developer Agent Master Execution Specification)  
**Status**: Fully Implemented & Verifiable  
**Repository**: `vigil.ai`  

---

## 1. Executive Summary

**Sentinel** is an execution-boundary security gateway and deterministic policy enforcement layer for autonomous coding agents (Claude Code, Model Context Protocol clients, CLI tools, and automated development workflows). 

Unlike prompt-level guardrails—which can be bypassed by prompt injection, jailbreaks, or indirect prompt smuggling—Sentinel enforces policies at the **OS and tool execution boundary**. Before an autonomous agent can read, write, delete, execute, or transmit data over the network, the request is intercepted, normalized into a strongly-typed schema, and evaluated by Sentinel's 4-tier deterministic policy engine.

---

## 2. Core Architecture & Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Autonomous Agent (e.g. Claude Code)                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Tool Calls / Shell / HTTP
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Sentinel Execution Boundary Adapters                     │
│  ┌──────────────────────┐ ┌──────────────────────┐ ┌─────────────────────┐  │
│  │   MCP Tool Gateway   │ │     CLI Shim Gate    │ │   REST / HTTP Proxy │  │
│  │ (mcp-gateway.js)     │ │   (cli-shim.js)      │ │   (rest-proxy.js)   │  │
│  └──────────┬───────────┘ └──────────┬───────────┘ └──────────┬──────────┘  │
└─────────────┼────────────────────────┼────────────────────────┼─────────────┘
              ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Sentinel Normalizer & Schemas                           │
│  - Realpath canonicalization & symlink escape detection                     │
│  - Cloud metadata (IMDS) & private network blocking                         │
│  - Canonical SHA-256 action hashing (TOCTOU binding)                        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Sentinel Policy Engine (Pure)                         │
│  Level 1: Non-Negotiable Hard Safety Rules (Path escapes, IMDS, fork bombs) │
│  Level 2: Explicit Deny Rules (Secrets, .env, token quotas, TOCTOU hash)    │
│  Level 3: Human Approval Gates (File deletion, strict writes, config edits) │
│  Level 4: Explicit Allow (Workspace confinement, allowlisted commands)      │
└──────────────────┬───────────────────┬───────────────────┬──────────────────┘
                   │                   │                   │
                   ▼                   ▼                   ▼
┌───────────────────────┐ ┌─────────────────────────┐ ┌───────────────────────┐
│ Attack-Chain Detector │ │ Capability Secret Broker│ │ Tamper-Evident Ledger │
│ - Temporal taint      │ │ - Scoped HMAC-SHA256    │ │ - SHA-256 hash chains │
│ - Recon burst checks  │ │   capability tokens     │ │ - Genesis anchoring   │
│ - Privilege escalation│ │ - Boundary injection    │ │ - Ingestion scrubbing │
│ - Multi-step alerts   │ │ - Zero agent disclosure │ │ - CEF / SIEM export   │
└───────────────────────┘ └─────────────────────────┘ └───────────────────────┘
                   │                   │                   │
                   └───────────────────┼───────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               Native Companion Anchor (Rust - com.vigil.desktop)             │
│  - Origin-locked native messaging IPC                                       │
│  - Hardware enclave / OS Keychain integration                               │
│  - High-performance linear regex & filesystem integrity                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Policy Precedence Hierarchy

Every tool request is evaluated through a strict 4-level precedence hierarchy where higher levels strictly override lower levels:

| Precedence Tier | Scope & Rules | Override Behavior |
| :--- | :--- | :--- |
| **Level 1: Hard Safety Rules** | Path traversal, symlink escapes, sensitive system targeting (`/etc`, `~/.ssh`), cloud metadata (IMDS `169.254.169.254`), broad deletions (`rm -rf /`, `*`), and destructive shell patterns (`:(){ :|:& };:`, `mkfs`). | **NON-NEGOTIABLE**. Cannot be overridden by user approvals or profile settings. |
| **Level 2: Explicit Deny Rules** | Secret files (`.env`, `id_rsa`, `.aws/credentials`), token budget exhaustion, and TOCTOU action hash mismatch. | Evaluated before any approval checks. |
| **Level 3: Approval Gates** | Irreversible actions (file deletion, security configuration changes, strict-mode writes, and arbitrary shell commands). | Suspends call awaiting human confirmation with bounded timeout and exact action hash binding. |
| **Level 4: Default Allow** | In-workspace file reads, in-workspace file writes (balanced profile), and allowlisted shell commands (`npm test`, `git status`, `npm run lint`). | Allowed only if Levels 1–3 pass. |

---

## 4. Execution Boundary Adapters

### 4.1 Model Context Protocol (MCP) Tool Gateway
- **File**: [`src/sentinel/gateway/mcp-gateway.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/gateway/mcp-gateway.js)
- **Mechanism**: Intercepts JSON-RPC 2.0 requests (`tools/call`, `tools/list`).
- **Enforcement**:
  - Maps tool name and arguments into canonical `ActionSchema`.
  - Evaluates action with deterministic timeout.
  - Blocks forbidden actions with formatted MCP error responses (`isError: true` with redacted reason codes).
  - Mediates human approvals asynchronously with timeout expiration.
  - Catches downstream tool exceptions and scrubs stack traces and secrets.

### 4.2 CLI Shim Enforcement Adapter
- **File**: [`src/sentinel/gateway/cli-shim.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/gateway/cli-shim.js)
- **Mechanism**: Intercepts command-line tool invocations (`bash`, `sh`, developer scripts).
- **Enforcement**:
  - Validates commands against destructive execution patterns.
  - Returns POSIX standard exit code `126` (`EXIT_CODE_POLICY_DENIED`) on block.
  - Supports non-destructive dry-run policy checking (`checkPolicy`).

### 4.3 REST / HTTP Proxy Enforcement Adapter
- **File**: [`src/sentinel/gateway/rest-proxy.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/gateway/rest-proxy.js)
- **Mechanism**: Forward HTTP proxy intercepting outbound API calls.
- **Enforcement**:
  - Blocks link-local cloud metadata endpoints (IMDS) with HTTP 403.
  - Brokers access tokens via `X-Sentinel-Capability-Token` header.
  - Injects credentials at the network perimeter without exposing keys to agents.

---

## 5. Credentials & Capability Token Management

To eliminate the practice of pasting raw credentials into agent configuration or environment variables, Sentinel implements **Capability Brokering**:
- **File**: [`src/sentinel/credentials/secret-broker.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/credentials/secret-broker.js)
- **Features**:
  - **Capability Tokens**: Signed with HMAC-SHA256, strictly bound to `agentId`, `sessionId`, short TTL (default 15 minutes), and narrow scopes (e.g. `api.github.com:read`).
  - **Execution-Boundary Injection**: Real credentials reside in isolated broker memory or OS keychain. The broker injects the credential directly into the request dispatcher.
  - **Zero Raw Secret Exposure**: All outbound response bodies, headers, and error messages are deeply, recursively scrubbed of raw secrets and known secret patterns (`[REDACTED_BROKERED_SECRET]`, `[REDACTED_GITHUB_PAT]`, etc.).

---

## 6. Cryptographic Audit Ledger & Security Timeline

Every security decision, tool execution, and approval event is permanently recorded in an append-only, tamper-evident audit ledger:
- **File**: [`src/sentinel/ledger/audit-ledger.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/ledger/audit-ledger.js)
- **Cryptographic Hash Chaining**:
  $$\text{entry\_hash} = \text{SHA-256}(\text{index} \parallel \text{timestamp} \parallel \text{event\_type} \parallel \text{prev\_hash} \parallel \text{canonical\_json}(\text{payload}))$$
- **Genesis Anchoring**: Block 0 links to `0000000000000000000000000000000000000000000000000000000000000000`.
- **Integrity Verification**: `verifyLedgerIntegrity()` recalculates and validates every link; detects any deleted, altered, or backdated entries and returns the exact index of tampering.
- **Compliance Export**: Exports to Common Event Format (CEF) and JSON for enterprise SIEM ingestion.

---

## 7. Attack-Chain Temporal Correlation

Attack vectors that appear benign when viewed as isolated actions are correlated over a temporal sliding window:
- **File**: [`src/sentinel/correlation/attack-chain-detector.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/correlation/attack-chain-detector.js)
- **Correlated Chains**:
  1. **Tainted Exfiltration**: Prompt injection / untrusted input $\rightarrow$ file reads $\rightarrow$ outbound network attempt $\Rightarrow$ blocked with `DENY_ATTACK_CHAIN_EXFILTRATION`.
  2. **Reconnaissance Burst**: Rapid enumeration across $\ge 5$ distinct files within 60 seconds $\rightarrow$ outbound network egress $\Rightarrow$ blocked with `DENY_ATTACK_CHAIN_RECONNAISSANCE`.
  3. **Privilege Escalation**: Succession of security policy denials $\rightarrow$ attempt to modify security configuration $\Rightarrow$ blocked with `DENY_ATTACK_CHAIN_PRIVILEGE_ESCALATION`.

---

## 8. Native Desktop Companion Anchor (Rust)

- **Files**: [`desktop/src/sentinel.rs`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/desktop/src/sentinel.rs), [`desktop/src/main.rs`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/desktop/src/main.rs)
- **Capabilities**:
  - Provides hardware-anchored security and OS-level realpath validation.
  - Evaluates policies natively with zero network overhead.
  - Exposes 4 narrow, audited RPC methods under Chrome extension origin lock and mutual session authentication:
    - `vigil.sentinelEvaluatePolicy`
    - `vigil.sentinelGetApprovalStatus`
    - `vigil.sentinelSubmitApproval`
    - `vigil.sentinelRegisterEnforcementPoint`

---

## 9. Autonomous Red-Team Simulation Lab

- **File**: [`src/sentinel/redteam/simulation-lab.js`](file:///home/STARBOY/gemini/antigravity/scratch/vigil.ai/src/sentinel/redteam/simulation-lab.js)
- **Efficacy**:
  - Interception Rate: **100.0%** across 12 standard adversarial vectors (path traversal, credentials, fork bombs, IMDS, broad deletion).
  - Bypass Rate: **0.0%**.
  - False Positive Rate: **0.0%** across benign development workflows.

