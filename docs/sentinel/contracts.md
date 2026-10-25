# Sentinel Stage 2: Shared Contracts & Schemas

**Document Version**: 1.0.0  
**Specification**: `Plan.pdf` (Stage 2: Design Contracts Before Implementation)  
**Date**: 2026-10-25  

---

## 1. Overview & Architectural Principles

Before constructing the Sentinel Tool Gateway and Policy Engine, all interfaces must be bound to versioned, strictly validated contracts.

### Core Principles
1. **Never Trust Model-Supplied Data**: Agent IDs, risk ratings, paths, and destinations must be validated at the trust boundary.
2. **Deterministic & Versioned**: Decisions must be reproducible and tied to specific schema and policy versions.
3. **No Secrets in Logs or Explanations**: Human-readable messages must be cleansed of raw credentials, tokens, or private keys.
4. **Time-of-Check to Time-of-Use (TOCTOU) Protection**: Every decision is cryptographically bound via a 64-character SHA-256 canonical action hash (`action_hash`). Any alteration of arguments or targets invalidates the approval.

---

## 2. Action Schema (`schema_version: "1.0.0"`)

Represents a normalized, pre-execution tool invocation proposed by an AI agent.

```json
{
  "schema_version": "1.0.0",
  "request_id": "req-8f4b-4a7b-a2e6-99c1",
  "session_id": "sess-agent-worktree-01",
  "agent_id": "claude-code-subagent",
  "adapter": {
    "id": "sentinel-mcp-gateway",
    "version": "1.0.0",
    "type": "mcp"
  },
  "action_type": "fs:write",
  "resource": "/workspace/src/content/content.js",
  "parameters": {
    "content": "console.log('safe update');",
    "overwrite": true
  },
  "requested_scope": "workspace",
  "timestamp": 1793081400000,
  "expiry": 1793081460000,
  "risk_signals": [
    {
      "id": "heuristic-syntax-clean",
      "level": "low",
      "source": "detection-engine",
      "confidence": 98
    }
  ],
  "correlation_id": "corr-prompt-turn-44",
  "idempotency_key": "idemp-write-content-v1"
}
```

### Action Types
| Action Type | Description | Canonical Resource Format |
| :--- | :--- | :--- |
| `fs:read` | Read file or directory contents | Canonical absolute path (`/path/to/file`) |
| `fs:write` | Create or update file contents | Canonical absolute path (`/path/to/file`) |
| `fs:delete` | Delete file or directory | Canonical absolute path (`/path/to/file`) |
| `fs:list` | List directory contents | Canonical absolute path (`/path/to/dir`) |
| `shell:exec` | Execute terminal command or binary | Normalized command binary and arguments |
| `net:request` | Outbound HTTP/socket connection | Canonical host and port (`host:port`) |
| `secret:access` | Retrieve or use stored credential | Secret identifier / key reference |
| `config:change` | Alter security policy or settings | Target configuration key |

---

## 3. Decision Schema (`schema_version: "1.0.0"`)

The output of the Sentinel Policy Engine before a side effect can occur.

```json
{
  "schema_version": "1.0.0",
  "decision": "allow",
  "reason_code": "ALLOW_WORKSPACE_WRITE",
  "explanation": "Write target resides within allowed repository workspace root.",
  "matched_policy_ids": [
    "rule-workspace-boundary-v1",
    "rule-non-destructive-v1"
  ],
  "policy_version": "1.0.0",
  "request_id": "req-8f4b-4a7b-a2e6-99c1",
  "required_constraints": {
    "max_bytes": 1048576,
    "atomic_write": true
  },
  "decision_expiry": 1793081460000,
  "audit_reference": "audit-ref-7721",
  "action_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Allowed Decision Outcomes
* **`allow`**: The action satisfies policy constraints and may proceed to execution.
* **`deny`**: The action violates policy constraints and is halted before any side effect.
* **`require_approval`**: The action is paused awaiting explicit human confirmation.

---

## 4. Policy Precedence Rules (Section 4.4)

When evaluating multiple rules, Sentinel applies a strict, non-negotiable precedence hierarchy:

```text
┌──────────────────────────────────────────────────────────┐
│ Level 1: Hard Safety Rules (NON-NEGOTIABLE)              │
│ - Path traversal / symlink escaping workspace root = DENY│
│ - System file modification (/etc, ~/.ssh) = DENY         │
│ - Cloud metadata exfiltration (169.254.169.254) = DENY   │
│ - Malformed schema or unknown action type = DENY         │
└──────────────────────────┬───────────────────────────────┘
                           │ If Level 1 passes
                           ▼
┌──────────────────────────────────────────────────────────┐
│ Level 2: Explicit Deny Rules                             │
│ - Blocked file extensions (.env, id_rsa)                 │
│ - Unapproved outbound domains                            │
│ - Quota or token budget exhaustion                       │
└──────────────────────────┬───────────────────────────────┘
                           │ If Level 2 passes
                           ▼
┌──────────────────────────────────────────────────────────┐
│ Level 3: Approval Gates                                  │
│ - Destructive file deletion                              │
│ - Arbitrary shell command execution                      │
│ - Access outside approved workspace                      │
└──────────────────────────┬───────────────────────────────┘
                           │ If Level 3 approved or satisfied
                           ▼
┌──────────────────────────────────────────────────────────┐
│ Level 4: Default Profile Rules (Balanced / Strict)       │
│ - Allow workspace-local reads and writes                 │
└──────────────────────────────────────────────────────────┘
```

> **Invariant**: An approval granted by a user or profile **CANNOT** override Level 1 Hard Safety Rules (e.g. symlink escapes or cloud metadata exfiltration).

---

## 5. Decision Reason-Code Registry

| Reason Code | Decision | Description |
| :--- | :---: | :--- |
| `ALLOW_WORKSPACE_READ` | `allow` | Read path confirmed within workspace root. |
| `ALLOW_WORKSPACE_WRITE` | `allow` | Write target confirmed within workspace root. |
| `ALLOW_SAFE_COMMAND` | `allow` | Command matched explicit safe CLI allowlist. |
| `ALLOW_PERMITTED_DESTINATION` | `allow` | Destination host is on approved network list. |
| `ALLOW_EXPLICIT_APPROVAL` | `allow` | Valid human approval recorded for exact action hash. |
| `DENY_INVALID_SCHEMA` | `deny` | Action payload failed schema validation. |
| `DENY_UNKNOWN_ACTION_TYPE` | `deny` | Unrecognized action type; fail-closed. |
| `DENY_WORKSPACE_ESCAPE` | `deny` | Target path resolves outside approved workspace. |
| `DENY_PATH_TRAVERSAL` | `deny` | Path traversal sequence (`..`) detected. |
| `DENY_SYMLINK_ESCAPE` | `deny` | Symlink points outside allowed workspace root. |
| `DENY_SYSTEM_FILE_ACCESS` | `deny` | Target matches sensitive OS/user directory. |
| `DENY_CLOUD_METADATA_BLOCKED` | `deny` | Outbound request targeted link-local metadata IP. |
| `DENY_UNSAFE_SHELL_COMMAND` | `deny` | Command contains dangerous shell injection syntax. |
| `DENY_BROAD_DELETION` | `deny` | Root or broad recursive deletion attempted. |
| `DENY_SECRET_EXFILTRATION` | `deny` | Payload contains unmasked credentials/keys. |
| `DENY_QUOTA_EXCEEDED` | `deny` | Session or daily token limit exhausted. |
| `DENY_POLICY_TIMEOUT` | `deny` | Policy engine evaluation timed out; fail-closed. |
| `DENY_ACTION_MUTATED_AFTER_APPROVAL` | `deny` | Action hash mismatch detected (TOCTOU guard). |
| `REQUIRE_APPROVAL_WORKSPACE_WRITE`| `require_approval` | Write in strict profile requires confirmation. |
| `REQUIRE_APPROVAL_SHELL_EXEC` | `require_approval` | Shell command requires confirmation. |
| `REQUIRE_APPROVAL_DELETION` | `require_approval` | File deletion requires confirmation. |

---

## 6. TOCTOU & Canonical Action Hashing (Section 4.6)

To prevent time-of-check to time-of-use races:
1. The tool request is normalized into canonical parameters and paths.
2. A cryptographic SHA-256 digest is calculated over the canonical tuple:
   $$\text{ActionHash} = \text{SHA-256}(\text{version} \parallel \text{request\_id} \parallel \text{agent\_id} \parallel \text{action\_type} \parallel \text{canonical\_resource} \parallel \text{sorted\_params})$$
3. When human approval is granted, the approval record stores this exact `ActionHash`.
4. At execution time, the gateway recomputes the hash of the payload about to execute. If even a single byte differs, the gateway returns `DENY_ACTION_MUTATED_AFTER_APPROVAL`.

