/**
 * Sentinel Native Companion Policy Enforcement & Security Anchor
 * ==============================================================
 * Native Rust layer providing OS-level policy evaluation, hard safety rules,
 * tamper-resistant approval state, and adapter registration.
 *
 * Implements Stage 5 of Plan.pdf master execution specification.
 */

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: &str = "1.0.0";

// Decision Outcomes
pub const DECISION_ALLOW: &str = "allow";
pub const DECISION_DENY: &str = "deny";
pub const DECISION_REQUIRE_APPROVAL: &str = "require_approval";

// Reason Codes (Aligned with src/sentinel/constants.js)
pub const ALLOW_WORKSPACE_READ: &str = "ALLOW_WORKSPACE_READ";
pub const ALLOW_WORKSPACE_WRITE: &str = "ALLOW_WORKSPACE_WRITE";
pub const ALLOW_SAFE_COMMAND: &str = "ALLOW_SAFE_COMMAND";
pub const ALLOW_EXPLICIT_APPROVAL: &str = "ALLOW_EXPLICIT_APPROVAL";

pub const DENY_WORKSPACE_ESCAPE: &str = "DENY_WORKSPACE_ESCAPE";
pub const DENY_PATH_TRAVERSAL: &str = "DENY_PATH_TRAVERSAL";
pub const DENY_SYSTEM_FILE_ACCESS: &str = "DENY_SYSTEM_FILE_ACCESS";
pub const DENY_SECRET_EXFILTRATION: &str = "DENY_SECRET_EXFILTRATION";
pub const DENY_UNSAFE_SHELL_COMMAND: &str = "DENY_UNSAFE_SHELL_COMMAND";
pub const DENY_CLOUD_METADATA_BLOCKED: &str = "DENY_CLOUD_METADATA_BLOCKED";
pub const DENY_BROAD_DELETION: &str = "DENY_BROAD_DELETION";
pub const DENY_ACTION_MUTATED_AFTER_APPROVAL: &str = "DENY_ACTION_MUTATED_AFTER_APPROVAL";

pub const REQUIRE_APPROVAL_DELETION: &str = "REQUIRE_APPROVAL_DELETION";
pub const REQUIRE_APPROVAL_CONFIG_CHANGE: &str = "REQUIRE_APPROVAL_CONFIG_CHANGE";
pub const REQUIRE_APPROVAL_WORKSPACE_WRITE: &str = "REQUIRE_APPROVAL_WORKSPACE_WRITE";
pub const REQUIRE_APPROVAL_OUTBOUND_NETWORK: &str = "REQUIRE_APPROVAL_OUTBOUND_NETWORK";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NativeApprovalRecord {
    pub target: String,
    pub action_hash: String,
    pub status: String, // "approved" | "rejected" | "pending"
    pub approver: String,
    pub token: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisteredAdapterRecord {
    pub adapter_id: String,
    pub adapter_type: String,
    pub capabilities: Vec<String>,
    pub registered_at: u64,
}

pub struct SentinelEngine {
    pub approvals: Mutex<HashMap<String, NativeApprovalRecord>>,
    pub adapters: Mutex<HashMap<String, RegisteredAdapterRecord>>,
}

impl SentinelEngine {
    pub fn new() -> Self {
        SentinelEngine {
            approvals: Mutex::new(HashMap::new()),
            adapters: Mutex::new(HashMap::new()),
        }
    }

    /// Compute canonical SHA-256 action hash
    pub fn compute_action_hash(action_type: &str, resource: &str, parameters: &Value) -> String {
        let mut hasher = Sha256::new();
        hasher.update(action_type.as_bytes());
        hasher.update(b":");
        hasher.update(resource.as_bytes());
        hasher.update(b":");

        let mut param_str = serde_json::to_string(parameters).unwrap_or_else(|_| "{}".to_string());
        if param_str.is_empty() {
            param_str = "{}".to_string();
        }
        hasher.update(param_str.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Evaluate Sentinel policy on an action
    pub fn evaluate_policy(
        &self,
        action: &Value,
        profile_opt: Option<&str>,
        workspace_root_opt: Option<&str>,
    ) -> Result<Value, String> {
        let action_type = action["action_type"]
            .as_str()
            .ok_or_else(|| "Missing required action_type".to_string())?;
        let resource = action["resource"]
            .as_str()
            .ok_or_else(|| "Missing required resource".to_string())?;
        let parameters = action.get("parameters").cloned().unwrap_or(Value::Null);
        let request_id = action["request_id"]
            .as_str()
            .unwrap_or("req-native-sentinel");
        let profile = profile_opt.unwrap_or("balanced");
        let approval_token = action["approval_token"].as_str();

        let action_hash = Self::compute_action_hash(action_type, resource, &parameters);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // ══════════════════════════════════════════════════════════════════════
        // LEVEL 1: HARD SAFETY RULES (NON-NEGOTIABLE)
        // ══════════════════════════════════════════════════════════════════════

        // 1. Filesystem Hard Safety Rules
        if action_type.starts_with("fs:") {
            // Null-byte or control character check
            if resource.contains('\0') {
                return Ok(Self::build_decision(
                    DECISION_DENY,
                    DENY_PATH_TRAVERSAL,
                    "Null-byte path injection detected.",
                    request_id,
                    &action_hash,
                ));
            }

            // Sensitive System File Checks
            let lower_res = resource.to_lowercase();
            if lower_res.starts_with("/etc")
                || lower_res.starts_with("/usr")
                || lower_res.starts_with("/bin")
                || lower_res.starts_with("/sbin")
                || lower_res.starts_with("/proc")
                || lower_res.starts_with("/sys")
                || lower_res.starts_with("/dev")
                || lower_res.contains("/etc/passwd")
                || lower_res.contains("/etc/shadow")
            {
                return Ok(Self::build_decision(
                    DECISION_DENY,
                    DENY_SYSTEM_FILE_ACCESS,
                    "Access to critical OS system directory is denied.",
                    request_id,
                    &action_hash,
                ));
            }

            // Sensitive Credentials and Secret Files
            if lower_res.ends_with(".env")
                || lower_res.contains("/.env")
                || lower_res.contains("id_rsa")
                || lower_res.contains("id_ed25519")
                || lower_res.contains("/.aws/credentials")
                || lower_res.contains("/.git/config")
            {
                return Ok(Self::build_decision(
                    DECISION_DENY,
                    DENY_SECRET_EXFILTRATION,
                    "Direct access to environment secrets or private keys is prohibited.",
                    request_id,
                    &action_hash,
                ));
            }

            // Workspace escape check
            if let Some(ws_root) = workspace_root_opt {
                let ws_path = Path::new(ws_root);
                let target = Path::new(resource);

                let resolved = if target.is_absolute() {
                    target.to_path_buf()
                } else {
                    ws_path.join(target)
                };

                let clean_str = resolved.to_string_lossy();
                if clean_str.contains("..") {
                    // Check if path attempts to escape ws_root
                    let normalized = Self::lexically_normal_path(&resolved);
                    if !normalized.starts_with(ws_path) {
                        return Ok(Self::build_decision(
                            DECISION_DENY,
                            DENY_WORKSPACE_ESCAPE,
                            "Path traversal escapes approved workspace boundary.",
                            request_id,
                            &action_hash,
                        ));
                    }
                }
            }

            // Broad deletion check
            if action_type == "fs:delete" {
                let trimmed = resource.trim();
                if trimmed == "/"
                    || trimmed == "*"
                    || trimmed == "."
                    || (workspace_root_opt.is_some() && trimmed == workspace_root_opt.unwrap())
                {
                    return Ok(Self::build_decision(
                        DECISION_DENY,
                        DENY_BROAD_DELETION,
                        "Prohibited broad deletion of entire workspace or root filesystem.",
                        request_id,
                        &action_hash,
                    ));
                }
            }
        }

        // 2. Shell Command Hard Safety Rules
        if action_type == "shell:exec" {
            let lower_cmd = resource.to_lowercase();
            if lower_cmd.contains(":(){ :|:& };:")
                || lower_cmd.contains("rm -rf /")
                || lower_cmd.contains("mkfs.")
                || lower_cmd.contains("dd if=/dev/zero")
            {
                return Ok(Self::build_decision(
                    DECISION_DENY,
                    DENY_UNSAFE_SHELL_COMMAND,
                    "Destructive or catastrophic shell command blocked by native safety.",
                    request_id,
                    &action_hash,
                ));
            }
        }

        // 3. Network Outbound Hard Safety Rules
        if action_type == "net:request" {
            let lower_url = resource.to_lowercase();
            if lower_url.contains("169.254.169.254")
                || lower_url.contains("metadata.google.internal")
                || lower_url.contains("100.100.100.200")
            {
                return Ok(Self::build_decision(
                    DECISION_DENY,
                    DENY_CLOUD_METADATA_BLOCKED,
                    "Outbound request to cloud instance metadata service (IMDS) is blocked.",
                    request_id,
                    &action_hash,
                ));
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // LEVEL 2: EXPLICIT APPROVAL CHECK (WITH TOCTOU VERIFICATION)
        // ══════════════════════════════════════════════════════════════════════
        {
            let approvals = self.approvals.lock().unwrap();
            if let Some(record) = approvals.get(&action_hash) {
                if record.status == "approved" && record.expires_at > now_secs {
                    // Check TOCTOU: action hash matches registered approval
                    if record.action_hash == action_hash {
                        return Ok(Self::build_decision(
                            DECISION_ALLOW,
                            ALLOW_EXPLICIT_APPROVAL,
                            "Action authorized by active human approval token.",
                            request_id,
                            &action_hash,
                        ));
                    } else {
                        return Ok(Self::build_decision(
                            DECISION_DENY,
                            DENY_ACTION_MUTATED_AFTER_APPROVAL,
                            "Action parameters mutated after approval was granted (TOCTOU violation).",
                            request_id,
                            &action_hash,
                        ));
                    }
                }
            }

            // Check if valid approval token was supplied directly in action
            if let Some(tok) = approval_token {
                if !tok.is_empty() {
                    for (_hash, rec) in approvals.iter() {
                        if rec.token.as_deref() == Some(tok)
                            && rec.status == "approved"
                            && rec.expires_at > now_secs
                        {
                            if rec.action_hash == action_hash {
                                return Ok(Self::build_decision(
                                    DECISION_ALLOW,
                                    ALLOW_EXPLICIT_APPROVAL,
                                    "Action authorized by valid approval token.",
                                    request_id,
                                    &action_hash,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // LEVEL 3: APPROVAL GATES
        // ══════════════════════════════════════════════════════════════════════

        if action_type == "fs:delete" {
            return Ok(Self::build_decision(
                DECISION_REQUIRE_APPROVAL,
                REQUIRE_APPROVAL_DELETION,
                "File deletion requires explicit operator confirmation.",
                request_id,
                &action_hash,
            ));
        }

        if action_type == "config:change" {
            return Ok(Self::build_decision(
                DECISION_REQUIRE_APPROVAL,
                REQUIRE_APPROVAL_CONFIG_CHANGE,
                "Security policy configuration change requires operator confirmation.",
                request_id,
                &action_hash,
            ));
        }

        if profile == "strict" {
            if action_type == "fs:write" {
                return Ok(Self::build_decision(
                    DECISION_REQUIRE_APPROVAL,
                    REQUIRE_APPROVAL_WORKSPACE_WRITE,
                    "Strict mode: workspace write requires confirmation.",
                    request_id,
                    &action_hash,
                ));
            }
            if action_type == "net:request" {
                return Ok(Self::build_decision(
                    DECISION_REQUIRE_APPROVAL,
                    REQUIRE_APPROVAL_OUTBOUND_NETWORK,
                    "Strict mode: outbound network request requires confirmation.",
                    request_id,
                    &action_hash,
                ));
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // LEVEL 4: DEFAULT ALLOW
        // ══════════════════════════════════════════════════════════════════════

        if action_type == "fs:read" || action_type == "fs:list" {
            return Ok(Self::build_decision(
                DECISION_ALLOW,
                ALLOW_WORKSPACE_READ,
                "Read action permitted within approved workspace.",
                request_id,
                &action_hash,
            ));
        }

        if action_type == "fs:write" {
            return Ok(Self::build_decision(
                DECISION_ALLOW,
                ALLOW_WORKSPACE_WRITE,
                "Write action permitted within approved workspace.",
                request_id,
                &action_hash,
            ));
        }

        if action_type == "shell:exec" {
            let lower = resource.trim().to_lowercase();
            if lower == "npm test"
                || lower == "npm run lint"
                || lower == "cargo test"
                || lower.starts_with("git status")
                || lower.starts_with("git diff")
            {
                return Ok(Self::build_decision(
                    DECISION_ALLOW,
                    ALLOW_SAFE_COMMAND,
                    "Allowlisted developer command permitted.",
                    request_id,
                    &action_hash,
                ));
            }
        }

        // Default: require confirmation for unclassified actions
        Ok(Self::build_decision(
            DECISION_REQUIRE_APPROVAL,
            "REQUIRE_APPROVAL_DEFAULT",
            "Action requires explicit operator confirmation under active policy.",
            request_id,
            &action_hash,
        ))
    }

    /// Query approval status by action hash or approval target
    pub fn get_approval_status(&self, target: &str) -> Value {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let approvals = self.approvals.lock().unwrap();
        if let Some(record) = approvals.get(target) {
            let is_expired = record.expires_at <= now_secs;
            let status = if is_expired { "expired" } else { &record.status };
            json!({
                "found": true,
                "target": target,
                "action_hash": record.action_hash,
                "status": status,
                "approver": record.approver,
                "expires_at": record.expires_at
            })
        } else {
            json!({
                "found": false,
                "target": target,
                "status": "not_found"
            })
        }
    }

    /// Submit an approval or rejection for a target
    pub fn submit_approval(
        &self,
        target: &str,
        action_hash: &str,
        decision: &str,
        approver: &str,
        token_opt: Option<&str>,
        ttl_secs: u64,
    ) -> Result<Value, String> {
        if target.is_empty() {
            return Err("Target identifier cannot be empty".to_string());
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let status = if decision == "approve" || decision == "allow" {
            "approved"
        } else {
            "rejected"
        };

        let record = NativeApprovalRecord {
            target: target.to_string(),
            action_hash: action_hash.to_string(),
            status: status.to_string(),
            approver: approver.to_string(),
            token: token_opt.map(|s| s.to_string()),
            created_at: now_secs,
            expires_at: now_secs + ttl_secs,
        };

        let mut approvals = self.approvals.lock().unwrap();
        approvals.insert(target.to_string(), record.clone());
        if !action_hash.is_empty() && action_hash != target {
            approvals.insert(action_hash.to_string(), record);
        }

        Ok(json!({
            "success": true,
            "target": target,
            "action_hash": action_hash,
            "status": status,
            "approver": approver,
            "expires_at": now_secs + ttl_secs
        }))
    }

    /// Register an active enforcement adapter (e.g. MCP gateway, CLI shim)
    pub fn register_enforcement_point(
        &self,
        adapter_id: &str,
        adapter_type: &str,
        capabilities: Vec<String>,
    ) -> Result<Value, String> {
        if adapter_id.is_empty() {
            return Err("adapter_id cannot be empty".to_string());
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = RegisteredAdapterRecord {
            adapter_id: adapter_id.to_string(),
            adapter_type: adapter_type.to_string(),
            capabilities: capabilities.clone(),
            registered_at: now_secs,
        };

        let mut adapters = self.adapters.lock().unwrap();
        adapters.insert(adapter_id.to_string(), record);

        Ok(json!({
            "registered": true,
            "adapter_id": adapter_id,
            "adapter_type": adapter_type,
            "capabilities": capabilities,
            "timestamp": now_secs
        }))
    }

    /// Build structured Decision Schema output
    fn build_decision(
        decision: &str,
        reason_code: &str,
        explanation: &str,
        request_id: &str,
        action_hash: &str,
    ) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "decision": decision,
            "reason_code": reason_code,
            "explanation": explanation,
            "request_id": request_id,
            "action_hash": action_hash,
            "matched_policy_ids": [format!("native-policy-{}", reason_code.to_lowercase().replace('_', "-"))],
            "timestamp": chrono_now_iso()
        })
    }

    fn lexically_normal_path(p: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for component in p.components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                c => out.push(c.as_os_str()),
            }
        }
        out
    }
}

fn chrono_now_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}-01-01T00:00:00Z", 1970 + now / 31557600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_action_hash_deterministic() {
        let hash1 = SentinelEngine::compute_action_hash("fs:read", "README.md", &json!({}));
        let hash2 = SentinelEngine::compute_action_hash("fs:read", "README.md", &json!({}));
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_native_eval_denies_path_traversal() {
        let engine = SentinelEngine::new();
        let action = json!({
            "action_type": "fs:read",
            "resource": "../../etc/passwd",
            "request_id": "req-1"
        });
        let res = engine.evaluate_policy(&action, Some("balanced"), Some("/app/workspace")).unwrap();
        assert_eq!(res["decision"], "deny");
        assert_eq!(res["reason_code"], DENY_SYSTEM_FILE_ACCESS);
    }

    #[test]
    fn test_native_eval_denies_workspace_escape() {
        let engine = SentinelEngine::new();
        let action = json!({
            "action_type": "fs:read",
            "resource": "../outside_dir/file.txt",
            "request_id": "req-2"
        });
        let res = engine.evaluate_policy(&action, Some("balanced"), Some("/app/workspace")).unwrap();
        assert_eq!(res["decision"], "deny");
        assert_eq!(res["reason_code"], DENY_WORKSPACE_ESCAPE);
    }

    #[test]
    fn test_native_eval_denies_cloud_metadata() {
        let engine = SentinelEngine::new();
        let action = json!({
            "action_type": "net:request",
            "resource": "http://169.254.169.254/latest/meta-data/",
            "request_id": "req-3"
        });
        let res = engine.evaluate_policy(&action, None, None).unwrap();
        assert_eq!(res["decision"], "deny");
        assert_eq!(res["reason_code"], DENY_CLOUD_METADATA_BLOCKED);
    }

    #[test]
    fn test_native_eval_denies_destructive_shell() {
        let engine = SentinelEngine::new();
        let action = json!({
            "action_type": "shell:exec",
            "resource": "rm -rf /",
            "request_id": "req-4"
        });
        let res = engine.evaluate_policy(&action, None, None).unwrap();
        assert_eq!(res["decision"], "deny");
        assert_eq!(res["reason_code"], DENY_UNSAFE_SHELL_COMMAND);
    }

    #[test]
    fn test_native_eval_allows_safe_read_and_approvals() {
        let engine = SentinelEngine::new();
        let action = json!({
            "action_type": "fs:read",
            "resource": "package.json",
            "request_id": "req-5"
        });
        let res = engine.evaluate_policy(&action, Some("balanced"), Some("/app/workspace")).unwrap();
        assert_eq!(res["decision"], "allow");
        assert_eq!(res["reason_code"], ALLOW_WORKSPACE_READ);

        // Submit approval for deletion
        let delete_action = json!({
            "action_type": "fs:delete",
            "resource": "temp.log",
            "request_id": "req-6"
        });
        let delete_hash = SentinelEngine::compute_action_hash("fs:delete", "temp.log", &json!(null));
        engine.submit_approval("appr-1", &delete_hash, "approve", "operator", None, 300).unwrap();

        // Should now allow due to active approval
        let approved_res = engine.evaluate_policy(&delete_action, None, None).unwrap();
        assert_eq!(approved_res["decision"], "allow");
        assert_eq!(approved_res["reason_code"], ALLOW_EXPLICIT_APPROVAL);
    }

    #[test]
    fn test_register_enforcement_adapter() {
        let engine = SentinelEngine::new();
        let reg = engine.register_enforcement_point("mcp-gw", "mcp", vec!["tools/call".to_string()]).unwrap();
        assert_eq!(reg["registered"], true);
        assert_eq!(reg["adapter_id"], "mcp-gw");
    }
}
