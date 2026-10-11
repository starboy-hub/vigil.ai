use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdeProxyStats {
    pub is_running: bool,
    pub port: u16,
    pub requests_inspected: u64,
    pub leaks_blocked: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentTokenAccount {
    pub agent_id: String,
    pub session_tokens: u64,
    pub daily_tokens: u64,
    pub last_reset_timestamp: u64,
    pub total_requests: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenBudgetConfig {
    pub session_limit: u64,
    pub daily_limit: u64,
    pub enforcement_mode: String, // "hard_block" | "soft_alert"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenBudgetVerdict {
    pub allowed: bool,
    pub hard_blocked: bool,
    pub soft_alert: bool,
    pub agent_id: String,
    pub added_tokens: u64,
    pub session_tokens: u64,
    pub session_limit: u64,
    pub daily_tokens: u64,
    pub daily_limit: u64,
    pub enforcement_mode: String,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct TokenBudgetEngine {
    pub config: Arc<Mutex<TokenBudgetConfig>>,
    pub accounts: Arc<Mutex<HashMap<String, AgentTokenAccount>>>,
}

impl Default for TokenBudgetEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenBudgetEngine {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(TokenBudgetConfig {
                session_limit: 50_000,
                daily_limit: 200_000,
                enforcement_mode: "hard_block".to_string(),
            })),
            accounts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn record_usage(&self, agent_id: &str, tokens: u64) -> TokenBudgetVerdict {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let config = self.config.lock().unwrap().clone();
        let mut accounts = self.accounts.lock().unwrap();

        let account = accounts.entry(agent_id.to_string()).or_insert_with(|| AgentTokenAccount {
            agent_id: agent_id.to_string(),
            session_tokens: 0,
            daily_tokens: 0,
            last_reset_timestamp: now,
            total_requests: 0,
        });

        // 24h daily rollover
        if now.saturating_sub(account.last_reset_timestamp) >= 86_400 {
            account.daily_tokens = 0;
            account.last_reset_timestamp = now;
        }

        let new_session = account.session_tokens + tokens;
        let new_daily = account.daily_tokens + tokens;

        let session_exceeded = new_session > config.session_limit;
        let daily_exceeded = new_daily > config.daily_limit;
        let budget_exceeded = session_exceeded || daily_exceeded;

        let hard_blocked = budget_exceeded && config.enforcement_mode == "hard_block";
        let soft_alert = budget_exceeded && config.enforcement_mode == "soft_alert";

        if !hard_blocked {
            account.session_tokens = new_session;
            account.daily_tokens = new_daily;
            account.total_requests += 1;
        }

        let reason = if session_exceeded {
            Some(format!("Session token limit exceeded ({} > {})", new_session, config.session_limit))
        } else if daily_exceeded {
            Some(format!("Daily token limit exceeded ({} > {})", new_daily, config.daily_limit))
        } else {
            None
        };

        TokenBudgetVerdict {
            allowed: !hard_blocked,
            hard_blocked,
            soft_alert,
            agent_id: agent_id.to_string(),
            added_tokens: tokens,
            session_tokens: account.session_tokens,
            session_limit: config.session_limit,
            daily_tokens: account.daily_tokens,
            daily_limit: config.daily_limit,
            enforcement_mode: config.enforcement_mode,
            reason,
        }
    }

    pub fn set_limits(&self, session_limit: Option<u64>, daily_limit: Option<u64>, mode: Option<String>) -> TokenBudgetConfig {
        let mut cfg = self.config.lock().unwrap();
        if let Some(s) = session_limit { cfg.session_limit = s; }
        if let Some(d) = daily_limit { cfg.daily_limit = d; }
        if let Some(m) = mode {
            // Strict mode validation: an unrecognized value previously left
            // enforcement enabled in name only (silently bypassing blocking).
            if m == "hard_block" || m == "soft_alert" {
                cfg.enforcement_mode = m;
            }
        }
        cfg.clone()
    }

    pub fn reset_agent(&self, agent_id: &str) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(acc) = accounts.get_mut(agent_id) {
            // A reset covers both quota windows and starts a fresh daily cycle
            acc.session_tokens = 0;
            acc.daily_tokens = 0;
            acc.last_reset_timestamp = now;
            true
        } else {
            false
        }
    }

    pub fn get_status(&self, agent_id: Option<&str>) -> serde_json::Value {
        let cfg = self.config.lock().unwrap().clone();
        let accounts = self.accounts.lock().unwrap().clone();
        if let Some(id) = agent_id {
            let acc = accounts.get(id).cloned().unwrap_or_else(|| AgentTokenAccount {
                agent_id: id.to_string(),
                session_tokens: 0,
                daily_tokens: 0,
                last_reset_timestamp: 0,
                total_requests: 0,
            });
            serde_json::json!({
                "config": cfg,
                "account": acc
            })
        } else {
            serde_json::json!({
                "config": cfg,
                "accounts": accounts
            })
        }
    }
}

#[derive(Clone)]
pub struct IdeProxyEngine {
    pub port: u16,
    pub is_running: bool,
    pub requests_inspected: Arc<AtomicU64>,
    pub leaks_blocked: Arc<AtomicU64>,
    pub token_budget: TokenBudgetEngine,
}

impl IdeProxyEngine {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            is_running: false,
            requests_inspected: Arc::new(AtomicU64::new(0)),
            leaks_blocked: Arc::new(AtomicU64::new(0)),
            token_budget: TokenBudgetEngine::new(),
        }
    }

    /// Inspects outbound prompt text from native developer IDEs (Cursor, Copilot, Ollama)
    pub fn inspect_prompt(&self, prompt: &str) -> (String, bool, Vec<String>) {
        self.requests_inspected.fetch_add(1, Ordering::SeqCst);
        let mut sanitized = prompt.to_string();
        let mut detected_types = Vec::new();
        let mut has_leak = false;

lazy_static::lazy_static! {
    static ref RE_AWS: regex::Regex = regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref RE_GH: regex::Regex = regex::Regex::new(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,}").unwrap();
    static ref RE_API: regex::Regex = regex::Regex::new(r"sk-[a-zA-Z0-9_-]{20,}").unwrap();
    static ref RE_PRIVATE_KEY: regex::Regex = regex::Regex::new(
        r"-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----"
    ).unwrap();
}

        // AWS Access Key ID
        if prompt.contains("AKIA") && RE_AWS.is_match(&sanitized) {
            sanitized = RE_AWS.replace_all(&sanitized, "[VIGIL-AWS-KEY-REDACTED]").to_string();
            detected_types.push("AWS_KEY".to_string());
            has_leak = true;
        }

        // GitHub Personal Access Token (Classic & Fine-Grained)
        if (prompt.contains("ghp_") || prompt.contains("github_pat_")) && RE_GH.is_match(&sanitized) {
            sanitized = RE_GH.replace_all(&sanitized, "[VIGIL-GITHUB-PAT-REDACTED]").to_string();
            detected_types.push("GITHUB_PAT".to_string());
            has_leak = true;
        }

        // OpenAI / Anthropic API Key
        if prompt.contains("sk-") && RE_API.is_match(&sanitized) {
            sanitized = RE_API.replace_all(&sanitized, "[VIGIL-API-KEY-REDACTED]").to_string();
            detected_types.push("AI_API_KEY".to_string());
            has_leak = true;
        }

        // Private RSA / SSH / EC / PKCS#8 Keys
        if prompt.contains("PRIVATE KEY") && RE_PRIVATE_KEY.is_match(&sanitized) {
            sanitized = RE_PRIVATE_KEY.replace_all(&sanitized, "[VIGIL-PRIVATE-KEY-REDACTED]").to_string();
            detected_types.push("PRIVATE_KEY".to_string());
            has_leak = true;
        }

        if has_leak {
            self.leaks_blocked.fetch_add(1, Ordering::SeqCst);
        }

        // Account token usage in TokenBudgetEngine
        let estimated_tokens = (prompt.len() / 4).max(1) as u64;
        self.token_budget.record_usage("default_ide", estimated_tokens);

        (sanitized, has_leak, detected_types)
    }

    pub fn get_stats(&self) -> IdeProxyStats {
        IdeProxyStats {
            is_running: self.is_running,
            port: self.port,
            requests_inspected: this_val(&self.requests_inspected),
            leaks_blocked: this_val(&self.leaks_blocked),
        }
    }
}

fn this_val(atomic: &AtomicU64) -> u64 {
    atomic.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_prompt_redacts_classic_and_fine_grained_github_pats() {
        let engine = IdeProxyEngine::new(8383);

        // Classic PAT
        let (sanitized_classic, has_leak1, types1) = engine.inspect_prompt("my token is ghp_111122223333444455556666777788889999 for deployment");
        assert!(has_leak1);
        assert!(types1.contains(&"GITHUB_PAT".to_string()));
        assert_eq!(sanitized_classic, "my token is [VIGIL-GITHUB-PAT-REDACTED] for deployment");

        // Fine-grained PAT
        let (sanitized_fg, has_leak2, types2) = engine.inspect_prompt("pushing using github_pat_11A1B2C3D4E5F6G7H8I9J0_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 to main");
        assert!(has_leak2);
        assert!(types2.contains(&"GITHUB_PAT".to_string()));
        assert_eq!(sanitized_fg, "pushing using [VIGIL-GITHUB-PAT-REDACTED] to main");
    }

    #[test]
    fn test_inspect_prompt_redacts_private_keys_rsa_and_pkcs8() {
        let engine = IdeProxyEngine::new(8383);

        // RSA private key
        let rsa_key = "deploy key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----END RSA PRIVATE KEY-----\nfor server";
        let (sanitized_rsa, has_leak_rsa, types_rsa) = engine.inspect_prompt(rsa_key);
        assert!(has_leak_rsa);
        assert!(types_rsa.contains(&"PRIVATE_KEY".to_string()));
        assert_eq!(sanitized_rsa, "deploy key:\n[VIGIL-PRIVATE-KEY-REDACTED]\nfor server");

        // PKCS#8 private key
        let pkcs8_key = "my secret:\n-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n-----END PRIVATE KEY-----";
        let (sanitized_pk8, has_leak_pk8, types_pk8) = engine.inspect_prompt(pkcs8_key);
        assert!(has_leak_pk8);
        assert!(types_pk8.contains(&"PRIVATE_KEY".to_string()));
        assert_eq!(sanitized_pk8, "my secret:\n[VIGIL-PRIVATE-KEY-REDACTED]");
    }
}
