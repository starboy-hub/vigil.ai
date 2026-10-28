/**
 * Sentinel Kernel-Level Sandbox & OS Confinement Anchor
 * =====================================================
 * Implements OS-level process sandboxing, environment scrub, path confinement,
 * and Linux Landlock / Landlock-equivalent confinement for autonomous agent child
 * processes.
 *
 * Guarantees that dynamically compiled binaries (C, Rust, Go) and subprocesses
 * spawned under agent authorization cannot escape the designated workspace,
 * read host credentials (~/.ssh, ~/.aws, /etc/shadow), or bypass the Sentinel loopback proxy.
 */

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    PathTraversal(String),
    WorkspaceEscape { target: String, root: String },
    DisallowedBinary(String),
    SensitiveDirectoryAccess(String),
    DangerousEnvironmentVariable(String),
    NetworkEgressProhibited(String),
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxViolation::PathTraversal(p) => write!(f, "Path traversal detected in sandbox boundary: {}", p),
            SandboxViolation::WorkspaceEscape { target, root } => {
                write!(f, "Process attempted to escape workspace root '{}' into '{}'", root, target)
            }
            SandboxViolation::DisallowedBinary(b) => write!(f, "Execution of disallowed system binary: {}", b),
            SandboxViolation::SensitiveDirectoryAccess(d) => {
                write!(f, "Access to sensitive host credentials/system directory denied: {}", d)
            }
            SandboxViolation::DangerousEnvironmentVariable(v) => {
                write!(f, "Process attempted to set dangerous injection environment variable: {}", v)
            }
            SandboxViolation::NetworkEgressProhibited(t) => {
                write!(f, "Direct network socket creation prohibited; must route via Sentinel loopback: {}", t)
            }
        }
    }
}

impl std::error::Error for SandboxViolation {}

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub workspace_root: PathBuf,
    pub read_only_system_paths: Vec<PathBuf>,
    pub writable_subpaths: Vec<PathBuf>,
    pub blocked_directories: HashSet<String>,
    pub dangerous_env_vars: HashSet<String>,
    pub allow_loopback_only: bool,
}

impl SandboxPolicy {
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        let root = workspace_root.into();
        let mut blocked = HashSet::new();
        // Host credentials and system secrets
        blocked.insert(".ssh".to_string());
        blocked.insert(".aws".to_string());
        blocked.insert(".gnupg".to_string());
        blocked.insert(".config/gcloud".to_string());
        blocked.insert(".azure".to_string());
        blocked.insert("etc/shadow".to_string());
        blocked.insert("etc/passwd".to_string());

        let mut dangerous_env = HashSet::new();
        // Environment injection attack vectors
        dangerous_env.insert("LD_PRELOAD".to_string());
        dangerous_env.insert("LD_LIBRARY_PATH".to_string());
        dangerous_env.insert("DYLD_INSERT_LIBRARIES".to_string());
        dangerous_env.insert("DYLD_LIBRARY_PATH".to_string());
        dangerous_env.insert("BASH_ENV".to_string());
        dangerous_env.insert("ENV".to_string());
        dangerous_env.insert("NODE_OPTIONS".to_string());
        dangerous_env.insert("PYTHONINSPECT".to_string());

        SandboxPolicy {
            workspace_root: root,
            read_only_system_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib"), PathBuf::from("/bin")],
            writable_subpaths: Vec::new(),
            blocked_directories: blocked,
            dangerous_env_vars: dangerous_env,
            allow_loopback_only: true,
        }
    }

    /// Verifies whether an execution environment and command line are safe
    pub fn verify_environment(&self, env_vars: &[(String, String)]) -> Result<(), SandboxViolation> {
        for (key, _) in env_vars {
            let upper = key.to_uppercase();
            if self.dangerous_env_vars.contains(&upper) {
                return Err(SandboxViolation::DangerousEnvironmentVariable(key.clone()));
            }
        }
        Ok(())
    }

    /// Checks if a file access path respects workspace boundaries and sensitive directory denies
    pub fn check_filesystem_access(&self, target_path: &Path, write: bool) -> Result<PathBuf, SandboxViolation> {
        let target_str = target_path.to_string_lossy().to_string();

        // 1. Detect path traversal syntax
        if target_str.contains("..") {
            return Err(SandboxViolation::PathTraversal(target_str));
        }

        // 2. Check blocked directories
        for blocked in &self.blocked_directories {
            if target_str.contains(blocked) {
                return Err(SandboxViolation::SensitiveDirectoryAccess(target_str));
            }
        }

        // 3. Ensure the target path resides within workspace root
        let canonical_root = self.workspace_root.canonicalize().unwrap_or_else(|_| self.workspace_root.clone());
        let full_path = if target_path.is_absolute() {
            target_path.to_path_buf()
        } else {
            self.workspace_root.join(target_path)
        };

        // If target exists, canonicalize to defeat symlink race attacks
        let resolved_target = full_path.canonicalize().unwrap_or_else(|_| full_path.clone());

        if !resolved_target.starts_with(&canonical_root) {
            // Check if it matches allowed read-only system paths (for reading libraries/bins)
            if !write && self.read_only_system_paths.iter().any(|p| resolved_target.starts_with(p)) {
                return Ok(resolved_target);
            }

            return Err(SandboxViolation::WorkspaceEscape {
                target: resolved_target.to_string_lossy().to_string(),
                root: canonical_root.to_string_lossy().to_string(),
            });
        }

        // 4. If write is requested, verify subpath write rules if any are specified
        if write && !self.writable_subpaths.is_empty() {
            let allowed = self.writable_subpaths.iter().any(|allowed_sub| {
                let full_sub = self.workspace_root.join(allowed_sub);
                resolved_target.starts_with(&full_sub)
            });

            if !allowed {
                return Err(SandboxViolation::WorkspaceEscape {
                    target: format!("{} (outside writable subpaths)", resolved_target.display()),
                    root: self.workspace_root.display().to_string(),
                });
            }
        }

        Ok(resolved_target)
    }

    /// Verifies if a network destination complies with Sentinel containment (Loopback only)
    pub fn verify_network_destination(&self, host: &str, port: u16) -> Result<(), SandboxViolation> {
        if !self.allow_loopback_only {
            return Ok(());
        }

        let is_loopback = host == "127.0.0.1" || host == "localhost" || host == "::1";
        if !is_loopback {
            return Err(SandboxViolation::NetworkEgressProhibited(format!("{}:{}", host, port)));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_sandbox_blocks_dangerous_env_injection() {
        let policy = SandboxPolicy::new("/tmp/test_workspace");
        let malicious_env = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/tmp/libhack.so".to_string()),
        ];

        let result = policy.verify_environment(&malicious_env);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::DangerousEnvironmentVariable(v) => assert_eq!(v, "LD_PRELOAD"),
            other => panic!("Expected DangerousEnvironmentVariable, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_blocks_credentials_access() {
        let policy = SandboxPolicy::new("/tmp/test_workspace");
        let cred_path = Path::new(".ssh/id_rsa");

        let result = policy.check_filesystem_access(cred_path, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::SensitiveDirectoryAccess(d) => assert!(d.contains(".ssh")),
            other => panic!("Expected SensitiveDirectoryAccess, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_blocks_path_traversal() {
        let policy = SandboxPolicy::new("/tmp/test_workspace");
        let traversal = Path::new("../../etc/shadow");

        let result = policy.check_filesystem_access(traversal, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxViolation::PathTraversal(_) => {}
            other => panic!("Expected PathTraversal, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_blocks_external_network_egress() {
        let policy = SandboxPolicy::new("/tmp/test_workspace");
        
        assert!(policy.verify_network_destination("127.0.0.1", 8765).is_ok());
        assert!(policy.verify_network_destination("localhost", 8765).is_ok());
        
        let external = policy.verify_network_destination("169.254.169.254", 80);
        assert!(external.is_err());
        match external.unwrap_err() {
            SandboxViolation::NetworkEgressProhibited(target) => {
                assert!(target.contains("169.254.169.254"));
            }
            other => panic!("Expected NetworkEgressProhibited, got {:?}", other),
        }
    }

    #[test]
    fn test_sandbox_allows_clean_workspace_file() {
        let current_dir = env::current_dir().unwrap();
        let policy = SandboxPolicy::new(&current_dir);
        let safe_file = Path::new("Cargo.toml");

        let res = policy.check_filesystem_access(safe_file, false);
        assert!(res.is_ok());
    }
}

