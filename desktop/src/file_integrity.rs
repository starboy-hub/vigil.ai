use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    Modified,
    Missing,
    UnauthorizedNew,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TamperedFile {
    pub path: String,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub kind: TamperKind,
    pub size_bytes: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IntegrityReport {
    pub is_valid: bool,
    pub total_files_checked: usize,
    pub passed_count: usize,
    pub tampered_count: usize,
    pub passed_files: Vec<String>,
    pub tampered_files: Vec<TamperedFile>,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RestoreResult {
    pub success: bool,
    pub restored_files: Vec<String>,
    pub failed_files: Vec<String>,
    pub error: Option<String>,
}

pub struct FileIntegrityEngine;

impl FileIntegrityEngine {
    /// Computes the cryptographic SHA-256 digest of a local file
    pub fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 16384];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Recursively collects all files in a directory, calculating their SHA-256
    pub fn generate_manifest(
        dir: &Path,
        ignore_names: &[&str],
    ) -> Result<HashMap<String, String>, std::io::Error> {
        let mut manifest = HashMap::new();
        Self::scan_dir_recursive(dir, dir, ignore_names, &mut manifest)?;
        Ok(manifest)
    }

    fn scan_dir_recursive(
        root: &Path,
        current: &Path,
        ignore_names: &[&str],
        manifest: &mut HashMap<String, String>,
    ) -> Result<(), std::io::Error> {
        if !current.exists() || !current.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if ignore_names.contains(&file_name) || file_name.starts_with('.') {
                continue;
            }

            if path.is_dir() {
                Self::scan_dir_recursive(root, &path, ignore_names, manifest)?;
            } else if path.is_file() {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().to_string();
                    if let Ok(hash) = Self::compute_file_sha256(&path) {
                        manifest.insert(rel_str, hash);
                    }
                }
            }
        }
        Ok(())
    }

    /// Verifies all files in a directory against a reference manifest
    pub fn verify_directory(
        target_dir: &Path,
        expected_manifest: &HashMap<String, String>,
    ) -> IntegrityReport {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut passed_files = Vec::new();
        let mut tampered_files = Vec::new();

        // 1. Check all expected files in manifest
        for (rel_path, expected_hash) in expected_manifest {
            let file_path = target_dir.join(rel_path);

            if !file_path.exists() {
                tampered_files.push(TamperedFile {
                    path: rel_path.clone(),
                    expected_hash: Some(expected_hash.clone()),
                    actual_hash: None,
                    kind: TamperKind::Missing,
                    size_bytes: None,
                });
                continue;
            }

            match Self::compute_file_sha256(&file_path) {
                Ok(actual_hash) => {
                    let size = fs::metadata(&file_path).map(|m| m.len()).ok();
                    if actual_hash.eq_ignore_ascii_case(expected_hash) {
                        passed_files.push(rel_path.clone());
                    } else {
                        tampered_files.push(TamperedFile {
                            path: rel_path.clone(),
                            expected_hash: Some(expected_hash.clone()),
                            actual_hash: Some(actual_hash),
                            kind: TamperKind::Modified,
                            size_bytes: size,
                        });
                    }
                }
                Err(_) => {
                    tampered_files.push(TamperedFile {
                        path: rel_path.clone(),
                        expected_hash: Some(expected_hash.clone()),
                        actual_hash: None,
                        kind: TamperKind::Modified,
                        size_bytes: None,
                    });
                }
            }
        }

        let is_valid = tampered_files.is_empty();

        // 3. Detect files present on disk that the manifest does not know
        // about (TamperKind::UnauthorizedNew) — a planted payload would
        // otherwise be invisible to a manifest-only diff.
        let mut on_disk: HashMap<String, Option<String>> = HashMap::new();
        Self::collect_files_recursive(target_dir, target_dir, &mut on_disk);
        for (rel_path, actual_hash) in &on_disk {
            if !expected_manifest.contains_key(rel_path) {
                tampered_files.push(TamperedFile {
                    path: rel_path.clone(),
                    expected_hash: None,
                    actual_hash: actual_hash.clone(),
                    kind: TamperKind::UnauthorizedNew,
                    size_bytes: fs::metadata(target_dir.join(rel_path)).map(|m| m.len()).ok(),
                });
            }
        }
        let is_valid = is_valid && tampered_files.is_empty();

        let total_checked = passed_files.len() + tampered_files.len();

        IntegrityReport {
            is_valid,
            total_files_checked: total_checked,
            passed_count: passed_files.len(),
            tampered_count: tampered_files.len(),
            passed_files,
            tampered_files,
            timestamp: now,
        }
    }

    /// Collects relative paths (and hashes) for every file under `root`,
    /// skipping hidden entries. Used for unauthorized-new-file detection.
    fn collect_files_recursive(
        root: &Path,
        current: &Path,
        out: &mut HashMap<String, Option<String>>,
    ) {
        if !current.exists() || !current.is_dir() {
            return;
        }
        if let Ok(entries) = fs::read_dir(current) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if file_name.starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    Self::collect_files_recursive(root, &path, out);
                } else if path.is_file() {
                    if let Ok(rel) = path.strip_prefix(root) {
                        let rel_str = rel.to_string_lossy().to_string();
                        let hash = Self::compute_file_sha256(&path).ok();
                        out.insert(rel_str, hash);
                    }
                }
            }
        }
    }

    /// Self-Healing: Restores tampered, corrupted, or missing files from a golden backup directory
    pub fn restore_tampered_files(
        target_dir: &Path,
        backup_dir: &Path,
        files_to_restore: &[String],
    ) -> RestoreResult {
        if !backup_dir.exists() {
            return RestoreResult {
                success: false,
                restored_files: Vec::new(),
                failed_files: files_to_restore.to_vec(),
                error: Some(format!(
                    "Golden backup directory not found at: {}",
                    backup_dir.display()
                )),
            };
        }

        let mut restored = Vec::new();
        let mut failed = Vec::new();

        for rel_path in files_to_restore {
            let backup_file = backup_dir.join(rel_path);
            let target_file = target_dir.join(rel_path);

            if !backup_file.exists() {
                failed.push(rel_path.clone());
                continue;
            }

            // Never trust the backup blindly: hash the source before copying
            let backup_hash = match Self::compute_file_sha256(&backup_file) {
                Ok(h) => h,
                Err(_) => {
                    failed.push(rel_path.clone());
                    continue;
                }
            };

            // Ensure parent directory exists in target
            if let Some(parent) = target_file.parent() {
                let _ = fs::create_dir_all(parent);
            }

            match fs::copy(&backup_file, &target_file) {
                Ok(_) => {
                    // Verify the restored copy matches the backup we read
                    match Self::compute_file_sha256(&target_file) {
                        Ok(h) if h == backup_hash => restored.push(rel_path.clone()),
                        _ => failed.push(rel_path.clone()),
                    }
                }
                Err(_) => {
                    failed.push(rel_path.clone());
                }
            }
        }

        let success = failed.is_empty() && !restored.is_empty();
        RestoreResult {
            success,
            restored_files: restored,
            failed_files: failed,
            error: None,
        }
    }
}
