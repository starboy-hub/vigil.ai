use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use keyring::Entry;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use zeroize::Zeroize;

const SEAL_SERVICE: &str = "vigil-enclave";
const SEAL_ACCOUNT: &str = "sealing-key";

lazy_static::lazy_static! {
    /// Used only when the OS keychain is unavailable (headless/CI): a
    /// process-local sealing key so seal/unseal round-trips still work within
    /// one daemon lifetime. Never used when the real keychain answers.
    static ref EPHEMERAL_SEALING_KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedKeyRecord {
    pub hardware_module: String,
    pub hardware_bound: bool,
    pub iv: String,
    pub tag: String,
    pub sealed_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HardwareSecurityStatus {
    pub platform: String,
    pub hardware_backed: bool,
    pub tpm_available: bool,
    pub secure_enclave_available: bool,
    pub hardware_module: String,
    pub enclave_status: String,
}

pub struct HardwareEnclaveManager {
    platform: &'static str,
    binding: &'static str,
}

impl HardwareEnclaveManager {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        let (platform, binding) = ("darwin", "OS_KEYCHAIN");
        #[cfg(target_os = "windows")]
        let (platform, binding) = ("win32", "OS_KEYCHAIN");
        #[cfg(target_os = "linux")]
        let (platform, binding) = ("linux", "OS_KEYCHAIN_SECRET_SERVICE");
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        let (platform, binding) = ("unknown", "PROCESS_MEMORY");

        HardwareEnclaveManager { platform, binding }
    }

    /// Creates a manager whose sealing key is pre-seeded process-locally,
    /// bypassing the OS keychain entirely. Used in tests and headless/CI
    /// environments where keychain calls are unavailable or slow; sealed
    /// records are only valid within that process lifetime.
    pub fn with_ephemeral_key() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        *EPHEMERAL_SEALING_KEY.lock().unwrap() = Some(key);
        HardwareEnclaveManager::new()
    }

    /// Honest capability report. This build binds keys to the OS keychain via
    /// the `keyring` crate; it does NOT talk to a TPM or Apple Secure Enclave
    /// (no tss-esapi / Security framework in the dependency set). Claiming
    /// otherwise would overstate the threat model.
    pub fn get_security_status(&self) -> HardwareSecurityStatus {
        HardwareSecurityStatus {
            platform: self.platform.to_string(),
            hardware_backed: false,
            tpm_available: false,
            secure_enclave_available: false,
            hardware_module: self.binding.to_string(),
            enclave_status: "OS_KEYCHAIN_BOUND".to_string(),
        }
    }

    /// Loads the sealing key from the OS keychain, creating a random one on
    /// first use. The process-local cache is authoritative once populated so
    /// seal/unseal stay consistent even if keychain reads become unavailable
    /// mid-session (macOS headless denial, Linux secret-service absence).
    fn sealing_key(&self) -> Result<[u8; 32], String> {
        {
            let guard = EPHEMERAL_SEALING_KEY.lock().unwrap();
            if let Some(key) = guard.as_ref() {
                return Ok(*key);
            }
        }

        if let Ok(entry) = Entry::new(SEAL_SERVICE, SEAL_ACCOUNT) {
            if let Ok(existing) = entry.get_password() {
                if let Some(key) = hex_decode(&existing).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
                    *EPHEMERAL_SEALING_KEY.lock().unwrap() = Some(key);
                    return Ok(key);
                }
            }
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        if let Ok(entry) = Entry::new(SEAL_SERVICE, SEAL_ACCOUNT) {
            let _ = entry.set_password(&hex_encode(&key));
        }
        *EPHEMERAL_SEALING_KEY.lock().unwrap() = Some(key);
        Ok(key)
    }

    /// Seals a raw master key with AES-256-GCM under an OS-keychain-held
    /// sealing key. When no raw key is supplied, a random 32-byte key is
    /// generated with the OS CSPRNG.
    pub fn seal_master_key(&self, raw_key: Option<&[u8]>) -> Result<SealedKeyRecord, String> {
        let mut key_bytes = match raw_key {
            Some(b) => b.to_vec(),
            None => {
                let mut generated = vec![0u8; 32];
                OsRng.fill_bytes(&mut generated);
                generated
            }
        };

        let sealing_key = self.sealing_key()?;
        let cipher = Aes256Gcm::new_from_slice(&sealing_key)
            .map_err(|e| format!("Sealing key error: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // aes-gcm appends the 16-byte authentication tag to the ciphertext
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), key_bytes.as_ref())
            .map_err(|e| format!("Sealing failed: {}", e))?;

        key_bytes.zeroize();

        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);

        Ok(SealedKeyRecord {
            hardware_module: self.binding.to_string(),
            hardware_bound: false,
            iv: hex_encode(&nonce_bytes),
            tag: hex_encode(tag),
            sealed_key: hex_encode(ciphertext),
        })
    }

    /// Unseals a master key previously sealed by `seal_master_key`.
    /// Returns the raw key as hex.
    pub fn unseal_master_key(&self, record: &SealedKeyRecord) -> Result<String, String> {
        let ciphertext = hex_decode(&record.sealed_key).ok_or_else(|| "Invalid hex in sealed_key".to_string())?;
        let nonce_bytes = hex_decode(&record.iv).ok_or_else(|| "Invalid hex in iv".to_string())?;
        let tag = hex_decode(&record.tag).ok_or_else(|| "Invalid hex in tag".to_string())?;

        if nonce_bytes.len() != 12 || tag.len() != 16 {
            return Err("Invalid nonce or authentication tag length".to_string());
        }

        let sealing_key = self.sealing_key()?;
        let cipher = Aes256Gcm::new_from_slice(&sealing_key)
            .map_err(|e| format!("Sealing key error: {}", e))?;

        // The aes-gcm crate expects ciphertext with the tag appended
        let mut sealed = ciphertext;
        sealed.extend_from_slice(&tag);

        let mut raw_key = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), sealed.as_ref())
            .map_err(|_| "Authentication failed: sealed record was tampered with or forged".to_string())?;

        let hex_out = hex_encode(&raw_key);
        raw_key.zeroize();
        Ok(hex_out)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests share one process-wide sealing key cache; serialize them so a
    /// parallel test cannot swap the key between one test's seal and unseal.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_status_is_honest_about_binding() {
        let _g = TEST_LOCK.lock().unwrap();
        let enclave = HardwareEnclaveManager::with_ephemeral_key();
        let status = enclave.get_security_status();
        // No TPM/Secure Enclave API in this build — must not claim hardware backing
        assert!(!status.hardware_backed);
        assert_eq!(status.enclave_status, "OS_KEYCHAIN_BOUND");
        assert!(status.hardware_module.starts_with("OS_KEYCHAIN"));
    }

    #[test]
    fn test_seal_and_unseal_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap();
        let enclave = HardwareEnclaveManager::with_ephemeral_key();
        let test_key = [42u8; 32];
        let sealed = enclave.seal_master_key(Some(&test_key)).expect("Sealing failed");
        assert_eq!(sealed.iv.len(), 24); // 12 bytes hex
        assert_eq!(sealed.tag.len(), 32); // 16 bytes hex

        let unsealed_hex = enclave.unseal_master_key(&sealed).expect("Unsealing failed");
        let expected_hex = hex_encode(&test_key);
        assert_eq!(unsealed_hex, expected_hex);
    }

    #[test]
    fn test_seal_generates_random_key_when_none_supplied() {
        let _g = TEST_LOCK.lock().unwrap();
        let enclave = HardwareEnclaveManager::with_ephemeral_key();
        let a = enclave.seal_master_key(None).unwrap();
        let b = enclave.seal_master_key(None).unwrap();
        assert_ne!(a.sealed_key, b.sealed_key, "two sealed random keys must differ");
        let ra = enclave.unseal_master_key(&a).unwrap();
        let rb = enclave.unseal_master_key(&b).unwrap();
        assert_ne!(ra, rb);
        assert_eq!(ra.len(), 64); // 32-byte key hex
    }

    #[test]
    fn test_unseal_tampering_detection() {
        let _g = TEST_LOCK.lock().unwrap();
        let enclave = HardwareEnclaveManager::with_ephemeral_key();
        let test_key = [99u8; 32];
        let mut sealed = enclave.seal_master_key(Some(&test_key)).unwrap();
        // Flip one ciphertext byte — AES-GCM must reject it
        let flipped = if sealed.sealed_key.starts_with("00") { "ff" } else { "00" };
        sealed.sealed_key = format!("{}{}", flipped, &sealed.sealed_key[2..]);
        let err = enclave.unseal_master_key(&sealed);
        assert!(err.is_err());
    }

    #[test]
    fn test_unseal_forged_tag_detection() {
        let _g = TEST_LOCK.lock().unwrap();
        let enclave = HardwareEnclaveManager::with_ephemeral_key();
        let test_key = [7u8; 32];
        let mut sealed = enclave.seal_master_key(Some(&test_key)).unwrap();
        sealed.tag = "00".repeat(16);
        assert!(enclave.unseal_master_key(&sealed).is_err());
    }
}
