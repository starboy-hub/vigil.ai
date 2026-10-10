use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetupStatus {
    pub success: bool,
    pub manifest_registered: bool,
    pub extension_deployed: bool,
    pub extension_path: String,
    pub registered_paths: Vec<String>,
    pub error: Option<String>,
}

pub struct VigilInstaller;

impl VigilInstaller {
    pub fn get_vigil_app_dir() -> PathBuf {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
        #[cfg(target_os = "macos")]
        {
            home.join("Library").join("Application Support").join("VIGIL")
        }
        #[cfg(not(target_os = "macos"))]
        {
            home.join(".vigil")
        }
    }

    pub fn get_native_messaging_dirs() -> Vec<PathBuf> {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let mut dirs = Vec::new();

        #[cfg(target_os = "macos")]
        {
            dirs.push(home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts"));
            dirs.push(home.join("Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"));
            dirs.push(home.join("Library/Application Support/Microsoft Edge/NativeMessagingHosts"));
            dirs.push(home.join("Library/Application Support/Mozilla/NativeMessagingHosts"));
        }

        #[cfg(target_os = "linux")]
        {
            dirs.push(home.join(".config/google-chrome/NativeMessagingHosts"));
            dirs.push(home.join(".config/BraveSoftware/Brave-Browser/NativeMessagingHosts"));
            dirs.push(home.join(".config/microsoft-edge/NativeMessagingHosts"));
            dirs.push(home.join(".mozilla/native-messaging-hosts"));
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
                let base = PathBuf::from(appdata);
                dirs.push(base.join("Google\\Chrome\\User Data\\NativeMessagingHosts"));
                dirs.push(base.join("BraveSoftware\\Brave-Browser\\User Data\\NativeMessagingHosts"));
                dirs.push(base.join("Microsoft\\Edge\\User Data\\NativeMessagingHosts"));
            }
        }

        dirs
    }

    pub fn register_manifest(binary_path: &Path) -> Result<Vec<String>, String> {
        let host_name = "com.vigil.desktop";
        let target_dirs = Self::get_native_messaging_dirs();
        let mut registered = Vec::new();

        let bin_str = binary_path.to_str().unwrap_or("/Applications/VIGIL.app/Contents/MacOS/vigil-desktop-companion");
        let manifest_content = serde_json::json!({
            "name": host_name,
            "description": "Vigil / VIGIL Native Desktop Security Companion Daemon",
            "path": bin_str,
            "type": "stdio",
            "allowed_origins": [
                "chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/",
                "chrome-extension://vigil-guardian-id/",
                "chrome-extension://vigil-guardian-id/"
            ]
        });

        let json_str = serde_json::to_string_pretty(&manifest_content).map_err(|e| e.to_string())?;

        for dir in target_dirs {
            let _ = fs::create_dir_all(&dir);
            let manifest_path = dir.join(format!("{}.json", host_name));
            if fs::write(&manifest_path, &json_str).is_ok() {
                registered.push(manifest_path.to_string_lossy().to_string());
            }
        }

        if registered.is_empty() {
            Err("Failed to write Native Messaging host manifest to browser directories".to_string())
        } else {
            Ok(registered)
        }
    }

    pub fn run_setup(source_extension_dir: Option<&str>) -> SetupStatus {
        let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vigil-desktop-companion"));
        let reg_res = Self::register_manifest(&exe_path);

        let vigil_dir = Self::get_vigil_app_dir();
        let target_ext_dir = vigil_dir.join("extension");
        let _ = fs::create_dir_all(&target_ext_dir);

        let mut extension_deployed = false;
        if let Some(src) = source_extension_dir {
            let src_path = Path::new(src);
            if src_path.exists() {
                extension_deployed = fs::copy(src_path.join("manifest.json"), target_ext_dir.join("manifest.json")).is_ok();
            }
        } else {
            extension_deployed = target_ext_dir.exists();
        }

        match reg_res {
            Ok(paths) => SetupStatus {
                success: true,
                manifest_registered: true,
                extension_deployed,
                extension_path: target_ext_dir.to_string_lossy().to_string(),
                registered_paths: paths,
                error: None,
            },
            Err(e) => SetupStatus {
                success: false,
                manifest_registered: false,
                extension_deployed,
                extension_path: target_ext_dir.to_string_lossy().to_string(),
                registered_paths: Vec::new(),
                error: Some(e),
            },
        }
    }
}
