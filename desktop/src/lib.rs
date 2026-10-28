pub mod audio_canary;
pub mod file_integrity;
pub mod hardware_enclave;
pub mod ide_proxy;
pub mod installer;
pub mod ml_offload;
pub mod phash;
pub mod sandbox;
pub mod sentinel;
pub mod siem_exporter;

pub use sentinel::{lexically_normalize_path, sanitize_resource_string, SentinelEngine};
