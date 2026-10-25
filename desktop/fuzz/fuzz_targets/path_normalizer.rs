#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use vigil_desktop_companion::sentinel::SentinelEngine;
use vigil_desktop_companion::{lexically_normalize_path, sanitize_resource_string};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // 1. Fuzz lexical path normalization with arbitrary unicode/nulls
        let path = PathBuf::from(s);
        let normalized = lexically_normalize_path(&path);

        // Invariant: Normalized path must never contain unresolved ".." components
        for comp in normalized.components() {
            if let std::path::Component::ParentDir = comp {
                panic!("INVARIANT VIOLATION: Unresolved ParentDir in normalized path: {:?}", normalized);
            }
        }

        // 2. Fuzz URL/percent decoding and sanitization
        let sanitized = sanitize_resource_string(s);
        assert!(!sanitized.contains('\0'), "INVARIANT VIOLATION: Null byte in sanitized output");

        // 3. Fuzz Native Sentinel Policy Engine evaluation against normalized path
        let engine = SentinelEngine::new();
        let _ = engine.evaluate_action("fs:read", s, &serde_json::json!({}), Some("/safe/workspace"), "balanced");
    }
});
