#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vigil_desktop_companion::sentinel::SentinelEngine;

fuzz_target!(|data: &[u8]| {
    // Attempt parsing arbitrary byte buffer as JSON-RPC MCP Gateway message
    if let Ok(parsed) = serde_json::from_slice::<Value>(data) {
        if let Some(obj) = parsed.as_object() {
            let action_type = obj
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let resource = obj
                .get("params")
                .and_then(|p| p.get("resource"))
                .and_then(|r| r.as_str())
                .unwrap_or("");
            let params = obj.get("params").cloned().unwrap_or(Value::Null);

            let engine = SentinelEngine::new();
            let _ = engine.evaluate_action(
                action_type,
                resource,
                &params,
                Some("/app/workspace"),
                "balanced",
            );
        }
    }
});
