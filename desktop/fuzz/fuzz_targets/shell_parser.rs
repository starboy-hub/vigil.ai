#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use vigil_desktop_companion::sentinel::SentinelEngine;

fuzz_target!(|data: &[u8]| {
    if let Ok(cmd) = std::str::from_utf8(data) {
        let engine = SentinelEngine::new();

        // Evaluate arbitrary raw command string as shell action
        let res = engine.evaluate_action(
            "shell:execute",
            cmd,
            &json!({ "command": cmd }),
            Some("/app/workspace"),
            "balanced",
        );

        if let Ok(decision) = res {
            // Invariant: Known destructive or IMDS commands must NEVER be permitted
            let lower = cmd.to_lowercase();
            let is_destructive = lower.contains("rm -rf")
                || lower.contains(":(){ :|:& };:")
                || lower.contains("mkfs.")
                || lower.contains("dd if=/dev/zero");
            let is_imds = lower.contains("169.254") || lower.contains("100.100.100.200");

            if (is_destructive || is_imds) && decision.decision == "ALLOW" {
                panic!("INVARIANT VIOLATION: Malicious shell payload permitted by policy: {}", cmd);
            }
        }
    }
});
