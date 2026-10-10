use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SiemLogEvent {
    pub incident_type: String,
    pub domain_hash: String,
    pub timestamp_iso: String,
    pub severity: u8,
    pub rule_id: String,
}

pub struct NativeSiemExporter;

impl NativeSiemExporter {
    /// Formats audit event into Common Event Format (CEF)
    pub fn format_cef(event: &SiemLogEvent) -> String {
        format!(
            "CEF:0|VIGIL|PrivacyShield|11.0.0|{}|{}|{}|src={}",
            event.rule_id, event.incident_type, event.severity, event.domain_hash
        )
    }

    /// Formats audit event into OCSF v1.1.0 Data Security event envelope
    pub fn format_ocsf(event: &SiemLogEvent) -> serde_json::Value {
        serde_json::json!({
            "class_uid": 2001,
            "category_uid": 2,
            "activity_id": 1,
            "severity_id": event.severity,
            "time": event.timestamp_iso,
            "type_name": event.incident_type,
            "device": { "type": "Browser Extension + Native Companion" },
            "unmapped": {
                "rule_id": event.rule_id,
                "domain_hash": event.domain_hash
            }
        })
    }

    /// Formats audit event into standard SIEM JSON envelope (Splunk HEC / Azure Sentinel)
    pub fn format_json(event: &SiemLogEvent) -> serde_json::Value {
        serde_json::json!({
            "event": {
                "action": "redact",
                "incident_type": event.incident_type,
                "domain_hash": event.domain_hash,
                "severity": event.severity,
                "rule_id": event.rule_id
            },
            "time": event.timestamp_iso,
            "source": "vigil-hybrid-shield",
            "sourcetype": "_json"
        })
    }

    /// Streams an audit event to an enterprise SIEM endpoint over real HTTP(S).
    /// HTTPS is required except for loopback HTTP targets used in testing.
    pub fn stream_to_endpoint(endpoint: &str, auth_header: Option<&str>, payload: &str) -> Result<serde_json::Value, String> {
        if endpoint.is_empty() {
            return Err("Empty SIEM endpoint URL".to_string());
        }
        let is_loopback_http = endpoint.starts_with("http://127.0.0.1") || endpoint.starts_with("http://localhost") || endpoint.starts_with("http://[::1]");
        if !endpoint.starts_with("https://") && !is_loopback_http {
            return Err("INSECURE_ENDPOINT: SIEM streaming requires HTTPS (loopback HTTP is allowed for testing)".to_string());
        }

        let token_present = auth_header.is_some() && !auth_header.unwrap_or_default().is_empty();
        let request = ureq::post(endpoint)
            .timeout(Duration::from_secs(10))
            .set("Content-Type", "application/json");
        let request = if token_present {
            request.set("Authorization", auth_header.unwrap_or_default())
        } else {
            request
        };

        match request.send_string(payload) {
            Ok(resp) => Ok(serde_json::json!({
                "status": "delivered",
                "httpStatus": resp.status(),
                "endpoint": endpoint,
                "bytesSent": payload.len(),
                "authenticated": token_present
            })),
            Err(ureq::Error::Status(code, _)) => Err(format!("SIEM endpoint rejected the event with HTTP {}", code)),
            Err(e) => Err(format!("SIEM delivery failed: {}", e)),
        }
    }
}

