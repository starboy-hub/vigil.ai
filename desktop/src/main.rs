mod audio_canary;
mod file_integrity;
mod hardware_enclave;
mod ide_proxy;
mod installer;
mod ml_offload;
mod phash;
mod siem_exporter;

use audio_canary::{VoiceCanaryResult, VoiceSpectralCanary};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use file_integrity::FileIntegrityEngine;
use hardware_enclave::{HardwareEnclaveManager, SealedKeyRecord};
use ide_proxy::IdeProxyEngine;
use installer::VigilInstaller;
use keyring::Entry;
use ml_offload::NativeMlEngine;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use siem_exporter::{NativeSiemExporter, SiemLogEvent};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// A session lives at most 15 minutes without re-handshake. The daemon is
/// short-lived per browser launch (native messaging), so this only bounds
/// stale session reuse within one daemon process.
const SESSION_TTL_SECS: u64 = 900;

#[derive(Clone, Debug)]
struct SessionInfo {
    extension_id: String,
    created_at: u64,
    expires_at: u64,
    last_seq: u64,
    host_seq: u64,
    client_pub_key: Option<String>,
    /// AES-256-GCM channel key: the raw ECDH shared secret (X coordinate),
    /// identical to what WebCrypto deriveKey({AES-GCM, 256}) produces on the
    /// JS side. Zeroized when the session record is dropped.
    shared_key: Option<Vec<u8>>,
}

impl Drop for SessionInfo {
    fn drop(&mut self) {
        if let Some(key) = &mut self.shared_key {
            key.zeroize();
        }
    }
}

const ALLOWED_EXTENSION_IDS: &[&str] = &[
    "emkokehejldjlfljlhhcimnfefcjcmon",
    "vigil-guardian-id",
    "vigil-guardian-id",
];

lazy_static::lazy_static! {
    static ref PROXY_ENGINE: Mutex<IdeProxyEngine> = Mutex::new(IdeProxyEngine::new(8383));
    static ref ML_ENGINE: NativeMlEngine = NativeMlEngine::new();
    static ref ENCLAVE_ENGINE: HardwareEnclaveManager = HardwareEnclaveManager::new();
    static ref ACTIVE_SESSIONS: Mutex<std::collections::HashMap<String, SessionInfo>> = Mutex::new(std::collections::HashMap::new());
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

fn read_native_message<R: Read>(reader: &mut R) -> io::Result<String> {
    let length = match reader.read_u32::<NativeEndian>() {
        Ok(l) => l as usize,
        Err(e) => return Err(e),
    };
    if length == 0 || length > 10 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid message length"));
    }
    let mut buffer = vec![0u8; length];
    reader.read_exact(&mut buffer)?;
    String::from_utf8(buffer).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn write_native_message<W: Write>(writer: &mut W, message: &str) -> io::Result<()> {
    let bytes = message.as_bytes();
    writer.write_u32::<NativeEndian>(bytes.len() as u32)?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// Keychain access is restricted to Vigil's own service namespaces. Without
/// this allowlist, an authenticated caller could read ANY keychain entry on
/// the machine by naming an arbitrary service/account.
fn is_allowed_keychain_service(service: &str) -> bool {
    const ALLOWED_SERVICES: &[&str] = &[
        "vigil-identity-vault",
        "vigil-identity-vault",
        "vigil-enclave",
        "vigil-enclave",
        "vigil-desktop",
        "vigil-desktop",
    ];
    service.len() <= 64
        && (ALLOWED_SERVICES.contains(&service)
            || service.starts_with("vigil.")
            || service.starts_with("vigil."))
}

fn is_safe_keychain_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 128
        && account
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.@".contains(c))
}

fn handle_keychain_get(service: &str, account: &str) -> Result<String, String> {
    if !is_allowed_keychain_service(service) {
        return Err(format!(
            "FORBIDDEN_SERVICE: keychain service '{}' is outside the Vigil allowlist",
            service
        ));
    }
    if !is_safe_keychain_account(account) {
        return Err("INVALID_ACCOUNT: malformed keychain account name".to_string());
    }
    let entry = Entry::new(service, account).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}

fn handle_keychain_set(service: &str, account: &str, secret: &str) -> Result<(), String> {
    if !is_allowed_keychain_service(service) {
        return Err(format!(
            "FORBIDDEN_SERVICE: keychain service '{}' is outside the Vigil allowlist",
            service
        ));
    }
    if !is_safe_keychain_account(account) {
        return Err("INVALID_ACCOUNT: malformed keychain account name".to_string());
    }
    if secret.len() > 64 * 1024 {
        return Err("SECRET_TOO_LARGE: keychain payload exceeds 64 KiB".to_string());
    }
    let entry = Entry::new(service, account).map_err(|e| e.to_string())?;
    entry.set_password(secret).map_err(|e| e.to_string())
}

fn handle_audio_analysis(params: &Value) -> Result<VoiceCanaryResult, String> {
    let samples_array = params["samples"].as_array().ok_or("Missing samples array")?;
    let samples: Vec<f32> = samples_array
        .iter()
        .filter_map(|v| v.as_f64().map(|f| f as f32))
        .collect();

    let canary = VoiceSpectralCanary::new(1024);
    Ok(canary.analyze_samples(&samples))
}

/// Authenticates a request against the session store. Returns a snapshot of
/// the (already expired-pruned) session on success.
fn authenticate(auth_token: &str) -> Result<SessionInfo, Value> {
    let now = unix_now_secs();
    {
        let mut sessions = ACTIVE_SESSIONS.lock().unwrap();
        sessions.retain(|_, s| s.expires_at > now);
        if let Some(s) = sessions.get(auth_token) {
            if s.expires_at > now {
                return Ok(s.clone());
            }
        }
    }
    Err(json!({
        "code": -32401,
        "message": "UNAUTHORIZED: Mutual authentication handshake required. Missing, invalid, or expired session token."
    }))
}

fn error_response(id: &Value, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: id.clone(),
        result: None,
        error: Some(json!({ "code": code, "message": message })),
    }
}

fn handle_rpc_request(req: JsonRpcRequest) -> JsonRpcResponse {
    let method = req.method.as_str();
    let params = req.params.clone().unwrap_or(Value::Null);

    // 1. Mutual Authentication Handshake
    if method == "vigil.auth.handshake" {
        return handle_handshake(req.id, &params);
    }

    // 2. Allow unauthenticated ping for liveness check
    if method == "vigil.ping" {
        return JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(json!({ "status": "active", "version": "11.0.0", "origin_lock": "enforced" })),
            error: None,
        };
    }

    // 3. For all privileged operations, verify an active, unexpired session
    let auth_token = params["auth_token"].as_str().unwrap_or("").to_string();
    let session = match authenticate(&auth_token) {
        Ok(s) => s,
        Err(err) => return error_response(&req.id, -32401, err["message"].as_str().unwrap_or("UNAUTHORIZED").to_string()),
    };

    // 4. Origin lock: a supplied origin must match the session's extension id
    if let Some(origin) = params["origin"].as_str() {
        let expected_origin = format!("chrome-extension://{}/", session.extension_id);
        if origin != expected_origin {
            return error_response(
                &req.id,
                -32403,
                format!(
                    "FORBIDDEN_ORIGIN_LOCK: Provided origin '{}' does not match session origin '{}'",
                    origin, expected_origin
                ),
            );
        }
    }

    // 5. Encrypted channel frames carry an inner request; they are dispatched
    //    under the already-authenticated session, never re-parsed as outer RPCs.
    if method == "vigil.encrypted_frame" || method == "vigil.encrypted_frame" {
        return handle_encrypted_frame(req.id, &auth_token, &params, &session);
    }

    dispatch_privileged(&req, &session)
}

fn handle_handshake(id: Value, params: &Value) -> JsonRpcResponse {
    let ext_id = params["extension_id"].as_str().unwrap_or("");
    let origin = params["origin"].as_str().unwrap_or("");

    if !ALLOWED_EXTENSION_IDS.contains(&ext_id) {
        return error_response(
            &id,
            -32403,
            format!(
                "FORBIDDEN_ORIGIN_LOCK: Origin '{}' is not authorized by the native host manifest policy",
                if !origin.is_empty() { origin } else { ext_id }
            ),
        );
    }

    let now_secs = unix_now_secs();
    // Prune expired sessions (the daemon is per-launch, but this bounds growth)
    {
        let mut sessions = ACTIVE_SESSIONS.lock().unwrap();
        sessions.retain(|_, s| s.expires_at > now_secs);

        // Single-origin lock: reject multi-extension pivot attempts
        for (_, existing_sess) in sessions.iter() {
            if existing_sess.extension_id != ext_id {
                return error_response(
                    &id,
                    -32403,
                    format!(
                        "ORIGIN_PIVOT_BLOCKED: Active session from '{}' exists. Multi-origin pivots are not permitted",
                        existing_sess.extension_id
                    ),
                );
            }
        }
    }

    let client_pub = params["client_pub_key"].as_str().map(|s| s.to_string());

    // Downgrade Prevention: Production extension MUST use an encrypted ECDH channel
    const REQUIRE_ENCRYPTION_EXTENSIONS: &[&str] = &[
        "emkokehejldjlfljlhhcimnfefcjcmon",
    ];
    if REQUIRE_ENCRYPTION_EXTENSIONS.contains(&ext_id) && client_pub.is_none() {
        eprintln!("[VIGIL_SECURITY] HANDSHAKE_DOWNGRADE_REJECTED: {} attempted unencrypted channel", ext_id);
        return error_response(
            &id,
            -32600,
            "ENCRYPTION_REQUIRED: Production extension must establish an encrypted ECDH channel (missing client_pub_key)".to_string(),
        );
    }

    // Random 192-bit session token — never a derivable timestamp
    let session_token = format!("vigil_sess_{}", random_hex(24));

    // Ephemeral host ECDH keypair per session. When the client supplies a
    // public key, both sides derive the same AES-256-GCM channel key (the raw
    // ECDH shared X coordinate — exactly what WebCrypto deriveKey yields).
    let host_secret = P256SecretKey::random(&mut OsRng);
    let host_pub_bytes = host_secret.public_key().to_encoded_point(false).as_bytes().to_vec();

    let shared_key = client_pub.as_ref().and_then(|hex_or_b64| {
        // The JS bridge sends its raw SEC1 public key base64-encoded.
        let client_bytes = b64_decode(hex_or_b64)
            .or_else(|| {
                // Tolerate hex for non-JS test clients
                (0..hex_or_b64.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_or_b64[i..i + 2], 16).ok())
                    .collect::<Option<Vec<u8>>>()
            })?;
        let client_pk = P256PublicKey::from_sec1_bytes(&client_bytes).ok()?;
        let shared = diffie_hellman(host_secret.to_nonzero_scalar(), client_pk.as_affine());
        Some(shared.raw_secret_bytes().to_vec())
    });
    let channel_encrypted = shared_key.is_some();

    {
        let mut sessions = ACTIVE_SESSIONS.lock().unwrap();
        sessions.insert(
            session_token.clone(),
            SessionInfo {
                extension_id: ext_id.to_string(),
                created_at: now_secs,
                expires_at: now_secs + SESSION_TTL_SECS,
                last_seq: 0,
                host_seq: 0,
                client_pub_key: client_pub.clone(),
                shared_key,
            },
        );
    }

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(json!({
            "authenticated": true,
            "session_token": session_token,
            "host_name": "com.vigil.desktop",
            "origin_locked": true,
            "extension_id": ext_id,
            "host_pub_key": b64_encode(&host_pub_bytes),
            "channel": if channel_encrypted { "encrypted" } else { "plaintext" },
            "client_pub_key_acknowledged": client_pub.is_some(),
            "session_ttl_secs": SESSION_TTL_SECS
        })),
        error: None,
    }
}

/// Decrypts an encrypted frame, dispatches the inner request under the
/// session established by the outer envelope, and encrypts the response.
fn handle_encrypted_frame(id: Value, auth_token: &str, params: &Value, session: &SessionInfo) -> JsonRpcResponse {
    let seq = params["seq"].as_u64().unwrap_or(0);

    // Replay protection: strictly increasing client sequence numbers
    {
        let mut sessions = ACTIVE_SESSIONS.lock().unwrap();
        if let Some(sess) = sessions.get_mut(auth_token) {
            if seq <= sess.last_seq {
                return error_response(
                    &id,
                    -32402,
                    format!(
                        "REPLAY_ATTACK_DETECTED: Received frame sequence {} <= last seen {}",
                        seq, sess.last_seq
                    ),
                );
            }
            const MAX_SEQ_SKIP: u64 = 10_000;
            if seq.saturating_sub(sess.last_seq) > MAX_SEQ_SKIP {
                return error_response(
                    &id,
                    -32404,
                    format!(
                        "SEQUENCE_ANOMALY: Sequence jump from {} to {} exceeds permitted threshold",
                        sess.last_seq, seq
                    ),
                );
            }
            sess.last_seq = seq;
        }
    }

    let key = match &session.shared_key {
        Some(k) if k.len() == 32 => k.clone(),
        _ => {
            return error_response(
                &id,
                -32500,
                "CHANNEL_NOT_ESTABLISHED: no shared key for this session; perform a crypto handshake".to_string(),
            )
        }
    };

    let iv = match params["iv"].as_str().and_then(b64_decode) {
        Some(v) if v.len() == 12 => v,
        _ => return error_response(&id, -32500, "INVALID_FRAME: missing or malformed 12-byte IV".to_string()),
    };
    let ciphertext = match params["ciphertext"].as_str().and_then(b64_decode) {
        Some(v) if !v.is_empty() => v,
        _ => return error_response(&id, -32500, "INVALID_FRAME: missing or malformed ciphertext".to_string()),
    };

    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => return error_response(&id, -32500, format!("CHANNEL_ERROR: {}", e)),
    };
    let plaintext: Vec<u8> = match cipher.decrypt(Nonce::from_slice(&iv), ciphertext.as_slice()) {
        Ok(p) => p,
        Err(_) => {
            return error_response(
                &id,
                -32500,
                "DECRYPT_FAILED: AES-GCM authentication failed — frame tampered or wrong channel key".to_string(),
            )
        }
    };

    let inner: JsonRpcRequest = match serde_json::from_slice(&plaintext) {
        Ok(r) => r,
        Err(e) => return error_response(&id, -32500, format!("INVALID_FRAME: inner payload is not a JSON-RPC request ({})", e)),
    };

    // The inner request is pre-authenticated by the outer envelope's session.
    let inner_resp = dispatch_privileged(&inner, session);

    // Encrypt the JSON-RPC response with a fresh random nonce. The plaintext
    // carries a monotonically increasing host seq so the client can run its
    // own replay check on responses.
    let mut host_seq = 0u64;
    {
        let mut sessions = ACTIVE_SESSIONS.lock().unwrap();
        if let Some(sess) = sessions.get_mut(auth_token) {
            sess.host_seq += 1;
            host_seq = sess.host_seq;
        }
    }

    let mut resp_value = match serde_json::to_value(&inner_resp) {
        Ok(v) => v,
        Err(e) => return error_response(&id, -32500, format!("CHANNEL_ERROR: response serialization failed ({})", e)),
    };
    resp_value["seq"] = json!(host_seq);

    let resp_bytes = match serde_json::to_vec(&resp_value) {
        Ok(b) => b,
        Err(e) => return error_response(&id, -32500, format!("CHANNEL_ERROR: response encoding failed ({})", e)),
    };

    let mut resp_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut resp_nonce);
    let resp_ct: Vec<u8> = match cipher.encrypt(Nonce::from_slice(&resp_nonce), resp_bytes.as_slice()) {
        Ok(c) => c,
        Err(e) => return error_response(&id, -32500, format!("CHANNEL_ERROR: response encryption failed ({})", e)),
    };

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(json!({
            "iv": b64_encode(&resp_nonce),
            "ciphertext": b64_encode(&resp_ct),
            "authenticated": true
        })),
        error: None,
    }
}

fn dispatch_privileged(req: &JsonRpcRequest, _session: &SessionInfo) -> JsonRpcResponse {
    let method = req.method.as_str();
    let params = req.params.clone().unwrap_or(Value::Null);
    let id = req.id.clone();

    let res = match method {
        "vigil.keychainGet" => {
            let service = params["service"].as_str().unwrap_or("vigil-identity-vault");
            let account = params["account"].as_str().unwrap_or("master-key");
            match handle_keychain_get(service, account) {
                Ok(secret) => Ok(json!({ "secret": secret })),
                Err(e) => Err(json!({ "code": -32001, "message": format!("Keychain read failed: {}", e) })),
            }
        }
        "vigil.keychainSet" => {
            let service = params["service"].as_str().unwrap_or("vigil-identity-vault");
            let account = params["account"].as_str().unwrap_or("master-key");
            let secret = params["secret"].as_str().unwrap_or("");
            match handle_keychain_set(service, account, secret) {
                Ok(_) => Ok(json!({ "success": true })),
                Err(e) => Err(json!({ "code": -32002, "message": format!("Keychain write failed: {}", e) })),
            }
        }
        "vigil.analyzeAudioSpectrum" => match handle_audio_analysis(&params) {
            Ok(result) => Ok(serde_json::to_value(result).unwrap_or(Value::Null)),
            Err(e) => Err(json!({ "code": -32003, "message": format!("Audio analysis failed: {}", e) })),
        },
        "vigil.inspectIdePrompt" => {
            let prompt = params["prompt"].as_str().unwrap_or("");
            let engine = PROXY_ENGINE.lock().unwrap();
            let (sanitized, has_leak, types) = engine.inspect_prompt(prompt);
            Ok(json!({
                "sanitizedPrompt": sanitized,
                "hasLeak": has_leak,
                "detectedTypes": types
            }))
        }
        "vigil.getProxyStats" => {
            let engine = PROXY_ENGINE.lock().unwrap();
            let stats = engine.get_stats();
            Ok(serde_json::to_value(stats).unwrap_or(Value::Null))
        }
        "vigil.tokenBudgetRecord" => {
            let agent_id = params["agent_id"].as_str().unwrap_or("default");
            let tokens = params["tokens"].as_u64().unwrap_or(0);
            let engine = PROXY_ENGINE.lock().unwrap();
            let verdict = engine.token_budget.record_usage(agent_id, tokens);
            Ok(serde_json::to_value(verdict).unwrap_or(Value::Null))
        }
        "vigil.tokenBudgetStatus" => {
            let agent_id = params["agent_id"].as_str();
            let engine = PROXY_ENGINE.lock().unwrap();
            let status = engine.token_budget.get_status(agent_id);
            Ok(status)
        }
        "vigil.tokenBudgetSetLimits" => {
            let session_limit = params["session_limit"].as_u64();
            let daily_limit = params["daily_limit"].as_u64();
            let mode = params["enforcement_mode"].as_str().map(|s| s.to_string());
            let engine = PROXY_ENGINE.lock().unwrap();
            let cfg = engine.token_budget.set_limits(session_limit, daily_limit, mode);
            Ok(serde_json::to_value(cfg).unwrap_or(Value::Null))
        }
        "vigil.tokenBudgetReset" => {
            let agent_id = params["agent_id"].as_str().unwrap_or("default");
            let engine = PROXY_ENGINE.lock().unwrap();
            let success = engine.token_budget.reset_agent(agent_id);
            Ok(json!({ "success": success, "agent_id": agent_id }))
        }
        "vigil.classifyTextNative" => {
            let text = params["text"].as_str().unwrap_or("");
            let res = ML_ENGINE.classify(text);
            Ok(serde_json::to_value(res).unwrap_or(Value::Null))
        }
        "vigil.exportSiemLog" => {
            let format = params["format"].as_str().unwrap_or("json");
            let event = SiemLogEvent {
                incident_type: params["incident_type"].as_str().unwrap_or("PII_REDACTION").to_string(),
                domain_hash: params["domain_hash"].as_str().unwrap_or("sha256:anon").to_string(),
                timestamp_iso: params["timestamp"].as_str().unwrap_or("2026-10-04T00:00:00Z").to_string(),
                severity: params["severity"].as_u64().unwrap_or(1) as u8,
                rule_id: params["rule_id"].as_str().unwrap_or("VIGIL-101").to_string(),
            };
            match format {
                "cef" => Ok(json!({ "formatted": NativeSiemExporter::format_cef(&event) })),
                "ocsf" => Ok(json!({ "formatted": NativeSiemExporter::format_ocsf(&event) })),
                _ => Ok(json!({ "formatted": NativeSiemExporter::format_json(&event) })),
            }
        }
        "vigil.streamSiemLog" => {
            let endpoint = params["endpoint"].as_str().unwrap_or("");
            let auth = params["authHeader"].as_str();
            let payload = params["payload"].as_str().unwrap_or("{}");
            match NativeSiemExporter::stream_to_endpoint(endpoint, auth, payload) {
                Ok(res) => Ok(res),
                Err(e) => Err(json!({ "code": -32004, "message": format!("SIEM Stream failed: {}", e) })),
            }
        }
        "vigil.setupInstaller" => {
            let src_dir = params["sourceExtensionDir"].as_str();
            let status = VigilInstaller::run_setup(src_dir);
            Ok(serde_json::to_value(status).unwrap_or(Value::Null))
        }
        "vigil.getSetupStatus" => {
            let status = VigilInstaller::run_setup(None);
            Ok(serde_json::to_value(status).unwrap_or(Value::Null))
        }
        "vigil.hardwareSealKey" => {
            let key_hex = params["key_hex"].as_str();
            let require_hw = params["require_hardware"].as_bool().unwrap_or(false);
            let raw_key = key_hex.and_then(|h| {
                if h.len() % 2 != 0 { return None; }
                (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i+2], 16).ok()).collect::<Option<Vec<u8>>>()
            });
            match ENCLAVE_ENGINE.seal_master_key_with_policy(raw_key.as_deref(), require_hw) {
                Ok(record) => Ok(serde_json::to_value(record).unwrap_or(Value::Null)),
                Err(e) => Err(json!({ "code": -32005, "message": format!("Key sealing failed: {}", e) })),
            }
        }
        "vigil.hardwareUnsealKey" => {
            let record: Result<SealedKeyRecord, _> = if params.get("sealed_key").is_some() {
                serde_json::from_value(params.clone())
            } else if let Some(rec) = params.get("record") {
                serde_json::from_value(rec.clone())
            } else {
                serde_json::from_value(params.clone())
            };
            match record {
                Ok(rec) => match ENCLAVE_ENGINE.unseal_master_key(&rec) {
                    Ok(raw_hex) => Ok(json!({ "rawKeyHex": raw_hex, "hardwareBound": rec.hardware_bound })),
                    Err(e) => Err(json!({ "code": -32006, "message": format!("Key unsealing failed: {}", e) })),
                },
                Err(e) => Err(json!({ "code": -32007, "message": format!("Invalid SealedKeyRecord parameters: {}", e) })),
            }
        }
        "vigil.getHardwareSecurityStatus" => {
            let status = ENCLAVE_ENGINE.get_security_status();
            Ok(serde_json::to_value(status).unwrap_or(Value::Null))
        }
        "vigil.verifyFileIntegrity" => {
            let default_dir = VigilInstaller::get_vigil_app_dir().join("extension");
            let target_dir_str = params["targetDir"].as_str();
            let target_path = target_dir_str
                .map(PathBuf::from)
                .unwrap_or(default_dir);

            let manifest: HashMap<String, String> = if let Some(m) = params.get("manifest") {
                serde_json::from_value(m.clone()).unwrap_or_default()
            } else {
                HashMap::new()
            };

            let report = FileIntegrityEngine::verify_directory(&target_path, &manifest);
            Ok(serde_json::to_value(report).unwrap_or(Value::Null))
        }
        "vigil.restoreFileIntegrity" => {
            let target_dir_str = params["targetDir"].as_str().unwrap_or("");
            let backup_dir_str = params["backupDir"].as_str().unwrap_or("");
            let files: Vec<String> = if let Some(arr) = params["files"].as_array() {
                arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
            } else {
                Vec::new()
            };

            let res = FileIntegrityEngine::restore_tampered_files(
                Path::new(target_dir_str),
                Path::new(backup_dir_str),
                &files,
            );
            Ok(serde_json::to_value(res).unwrap_or(Value::Null))
        }
        "vigil.generateIntegrityManifest" => {
            let default_dir = VigilInstaller::get_vigil_app_dir().join("extension");
            let target_dir_str = params["targetDir"].as_str();
            let target_path = target_dir_str
                .map(PathBuf::from)
                .unwrap_or(default_dir);

            match FileIntegrityEngine::generate_manifest(&target_path, &["vigil-integrity.json", ".git", ".DS_Store"]) {
                Ok(manifest) => Ok(json!({ "manifest": manifest, "count": manifest.len() })),
                Err(e) => Err(json!({ "code": -32008, "message": format!("Manifest generation failed: {}", e) })),
            }
        }
        "vigil.regexScanLinear" => {
            let pattern_str = params["pattern"].as_str().unwrap_or("");
            let text = params["text"].as_str().unwrap_or("");
            let find_all = params["find_all"].as_bool().unwrap_or(true);

            match regex::Regex::new(pattern_str) {
                Ok(re) => {
                    if find_all {
                        let matches: Vec<String> = re.find_iter(text).map(|m| m.as_str().to_string()).collect();
                        Ok(json!({
                            "matched": !matches.is_empty(),
                            "count": matches.len(),
                            "matches": matches,
                            "linearTimeGuaranteed": true
                        }))
                    } else {
                        let hit = re.find(text).map(|m| m.as_str().to_string());
                        Ok(json!({
                            "matched": hit.is_some(),
                            "firstMatch": hit,
                            "linearTimeGuaranteed": true
                        }))
                    }
                }
                Err(e) => Err(json!({ "code": -32009, "message": format!("Invalid regex syntax: {}", e) })),
            }
        }
        "vigil.phashGrayscale" => {
            // Blueprint #6 companion: perceptual hash over a grayscale
            // downsample computed by the caller (canvas). Returns the 64-bit
            // hash as hex for blocklist comparison on the JS side.
            let pixels: Vec<u8> = params["pixels"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect())
                .unwrap_or_default();
            let width = params["width"].as_u64().unwrap_or(0) as usize;
            let height = params["height"].as_u64().unwrap_or(0) as usize;
            match phash::perceptual_hash(&pixels, width, height) {
                Some(hash) => Ok(json!({ "hash": format!("{:016x}", hash) })),
                None => Err(json!({ "code": -32010, "message": "Invalid pixel buffer for perceptual hashing" })),
            }
        }
        _ => Err(json!({ "code": -32601, "message": format!("Method not found: {}", method) })),
    };

    match res {
        Ok(result) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        },
        Err(err_obj) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(err_obj),
        },
    }
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        match read_native_message(&mut reader) {
            Ok(msg_str) => {
                if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&msg_str) {
                    let response = handle_rpc_request(req);
                    if let Ok(resp_str) = serde_json::to_string(&response) {
                        let _ = write_native_message(&mut writer, &resp_str);
                    }
                }
            }
            Err(_) => break, // Exit cleanly on EOF / disconnect
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_with_client(client_secret: &P256SecretKey) -> (String, Aes256Gcm) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let client_pub_b64 = b64_encode(client_secret.public_key().to_encoded_point(false).as_bytes());
        let hs_req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "vigil.auth.handshake".into(),
            params: Some(json!({
                "extension_id": "vigil-guardian-id",
                "origin": "chrome-extension://vigil-guardian-id/",
                "client_pub_key": client_pub_b64
            })),
        };
        let hs_resp = handle_rpc_request(hs_req);
        let result = hs_resp.result.expect("handshake must succeed");
        assert_eq!(result["channel"], "encrypted");
        let token = result["session_token"].as_str().unwrap().to_string();

        let host_bytes = b64_decode(result["host_pub_key"].as_str().unwrap()).expect("host pub key");
        let host_pk = P256PublicKey::from_sec1_bytes(&host_bytes).expect("valid SEC1 point");
        let shared = diffie_hellman(client_secret.to_nonzero_scalar(), host_pk.as_affine());
        let key = shared.raw_secret_bytes().to_vec();
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
        (token, cipher)
    }

    #[test]
    fn test_encrypted_channel_roundtrip() {
        let client_secret = P256SecretKey::random(&mut OsRng);
        let (token, cipher) = handshake_with_client(&client_secret);

        // Encrypt an inner privileged request with the shared key
        let inner = json!({
            "jsonrpc": "2.0", "id": 2,
            "method": "vigil.regexScanLinear",
            "params": { "pattern": "\\d+", "text": "abc 123" }
        });
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), serde_json::to_vec(&inner).unwrap().as_slice())
            .unwrap();

        let frame_req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(3),
            method: "vigil.encrypted_frame".into(),
            params: Some(json!({
                "auth_token": token, "seq": 1,
                "iv": b64_encode(&nonce), "ciphertext": b64_encode(&ct)
            })),
        };
        let frame_resp = handle_rpc_request(frame_req);
        let fr = frame_resp.result.expect("encrypted frame must be answered");

        // The response must decrypt with the same key and carry the inner result
        let resp_iv = b64_decode(fr["iv"].as_str().unwrap()).unwrap();
        let resp_ct = b64_decode(fr["ciphertext"].as_str().unwrap()).unwrap();
        let pt = cipher
            .decrypt(Nonce::from_slice(&resp_iv), resp_ct.as_slice())
            .expect("response must decrypt with the derived channel key");
        let inner_resp: Value = serde_json::from_slice(&pt).unwrap();
        assert_eq!(inner_resp["result"]["matched"], true);
        assert_eq!(inner_resp["result"]["matches"], json!(["123"]));
        assert!(inner_resp["seq"].as_u64().unwrap() >= 1, "response carries a host seq for client replay checks");
    }

    #[test]
    fn test_replay_rejected() {
        let client_secret = P256SecretKey::random(&mut OsRng);
        let (token, cipher) = handshake_with_client(&client_secret);

        let inner = json!({"jsonrpc": "2.0", "id": 2, "method": "vigil.ping", "params": {}});
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), serde_json::to_vec(&inner).unwrap().as_slice())
            .unwrap();
        let frame = |seq: u64| JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(seq),
            method: "vigil.encrypted_frame".into(),
            params: Some(json!({
                "auth_token": token, "seq": seq,
                "iv": b64_encode(&nonce), "ciphertext": b64_encode(&ct)
            })),
        };

        assert!(handle_rpc_request(frame(1)).result.is_some(), "first frame accepted");
        let replay = handle_rpc_request(frame(1));
        assert!(replay.error.is_some());
        assert!(replay.error.unwrap()["message"].as_str().unwrap().contains("REPLAY_ATTACK_DETECTED"));
    }

    #[test]
    fn test_keychain_allowlist_blocks_foreign_services() {
        let client_secret = P256SecretKey::random(&mut OsRng);
        let (token, _cipher) = handshake_with_client(&client_secret);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(9),
            method: "vigil.keychainGet".into(),
            params: Some(json!({
                "auth_token": token,
                "service": "com.apple.something.private",
                "account": "victim"
            })),
        };
        let resp = handle_rpc_request(req);
        let err = resp.error.expect("foreign service must be rejected");
        assert!(err["message"].as_str().unwrap().contains("FORBIDDEN_SERVICE"));
    }

    #[test]
    fn test_unencrypted_frame_rejected_when_no_channel_key() {
        // Handshake WITHOUT a client pub key → no shared key
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "vigil.auth.handshake".into(),
            params: Some(json!({ "extension_id": "vigil-guardian-id" })),
        };
        let result = handle_rpc_request(req).result.unwrap();
        let token = result["session_token"].as_str().unwrap().to_string();
        assert_eq!(result["channel"], "plaintext");

        let frame_req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(2),
            method: "vigil.encrypted_frame".into(),
            params: Some(json!({ "auth_token": token, "seq": 1, "iv": "AAAA", "ciphertext": "BBBB" })),
        };
        let resp = handle_rpc_request(frame_req);
        assert!(resp.error.unwrap()["message"].as_str().unwrap().contains("CHANNEL_NOT_ESTABLISHED"));
    }

    #[test]
    fn test_downgrade_rejected_for_prod_extension() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: "vigil.auth.handshake".into(),
            params: Some(json!({ "extension_id": "emkokehejldjlfljlhhcimnfefcjcmon" })),
        };
        let resp = handle_rpc_request(req);
        assert!(resp.error.is_some(), "handshake without client pub key must fail for prod extension");
        assert!(resp.error.unwrap()["message"].as_str().unwrap().contains("ENCRYPTION_REQUIRED"));
    }

    #[test]
    fn test_sequence_jump_anomaly_rejected() {
        let client_secret = P256SecretKey::random(&mut OsRng);
        let (token, cipher) = handshake_with_client(&client_secret);

        let inner = json!({"jsonrpc": "2.0", "id": 1, "method": "vigil.ping", "params": {}});
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), serde_json::to_vec(&inner).unwrap().as_slice())
            .unwrap();

        let frame = |seq: u64| JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(seq),
            method: "vigil.encrypted_frame".into(),
            params: Some(json!({
                "auth_token": token, "seq": seq,
                "iv": b64_encode(&nonce), "ciphertext": b64_encode(&ct)
            })),
        };

        // Seq 1 is fine
        assert!(handle_rpc_request(frame(1)).result.is_some());
        // Seq 50,000 exceeds MAX_SEQ_SKIP (10,000)
        let jump = handle_rpc_request(frame(50_000));
        assert!(jump.error.is_some());
        assert!(jump.error.unwrap()["message"].as_str().unwrap().contains("SEQUENCE_ANOMALY"));
    }
}

