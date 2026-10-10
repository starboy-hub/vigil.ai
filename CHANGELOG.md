# Changelog

All notable changes to Vigil AI Guardian will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-10

### Initial Clean Slate Release — Vigil AI Guardian v1.0.0

Vigil AI Guardian is a 100% local-first, zero-trust endpoint DLP and AI privacy shield designed to inspect, sanitize, and defend against AI-era threats across browsers, IDEs, and autonomous agent loops.

#### Core Capabilities & Architecture

- **Zero-Trust Identity Vault & Blind Indexing**: AES-256-GCM encrypted local vault for sensitive PII and credentials. Employs salted SHA-256 blind indexing so candidate matching occurs without keeping plaintext dictionaries in the DOM, with resilient error handling.
- **Fail-Closed Byzantine Consensus Firewall**: 3-tier local consensus engine (Regex deterministic filter, fine-tuned MobileBERT neural classifier in offscreen WebGPU/WASM, and semantic entropy analysis) with Byzantine quorum rules (2+ BLOCK = hard block; 1 BLOCK + 1+ ABSTAIN = soft block with user override; no BLOCK = pass).
- **Adversarial Pre-Processing Engine**: Normalizes prompt text prior to analysis by stripping zero-width steganography, folding Cyrillic/Greek homoglyphs, NFKD fullwidth folding, leet unfolding, and whitespace canonicalization.
- **Loopback Proxy Interception**:
  - `ide_proxy.rs` (port 8888): High-throughput forward proxy protecting IDE assistants (Cursor, GitHub Copilot, Ollama), enforcing per-agent token limits and stripping credentials before egress.
  - `vigil-agent-firewall.js` (port 8765): Forward proxy intercepting autonomous agent CLI/tool calls (`HTTP_PROXY=127.0.0.1:8765`) with live Server-Sent Events (SSE) streaming token reconstitution.
- **Synthetic Media & Vision Steganography Canary**: 64-bit DCT perceptual hashing (`vigil.phashGrayscale` native and JS fallback) against known synthetic-media blocklists, alongside offscreen spatial frequency Laplacian analysis and alpha-channel steganography inspection.
- **Native Desktop Companion (Rust)**:
  - Ephemeral ECDH P-256 handshake with AES-256-GCM framed native messaging channel.
  - OS Keychain integration strictly bound to Vigil-namespaced services.
  - Audio spectral canary detecting ultrasonic and high-frequency audio covert channels.
  - File integrity monitor calculating SHA-256 manifests with automatic tampering detection.
- **Differential-Privacy Swarm Threat Exchange**: Opt-in privacy-preserving LoRA adapter delta sharing using Gaussian noise mechanism (ε = 1.0, δ = 10⁻⁵) with element-wise federated aggregation.
- **Enterprise SIEM & Compliance Exporter**: Real-time event formatting supporting CEF, OCSF, and JSON with loopback/HTTPS streaming delivery.
- **Hardened Security & CI/CD**:
  - Immutable commit SHA pinning for all GitHub Actions.
  - Pinned exact patch dependency versions in `desktop/Cargo.toml`.
  - Zero-exception security audit enforcement (`npm audit`, `cargo audit`).
  - Gated continuous adversarial benchmarking (≥95% catch rate, ≤5% FP).
