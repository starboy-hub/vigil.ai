<!--
Sync Impact Report:
- Version change: [Uninitialized] → 1.0.0 (Initial Ratification)
- Modified principles: Ratified 5 core principles from project architecture and README
  * Principle I: Zero-Cloud & Local-First Invariance (NON-NEGOTIABLE)
  * Principle II: Manifest V3 Compatibility & Low-Latency Execution
  * Principle III: Comprehensive Multi-Tier Testing & Adversarial Benchmarks (NON-NEGOTIABLE)
  * Principle IV: Tiered Severity Routing & Zero Alert Fatigue
  * Principle V: Deterministic Reproducibility & Strict Release Gates
- Added sections:
  * Security & Privacy Architecture Requirements
  * Development Workflow & Quality Gates
  * Governance & Amendment Procedures
- Removed sections: None
- Deferred TODOs: None
-->

# Vigil AI Guardian Constitution

## Core Principles

### I. Zero-Cloud & Local-First Invariance (NON-NEGOTIABLE)
All data scanning, detection, PII masking, tokenization, ONNX inference, and model evaluations MUST execute 100% locally on the user's client machine. Zero user text, prompts, logs, or personal artifacts may ever be transmitted to external servers, cloud services, or telemetry endpoints. Network access is strictly restricted to optional, user-initiated local model downloads and updates with cryptographically verified checksums.
*Rationale: Vigil AI Guardian is designed as a zero-trust AI security shield. Any cloud transmission or telemetry breaks the foundational premise of user privacy and client-side protection.*

### II. Manifest V3 Compatibility & Low-Latency Execution
The extension MUST comply with WebExtensions Manifest V3 (MV3) standards across both Chromium (`dist/`) and Firefox (`dist-firefox/`). The real-time keystroke interception and DOM evaluation pipeline MUST operate within a strict latency ceiling of under 50ms, ensuring zero user-perceptible input lag. Intensive neural network inferences or large-document scans MUST execute asynchronously in background service workers or offscreen documents without locking the browser's active DOM thread.
*Rationale: Security tooling that degrades browser responsiveness or typing fluidity will be disabled by users, defeating its protection objective.*

### III. Comprehensive Multi-Tier Testing & Adversarial Benchmarks (NON-NEGOTIABLE)
A rigorous Test-Driven Development (TDD) approach is mandatory across the codebase. Every new heuristic, sanitizer, or feature MUST be accompanied by comprehensive Jest unit tests and Playwright end-to-end browser tests. Critical detection modules MUST be evaluated against adversarial benchmarks (`npm run benchmark:adversarial`) and verified against industry canaries to guarantee a 0.00% false positive rate on baseline conversational texts.
*Rationale: A data-leak and prompt-injection firewall must possess verifiable, quantifiable precision before deployment to avoid breaking legitimate user interactions or allowing breaches.*

### IV. Tiered Severity Routing & Zero Alert Fatigue
Interceptions MUST be routed into explicit severity categories:
1. **Critical Secrets (Hard Interrupt):** Passwords, high-entropy API keys, private keys, and payment card numbers display a high-visibility blocking warning pill requiring intentional user override.
2. **Medium-Risk Data (Non-Blocking Context):** Financial metrics, health disclosures, and code snippets display subtle inline contextual indicators with quick review options.
3. **Low-Risk PII (Silent Masking):** Names, emails, and phone numbers are silently transformed with privacy-preserving placeholders accompanied by ephemeral status toasts.
Modals and intrusive alerts MUST NEVER be triggered for benign or low-severity events.
*Rationale: Excessive alerts desensitize users to real threats. Tiered handling preserves user workflow while aggressively guarding high-stakes secrets.*

### V. Deterministic Reproducibility & Strict Release Gates
All extension builds and packages MUST be strictly deterministic and verifiable across platforms. Before any release candidate is published, it MUST pass the automated release gate (`npm run release:gate`), zero-warning ESLint checks, reproducible build hash verifications (`npm run build:hash`), and clean dependency security audits.
*Rationale: Zero-trust client extensions require verifiable supply chains so contributors and organizations can audit that the distributed binaries match the open-source code.*

## Security & Privacy Architecture Requirements

- **Zero-Telemetry Standard:** No analytics, crash reporters, or tracking beacons may be incorporated into the codebase.
- **Least-Privilege MV3 Permissions:** Host permissions and browser API entitlements MUST be restricted to the minimum set required for content script injection and secure local storage.
- **Secure Model Management:** Machine learning weights (`@huggingface/transformers`, `onnxruntime-web`) MUST be pinned to verified SHA-256 hashes and loaded through isolated local worker threads.

## Development Workflow & Quality Gates

- **Continuous Verification:** Every pull request MUST pass `npm run build:all`, `npm run lint`, `npm test`, and `npm run test:e2e` in CI prior to review.
- **Regression Guarding:** Any bug report involving a bypass or false negative MUST be accompanied by a reproducible test case added to the permanent test harness before a fix is merged.
- **Semantic Versioning:** Releases adhere to SemVer (MAJOR.MINOR.PATCH) reflecting architectural and compatibility changes.

## Governance

1. **Constitutional Precedence:** This constitution establishes the supreme technical principles for Vigil AI Guardian. All architecture decisions, code reviews, pull requests, and roadmap items MUST comply with these principles.
2. **Amendment Procedure:** Amendments require an explicit rationale, documented consensus among maintainers, and a semantic version increment.
   - **MAJOR bump:** Modifying, weakening, or removing core principles.
   - **MINOR bump:** Introducing new principles, security tiers, or architectural requirements.
   - **PATCH bump:** Wording refinements, documentation alignments, or non-normative clarifications.
3. **Compliance Audits:** All code reviews MUST explicitly check pull requests against the Zero-Cloud and Multi-Tier Testing invariants.

**Version**: 1.0.0 | **Ratified**: 2026-10-13 | **Last Amended**: 2026-10-13
