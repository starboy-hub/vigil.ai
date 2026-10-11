VIGIL AI: SECURITY AND ENGINEERING BLUEPRINT
Repository: https://github.com/starboy-hub/vigil.ai
Review date: 11 October 2026

PURPOSE

The goal is to make Vigil AI as secure, reliable, and useful as possible without breaking its core functionality.

The wrong approach would be to remove broad website support, disable important scanning features, or add so many security checks that the extension becomes slow and frustrating. The right approach is to preserve the tool's intended behavior while making its security boundaries explicit, its failures predictable, and its detection results more trustworthy.

The review should validate each finding against actual code paths, data flows, configuration, and runtime behavior before assigning a final severity.

Four priorities:
1. Preserve the user experience and existing functionality.
2. Fix vulnerabilities at their root cause instead of adding superficial patches.
3. Measure whether each change improves security without creating false positives, missed detections, or performance regressions.
4. Verify the result through reproducible tests, adversarial testing, and realistic browser workflows.

PART I. SECURITY REMEDIATION BLUEPRINTS

BLUEPRINT 01. MAKE THE NATIVE BRIDGE FAIL CLOSED
Priority: P0
Files: src/background/native-bridge.js

Current evidence:
The bridge catches a failed cryptographic handshake and retries with an unkeyed handshake in two request paths. It also permits a successfully authenticated session to remain active without establishing the encrypted channel.

Why this matters:
The native companion can access capabilities beyond those of an ordinary content script. Depending on its implementation, those capabilities may include local files, OS keychain access, IDE traffic, or local AI services.

If encryption is intended to protect this channel, a cryptographic failure must not silently change the security properties of the session.

Authentication and encryption serve different purposes. A valid session token does not, by itself, prove that all subsequent traffic is encrypted or protected against replay.

Blueprint:
- Remove the automatic unkeyed retry.
- Treat failed key import, ECDH derivation, or authentication as a failed session.
- Keep non-sensitive status checks available through a clearly separate, explicitly unauthenticated path if needed.
- Require encryption for every operation classified as sensitive.
- Validate message types, sequence numbers, and response schemas.
- Reject encrypted frames that lack a valid sequence number.
- Clear pending requests, tokens, keys, and session state on disconnect.
- Do not log tokens, prompts, decrypted frames, or other sensitive payloads.

Acceptance tests:
- Failed ECDH negotiation never permits a keychain operation.
- Invalid session tokens are rejected.
- Replayed encrypted frames are rejected.
- Missing or malformed sequence numbers are rejected.
- A daemon restart cannot reuse the previous session.
- Normal successful sessions still support all intended native features.

Success criterion:
Every privileged operation has a documented authentication and encryption requirement, and no failure path bypasses it.

BLUEPRINT 02. CORRECT CRYPTOGRAPHIC KEY HANDLING
Priority: P0
Files: src/background/native-bridge.js, src/background/vigil-vault.js

Current evidence:
The source creates an ECDH key pair with extractable: true and derives an AES key with extractable: true. The vault also stores its AES key in browser-local storage and imports it as extractable.

Why this matters:
Extractability does not mean an attacker can automatically retrieve a key. It does mean the application permits key export through Web Crypto APIs if code with access to that key invokes the appropriate operation.

The vault's storage design also places the encrypted data and the material needed to decrypt it within the same local trust boundary.

Blueprint:
- Make derived AES session keys non-extractable.
- Minimize private-key exportability while retaining the ability to send the ECDH public key.
- Never export a private key for routine communication.
- Use a fresh session key for each authenticated session.
- Use cryptographically secure randomness exclusively.
- Authenticate handshake context, protocol version, and peer identity.
- Use explicit protocol versioning instead of silently downgrading encryption.

For the vault:
- Use the OS credential store through the native companion where available.
- Offer a passphrase-derived encryption key as a portable alternative.
- Keep a device-local mode for users who prioritize convenience.
- Clearly explain the different threat models.

The existing vault code contains a PBKDF2-SHA-256 derivation function with 600,000 iterations. This is a useful starting point, but it is not sufficient by itself. The derivation must be integrated into a complete key lifecycle, with random salts, correct key verification, migration, and recovery behavior.

Do not change encryption formats without a migration plan. Existing vault data must remain recoverable.

Acceptance tests:
- Key export attempts fail for non-extractable keys.
- Existing vaults migrate successfully.
- Wrong passphrases never overwrite stored data.
- New sessions use new key material.

BLUEPRINT 03. REMOVE INSECURE RANDOMNESS FALLBACK
Priority: P0
File: src/background/native-bridge.js

Current evidence:
The bridge's getRandomValues() helper falls back to Math.random() if the Web Crypto and Node cryptographic APIs are unavailable.

Why this matters:
Math.random() is not designed for cryptographic security. This fallback should not exist in a security-sensitive implementation.

Blueprint:
Replace the fallback with a hard failure. Adapt this pattern to the project's supported browser and Node runtimes.

Example:
function getRandomValues(arr) {
  const cryptoApi =
    globalThis.crypto?.getRandomValues
      ? globalThis.crypto
      : globalThis.crypto?.webcrypto;

  if (!cryptoApi?.getRandomValues) {
    throw new Error("Cryptographically secure randomness unavailable");
  }

  return cryptoApi.getRandomValues(arr);
}

Use the same rule for:
- Session nonces.
- AES-GCM IVs.
- Vault encryption keys.
- Pseudonym identifiers.
- Authentication tokens.
- Honeytoken generation.

Acceptance tests:
- Simulating unavailable cryptographic randomness stops sensitive operations.
- No insecure fallback can generate session keys, tokens, or encryption IVs.

BLUEPRINT 04. PREVENT SILENT VAULT CORRUPTION AND DATA LOSS
Priority: P0
File: src/background/vigil-vault.js

Current evidence:
The vault's decryptJson() function catches decryption errors and returns an error object. The subsequent loading code defaults missing entries and trusted arrays to empty arrays. This can make corrupted or undecryptable data appear to be an empty vault. A later write could overwrite the original encrypted data.

Why this matters:
This is primarily a data-integrity and recoverability concern. It becomes a security concern when users depend on the vault to preserve sensitive identity mappings.

Blueprint:
Implement explicit vault states:
- EMPTY: no vault has been created.
- LOCKED: valid vault exists but the key is unavailable.
- READY: vault decrypted and validated successfully.
- CORRUPT: decryption or integrity validation failed.
- MIGRATION_REQUIRED: vault format is old but potentially recoverable.

Never treat CORRUPT as EMPTY.

Required changes:
- Preserve the original encrypted blob on decryption failure.
- Block writes until the user resolves corruption.
- Offer recovery from an authenticated backup.
- Validate schema versions and entry types after decryption.
- Write new vault data atomically where the storage mechanism permits.
- Keep a recoverable previous version during migration.
- Explain what the user can do without displaying sensitive contents.

Review clearAll() as well. It removes vault data and pseudonym mappings but leaves the stored vault key behind. Decide whether this means "delete entries" or "reset the vault," and implement the user-visible behavior accordingly.

Acceptance tests:
- Corrupted vault data is never silently replaced with an empty vault.
- Users can recover from a backup.
- Explicit reset removes all intended data and key material.

BLUEPRINT 05. ELIMINATE UNSAFE HTML RENDERING
Priority: P0
File: src/content/content.js

Current evidence:
The consensus modal inserts dynamic values into innerHTML, including details and style-related strings. The vote display also interpolates classifier names and vote values into HTML.

Why this matters:
This does not establish a working XSS exploit. The risk depends on whether the interpolated values can be controlled by untrusted page content, model output, or another external source. However, it is unnecessary to rely on that trust assumption for most of these fields.

Blueprint:
- Build the modal with document.createElement().
- Insert plain text with textContent.
- Set CSS properties through validated values.
- Allow-list classifier names and vote values.
- Avoid interpolating external values into HTML or CSS.
- If rich text is essential, use a maintained sanitizer with a strict allow-list.

Example:
const detailElement = document.createElement("div");
detailElement.textContent = details;
modal.appendChild(detailElement);

This preserves displayed content without parsing it as HTML. OWASP recommends safe DOM APIs and warns against passing untrusted data to innerHTML.

Acceptance tests:
- Inject HTML payloads into every dynamic modal field.
- Payloads display as text and do not create executable elements or event handlers.

BLUEPRINT 06. PRESERVE BROAD WEBSITE COVERAGE WHILE REDUCING PERMISSION RISK
Priority: P1
File: src/manifest.json

Current evidence:
The manifest requests <all_urls> host permissions and injects a large set of content scripts into all matching frames.

Why this matters:
Vigil's purpose is broad protection, so removing universal website support outright would damage its value. Broad access also increases the amount of sensitive page data the extension may encounter and the potential impact of an extension compromise.

Chrome supports optional host permissions and runtime permission requests. OWASP recommends limiting extension permissions to what the feature actually needs.

Blueprint:
Use three access modes:

Mode A. On demand
The user activates Vigil on the current site. Best for minimal permissions and privacy-conscious users.

Mode B. Protected sites
Continuous monitoring on user-selected AI platforms, webmail services, and other supported sites.

Mode C. All-site protection
The existing broad-coverage experience, enabled through explicit permission and a clear explanation.

Implementation requirements:
- Keep all-site protection available.
- Use optional host permissions where feasible.
- Separate detection logic from permission acquisition.
- Apply sensitive-site exclusions consistently.
- Do not run expensive AI inference on unrelated pages.
- Test nested frames and supported embedded AI interfaces.
- Provide a clear status indicator when Vigil cannot access a site.

Acceptance tests:
- All three modes work.
- Permission denial does not crash the extension.
- Users can enable broad access later without losing settings.

BLUEPRINT 07. MAKE DOM-BASED SCANNING SAFE AND PREDICTABLE
Priority: P1

Why this matters:
Vigil needs to inspect page content to identify sensitive prompts, phishing content, and injection attempts. But the page is controlled by a website, not by Vigil.

Content scripts normally execute in an isolated JavaScript world, but they interact with the same page DOM. Chrome's extension guidance makes the distinction between isolated and main execution worlds explicit.

Blueprint:
- Keep sensitive data and cryptographic keys in the extension's privileged contexts.
- Treat all DOM content as untrusted.
- Never rely on page-provided data as proof of authorization.
- Validate every message sent from a content script to the background worker.
- Validate sender identity, allowed action names, and input schemas.
- Do not place real secrets in page DOM attributes, hidden elements, or custom events.
- Render sensitive diagnostics in extension-owned UI, not in the website's DOM.

Page scripts may inspect data rendered into their DOM, even when the extension uses a Shadow DOM for styling. OWASP recommends extension-controlled popups, options pages, or side panels for sensitive UI.

Acceptance tests:
- A hostile page cannot invoke privileged background operations, read vault contents, or obtain sensitive diagnostic data by manipulating DOM elements or sending malformed messages.

BLUEPRINT 08. REDESIGN HONEYTOKENS WITHOUT DISCARDING THE DETECTION FEATURE
Priority: P1
Feature: Agent Honeytoken System

Current evidence:
The README describes planting invisible decoy credentials in the DOM of every page and alerting when they are echoed back.

Why this matters:
A decoy can help detect unauthorized data access. But placing it in a page DOM means scripts on that page may be able to read it. It may also be picked up by accessibility tools, crawlers, browser extensions, or unrelated page logic.

A detected canary can be useful evidence, but it does not automatically establish which component accessed it or whether an actual secret was stolen.

Blueprint:
- Make honeytokens opt-in initially, with a clear explanation.
- Use synthetic, non-functional identifiers. Never create real-looking credentials that could be mistaken for valid secrets.
- Scope each token to a session and origin.
- Avoid placing tokens on unrelated websites.
- Record only the minimum event metadata needed for diagnosis.
- Distinguish "canary observed" from "confirmed exfiltration."
- Measure false alarms caused by page scripts and benign automation.
- Provide a kill switch and a per-site exclusion.

Acceptance tests:
Test against ordinary page scripts, screen readers, browser automation, and controlled scraping scenarios. Verify that canary events do not reveal real identity data.

BLUEPRINT 09. MAKE PRIVACY CLAIMS MATCH ACTUAL DATA FLOWS
Priority: P1

Current evidence:
The README states that all detection and inference happen locally and that no data leaves the device. It also documents optional SIEM telemetry and a self-hosted threat exchange.

Why this matters:
These features can coexist, but the privacy statement needs to distinguish local default behavior from explicitly enabled integrations.

Blueprint:
Create a data-flow inventory covering:

- Raw prompts: Local by default. Never transmit without an explicit, documented feature requiring it.
- PII and credentials: Never include in routine diagnostics or telemetry.
- Detection events: Store locally with configurable retention.
- Threat signatures: Share only when the user enables the feature.
- Model updates: Validate source, version, and integrity before activation.
- SIEM events: Require explicit configuration and disclose which fields are sent.
- Vault contents: Never include in logs, crash reports, or analytics.

Add automated network-egress tests that monitor the extension and companion during ordinary workflows. Test every optional integration separately.

Acceptance tests:
- A default installation produces no unauthorized external data transfers.
- Optional integrations transmit only documented fields after activation.
- Users can disable integrations and remove locally retained event data.

BLUEPRINT 10. ESTABLISH A SAFE PSEUDONYMIZATION AND REHYDRATION BOUNDARY
Priority: P0
Files: src/content/modules/semantic-abstractor.js, src/content/modules/rehydration-engine.js, src/background/vigil-vault.js

Current evidence:
Vigil's design replaces real identities with surrogates before sending prompts to an AI platform, then restores real identities in responses. The README describes this as a way to preserve reasoning utility without exposing real context to the remote model.

Why this matters:
Rehydration creates a second sensitive-data boundary. If the replacement engine restores a real identity in the wrong location, the original secret could reappear in content that the user later shares or submits.

Blueprint:
- Use opaque, unpredictable placeholders rather than realistic surrogate strings where possible.
- Scope each mapping to a site, session, and specific replacement operation.
- Restore only exact known placeholders.
- Restore only in approved AI response text nodes.
- Never restore inside links, URLs, attributes, scripts, form controls, or unrelated page content.
- Do not rehydrate responses from untrusted origins or unrelated frames.
- Validate the mapping and session before restoring any value.
- Provide a preview of restored output when the context is ambiguous.
- Clear mappings according to an explicit retention policy.

Preserve consistency across conversations by keeping mappings stable within the authorized session. Do not require users to manually reconstruct every redacted entity.

Acceptance tests:
- A model cannot trigger rehydration by merely mentioning a real name or secret.
- Placeholder collisions do not reveal unrelated identities.
- Rehydration cannot modify URLs, script contexts, or user-authored messages.

PART II. DETECTION QUALITY AND AI DEFENSE BLUEPRINTS

BLUEPRINT 11. REPLACE THE HEADLINE SECURITY SCORE WITH A REAL EVALUATION PROGRAM
Priority: P0
File: SECURITY_SCORE.md

Current evidence:
The published score reports 160 out of 160 mutated attacks detected and zero false positives among 20 benign examples. The documented process starts from seed attacks and applies a limited set of transformations.

Why this matters:
A 100% result on a small, generated test set does not establish 100% real-world detection. The system may recognize the mutation patterns used by the test generator while missing different attacks or incorrectly flagging legitimate content.

Research published on 2 October 2026 found that prompt-injection detector rankings transferred poorly between benchmarks. In that study, some detectors had false-positive rates exceeding 90% on certain agent-style outputs. This is a preprint, not a universal estimate of production performance, but it shows why benchmark selection matters.

Blueprint:
Build four independent datasets:
- Training: Used to develop rules and models.
- Validation: Used to choose thresholds.
- Held-out test: Used only for final performance estimates.
- Live regression corpus: Sanitized, reproducible cases from confirmed bugs and user-reported mistakes.

Measure these separately:
- Recall: How many real threats are detected.
- Precision: How many alerts actually correspond to threats.
- False-positive rate: How often benign content is incorrectly flagged.
- False-negative rate: How often threats pass undetected.
- Latency: How much delay the user experiences.
- Utility preservation: Whether masking and rewriting preserve the intended task.
- Coverage: Which websites, input types, languages, and threat classes are actually tested.

Report results by threat class and by operating mode. Measure the false-positive rate at the thresholds used in production, not only at the best threshold on a test set.

Use held-out, previously unseen attacks. Include realistic benign text such as security documentation, fictional examples, code snippets, and discussions of prompt injection itself.

Acceptance criteria:
Release decisions require pre-agreed recall, precision, latency, and utility targets. A single headline score cannot override a failure in a critical threat category.

BLUEPRINT 12. TREAT PROMPT INJECTION AS A LAYERED SECURITY PROBLEM
Priority: P0
Feature: Prompt Injection Firewall

Current evidence:
The README lists direct instruction patterns, delimiter attacks, encoded payloads, and invisible Unicode characters.

Why this matters:
Prompt injection is a problem of instruction hierarchy, context, and permitted actions. A malicious instruction can be phrased naturally, embedded in otherwise useful content, or adapted to bypass known patterns.

A browser extension can reduce exposure before submission. It cannot guarantee that every downstream AI model or agent will correctly distinguish trusted instructions from untrusted content.

Research such as PromptArmor reports promising detection and sanitization results on specific benchmarks, while later work emphasizes that performance may not transfer to other environments. The correct lesson is to evaluate multiple defense layers, not to assume one classifier solves the problem.

Blueprint:
1. Normalize Unicode and common encodings without destroying the original text.
2. Apply fast deterministic rules for known patterns.
3. Use a local classifier for ambiguous content when enabled.
4. Use deeper local analysis only when the expected benefit justifies the latency.
5. Distinguish suspicious quoted material from instructions the user is actually following.
6. Explain why a prompt was flagged and show the exact affected region.
7. Let users review, edit, mask, or proceed according to policy.
8. Keep hard blocks for clearly defined, high-confidence policy violations.
9. Re-evaluate the final prompt after masking or paraphrasing.

Do not let the detection model's output directly execute an action. A classifier should produce a structured verdict, confidence, evidence, and reason. A separate policy layer should decide what happens next.

Acceptance tests:
Test direct and indirect injection, multilingual instructions, obfuscated content, benign security research, quoted attacks, and adaptive attacks from held-out sources.

BLUEPRINT 13. IMPROVE PII AND SECRET DETECTION WITHOUT DESTROYING PROMPT MEANING
Priority: P1
Files: src/content/modules/detection-engine.js, src/content/modules/secret-engine.js, src/content/modules/semantic-abstractor.js

Current evidence:
The README describes regex, entropy, pattern matching, semantic analysis, and pseudonymization.

Why this matters:
Overly aggressive masking makes an AI assistant less useful. Under-masking allows private information to escape.

For example, a medical prompt may need to preserve the relationship between a symptom, duration, medication, and age range while replacing the patient's identity. Replacing every potentially sensitive term can destroy the clinical meaning.

Blueprint:
Use a typed detection pipeline:
- Exact high-confidence patterns for known secret formats.
- Validation rules for structured identifiers.
- Context-aware detection for names, health information, and financial disclosures.
- Entropy as supporting evidence, not a standalone secret detector.
- User-managed identity entries with explicit controls.
- Type-preserving replacement for fields whose meaning must remain intact.

Separate detection from the masking policy. A detection engine identifies a candidate. A policy engine decides whether to mask, warn, or allow.

For pseudonymization:
- Preserve relationships between entities.
- Use consistent mappings within the intended scope.
- Do not claim perfect semantic equivalence.
- Show users when paraphrasing changes meaning.
- Re-scan the transformed prompt before submission.

Acceptance tests:
Evaluate precision and recall by PII category, including realistic synthetic examples, multilingual content, code, medical text, financial discussions, and ordinary text that resembles a secret.

BLUEPRINT 14. PREVENT UNSAFE ONLINE LEARNING AND FEEDBACK POISONING
Priority: P1
Feature: Local LoRA, DPO, and self-play

Current evidence:
The README states that Mask and Allow actions provide training signals and that idle self-play generates adversarial mutations for further training.

Why this matters:
A user choosing Allow does not necessarily mean the content is objectively safe. A user choosing Mask may be expressing a privacy preference rather than identifying an attack.

If those actions directly update a live detector, the model can learn noisy labels. Synthetic self-play can also improve performance on generated mutations while reducing performance on real attacks.

Blueprint:
- Make adaptive training opt-in.
- Separate the baseline model from the experimental adapter.
- Collect minimal feedback and provide a clear deletion option.
- Train candidate versions offline or in a controlled background job.
- Evaluate candidates on a frozen regression corpus.
- Promote only candidates that pass security and utility gates.
- Roll back automatically if performance degrades.
- Never let a candidate model weaken mandatory policy enforcement.
- Track model version, dataset version, and evaluation results.

Acceptance tests:
A stream of incorrect Allow labels cannot disable core secret detection. Training on synthetic attacks cannot ship a model that fails the held-out regression suite.

BLUEPRINT 15. RE-SCOPE VISION AND PROVENANCE CLAIMS
Priority: P1
Feature: Multimodal Vision Firewall

Current evidence:
The README describes perceptual hashing, spatial-frequency analysis, alpha-channel analysis, and C2PA metadata inspection.

Why this matters:
These methods answer different questions:
- Perceptual hashing can identify visual similarity.
- Frequency analysis can identify unusual image characteristics.
- Alpha-channel analysis can inspect one possible hiding mechanism.
- C2PA inspection can verify supported provenance assertions.

None of these methods alone establishes that an image is AI-generated or malicious. Missing provenance metadata is not proof of manipulation, and a known perceptual hash cannot cover every altered version of an image.

Blueprint:
- Report the evidence type for each finding.
- Distinguish provenance verification from AI-image classification.
- Use calibrated confidence levels.
- Do not hard-block ordinary images solely because they have unusual frequency characteristics.
- Test resized, compressed, cropped, recompressed, and otherwise transformed images.
- Add representative non-AI images that naturally contain high-frequency detail.
- Keep image inspection optional when it has a material performance cost.

Acceptance tests:
Evaluate false positives on photographs, screenshots, diagrams, scanned documents, and generated images. Publish separate metrics for each technique rather than combining them into a single "AI detection" score.

PART III. RELIABILITY, PERFORMANCE, AND MAINTAINABILITY

BLUEPRINT 16. REDUCE THE COST OF UNIVERSAL MONITORING
Priority: P1
Files: src/manifest.json, src/background/background.js

Current evidence:
The manifest injects a long list of scripts into all matching frames. The background service worker also imports numerous engines at startup.

Why this matters:
Universal coverage is useful, but running every engine on every page can increase memory use, CPU consumption, startup time, and interference with websites.

It can also create more places where untrusted page content interacts with complex logic.

Blueprint:
1. A lightweight bootstrap identifies whether the page has a supported input or relevant content.
2. Cheap deterministic checks run first.
3. More expensive scanning starts only when relevant content changes.
4. Local inference runs only when the first stages need it.
5. Deep scans run asynchronously and use bounded workloads.
6. The extension reports when a scan is incomplete rather than implying full protection.

Use incremental scanning and debounce rapid input events. Avoid rescanning the full page after every keystroke.

Preserve universal support as an option. The optimization should reduce unnecessary work, not remove protection from users who need broad coverage.

Acceptance tests:
Measure CPU, memory, input latency, startup time, and scan completion across representative pages and embedded frames. Verify that optimization does not reduce detection recall.

BLUEPRINT 17. AUDIT DEPENDENCIES AND THE RELEASE SUPPLY CHAIN
Priority: P1
File: package.json

Current evidence:
The manifest pins Playwright 1.44.1, ONNX Runtime Web 1.19.2, ESLint 8.57.1, and other dependencies. These versions justify a current vulnerability and maintenance review, but their presence alone does not prove that the project has an exploitable dependency vulnerability.

Blueprint:
- Run npm audit and a second vulnerability scanner such as OSV-Scanner.
- Review direct and transitive dependencies.
- Update vulnerable dependencies through controlled, tested changes.
- Add automated dependency update pull requests.
- Generate a software bill of materials for releases.
- Pin and verify downloaded model artifacts.
- Produce reproducible builds where practical.
- Ensure release checks run on the exact artifact users receive.
- Add secret scanning and code scanning to CI.
- Document the supported browser and companion versions.

NIST's Secure Software Development Framework provides a useful basis for making these practices part of the development lifecycle instead of treating them as one-off cleanup. NIST SP 800-218 Version 1.1 is the finalized baseline. Check the NIST site for the current status of later revisions.

Acceptance tests:
The release gate rejects known high-risk vulnerabilities unless an explicit, documented exception is approved. Model and extension artifacts are versioned and verifiable.

BLUEPRINT 18. BUILD A REPEATABLE SECURITY TESTING SYSTEM

Current evidence:
The repository defines commands for unit tests, end-to-end tests, adversarial benchmarks, latency benchmarks, and release gates.

The next step is to make those checks evidence of actual behavior.

Required release pipeline:
1. Static analysis: lint, type/schema checks, secret scanning, unsafe DOM sinks.
2. Unit tests: cryptography, vault recovery, policy decisions, normalization.
3. Browser tests: supported websites, frames, contenteditable fields, dynamic DOM changes.
4. Adversarial tests: prompt injection, PII evasion, malicious DOM values, replay attempts.
5. Performance tests: latency, CPU, memory, large prompts, long sessions.
6. Release gate: dependency status, reproducible artifact, regression results, version metadata.

A passing test suite should mean that the tested scenarios passed. It should not be presented as proof that the tool is universally secure.

PART IV. IMPLEMENTATION ROADMAP

Phase 1. Eliminate critical failure paths
- Remove cryptographic downgrade retries.
- Remove insecure randomness fallback.
- Make vault corruption fail safely.
- Fix unsafe HTML interpolation.
- Write regression tests before modifying the affected code.

Phase 2. Prove detection quality
- Build held-out attack and benign datasets.
- Measure precision, recall, false positives, and latency.
- Validate the masking and rehydration pipeline end to end.
- Test realistic website interactions and failure modes.

Phase 3. Reduce unnecessary risk and resource use
- Add optional site permissions while retaining all-site mode.
- Restrict expensive analysis to relevant inputs.
- Make honeytokens and adaptive learning opt-in.
- Document local-only behavior and optional integrations precisely.

Phase 4. Establish release discipline
- Automate dependency and supply-chain checks.
- Require a complete release-gate report.
- Publish reproducible evaluation results and known limitations.
- Review the threat model after each major feature change.

PART V. WHAT SHOULD NOT BE SACRIFICED

Universal protection:
Keep all-site mode, but make access explicit and configurable.

Low-latency scanning:
Run cheap rules first and use heavier analysis only when justified.

Local inference:
Keep local models as the default. Do not require a cloud service to use core protections.

Consistent pseudonyms:
Keep session-scoped mappings and validate rehydration carefully.

Custom user preferences:
Preserve Allow, Mask, and site-specific policies while preventing unsafe learning updates.

Phishing and injection detection:
Combine deterministic rules, context-aware models, and explicit policy enforcement.

Native companion:
Preserve native features, but require secure session establishment for privileged operations.

Privacy:
Keep integrations optional and verify actual network behavior.

PART VI. RESEARCH AND ENGINEERING REFERENCES

1. OWASP Browser Extension Vulnerabilities Cheat Sheet
https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html
Relevant to excessive permissions, message validation, DOM data exposure, XSS, and dependency management.

2. OWASP DOM-based XSS Prevention Cheat Sheet
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
Relevant to safe DOM APIs and avoiding untrusted data in innerHTML.

3. NIST Secure Software Development Framework
https://csrc.nist.gov/projects/ssdf
A structured way to incorporate vulnerability prevention, verification, and release controls into development.

4. NIST SP 800-218
https://csrc.nist.gov/pubs/sp/800/218/final
Secure software development practices.

5. PromptArmor research paper
https://arxiv.org/abs/2507.15219
Studies detection and removal of injected instructions before an agent processes its input. Results are benchmark-specific and should be independently reproduced for Vigil's local environment.

6. Prompt-injection detector benchmark generalization preprint, cited as October 2026
https://arxiv.org/abs/2610.03448
Examines whether detector performance transfers to real agent-style outputs. Verify the paper's current publication status and findings before using it as a formal basis for product claims.

7. Chrome extension permissions documentation
https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
Official guidance for optional host permissions.

8. Chrome content scripts documentation
https://developer.chrome.com/docs/extensions/reference/manifest/content-scripts
Official guidance on content-script execution contexts and behavior.

PART VII. FINAL ASSESSMENT

The most important change is to move from feature claims to verifiable guarantees.

Vigil should be able to demonstrate that:
- Sensitive data does not leave the device through undocumented paths.
- A failed security handshake cannot enable privileged operations.
- Vault failures do not silently destroy data.
- Untrusted page content cannot execute through the extension's UI.
- Prompt-injection defenses work on unseen examples without blocking ordinary work excessively.
- Pseudonymization preserves task utility without accidentally restoring sensitive values in unsafe contexts.
- Every release passes security, performance, and functional regression tests.

The existing architecture can support these goals. The recommended approach is incremental hardening, explicit policy boundaries, measured detection quality, and controlled rollout. It does not require removing Vigil's core features.

SCOPE LIMITATION

This is a repository-source and public-research review, not a completed dynamic penetration test. The code was not executed, the extension was not installed, the test suite was not run, and the native companion's runtime behavior was not verified. Findings that depend on those behaviors should remain open until reproduced.

RECOMMENDED VALIDATION COMMANDS

Run these in a disposable development environment:

git clone https://github.com/starboy-hub/vigil.ai.git
cd vigil.ai
npm ci
npm audit
npm test
npm run lint
npm run release:gate

If the Rust companion is part of the build, run its Cargo tests from the appropriate project directory.

For the native bridge, test failed ECDH setup, failed key derivation, missing session tokens, malformed encrypted frames, and replayed sequence numbers. Confirm that no privileged request succeeds through an unintended fallback.

For DOM injection, trace every dynamic innerHTML value and test with controlled HTML payloads in a disposable browser.

These commands are validation steps, not test results. They have not been run as part of this document.

END OF BLUEPRINT

