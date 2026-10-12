# Vigil AI Security Hall of Fame

The Vigil AI team is committed to the highest standards of endpoint security, local-first privacy, and transparent cryptographic assurance. We extend our deepest gratitude to the independent security researchers, cryptographers, and engineers who dedicate their time, expertise, and scrutiny to identifying vulnerabilities and responsibly coordinating their disclosure with us.

---

## 🏆 Honored Contributors

The following researchers have helped secure Vigil AI and protect our users through coordinated, responsible vulnerability disclosure:

| Date | Researcher | Scope & Key Contributions | Severity | Fixed In |
| :--- | :--- | :--- | :---: | :---: |
| **2026-10-11** | **Independent Security Researcher**<br> | **v1.0.0 Security Verification & Supply-Chain Hardening**<br>• Identified potential hash overwrite vector in Gate 3 build reproducibility verification; prompted strict fail-closed enforcement and `--update-baseline` flag.<br>• Identified submission guard edge-cases on plaintext-only contenteditable surfaces and negative-control buttons (cancel/attach).<br>• Recommended sensitive context deny-list surface expansion across enterprise IdPs (Okta preview, Ping, Duo, OneLogin) and financial portals.<br>• Recommended administrative vault IPC hardening in the background service worker. | **Medium** | `v1.0.0` |

---

## 📜 Eligibility & Recognition Guidelines

We welcome vulnerability reports and code audits from the global security community. 

### Inclusion Criteria
To be eligible for recognition in the Vigil AI Hall of Fame:
1. **First to Report:** You must be the first person to responsibly disclose the specific vulnerability or security limitation to us.
2. **Coordinated Disclosure:** You must adhere to responsible disclosure principles by keeping findings private until a fix is released and verified.
3. **In-Scope Surface:** The vulnerability must affect in-scope production code (browser extension, native companion daemon, or release pipeline) as outlined in [SECURITY.md](SECURITY.md).
4. **Reproducible Report:** Provide a clear description, proof of concept (PoC), reproduction steps, or actionable remediation advice.

### What We Offer
Vigil AI is an independent, community-driven open-source project maintained on a volunteer basis. We do **not** offer financial bounties or cash compensation. We offer:
- **Public Recognition:** Permanent listing in this Hall of Fame with your preferred name, GitHub profile, personal website, or social handle.
- **Release Notes Credit:** Prominent attribution in GitHub release notes and security advisories.
- **Reference & Recommendation:** We are glad to serve as a professional reference or verify your research contributions for prospective employers or academic programs.

---

## 🛡️ Reporting a Vulnerability

If you discover a security issue or potential weakness in Vigil AI:

- **Preferred Channel:** Open a private advisory report via [GitHub Security Advisories](https://github.com/starboy-hub/vigil.ai/security/advisories/new).
- **Email Contact:** Reach out directly to `security@vigil-ai.org` or repository maintainers (`starboy-hub`).
- **Policy Details:** Review our full SLA commitments and scope in [SECURITY.md](SECURITY.md) and RFC 9116 [security.txt](.well-known/security.txt).

Thank you for helping keep Vigil AI secure for everyone!

