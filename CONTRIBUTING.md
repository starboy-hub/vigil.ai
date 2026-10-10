# Contributing to Vigil AI Guardian

Thank you for your interest in contributing to **Vigil AI Guardian**! Projects like this thrive because of contributors who care about data privacy, AI security, and open-source zero-trust tooling.

Please take a moment to review this document before submitting bug reports, proposing enhancements, or creating pull requests.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Ways to Contribute](#ways-to-contribute)
3. [Local Development Setup](#local-development-setup)
4. [Development Guidelines](#development-guidelines)
5. [Adding New Language Contexts](#adding-new-language-contexts)
6. [Submitting Pull Requests](#submitting-pull-requests)
7. [Reporting Bugs & Requesting Features](#reporting-bugs--requesting-features)

---

## Code of Conduct

This project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating in discussions or submitting code, you are expected to uphold a welcoming, respectful, and inclusive environment.

---

## Ways to Contribute

You do not need to be a core compiler expert to contribute:

* **Report Bugs:** Identify edge cases, broken DOM bindings, or uncaught PII formats.
* **Feature Requests:** Propose new detection heuristics, platform adapters, or workflows.
* **Translations & Locales:** Add or refine multi-language contextual markers for your native language.
* **Testing:** Verify performance and extension behavior across Chromium-based browsers (Brave, Edge, Chrome) and Firefox.
* **Documentation:** Clarify instructions, document architecture details, or fix typos in guides.

---

## Local Development Setup

Vigil AI is built using standard **Vanilla JavaScript (ES6+)** adhering to **Chrome Extension Manifest V3 (MV3)** and WebExtension standards.

### 1. Clone Your Fork

```bash
git clone https://github.com/<your-username>/vigil.ai.git
cd vigil.ai
```

### 2. Install & Build Distributables

```bash
npm install
npm run build:all        # Builds Chromium (dist/) and Firefox (dist-firefox/)
```

### 3. Load into Your Chromium Browser

1. Open your browser and navigate to the extension manager:
   * **Google Chrome:** `chrome://extensions/`
   * **Brave:** `brave://extensions/`
   * **Microsoft Edge:** `edge://extensions/`
2. Enable **Developer mode** via the toggle switch in the upper-right corner.
3. Click **Load unpacked**.
4. Select the `dist/` directory inside your cloned repository.
5. Whenever you edit files, run `npm run build:all` and click the 🔄 reload icon on the Vigil AI card in `chrome://extensions/`.

### 4. Running the Test Suite

```bash
npm test                 # Executes 276 Jest unit & integration tests
npm run lint             # Runs ESLint static analysis
```

---

## Development Guidelines

To ensure compatibility, reliability, and auditability:

1. **Zero Runtime Dependencies:**
   * Do not introduce external CDN bundles or cloud tracking into runtime scripts (`content.js`, `background.js`, `popup.js`).
   * Keep the footprint lightweight to preserve sub-millisecond input performance.

2. **Privacy First & Local Isolation:**
   * Never introduce network analytics or telemetry endpoints.
   * All analysis must execute locally within the browser sandbox, WebGPU neural engine, or communicate with the user-hosted loopback (`localhost:11434` for Ollama).

3. **Performance & DOM Safety:**
   * Always debounce input event listeners attached to the DOM.
   * Ensure mutations to user-editable inputs preserve native cursor placement and undo history.

---

## Submitting Pull Requests

1. **Branching Strategy:**
   * Branch off `main`:
     ```bash
     git checkout -b feature/your-feature-name
     ```

2. **Commit Messages:**
   * Follow standard conventional commits:
     * `feat: add Italian contextual financial markers`
     * `fix: prevent race condition on contenteditable paste event`
     * `docs: update installation instructions for Brave`

3. **Pre-PR Checklist:**
   - [ ] Verified tests pass cleanly (`npm test`).
   - [ ] No regression on existing regex patterns or Luhn checks.
   - [ ] Ensured code passes linter (`npm run lint`).
   - [ ] Updated `README.md` or documentation if changing features or options.

4. **Open a PR:**
   * Push your branch to GitHub and open a Pull Request targeting `starboy-hub/vigil.ai:main`.

---

## Reporting Bugs & Requesting Features

* **Bug Reports:** Open an issue on [GitHub Issues](https://github.com/starboy-hub/vigil.ai/issues).
* **Feature Suggestions:** Describe the motivation, threat scenario, and proposed user experience.
