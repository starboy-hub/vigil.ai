#!/usr/bin/env bash
# ==============================================================================
# VIGIL AI (v1.0.0) — Automated Full System & Desktop Setup Script
# ==============================================================================
# Sets up the entire Vigil AI Ecosystem on Fedora Linux:
#  1. Native C/C++ Build Tools & Audio/Crypto Development Headers
#  2. Node.js & npm Core Environments
#  3. Rust Toolchain (rustup, cargo, rustc)
#  4. Local AI Inference Server (Ollama + llama3.2 & nomic-embed-text)
#  5. Dual Browser Extensions (Chromium & Mozilla Firefox)
#  6. Rust Native Desktop Companion Daemon (com.vigil.desktop + Native Messaging)
#  7. System-Wide Agent Firewall Loopback Proxy (HTTP_PROXY on port 8765)
#  8. CLI Integrations (vigil-wrap, vigil-firewall, vigil-companion) in ~/.local/bin
#  9. Systemd User Service & Desktop Application Entry
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================================="
echo "🛡️  VIGIL AI FULL ECOSYSTEM SETUP (DESKTOP + LOCAL AI + SENTINEL)"
echo "=================================================================="
echo "Project Path: $SCRIPT_DIR"
echo "Host OS:      Fedora Linux ($(uname -m))"
echo "Timestamp:    $(date)"
echo "=================================================================="
echo ""

# ------------------------------------------------------------------------------
# 1. System Packages & Build Headers via DNF
# ------------------------------------------------------------------------------
echo "==> [1/8] Checking system compilers, ALSA audio & crypto dev packages..."

REQUIRED_PACKAGES=(
    git
    nodejs
    npm
    gcc
    gcc-c++
    make
    pkgconf-pkg-config
    openssl-devel
    alsa-lib-devel
    libxcb-devel
    libX11-devel
)

MISSING_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! rpm -q "$pkg" &>/dev/null; then
        MISSING_PACKAGES+=("$pkg")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo "Installing missing system packages via dnf: ${MISSING_PACKAGES[*]}"
    echo "Prompting for sudo password..."
    sudo dnf install -y "${MISSING_PACKAGES[@]}"
else
    echo "✅ All required system libraries and compilers are installed."
fi

# ------------------------------------------------------------------------------
# 2. Rust Toolchain (Cargo & Rustc)
# ------------------------------------------------------------------------------
echo ""
echo "==> [2/8] Setting up Rust toolchain (required for Desktop Companion)..."

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

if ! command -v cargo &>/dev/null; then
    echo "Installing Rust toolchain via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

echo "✅ Rust toolchain ready: $(cargo --version) / $(rustc --version)"

# ------------------------------------------------------------------------------
# 3. Local AI Inference Engine (Ollama)
# ------------------------------------------------------------------------------
echo ""
echo "==> [3/8] Setting up Local AI Engine (Ollama + Models)..."

if ! command -v ollama &>/dev/null; then
    echo "Installing Ollama on Linux..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

if command -v systemctl &>/dev/null; then
    if ! systemctl is-active --quiet ollama 2>/dev/null; then
        echo "Starting Ollama systemd service..."
        sudo systemctl enable --now ollama 2>/dev/null || true
    fi
fi

# Give Ollama a moment to boot if just started
sleep 2

echo "Checking Ollama connectivity and pulling recommended local models..."
if curl -s http://127.0.0.1:11434/api/tags &>/dev/null; then
    echo "  • Pulling llama3.2 (fast reasoning model)..."
    ollama pull llama3.2 || true
    echo "  • Pulling nomic-embed-text (local vector embeddings)..."
    ollama pull nomic-embed-text || true
    echo "✅ Local AI Engine active at http://127.0.0.1:11434"
else
    echo "⚠️ Ollama daemon not responding at 127.0.0.1:11434 yet."
    echo "   You can start it in the background using: ollama serve"
fi

# ------------------------------------------------------------------------------
# 4. Node.js Dependencies & Extension Build
# ------------------------------------------------------------------------------
echo ""
echo "==> [4/8] Installing Node dependencies and compiling browser extensions..."

if [ -f "package-lock.json" ]; then
    npm ci || npm install
else
    npm install
fi

echo "Building Chromium & Firefox extension bundles..."
npm run build:all

echo "✅ Browser extension bundles built:"
echo "   - Chromium (Chrome/Brave/Edge): $SCRIPT_DIR/dist"
echo "   - Mozilla Firefox:              $SCRIPT_DIR/dist-firefox"

# ------------------------------------------------------------------------------
# 5. Compile Rust Native Desktop Security Companion
# ------------------------------------------------------------------------------
echo ""
echo "==> [5/8] Compiling Rust Native Desktop Companion (Keyring, Audio Spectral FFT, SIEM)..."

cd "$SCRIPT_DIR/desktop"
cargo build --release
cd "$SCRIPT_DIR"

mkdir -p "$SCRIPT_DIR/companion"
cp -f "$SCRIPT_DIR/desktop/target/release/vigil-desktop-companion" "$SCRIPT_DIR/companion/vigil-native-host"
chmod +x "$SCRIPT_DIR/companion/vigil-native-host"

echo "✅ Rust Native Companion compiled:"
echo "   - Binary: $SCRIPT_DIR/companion/vigil-native-host"

# ------------------------------------------------------------------------------
# 6. Register Native Messaging Hosts for Installed Browsers
# ------------------------------------------------------------------------------
echo ""
echo "==> [6/8] Registering Native Messaging Host bridges for browsers..."

node "$SCRIPT_DIR/companion/installer/install-all.js"

# Ensure Firefox Native Messaging Manifest is placed
MOZILLA_NATIVE_DIR="$HOME/.mozilla/native-messaging-hosts"
mkdir -p "$MOZILLA_NATIVE_DIR"
cat <<EOF > "$MOZILLA_NATIVE_DIR/com.vigil.desktop.json"
{
  "name": "com.vigil.desktop",
  "description": "Vigil Local Security Sentinel & Local AI Enclave Bridge (Firefox)",
  "path": "$SCRIPT_DIR/companion/vigil-native-host",
  "type": "stdio",
  "allowed_extensions": [
    "vigil@starboy-hub.github.io"
  ]
}
EOF
echo "✅ Firefox Native Messaging Manifest registered at: $MOZILLA_NATIVE_DIR/com.vigil.desktop.json"

# ------------------------------------------------------------------------------
# 7. System-Wide Agent Firewall & CLI Tooling Setup
# ------------------------------------------------------------------------------
echo ""
echo "==> [7/8] Installing CLI tools and Agent Firewall into ~/.local/bin..."

BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

# 1. vigil-firewall: Starts the loopback HTTP firewall proxy
cat <<EOF > "$BIN_DIR/vigil-firewall"
#!/usr/bin/env bash
exec node "$SCRIPT_DIR/companion/vigil-agent-firewall.js" "\$@"
EOF
chmod +x "$BIN_DIR/vigil-firewall"

# 2. vigil-wrap: Wraps any desktop AI agent (Cursor, Claude Code, CLI) under the firewall
cat <<EOF > "$BIN_DIR/vigil-wrap"
#!/usr/bin/env bash
exec node "$SCRIPT_DIR/companion/vigil-wrap.js" "\$@"
EOF
chmod +x "$BIN_DIR/vigil-wrap"

# 3. vigil-playground: Starts the interactive local testing playground
cat <<EOF > "$BIN_DIR/vigil-playground"
#!/usr/bin/env bash
exec node "$SCRIPT_DIR/playground/server.js" "\$@"
EOF
chmod +x "$BIN_DIR/vigil-playground"

echo "✅ Installed CLI tools in $BIN_DIR:"
echo "   • vigil-wrap       — Protect CLI tools/agents (e.g. vigil-wrap -- claude)"
echo "   • vigil-firewall   — Run local Agent Firewall proxy (127.0.0.1:8765)"
echo "   • vigil-playground — Launch interactive security playground"

# ------------------------------------------------------------------------------
# 8. Desktop App Entry & Optional Systemd Service
# ------------------------------------------------------------------------------
echo ""
echo "==> [8/8] Creating Desktop Application launcher & Systemd User Service..."

APP_DIR="$HOME/.local/share/applications"
mkdir -p "$APP_DIR"
cat <<EOF > "$APP_DIR/vigil-ai.desktop"
[Desktop Entry]
Name=Vigil AI Guardian
Comment=Local AI Threat Sentinel & Agent Firewall
Exec=$SCRIPT_DIR/companion/vigil-desktop-launcher.sh
Icon=$SCRIPT_DIR/src/icons/icon128.png
Terminal=false
Type=Application
Categories=Utility;Security;Development;
EOF
chmod +x "$APP_DIR/vigil-ai.desktop"

# Systemd user service for background Agent Firewall
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
cat <<EOF > "$SYSTEMD_USER_DIR/vigil-firewall.service"
[Unit]
Description=Vigil AI Agent Traffic Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node $SCRIPT_DIR/companion/vigil-agent-firewall.js --mode=guard
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload 2>/dev/null || true

echo "✅ Desktop Entry installed: $APP_DIR/vigil-ai.desktop"
echo "✅ Systemd service generated: $SYSTEMD_USER_DIR/vigil-firewall.service"

# ------------------------------------------------------------------------------
# Summary & Usage Instructions
# ------------------------------------------------------------------------------
echo ""
echo "=================================================================="
echo "🎉 VIGIL AI FULL ECOSYSTEM SETUP COMPLETE!"
echo "=================================================================="
echo ""
echo "1. 🤖 LOCAL AI INFERENCE (OLLAMA):"
echo "   • Ollama API is active at: http://127.0.0.1:11434"
echo "   • Models installed: llama3.2, nomic-embed-text"
echo "   • Check models:     ollama list"
echo ""
echo "2. 🖥️ SYSTEM-WIDE DESKTOP AGENT FIREWALL:"
echo "   • Run firewall in background (systemd):"
echo "       systemctl --user enable --now vigil-firewall"
echo "   • Run manually:"
echo "       vigil-firewall --mode=guard"
echo "   • Wrap any AI agent tool or CLI:"
echo "       vigil-wrap -- claude"
echo "       vigil-wrap -- cursor"
echo ""
echo "3. 🛡️ RUST NATIVE DESKTOP COMPANION:"
echo "   • Binary: $SCRIPT_DIR/companion/vigil-native-host"
echo "   • Audio Spectral FFT, Hardware Enclave, SIEM Exporter, IDE Proxy."
echo ""
echo "4. 🦊 BROWSER EXTENSION (FIREFOX):"
echo "   • Open: about:debugging#/runtime/this-firefox"
echo "   • Click 'Load Temporary Add-on...'"
echo "   • Select: $SCRIPT_DIR/dist-firefox/manifest.json"
echo ""
echo "5. 🧪 INTERACTIVE TESTING & BENCHMARKS:"
echo "   • Run local playground:  vigil-playground (http://localhost:3000)"
echo "   • Run test suites:       npm test"
echo "   • Run companion tests:   cargo test --manifest-path desktop/Cargo.toml"
echo "=================================================================="

