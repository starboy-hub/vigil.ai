#!/bin/bash
set -e

echo "================================================================"
echo " 🛡️ VIGIL Hybrid Architecture Installer (macOS & Linux)"
echo " Compiling Rust Companion Daemon & Registering Host Manifest"
echo "================================================================"
echo ""

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

cd "$PROJECT_ROOT"

if command -v cargo &> /dev/null; then
    echo "📦 Compiling VIGIL Desktop Companion daemon binary..."
    cd desktop
    cargo build --release
    HOST_BINARY_PATH="$(pwd)/target/release/vigil-desktop-companion"
    echo "✅ Daemon binary compiled at: $HOST_BINARY_PATH"
    cd "$PROJECT_ROOT"
else
    echo "⚠️  Cargo (Rust) not found in PATH. Using standard prebuilt binary stub fallback."
    HOST_BINARY_PATH="$PROJECT_ROOT/desktop/target/release/vigil-desktop-companion"
fi

HOST_NAME="com.vigil.desktop"

# Detect OS
OS_TYPE="$(uname -s)"
if [ "$OS_TYPE" = "Darwin" ]; then
    TARGET_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    BRAVE_TARGET_DIR="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    EDGE_TARGET_DIR="$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
    SYS_TARGET_DIR="/Library/Google/Chrome/NativeMessagingHosts"
else
    TARGET_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    BRAVE_TARGET_DIR="$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    EDGE_TARGET_DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts"
    SYS_TARGET_DIR="/etc/opt/chrome/native-messaging-hosts"
fi

EXT_ID="${1:-emkokehejldjlfljlhhcimnfefcjcmon}"

echo "📋 Registering Native Messaging Host manifest for Chrome, Brave, and Edge..."

mkdir -p "$TARGET_DIR" "$BRAVE_TARGET_DIR" "$EDGE_TARGET_DIR" 2>/dev/null || true

# Generate resolved manifest with absolute path to binary
cat <<EOF > "$TARGET_DIR/$HOST_NAME.json"
{
  "name": "$HOST_NAME",
  "description": "VIGIL Native Desktop Security Companion Daemon",
  "path": "$HOST_BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF

cp "$TARGET_DIR/$HOST_NAME.json" "$BRAVE_TARGET_DIR/$HOST_NAME.json" 2>/dev/null || true
cp "$TARGET_DIR/$HOST_NAME.json" "$EDGE_TARGET_DIR/$HOST_NAME.json" 2>/dev/null || true

echo "✅ Registered manifest to:"
echo "   - $TARGET_DIR/$HOST_NAME.json"
echo "   - $BRAVE_TARGET_DIR/$HOST_NAME.json"
echo "   - $EDGE_TARGET_DIR/$HOST_NAME.json"
echo ""
echo "🎉 VIGIL Desktop Companion setup complete!"
