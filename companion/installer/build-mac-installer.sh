#!/bin/bash
# Vigil AI Guardian — 1-Click Universal macOS Installer Builder (.dmg & .pkg)
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$DIR/../.." && pwd )"

echo "======================================================="
echo "🛡️  Building Vigil AI Guardian 1-Click macOS Installer"
echo "======================================================="

cd "$ROOT_DIR"

# 1. Build Extension Distributables (Chromium & Firefox)
echo "📦 Building Browser Extensions (Chromium & Firefox)..."
node build.js
node build.js --firefox

# 2. Build Native Desktop App Bundle
echo "🔨 Building Native macOS App Bundle..."
"$ROOT_DIR/companion/native-app/build-app.sh"

# 3. Register Native Messaging Hosts
echo "🔌 Registering Native Messaging Hosts for installed browsers..."
node companion/installer/register-native-hosts.js

# 4. Assemble macOS Installer Directory
DIST_INSTALLER_DIR="$ROOT_DIR/releases/macOS"
mkdir -p "$DIST_INSTALLER_DIR"

APP_PATH="$ROOT_DIR/companion/native-app/Vigil Desktop.app"

# Create installer DMG using hdiutil if available
DMG_NAME="Vigil-AI-macOS-v11.0.0.dmg"
DMG_PATH="$DIST_INSTALLER_DIR/$DMG_NAME"

echo "💿 Packaging $DMG_NAME..."
rm -f "$DMG_PATH"

if command -v hdiutil &> /dev/null; then
    TEMP_DMG_DIR="/tmp/vigil_dmg_temp"
    rm -rf "$TEMP_DMG_DIR"
    mkdir -p "$TEMP_DMG_DIR"
    
    cp -R "$APP_PATH" "$TEMP_DMG_DIR/"
    ln -s /Applications "$TEMP_DMG_DIR/Applications"
    
    # Create 1-click launcher inside DMG
    cat << 'EOF' > "$TEMP_DMG_DIR/1-Click-Setup.command"
#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "🛡️  Vigil AI Guardian 1-Click Setup..."
cp -R "$DIR/Vigil Desktop.app" /Applications/ 2>/dev/null || true
open "/Applications/Vigil Desktop.app"
echo "✅ Vigil AI Guardian active in macOS Menu Bar!"
EOF
    chmod +x "$TEMP_DMG_DIR/1-Click-Setup.command"

    hdiutil create -volname "Vigil AI Setup" -srcfolder "$TEMP_DMG_DIR" -ov -format UDZO "$DMG_PATH"
    rm -rf "$TEMP_DMG_DIR"
    
    # Also maintain VIGIL-Guardian-macOS-v11.0.0.dmg alias
    cp "$DMG_PATH" "$DIST_INSTALLER_DIR/VIGIL-Guardian-macOS-v11.0.0.dmg" 2>/dev/null || true
fi

echo "======================================================="
echo "✅ macOS Installer created: $DMG_PATH"
echo "======================================================="
