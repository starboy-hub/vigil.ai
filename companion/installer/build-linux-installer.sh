#!/bin/bash
# Vigil AI Guardian — Linux (.deb & Tarball) 1-Click Packager
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$DIR/../.." && pwd )"

echo "======================================================="
echo "🛡️  Building Vigil AI Guardian Linux Installer (.deb)"
echo "======================================================="

cd "$ROOT_DIR"

# 1. Build Distributables
node build.js
node build.js --firefox

DIST_INSTALLER_DIR="$ROOT_DIR/releases/Linux"
mkdir -p "$DIST_INSTALLER_DIR"

# 2. Assemble .deb Package Structure
DEB_NAME="vigil-ai_11.0.0_amd64"
DEB_DIR="/tmp/$DEB_NAME"

rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/opt/vigil-ai"
mkdir -p "$DEB_DIR/usr/bin"
mkdir -p "$DEB_DIR/usr/share/applications"

# Copy source files into package
cp -r dist "$DEB_DIR/opt/vigil-ai/extension-chromium"
cp -r dist-firefox "$DEB_DIR/opt/vigil-ai/extension-firefox"
cp -r companion "$DEB_DIR/opt/vigil-ai/companion"

# Create Control File
cat << 'EOF' > "$DEB_DIR/DEBIAN/control"
Package: vigil-ai
Version: 11.0.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Vigil AI Contributors <https://github.com/starboy-hub/vigil.ai>
Description: Vigil AI Guardian — Local-First AI Threat Firewall & Privacy Enclave
 Vigil provides real-time local protection against prompt injection, data leaks,
 and scam threats across Chrome, Brave, Edge, and Firefox.
EOF

# Create Post-Install Script
cat << 'EOF' > "$DEB_DIR/DEBIAN/postinst"
#!/bin/sh
set -e
echo "🛡️ Vigil AI Post-Install Setup..."
node /opt/vigil-ai/companion/installer/register-native-hosts.js || true
chmod +x /opt/vigil-ai/companion/vigil-agent-firewall.js
EOF
chmod +x "$DEB_DIR/DEBIAN/postinst"

# Create Launcher Script
cat << 'EOF' > "$DEB_DIR/usr/bin/vigil-ai"
#!/bin/sh
node /opt/vigil-ai/companion/vigil-agent-firewall.js "$@"
EOF
chmod +x "$DEB_DIR/usr/bin/vigil-ai"

# Create Desktop Application Entry
cat << 'EOF' > "$DEB_DIR/usr/share/applications/vigil-ai.desktop"
[Desktop Entry]
Name=Vigil AI Guardian
Comment=Zero-Trust Local AI Threat Sentinel
Exec=/usr/bin/vigil-ai --gui
Icon=/opt/vigil-ai/companion/native-app/shield_template.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF

# 3. Build .deb with dpkg-deb if available
if command -v dpkg-deb &> /dev/null; then
    echo "📦 Building Debian package..."
    dpkg-deb --build "$DEB_DIR" "$DIST_INSTALLER_DIR/${DEB_NAME}.deb"
    cp "$DIST_INSTALLER_DIR/${DEB_NAME}.deb" "$DIST_INSTALLER_DIR/vigil-guardian_11.0.0_amd64.deb" 2>/dev/null || true
    echo "✅ DEB package created at $DIST_INSTALLER_DIR/${DEB_NAME}.deb"
fi

# 4. Create Universal Linux Tarball
echo "📦 Creating Linux universal tarball..."
TAR_PATH="$DIST_INSTALLER_DIR/vigil-ai-v11.0.0-linux-x64.tar.gz"
tar -czf "$TAR_PATH" -C /tmp "$DEB_NAME"
cp "$TAR_PATH" "$DIST_INSTALLER_DIR/vigil-guardian-v11.0.0-linux-x64.tar.gz" 2>/dev/null || true
rm -rf "$DEB_DIR"

echo "======================================================="
echo "✅ Linux packages generated in $DIST_INSTALLER_DIR"
echo "======================================================="
