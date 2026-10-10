#!/bin/bash
# Vigil AI Guardian — Native macOS Menu Bar App Builder
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$DIR/../.." && pwd )"

echo "======================================================="
echo "🛡️  Building Vigil AI Native macOS Menu Bar Desktop App"
echo "======================================================="

cd "$DIR"

# 0. Compile Objective-C source into binary
echo "🔨 Compiling Objective-C Cocoa Status Bar Binary..."
clang -fmodules -framework Cocoa -framework WebKit -framework UserNotifications vigil_tray.m -o VigilDesktop

# 1. Build .app Bundle structure
APP_NAME="Vigil Desktop.app"
APP_DIR="$DIR/$APP_NAME"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "📁 Creating macOS App Bundle structure at $APP_DIR..."
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

# 2. Create Info.plist (LSUIElement = true hides Dock icon, turns it into a pure Menu Bar / Tray app)
cat << 'EOF' > "$CONTENTS_DIR/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>VigilDesktop</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.vigil.desktop.guardian</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Vigil Desktop Guardian</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF

# 3. Copy Binary & Resources
cp VigilDesktop "$MACOS_DIR/VigilDesktop"
chmod +x "$MACOS_DIR/VigilDesktop"

if [ -f "shield_template.png" ]; then
    cp shield_template.png "$RESOURCES_DIR/shield_template.png"
fi
if [ -f "AppIcon.png" ]; then
    cp AppIcon.png "$RESOURCES_DIR/AppIcon.png"
fi

echo "======================================================="
echo "✅ Vigil AI Native macOS App built successfully!"
echo "📍 Location: $APP_DIR"
echo "======================================================="
