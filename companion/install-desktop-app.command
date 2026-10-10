#!/bin/bash
# VIGIL Desktop Guardian — Pure Native System Tray App Launcher
# Double-click this file in Finder to launch VIGIL as a pure native macOS Menu Bar Desktop App!

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "$DIR"

echo "======================================================="
echo "🛡️  VIGIL Desktop Guardian — Pure Native App Launcher"
echo "======================================================="

# Stop any existing firewall instance or previous desktop app instance
pkill -f "vigil-agent-firewall.js" 2>/dev/null || true
pkill -f "VIGILDesktop" 2>/dev/null || true

sleep 0.5

# Start agent firewall server in background
echo "🚀 Starting VIGIL Security Firewall Node.js Engine..."
node companion/vigil-agent-firewall.js --mode=guard > /tmp/vigil-desktop.log 2>&1 &

sleep 1

# Launch Pure Native macOS Menu Bar Desktop App
NATIVE_APP="$DIR/companion/native-app/VIGIL Desktop.app"

if [ -d "$NATIVE_APP" ]; then
    echo "🚀 Launching VIGIL Native Menu Bar System Tray App..."
    open "$NATIVE_APP"
    echo "======================================================="
    echo "✅ VIGIL Native System Tray App is active!"
    echo "📍 Look at your top macOS Menu Bar for the 🛡️ VIGIL icon!"
    echo "   Click 🛡️ VIGIL anytime to open/close your Guardian Dashboard."
    echo "======================================================="
else
    echo "⚠️  Native app bundle not found. Building now..."
    "$DIR/companion/native-app/build-app.sh"
    open "$NATIVE_APP"
fi
