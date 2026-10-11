#!/usr/bin/env bash
# ==============================================================================
# Vigil AI Guardian — Universal Linux Desktop GUI Launcher
# ==============================================================================
# Ensures the Agent Firewall daemon is running in the background and immediately
# opens the graphical Security Dashboard in the user's browser.
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$DIR/.." && pwd)"
PORT=8765
URL="http://127.0.0.1:${PORT}/vigil-dashboard"

# 1. Ensure Agent Firewall daemon is active
if ! curl -s --max-time 1 "http://127.0.0.1:${PORT}/vigil-status" >/dev/null 2>&1; then
    nohup node "$DIR/vigil-agent-firewall.js" --mode=guard >/dev/null 2>&1 &
    # Wait up to 3 seconds for port to open
    for _ in {1..15}; do
        if curl -s --max-time 1 "http://127.0.0.1:${PORT}/vigil-status" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
fi

# 2. Open GUI Dashboard in the active browser
if command -v firefox >/dev/null 2>&1; then
    nohup firefox --new-window "$URL" >/dev/null 2>&1 &
elif command -v google-chrome >/dev/null 2>&1; then
    nohup google-chrome --app="$URL" >/dev/null 2>&1 &
elif command -v chromium >/dev/null 2>&1; then
    nohup chromium --app="$URL" >/dev/null 2>&1 &
elif command -v brave-browser >/dev/null 2>&1; then
    nohup brave-browser --app="$URL" >/dev/null 2>&1 &
elif command -v gio >/dev/null 2>&1; then
    nohup gio open "$URL" >/dev/null 2>&1 &
else
    nohup xdg-open "$URL" >/dev/null 2>&1 &
fi

