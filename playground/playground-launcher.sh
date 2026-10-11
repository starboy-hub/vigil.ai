#!/usr/bin/env bash
# ==============================================================================
# Vigil Cyber Range Playground — Desktop Launcher
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=4006
URL="http://127.0.0.1:${PORT}"

# 1. Start Playground server if not active
if ! curl -s --max-time 1 "$URL" >/dev/null 2>&1; then
    nohup node "$DIR/server.js" >/dev/null 2>&1 &
    for _ in {1..15}; do
        if curl -s --max-time 1 "$URL" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
fi

# 2. Open Cyber Range in browser
if command -v firefox >/dev/null 2>&1; then
    nohup firefox --new-window "$URL" >/dev/null 2>&1 &
elif command -v google-chrome >/dev/null 2>&1; then
    nohup google-chrome --app="$URL" >/dev/null 2>&1 &
elif command -v chromium >/dev/null 2>&1; then
    nohup chromium --app="$URL" >/dev/null 2>&1 &
elif command -v gio >/dev/null 2>&1; then
    nohup gio open "$URL" >/dev/null 2>&1 &
else
    nohup xdg-open "$URL" >/dev/null 2>&1 &
fi

