#!/bin/bash

echo "========================================"
echo "  VIGIL: Universal AI Privacy Shield"
echo "  Mac/Linux Installation Script"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "manifest.json" ]; then
    echo "ERROR: Please run this script from the VIGIL folder!"
    echo "Make sure you're in the folder that contains manifest.json"
    exit 1
fi

echo "✅ Found VIGIL files!"
echo ""
echo "INSTRUCTIONS:"
echo ""
echo "1. Open your browser (Chrome, Brave, or Edge)"
echo "2. Go to: chrome://extensions/"
echo "3. Enable 'Developer mode' (toggle in top right)"
echo "4. Click 'Load unpacked'"
echo "5. Select this folder: $(pwd)"
echo "6. Done! Look for the shield icon in bottom-right of any page"
echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Press Enter to open Chrome extensions page..."
read
open -a "Google Chrome" "chrome://extensions/" 2>/dev/null || open -a "Brave Browser" "chrome://extensions/" 2>/dev/null || echo "Please manually open chrome://extensions/ in your browser"
