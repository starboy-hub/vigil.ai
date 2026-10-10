@echo off
echo ========================================
echo   VIGIL: Universal AI Privacy Shield
echo   Windows Installation Script
echo ========================================
echo.

REM Check if we're in the right directory
if not exist "manifest.json" (
    echo ERROR: Please run this script from the VIGIL folder!
    echo Make sure you're in the folder that contains manifest.json
    pause
    exit /b 1
)

echo ✅ Found VIGIL files!
echo.
echo INSTRUCTIONS:
echo.
echo 1. Open your browser (Chrome, Brave, or Edge)
echo 2. Go to: chrome://extensions/
echo 3. Enable "Developer mode" (toggle in top right)
echo 4. Click "Load unpacked"
echo 5. Select this folder: %CD%
echo 6. Done! Look for the shield icon in bottom-right of any page
echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Press any key to open Chrome extensions page...
pause > nul
start chrome://extensions/
