# VIGIL Hybrid Architecture Windows Installer (PowerShell)
# Compiles Rust Companion Daemon & Registers Windows Registry Host Manifest

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ VIGIL Hybrid Architecture Windows Companion Installer" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = Split-Path -Parent $PSScriptRoot

Set-Location $ProjectRoot

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "📦 Compiling VIGIL Desktop Companion daemon binary..." -ForegroundColor Green
    Set-Location "$ProjectRoot\desktop"
    cargo build --release
    $BinaryPath = "$ProjectRoot\desktop\target\release\vigil-desktop-companion.exe"
    Write-Host "✅ Daemon binary compiled at: $BinaryPath" -ForegroundColor Green
    Set-Location $ProjectRoot
} else {
    Write-Host "⚠️ Cargo (Rust) not found in PATH. Using standard binary path location." -ForegroundColor Yellow
    $BinaryPath = "$ProjectRoot\desktop\target\release\vigil-desktop-companion.exe"
}

$HostName = "com.vigil.desktop"
$ManifestPath = "$ProjectRoot\desktop\com.vigil.desktop.json"

# Write manifest file
$ManifestContent = @"
{
  "name": "$HostName",
  "description": "VIGIL Native Desktop Security Companion Daemon",
  "path": "$($BinaryPath.Replace('\', '\\'))",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://*/"
  ]
}
"@

$ManifestContent | Out-File -FilePath $ManifestPath -Encoding utf8 -Force

# Windows Registry Native Messaging Keys
$RegPathChrome = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$RegPathEdge   = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"

New-Item -Path $RegPathChrome -Force | Out-Null
Set-ItemProperty -Path $RegPathChrome -Name "(default)" -Value $ManifestPath

New-Item -Path $RegPathEdge -Force | Out-Null
Set-ItemProperty -Path $RegPathEdge -Name "(default)" -Value $ManifestPath

Write-Host "✅ Registered HKCU Registry keys:" -ForegroundColor Green
Write-Host "   - Chrome: $RegPathChrome -> $ManifestPath" -ForegroundColor Gray
Write-Host "   - Edge:   $RegPathEdge -> $ManifestPath" -ForegroundColor Gray
Write-Host ""
Write-Host "🎉 VIGIL Desktop Companion Windows setup complete!" -ForegroundColor Cyan
