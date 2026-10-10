; Vigil AI Guardian — Windows Inno Setup Script
; Generates Vigil-AI-Windows-v11.0.0-Setup.exe

#define MyAppName "Vigil AI Guardian"
#define MyAppVersion "11.0.0"
#define MyAppPublisher "Vigil AI Security Team"
#define MyAppURL "https://github.com/starboy-hub/vigil.ai"
#define MyAppExeName "Vigil.exe"

[Setup]
AppId={{C8E28564-9214-46E0-B77C-0C59D96E14B2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=Vigil-AI-Windows-v11.0.0-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Automatically start Vigil AI Guardian when Windows boots"; GroupDescription: "Startup Settings"

[Files]
Source: "..\..\dist\*"; DestDir: "{app}\extension-chromium"; Flags: recursesubdirs createallsubdirs
Source: "..\..\dist-firefox\*"; DestDir: "{app}\extension-firefox"; Flags: recursesubdirs createallsubdirs
Source: "..\..\companion\*"; DestDir: "{app}\companion"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\companion\install-desktop-app.command"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\companion\install-desktop-app.command"; Tasks: desktopicon

[Registry]
; Windows Registry Native Messaging Hosts registration for Chrome, Brave, Edge & Firefox
Root: HKCU; Subkey: "Software\Google\Chrome\NativeMessagingHosts\com.vigil.desktop.guardian"; ValueType: string; ValueName: ""; ValueData: "{app}\companion\native-manifests\com.vigil.desktop.guardian-chrome.json"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.vigil.desktop.guardian"; ValueType: string; ValueName: ""; ValueData: "{app}\companion\native-manifests\com.vigil.desktop.guardian-chrome.json"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\com.vigil.desktop.guardian"; ValueType: string; ValueName: ""; ValueData: "{app}\companion\native-manifests\com.vigil.desktop.guardian-chrome.json"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Mozilla\NativeMessagingHosts\com.vigil.desktop.guardian"; ValueType: string; ValueName: ""; ValueData: "{app}\companion\native-manifests\com.vigil.desktop.guardian-firefox.json"; Flags: uninsdeletekey

; Autostart on Windows startup
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Vigil AI Guardian"; ValueData: """{app}\companion\vigil-agent-firewall.js"" --mode=guard"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "node.exe"; Parameters: "{app}\companion\installer\register-native-hosts.js"; Description: "Register Browser Native Messaging Hosts"; Flags: runhidden
