; ============================================================
;  AEGIS XII v3.0 — InnoSetup Installer Script
;  Packages: firewall.exe + dashboard + config
; ============================================================

#define MyAppName      "AEGIS XII"
#define MyAppVersion   "3.0"
#define MyAppPublisher "ASD Solutions"
#define MyAppURL       "https://aegisxii.vercel.app/"
#define MyAppExeName   "firewall.exe"
#define BuildDir       "D:\AASHISH\Projects\Firewall\cmake-build-release"

[Setup]
AppId={{B105FD15-8A21-4CC3-8AA9-C36CD5C8EC0D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Install to Program Files\AEGIS XII
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

; Architecture
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Require Administrator (needed for raw socket packet capture)
PrivilegesRequired=admin

; Appearance
WizardStyle=modern
DisableProgramGroupPage=yes
SolidCompression=yes

; Output
OutputDir=D:\AASHISH\Projects\Firewall
OutputBaseFilename=AEGIS_XII_Setup_v3

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; ── C++ Executable and assets ──
Source: "{#BuildDir}\firewall.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\AASHISH\Projects\Firewall\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "D:\AASHISH\Projects\Firewall\dashboard\dist\*"; DestDir: "{app}\dashboard"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Writable logs directory inside the installation folder
Name: "{app}\logs"

[Icons]
; Start Menu
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
; Desktop (optional)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Auto-start on Windows login
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue

[Run]
; Launch AEGIS XII immediately after installation
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Terminate AEGIS XII before uninstall
Filename: "taskkill.exe"; Parameters: "/F /IM ""{#MyAppExeName}"""; Flags: runhidden

[UninstallDelete]
; Clean up the logs directory on uninstall
Type: filesandordirs; Name: "{app}\logs"
