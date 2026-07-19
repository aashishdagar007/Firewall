; ============================================================
;  AEGIS XII v3.0 — InnoSetup Installer Script
;  Packages: AegisXII.exe + config (Native Dual-Mode Architecture)
; ============================================================

#define MyAppName      "AEGIS XII"
#define MyAppVersion   "3.0"
#define MyAppPublisher "ASD Solutions"
#define MyAppURL       "https://aegisxii.vercel.app/"
#define MyAppExeName   "AegisXII.exe"
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

; Require Administrator (needed for raw socket packet capture and Service installation)
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
Source: "{#BuildDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\AASHISH\Projects\Firewall\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Writable logs directory inside the installation folder
Name: "{app}\logs"

[Icons]
; Start Menu
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
; Desktop (optional)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; 1. Register the Windows Service (runs elevated implicitly since installer is admin)
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install"; Description: "Install Aegis Background Service"; Flags: runhidden postinstall
; 2. Launch the un-elevated GUI client immediately after installation
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} GUI"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Terminate AEGIS XII GUI and Background Service before uninstall
Filename: "taskkill.exe"; Parameters: "/F /IM ""{#MyAppExeName}"""; Flags: runhidden
; Attempt to delete the service if running
Filename: "sc.exe"; Parameters: "delete AegisXII"; Flags: runhidden

[UninstallDelete]
; Clean up the logs directory on uninstall
Type: filesandordirs; Name: "{app}\logs"
