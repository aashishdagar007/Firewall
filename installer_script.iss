; AEGIS XII Windows installer. BuildDir is supplied by scripts/build_windows_installer.ps1.
#ifndef BuildDir
  #define BuildDir AddBackslash(SourcePath) + "cmake-build-release"
#endif

#define MyAppName      "AEGIS XII"
#define MyAppVersion   "3.0"
#define MyAppPublisher "ASD Solutions"
#define MyAppURL       "https://aegisxii.vercel.app/"
#define MyAppExeName   "AegisXII.exe"
#define OutputDir      AddBackslash(SourcePath) + "dist\windows"

[Setup]
AppId={{B105FD15-8A21-4CC3-8AA9-C36CD5C8EC0D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
DisableProgramGroupPage=yes
SolidCompression=yes
OutputDir={#OutputDir}
OutputBaseFilename=AEGIS_XII_Setup_v3

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; AegisXII.exe contains both the native GUI and the firewall/API service.
Source: "{#BuildDir}\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#BuildDir}\dashboard\*"; DestDir: "{app}\dashboard"; Flags: ignoreversion recursesubdirs createallsubdirs
; Include the optional WinDivert runtime only when the configured build produced it.
#if FileExists(AddBackslash(BuildDir) + "WinDivert.dll")
Source: "{#BuildDir}\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
#endif
#if FileExists(AddBackslash(BuildDir) + "WinDivert64.sys")
Source: "{#BuildDir}\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion
#endif

[Dirs]
; The LocalSystem service writes logs, ledger, and graph data below the install root.
Name: "{app}\logs"

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Register and start the backend before offering the GUI, so its named-pipe endpoint exists.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start AegisXII"; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop AegisXII"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete AegisXII"; Flags: runhidden
