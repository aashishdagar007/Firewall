# Windows installer build

The Windows setup contains one `AegisXII.exe` with both the native desktop UI
and firewall backend. The installer also includes the `config` directory and
the web dashboard served by the backend. During setup it registers and starts
the `AegisXII` Windows service before offering to launch the desktop UI; the UI
connects to the service over the named pipe.

From a PowerShell prompt at the repository root, run:

```powershell
./scripts/build_windows_installer.ps1
```

The script configures and builds the Windows application with CMake, checks the
executable and required frontend/config files, and compiles
`installer_script.iss` using Inno Setup 7. To use a separate build directory or
explicit compiler path:

```powershell
./scripts/build_windows_installer.ps1 `
  -BuildDir "$env:TEMP\aegisxii-release" `
  -InnoCompiler "C:\Program Files\Inno Setup 7\ISCC.exe"
```

The installer is written to `dist/windows/AEGIS_XII_Setup_v3.exe`. The Windows
CI job runs the same build and packaging script and uploads the resulting
installer artifact. CMake stages the executable's non-system DLL dependencies,
MSVC runtime libraries, config, and dashboard into the installer payload.
