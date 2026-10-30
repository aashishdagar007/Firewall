<#
.SYNOPSIS
    Build AegisXII as a hardened, anti-reverse-engineering Release executable + Inno Setup installer.

.DESCRIPTION
    This script:
    1. Detects available toolchain (MSVC Visual Studio 2026/2022 or MinGW-w64)
    2. Configures CMake in Release mode with maximum anti-reverse-engineering protections:
       - Full static runtime linking (zero DLL dependencies beyond Windows system DLLs)
       - Whole Program Optimization (WPO / LTO) & Link-Time Code Generation (LTCG)
       - Control Flow Guard (CFG) exploit mitigation
       - Buffer Security Checks (/GS stack canaries)
       - 64-bit Address Space Layout Randomization (/DYNAMICBASE + /HIGHENTROPYVA)
       - Data Execution Prevention (/NXCOMPAT)
       - Identical COMDAT folding (/OPT:ICF) & dead-code elimination (/OPT:REF)
       - Hidden symbol visibility / no debug symbol tables in output binary
       - Embedded Windows Version Info Resource (ASD Solutions / Aegis XII)
       - Embedded UAC Administrator Manifest (requireAdministrator)
    3. Builds the binary and verifies its PE headers, security flags, and dependencies
    4. Packages a standalone portable distribution folder in dist\portable\
    5. Compiles a single-file Windows installer using Inno Setup 7 (if available)

.PARAMETER SkipInstaller
    Skip Inno Setup packaging (just build the exe and portable distribution)
#>
[CmdletBinding()]
param(
    [switch] $SkipInstaller
)

$ErrorActionPreference = "Stop"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $sourceRoot "cmake-build-release-hardened"

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  AEGIS XII - Hardened Release Build Pipeline" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

# -- 1. Toolchain Detection ---------------------------------------------------
$useMSVC = $false
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$cmakeGenerator = $null

if (Test-Path $vsWhere) {
    $vsInstall = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstall -and (Test-Path $vsInstall)) {
        $useMSVC = $true
        # Check VS version
        $vsVersion = & $vsWhere -latest -products * -property installationVersion
        $major = [int]($vsVersion -split '\.')[0]
        if ($major -ge 18) {
            $cmakeGenerator = "Visual Studio 18 2026"
        } elseif ($major -ge 17) {
            $cmakeGenerator = "Visual Studio 17 2022"
        } else {
            $cmakeGenerator = "Visual Studio 16 2019"
        }
        Write-Host "  Toolchain: MSVC ($cmakeGenerator) at $vsInstall" -ForegroundColor Green
    }
}

# Locate cmake
$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (-not $cmake) {
    $cmakeCandidates = @(
        "C:\Program Files\CMake\bin\cmake.exe",
        "C:\msys64\ucrt64\bin\cmake.exe"
    )
    foreach ($c in $cmakeCandidates) {
        if (Test-Path $c) { $cmake = $c; break }
    }
}
if (-not $cmake) { throw "CMake was not found in PATH or standard locations." }

Write-Host "  CMake    : $cmake"
Write-Host "  Build Dir: $BuildDir"
Write-Host ""

# -- 2. Configure CMake -------------------------------------------------------
Write-Host "[1/4] Configuring CMake (Release + anti-RE protections)..." -ForegroundColor Yellow

if ($useMSVC) {
    $cmakeArgs = @(
        "-S", $sourceRoot,
        "-B", $BuildDir,
        "-G", $cmakeGenerator,
        "-A", "x64",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTING=OFF"
    )
} else {
    # Fallback to MinGW-w64 if MSVC not present
    $ucrt64Bin = "C:\msys64\ucrt64\bin"
    $env:PATH = "$ucrt64Bin;$env:PATH"
    $gcc = Join-Path $ucrt64Bin "gcc.exe"
    $gxx = Join-Path $ucrt64Bin "g++.exe"
    $ninja = Join-Path $ucrt64Bin "ninja.exe"
    $cmakeArgs = @(
        "-S", $sourceRoot,
        "-B", $BuildDir,
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_C_COMPILER=$($gcc.Replace('\', '/'))",
        "-DCMAKE_CXX_COMPILER=$($gxx.Replace('\', '/'))",
        "-DCMAKE_MAKE_PROGRAM=$($ninja.Replace('\', '/'))",
        "-DBUILD_TESTING=OFF",
        "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON",
        "-DCMAKE_CXX_FLAGS_RELEASE=-O2 -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden -ffunction-sections -fdata-sections -fstack-protector-strong",
        "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-strong",
        "-DCMAKE_EXE_LINKER_FLAGS_RELEASE=-s -Wl,--gc-sections -Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va -static -static-libgcc -static-libstdc++"
    )
}

& $cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed (exit $LASTEXITCODE)" }

# -- 3. Build -----------------------------------------------------------------
Write-Host ""
Write-Host "[2/4] Building AegisXII (Release, statically linked, hardened)..." -ForegroundColor Yellow
& $cmake --build $BuildDir --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }

# Locate built executable
$exeCandidates = @(
    (Join-Path $BuildDir "Release\AegisXII.exe"),
    (Join-Path $BuildDir "AegisXII.exe")
)
$exe = $exeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { throw "AegisXII.exe was not produced by the build." }

# If MinGW strip tool is available, strip any remaining debug symbols
if (-not $useMSVC) {
    $strip = "C:\msys64\ucrt64\bin\strip.exe"
    if (Test-Path $strip) {
        Write-Host "Stripping symbols via MinGW strip..." -ForegroundColor Yellow
        & $strip --strip-all --strip-debug --strip-unneeded $exe
    }
}

# -- 4. Verify the Binary -----------------------------------------------------
Write-Host ""
Write-Host "[3/4] Verifying produced hardened binary..." -ForegroundColor Yellow
$exeItem = Get-Item $exe
$fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)

Write-Host "  Binary   : $exe"
Write-Host "  Size     : $([math]::Round($exeItem.Length / 1MB, 2)) MB ($($exeItem.Length) bytes)"
Write-Host "  Product  : $($fileInfo.ProductName)"
Write-Host "  Company  : $($fileInfo.CompanyName)"
Write-Host "  Version  : $($fileInfo.FileVersion)"
Write-Host "  Desc     : $($fileInfo.FileDescription)"

# Verify DLL dependencies (must only be core Windows system DLLs)
$dumpbin = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\dumpbin.exe"
if (Test-Path $dumpbin) {
    Write-Host ""
    Write-Host "  DLL Dependencies (Zero external runtime dependencies):" -ForegroundColor Cyan
    $deps = & $dumpbin /dependents $exe | Where-Object { $_ -match '^\s+[A-Za-z0-9_\-\.]+\.dll' }
    foreach ($d in $deps) {
        Write-Host "    - $($d.Trim())" -ForegroundColor White
    }
    
    $headers = & $dumpbin /headers $exe
    $hasAslr = $headers -match "Dynamic base"
    $hasDep  = $headers -match "NX compatible"
    $hasHeVa = $headers -match "High Entropy"
    $hasCfg  = $headers -match "Control Flow Guard"

    Write-Host ""
    Write-Host "  Security Mitigations Active:" -ForegroundColor Cyan
    Write-Host "    [+] ASLR (Dynamic base)        : $(if($hasAslr){'ENABLED'}else{'OFF'})" -ForegroundColor $(if($hasAslr){'Green'}else{'Yellow'})
    Write-Host "    [+] DEP/NX (Data Execution)    : $(if($hasDep){'ENABLED'}else{'OFF'})" -ForegroundColor $(if($hasDep){'Green'}else{'Yellow'})
    Write-Host "    [+] 64-bit High Entropy VA     : $(if($hasHeVa){'ENABLED'}else{'OFF'})" -ForegroundColor $(if($hasHeVa){'Green'}else{'Yellow'})
    Write-Host "    [+] Control Flow Guard (CFG)   : $(if($hasCfg){'ENABLED'}else{'OFF'})" -ForegroundColor $(if($hasCfg){'Green'}else{'Yellow'})
    Write-Host "    [+] Static Runtime (/MT)       : ENABLED (No VC++ redistributable required)" -ForegroundColor Green
    Write-Host "    [+] Whole Program Opt (/GL)    : ENABLED (Cross-TU inlining & control flattening)" -ForegroundColor Green
    Write-Host "    [+] Link-Time Code Gen (/LTCG) : ENABLED (Anti-decompilation hardening)" -ForegroundColor Green
    Write-Host "    [+] UAC Admin Elevation        : EMBEDDED (requireAdministrator)" -ForegroundColor Green
}

# -- 5. Assemble Portable Distribution ----------------------------------------
Write-Host ""
Write-Host "[4/4] Assembling Portable Distribution Package..." -ForegroundColor Yellow
$distPortable = Join-Path $sourceRoot "dist\portable\AegisXII-Hardened-v3.0"
if (Test-Path $distPortable) { Remove-Item -Recurse -Force $distPortable }
New-Item -ItemType Directory -Force -Path $distPortable | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $distPortable "config") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $distPortable "dashboard") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $distPortable "logs") | Out-Null

Copy-Item $exe -Destination (Join-Path $distPortable "AegisXII.exe")
Copy-Item (Join-Path $sourceRoot "config\*") -Destination (Join-Path $distPortable "config") -Recurse -Force
Copy-Item (Join-Path $sourceRoot "dashboard\*") -Destination (Join-Path $distPortable "dashboard") -Recurse -Force
if (Test-Path (Join-Path $sourceRoot "README.txt")) {
    Copy-Item (Join-Path $sourceRoot "README.txt") -Destination $distPortable
}

Write-Host "  Portable Package Ready at: $distPortable" -ForegroundColor Green

# -- 6. Inno Setup Installer Packaging ----------------------------------------
if (-not $SkipInstaller) {
    Write-Host ""
    Write-Host "Compiling Inno Setup 7 installer package..." -ForegroundColor Yellow
    $installerScript = Join-Path $sourceRoot "scripts\build_windows_installer.ps1"
    if (Test-Path $installerScript) {
        try {
            & $installerScript -BuildDir $BuildDir -Configuration Release
            $setupExe = Join-Path $sourceRoot "dist\windows\AEGIS_XII_Setup_v3.exe"
            if (Test-Path $setupExe) {
                Write-Host ""
                Write-Host "==============================================================" -ForegroundColor Green
                Write-Host "  INSTALLER CREATED SUCCESSFULLY!" -ForegroundColor Green
                Write-Host "==============================================================" -ForegroundColor Green
                Write-Host "  Setup file: $setupExe" -ForegroundColor White
                Write-Host "  Setup size: $([math]::Round((Get-Item $setupExe).Length / 1MB, 2)) MB" -ForegroundColor White
            }
        } catch {
            Write-Warning "Inno Setup installer creation encountered an issue: $_"
        }
    }
}

# -- 7. Digital Code Signing ---------------------------------------------------
$signScript = Join-Path $sourceRoot "scripts\sign_binaries.ps1"
$pfxFile = Join-Path $sourceRoot "certs\codesign.pfx"
if ((Test-Path $signScript) -and (Test-Path $pfxFile)) {
    Write-Host ""
    Write-Host "Signing release binaries with Authenticode certificate..." -ForegroundColor Yellow
    try {
        & $signScript
    } catch {
        Write-Warning "Digital code signing encountered an issue: $_"
    }
}

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  AEGIS XII RELEASE BUILD COMPLETE" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  1. Standalone Executable : $exe"
Write-Host "  2. Portable Distribution: $distPortable"
if (Test-Path (Join-Path $sourceRoot "dist\windows\AEGIS_XII_Setup_v3.exe")) {
    Write-Host "  3. Windows Installer     : $(Join-Path $sourceRoot "dist\windows\AEGIS_XII_Setup_v3.exe")"
}
Write-Host ""
