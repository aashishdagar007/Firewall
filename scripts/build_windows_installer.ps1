[CmdletBinding()]
param(
    [string] $BuildDir = (Join-Path $PSScriptRoot "..\cmake-build-release"),
    [string] $Configuration = "Release",
    [string] $InnoCompiler
)

$ErrorActionPreference = "Stop"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)

Write-Host "Configuring complete Windows application in $BuildDir"
& cmake -S $sourceRoot -B $BuildDir -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=$Configuration
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed with exit code $LASTEXITCODE" }

Write-Host "Building native frontend and firewall backend"
& cmake --build $BuildDir --config $Configuration --parallel
if ($LASTEXITCODE -ne 0) { throw "Application build failed with exit code $LASTEXITCODE" }

$exeCandidates = @(
    (Join-Path $BuildDir "AegisXII.exe"),
    (Join-Path $BuildDir "$Configuration\AegisXII.exe")
)
$exe = $exeCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
$dashboardIndex = Join-Path $BuildDir "dashboard\index.html"
$rules = Join-Path $BuildDir "config\rules.conf"
foreach ($required in @($dashboardIndex, $rules)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required installer input was not produced: $required"
    }
}
if (-not $exe) { throw "CMake did not produce AegisXII.exe in $BuildDir or its configuration directory." }

if (-not $InnoCompiler) {
    $InnoCompiler = (Get-Command "ISCC.exe" -ErrorAction SilentlyContinue | Select-Object -First 1).Source
}
if (-not $InnoCompiler) {
    $programRoots = @($env:ProgramW6432, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ } | Select-Object -Unique
    $installDirs = foreach ($root in $programRoots) {
        Get-ChildItem -LiteralPath $root -Directory -Filter "Inno Setup 7*" -ErrorAction SilentlyContinue
    }
    $InnoCompiler = $installDirs |
        ForEach-Object { Join-Path $_.FullName "ISCC.exe" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if (-not $InnoCompiler) {
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installLocations = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "Inno Setup 7*" -and $_.InstallLocation } |
        Select-Object -ExpandProperty InstallLocation
    $InnoCompiler = $installLocations |
        ForEach-Object { Join-Path $_ "ISCC.exe" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw "Inno Setup 7 ISCC.exe was not found. Install Inno Setup 7 or pass -InnoCompiler."
}

$outputDir = Join-Path $sourceRoot "dist\windows"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$payloadDir = Join-Path ([System.IO.Path]::GetTempPath()) ("aegisxii-installer-payload-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $payloadDir | Out-Null
try {
    & cmake --install $BuildDir --config $Configuration --prefix $payloadDir
    if ($LASTEXITCODE -ne 0) { throw "CMake install staging failed with exit code $LASTEXITCODE" }

    foreach ($required in @(
        (Join-Path $payloadDir "AegisXII.exe"),
        (Join-Path $payloadDir "config\rules.conf"),
        (Join-Path $payloadDir "dashboard\index.html")
    )) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "CMake install tree is missing required application content: $required"
        }
    }

    $opensslDllDirectory = $null
    $cacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if (Test-Path -LiteralPath $cacheFile -PathType Leaf) {
        $opensslCandidates = [System.Collections.Generic.List[string]]::new()
        foreach ($cacheLine in Get-Content -LiteralPath $cacheFile) {
            if ($cacheLine -match '^OPENSSL_ROOT_DIR:[^=]+=(.+)$' -and $Matches[1]) {
                $opensslCandidates.Add((Join-Path $Matches[1] "bin"))
            } elseif ($cacheLine -match '^OPENSSL_(?:SSL|CRYPTO)_LIBRARY:[^=]+=(.+)$' -and $Matches[1]) {
                $candidate = Split-Path -Parent $Matches[1]
                for ($i = 0; $i -lt 6 -and $candidate; $i++) {
                    $opensslCandidates.Add((Join-Path $candidate "bin"))
                    $candidate = Split-Path -Parent $candidate
                }
            }
        }
        foreach ($candidate in ($opensslCandidates | Select-Object -Unique)) {
            if ((Test-Path -LiteralPath $candidate -PathType Container) -and
                (Get-ChildItem -LiteralPath $candidate -Filter "libssl*.dll" -File -ErrorAction SilentlyContinue | Select-Object -First 1) -and
                (Get-ChildItem -LiteralPath $candidate -Filter "libcrypto*.dll" -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
                $opensslDllDirectory = $candidate
                break
            }
        }
    }

    $dependencyScript = Join-Path $sourceRoot "scripts\copy_windows_runtime_dependencies.cmake"
    $dependencyArguments = @(
        "-DAEGIS_EXECUTABLE=$exe",
        "-DAEGIS_DESTINATION=$payloadDir"
    )
    if ($opensslDllDirectory) {
        $dependencyArguments += "-DAEGIS_DLL_DIRECTORY=$opensslDllDirectory"
    }
    & cmake @dependencyArguments -P $dependencyScript
    if ($LASTEXITCODE -ne 0) { throw "Windows runtime dependency staging failed with exit code $LASTEXITCODE" }

    $winDivertDll = Join-Path (Split-Path $exe -Parent) "WinDivert.dll"
    if (Test-Path -LiteralPath $winDivertDll -PathType Leaf) {
        Copy-Item -LiteralPath $winDivertDll -Destination $payloadDir
        $winDivertDriver = Join-Path (Split-Path $exe -Parent) "WinDivert64.sys"
        if (Test-Path -LiteralPath $winDivertDriver -PathType Leaf) {
            Copy-Item -LiteralPath $winDivertDriver -Destination $payloadDir
        }
    }

    $script = Join-Path $sourceRoot "installer_script.iss"
    $buildDefine = "/DBuildDir=$payloadDir"
    Write-Host "Packaging executable, config, and dashboard assets with Inno Setup 7"
    & $InnoCompiler $buildDefine $script
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed with exit code $LASTEXITCODE" }
}
finally {
    Remove-Item -LiteralPath $payloadDir -Recurse -Force
}

$installer = Join-Path $outputDir "AEGIS_XII_Setup_v3.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Inno Setup reported success but did not create $installer"
}
Write-Host "Installer created: $installer"
