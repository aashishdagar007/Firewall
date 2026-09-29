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
    $candidates = @(
        "${env:ProgramFiles}\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe"
    )
    $InnoCompiler = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (-not $InnoCompiler -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    throw "Inno Setup 7 ISCC.exe was not found. Install Inno Setup 7 or pass -InnoCompiler."
}

$outputDir = Join-Path $sourceRoot "dist\windows"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$payloadDir = Join-Path ([System.IO.Path]::GetTempPath()) ("aegisxii-installer-payload-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $payloadDir | Out-Null
try {
    Copy-Item -LiteralPath $exe -Destination (Join-Path $payloadDir "AegisXII.exe")
    Copy-Item -LiteralPath (Join-Path $BuildDir "config") -Destination $payloadDir -Recurse
    Copy-Item -LiteralPath (Join-Path $BuildDir "dashboard") -Destination $payloadDir -Recurse

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
