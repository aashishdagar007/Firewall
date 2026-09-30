[CmdletBinding()]
param(
    [string] $BuildDir = (Join-Path $PSScriptRoot "..\cmake-build-release"),
    [string] $Configuration = "Release",
    [string] $InnoCompiler,
    [switch] $RunInstallSmokeTest
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

$innoCandidates = [System.Collections.Generic.List[string]]::new()
if ($InnoCompiler) {
    $innoCandidates.Add($InnoCompiler)
} else {
    $programRoots = @($env:ProgramW6432, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}) |
        Where-Object { $_ } | Select-Object -Unique
    $installRoots = @($programRoots, (Join-Path $env:LOCALAPPDATA "Programs")) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique
    $installDirs = foreach ($root in $installRoots) {
        Get-ChildItem -LiteralPath $root -Directory -Filter "Inno Setup 7*" -ErrorAction SilentlyContinue
    }
    $uninstallKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installLocations = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "Inno Setup 7*" -and $_.InstallLocation } |
        Select-Object -ExpandProperty InstallLocation
    foreach ($directory in $installDirs) {
        $innoCandidates.Add((Join-Path $directory.FullName "ISCC.exe"))
    }
    foreach ($location in $installLocations) {
        $innoCandidates.Add((Join-Path $location "ISCC.exe"))
    }
    foreach ($command in (Get-Command "ISCC.exe" -All -ErrorAction SilentlyContinue)) {
        if ($command.Source) { $innoCandidates.Add($command.Source) }
    }
}
$compilerDiagnostics = [System.Collections.Generic.List[string]]::new()
$selectedInnoCompiler = $null
foreach ($candidate in ($innoCandidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    $candidateVersion = (& $candidate --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $candidateVersion -match '^7\.') {
        $selectedInnoCompiler = $candidate
        break
    }
    $compilerDiagnostics.Add("$candidate ($candidateVersion)")
}
if (-not $selectedInnoCompiler) {
    $available = if ($compilerDiagnostics.Count) { $compilerDiagnostics -join "; " } else { "no ISCC.exe candidates found" }
    throw "Inno Setup 7 ISCC.exe was not found. Install Inno Setup 7 or pass -InnoCompiler. Candidates: $available"
}
$InnoCompiler = $selectedInnoCompiler
Write-Host "Using Inno Setup 7 compiler: $InnoCompiler"

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
    $opensslCandidates = [System.Collections.Generic.List[string]]::new()
    foreach ($programRoot in @($env:ProgramW6432, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique) {
        $opensslCandidates.Add((Join-Path $programRoot "OpenSSL\bin"))
    }
    $cacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if (Test-Path -LiteralPath $cacheFile -PathType Leaf) {
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
        Write-Host "Using OpenSSL runtime DLL directory: $opensslDllDirectory"
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

    Write-Host "Checking the staged GUI-to-service IPC handshake"
    $payloadExe = Join-Path $payloadDir "AegisXII.exe"
    $previousSmokeFlag = $env:AEGISXII_IPC_SMOKE_TEST
    $env:AEGISXII_IPC_SMOKE_TEST = "1"
    try {
        $smokeProcess = Start-Process -FilePath $payloadExe -ArgumentList "--ipc-smoke-test" `
            -WorkingDirectory $payloadDir -PassThru -WindowStyle Hidden
    } finally {
        $env:AEGISXII_IPC_SMOKE_TEST = $previousSmokeFlag
    }
    if (-not $smokeProcess.WaitForExit(30000)) {
        $smokeProcess.Kill()
        throw "GUI-to-service IPC smoke test timed out."
    }
    if ($smokeProcess.ExitCode -ne 0) {
        $smokeResultFile = Join-Path $payloadDir "ipc-smoke-test-result.txt"
        $smokeResult = Get-Content -LiteralPath $smokeResultFile -Raw -ErrorAction SilentlyContinue
        $smokeLogFile = Join-Path $payloadDir "ipc-smoke-server.log"
        $smokeLog = Get-Content -LiteralPath $smokeLogFile -Raw -ErrorAction SilentlyContinue
        $smokeResultSummary = if ($smokeResult) { $smokeResult.Trim() } else { "no test result file" }
        $smokeLogSummary = if ($smokeLog) { $smokeLog.Trim() } else { "no server log" }
        throw "GUI-to-service IPC smoke test failed ($smokeResultSummary). Server log: $smokeLogSummary"
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

if ($RunInstallSmokeTest) {
    $serviceControl = Join-Path $env:SystemRoot "System32\sc.exe"
    & $serviceControl query AegisXII 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        throw "Refusing installer lifecycle smoke test because an AegisXII service already exists."
    }

    Write-Host "Verifying clean install, service startup, GUI IPC, and uninstall"
    $testInstallDir = Join-Path ([System.IO.Path]::GetTempPath()) ("aegisxii-install-smoke-" + [guid]::NewGuid().ToString("N"))
    $serviceMayExist = $false
    try {
        $setupLogPath = Join-Path ([System.IO.Path]::GetTempPath()) ("aegisxii-setup-" + [guid]::NewGuid().ToString("N") + ".log")
        $setupArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG=`"$setupLogPath`" /DIR=`"$testInstallDir`""
        $serviceMayExist = $true
        $testInstallerProcess = Start-Process -FilePath $installer -ArgumentList $setupArguments -WorkingDirectory $outputDir -PassThru -WindowStyle Hidden
        if (-not $testInstallerProcess.WaitForExit(120000)) {
            $testInstallerProcess.Kill()
            throw "Windows installer smoke test timed out during install."
        }
        if ($testInstallerProcess.ExitCode -ne 0) {
            throw "Windows installer smoke test failed during install with exit code $($testInstallerProcess.ExitCode)."
        }

        $installedExe = Join-Path $testInstallDir "AegisXII.exe"
        if (-not (Test-Path -LiteralPath $installedExe -PathType Leaf)) {
            throw "Windows installer smoke test did not install AegisXII.exe."
        }

        $serviceReady = $false
        $serviceStateSummary = "service state was not available"
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $serviceState = & $serviceControl query AegisXII 2>$null
            if ($serviceState) {
                $serviceStateSummary = ($serviceState -join " ").Trim()
            }
            if ($LASTEXITCODE -eq 0 -and ($serviceState -match "RUNNING")) {
                $serviceReady = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $serviceReady) {
            $backendLogPath = Join-Path $testInstallDir "logs\aegix.log"
            $backendLog = Get-Content -LiteralPath $backendLogPath -Tail 40 -ErrorAction SilentlyContinue
            $backendLogSummary = if ($backendLog) { $backendLog -join " | " } else { "no backend log was produced" }
            $serviceInstallLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "AegisXII-service-install.log"
            $serviceInstallLog = Get-Content -LiteralPath $serviceInstallLogPath -Tail 20 -ErrorAction SilentlyContinue
            $serviceInstallSummary = if ($serviceInstallLog) { $serviceInstallLog -join " | " } else { "no service registration error log was produced" }
            $setupLog = Get-Content -LiteralPath $setupLogPath -Tail 60 -ErrorAction SilentlyContinue
            $setupLogSummary = if ($setupLog) { $setupLog -join " | " } else { "no setup log was produced" }
            throw "Windows installer smoke test did not start the AegisXII service. SCM: $serviceStateSummary Registration: $serviceInstallSummary Backend: $backendLogSummary Setup: $setupLogSummary"
        }

        $clientProcess = Start-Process -FilePath $installedExe -ArgumentList "--ipc-client-smoke-test" -WorkingDirectory $testInstallDir -PassThru -WindowStyle Hidden
        if (-not $clientProcess.WaitForExit(30000)) {
            $clientProcess.Kill()
            throw "Installed GUI-to-service IPC check timed out."
        }
        if ($clientProcess.ExitCode -ne 0) {
            throw "Installed GUI-to-service IPC check failed with exit code $($clientProcess.ExitCode)."
        }

        $uninstaller = Join-Path $testInstallDir "unins000.exe"
        if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
            throw "Windows installer smoke test did not create its uninstaller."
        }
        $uninstallProcess = Start-Process -FilePath $uninstaller -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" -WorkingDirectory $testInstallDir -PassThru -WindowStyle Hidden
        if (-not $uninstallProcess.WaitForExit(60000)) {
            $uninstallProcess.Kill()
            throw "Windows installer smoke test timed out during uninstall."
        }
        if ($uninstallProcess.ExitCode -ne 0) {
            throw "Windows installer smoke test failed during uninstall with exit code $($uninstallProcess.ExitCode)."
        }

        $serviceRemoved = $false
        for ($attempt = 0; $attempt -lt 15; $attempt++) {
            & $serviceControl query AegisXII 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $serviceRemoved = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $serviceRemoved) {
            throw "Windows installer smoke test left the AegisXII service registered."
        }
        Write-Host "Clean install, service startup, GUI IPC, and uninstall passed."
    } finally {
        if ($serviceMayExist) {
            & $serviceControl stop AegisXII 2>$null | Out-Null
            & $serviceControl delete AegisXII 2>$null | Out-Null
        }
        if (Test-Path -LiteralPath $testInstallDir -PathType Container) {
            $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
            $resolvedInstallDir = [System.IO.Path]::GetFullPath($testInstallDir)
            if (-not $resolvedInstallDir.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove installer smoke-test directory outside the temporary root: $resolvedInstallDir"
            }
            Remove-Item -LiteralPath $resolvedInstallDir -Recurse -Force
        }
        $serviceInstallLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "AegisXII-service-install.log"
        Remove-Item -LiteralPath $serviceInstallLogPath -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "Installer lifecycle smoke test skipped; pass -RunInstallSmokeTest to enable it."
}

# The expected post-uninstall `sc.exe` checks leave a non-zero native exit
# code behind. Return success explicitly after every validation completes.
exit 0
