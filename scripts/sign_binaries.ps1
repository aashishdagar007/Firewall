<#
.SYNOPSIS
    Signs Windows binaries (exes, installers) using signtool.exe,
    the generated Code Signing Certificate (.pfx), and RFC 3161 timestamping.

.DESCRIPTION
    This script:
    1. Locates Windows SDK signtool.exe
    2. Uses certs\codesign.pfx
    3. Signs binaries with SHA-256 Authenticode signature
    4. Attaches a trusted RFC 3161 cryptographic timestamp (DigiCert / Sectigo)
    5. Verifies and displays the embedded signature metadata

.PARAMETER Files
    Optional array of files to sign. If omitted, signs all project release binaries.

.PARAMETER PfxPassword
    Password for certs\codesign.pfx (default: "ASD@AegisXII2026!")

.PARAMETER NoTimestamp
    Skip RFC 3161 timestamping (for offline machines)
#>
[CmdletBinding()]
param(
    [string[]] $Files,
    [string] $PfxPassword = "ASD@AegisXII2026!",
    [switch] $NoTimestamp
)

$ErrorActionPreference = "Stop"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$certsDir = Join-Path $sourceRoot "certs"
$pfxFile = Join-Path $certsDir "codesign.pfx"

if (-not (Test-Path $pfxFile)) {
    throw "Code signing certificate not found at $pfxFile. Run 'scripts/create_code_signing_cert.ps1' first."
}

# 1. Locate Windows SDK signtool.exe
$signtoolCandidates = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } | Select-Object -ExpandProperty FullName -First 1),
    (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source
)
$signtool = $signtoolCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows 10/11 SDK or Visual Studio C++ workload."
}

# 2. Determine target files
if (-not $Files -or $Files.Count -eq 0) {
    $Files = @(
        (Join-Path $sourceRoot "cmake-build-release-hardened\Release\AegisXII.exe"),
        (Join-Path $sourceRoot "dist\portable\AegisXII-Hardened-v3.0\AegisXII.exe"),
        (Join-Path $sourceRoot "dist\windows\AEGIS_XII_Setup_v3.exe")
    ) | Where-Object { Test-Path $_ }
}

if ($Files.Count -eq 0) {
    throw "No files found to sign. Build the project first using 'scripts/build_hardened_release.ps1'."
}

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  AEGIS XII - Code Signing Pipeline (signtool.exe)" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  Signtool   : $signtool"
Write-Host "  Certificate: $pfxFile"
Write-Host ""

$timestampServers = @(
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://tsa.starfieldtech.com",
    "http://timestamp.identrust.com"
)

function Sign-SingleFile {
    param([string]$targetFile)

    Write-Host "Signing: $targetFile" -ForegroundColor Yellow
    $signedSuccessfully = $false

    if (-not $NoTimestamp) {
        foreach ($server in $timestampServers) {
            Write-Host "  Attempting timestamp via $server ..." -ForegroundColor Gray
            $args = @(
                "sign",
                "/f", $pfxFile,
                "/p", $PfxPassword,
                "/fd", "SHA256",
                "/tr", $server,
                "/td", "SHA256",
                "/d", "Aegis XII Firewall",
                "/du", "https://asdsolutions.com",
                $targetFile
            )
            & $signtool @args *>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [+] Signed & timestamped successfully ($server)" -ForegroundColor Green
                $signedSuccessfully = $true
                break
            }
        }
    }

    if (-not $signedSuccessfully) {
        if (-not $NoTimestamp) {
            Write-Warning "Timestamp servers unreachable; signing without timestamp fallback..."
        }
        $args = @(
            "sign",
            "/f", $pfxFile,
            "/p", $PfxPassword,
            "/fd", "SHA256",
            "/d", "Aegis XII Firewall",
            "/du", "https://asdsolutions.com",
            $targetFile
        )
        & $signtool @args
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to sign $targetFile"
        }
        Write-Host "  [+] Signed successfully (without timestamp)" -ForegroundColor Green
    }

    # Verify signature
    $sig = Get-AuthenticodeSignature $targetFile
    Write-Host "  Signer     : $($sig.SignerCertificate.Subject)" -ForegroundColor White
    Write-Host "  Issuer     : $($sig.SignerCertificate.Issuer)" -ForegroundColor White
    if ($sig.TimeStamperCertificate) {
        Write-Host "  TimeStamper: $($sig.TimeStamperCertificate.Subject)" -ForegroundColor White
    }
    Write-Host ""
}

foreach ($f in $Files) {
    if (Test-Path $f) {
        Sign-SingleFile -targetFile $f
    }
}

Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  ALL BINARIES SIGNED SUCCESSFULLY" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green

