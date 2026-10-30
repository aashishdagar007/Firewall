<#
.SYNOPSIS
    Generates a commercial-grade Code Signing Certificate authority (Root CA)
    and Code Signing Certificate (.pfx) using OpenSSL and Windows SDK tools.

.DESCRIPTION
    This script:
    1. Locates OpenSSL (MSYS2, Git, or system PATH)
    2. Generates a private Root CA key and self-signed Root CA certificate
    3. Generates a 4096-bit RSA Code Signing private key and Certificate Signing Request (CSR)
    4. Issues the Code Signing Certificate signed by the Root CA with critical Microsoft
       Authenticode Code Signing extensions:
       - EKU: codeSigning (1.3.6.1.5.5.7.3.3)
       - EKU: msCodeInd (1.3.6.1.4.1.311.2.1.21 - Individual Code Signing)
       - EKU: msCodeCom (1.3.6.1.4.1.311.2.1.22 - Commercial Code Signing)
       - Key Usage: digitalSignature
    5. Exports the complete chain to PKCS#12 (.pfx) ready for signtool.exe
    6. Optionally trusts the Root CA in Windows so signatures verify as "OK"

.PARAMETER CompanyName
    Organization name for the certificate (default: "ASD Solutions")

.PARAMETER PfxPassword
    Password to encrypt the .pfx file (default: "ASD@AegisXII2026!")

.PARAMETER ValidDays
    Certificate validity in days (default: 1825 = 5 years)
#>
[CmdletBinding()]
param(
    [string] $CompanyName = "ASD Solutions",
    [string] $CommonName = "ASD Solutions",
    [string] $PfxPassword = "ASD@AegisXII2026!",
    [int] $ValidDays = 1825,
    [string] $Country = "US",
    [string] $State = "California",
    [string] $City = "San Francisco"
)

$ErrorActionPreference = "Stop"
$sourceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$certsDir = Join-Path $sourceRoot "certs"
New-Item -ItemType Directory -Force -Path $certsDir | Out-Null

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  AEGIS XII - Code Signing Certificate Generator (OpenSSL)" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Cyan

# 1. Locate OpenSSL
$opensslCandidates = @(
    "C:\msys64\ucrt64\bin\openssl.exe",
    "C:\msys64\usr\bin\openssl.exe",
    "C:\Program Files\Git\mingw64\bin\openssl.exe",
    "C:\Program Files\Git\usr\bin\openssl.exe",
    (Get-Command openssl -ErrorAction SilentlyContinue).Source
)
$openssl = $opensslCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $openssl) {
    throw "OpenSSL was not found. Please install OpenSSL or MSYS2/Git."
}
Write-Host "  Using OpenSSL: $openssl" -ForegroundColor Green
Write-Host "  Output Dir   : $certsDir"
Write-Host "  Organization : $CompanyName"
Write-Host ""

# 2. Write Configuration Files
$caCnf = @"
[ req ]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_ca

[ req_distinguished_name ]
C = $Country
ST = $State
L = $City
O = $CompanyName
OU = Security Operations
CN = $CompanyName Root CA

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"@
[IO.File]::WriteAllText((Join-Path $certsDir "ca.cnf"), $caCnf)

$certCnf = @"
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C = $Country
ST = $State
L = $City
O = $CompanyName
OU = Release Engineering
CN = $CommonName

[ v3_codesign ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning, 1.3.6.1.4.1.311.2.1.21, 1.3.6.1.4.1.311.2.1.22
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"@
[IO.File]::WriteAllText((Join-Path $certsDir "codesign.cnf"), $certCnf)

# 3. Generate Root CA Key & Certificate (Valid 10 years)
Write-Host "[1/4] Generating 4096-bit Root CA (ASD Solutions Root CA)..." -ForegroundColor Yellow
$caKey = Join-Path $certsDir "ca.key"
$caCrt = Join-Path $certsDir "ca.crt"
& $openssl genrsa -out $caKey 4096
& $openssl req -x509 -new -nodes -key $caKey -sha256 -days 3650 -out $caCrt -config (Join-Path $certsDir "ca.cnf")

# 4. Generate Code Signing Key & CSR
Write-Host "[2/4] Generating 4096-bit Code Signing Key and CSR..." -ForegroundColor Yellow
$csKey = Join-Path $certsDir "codesign.key"
$csCsr = Join-Path $certsDir "codesign.csr"
& $openssl genrsa -out $csKey 4096
& $openssl req -new -key $csKey -out $csCsr -config (Join-Path $certsDir "codesign.cnf")

# 5. Sign Certificate with Root CA
Write-Host "[3/4] Issuing Authenticode Code Signing Certificate ($ValidDays days)..." -ForegroundColor Yellow
$csCrt = Join-Path $certsDir "codesign.crt"
& $openssl x509 -req -in $csCsr -CA $caCrt -CAkey $caKey -CAcreateserial -out $csCrt -days $ValidDays -sha256 -extfile (Join-Path $certsDir "codesign.cnf") -extensions v3_codesign

# 6. Export to PKCS#12 (.pfx)
Write-Host "[4/4] Bundling into PKCS#12 PFX for Windows Signtool..." -ForegroundColor Yellow
$csPfx = Join-Path $certsDir "codesign.pfx"
& $openssl pkcs12 -export -out $csPfx -inkey $csKey -in $csCrt -certfile $caCrt -passout "pass:$PfxPassword"

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  CODE SIGNING CERTIFICATE READY" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  Private PFX Keybundle : $csPfx" -ForegroundColor White
Write-Host "  PFX Password          : $PfxPassword" -ForegroundColor White
Write-Host "  Public Root CA Cert   : $caCrt" -ForegroundColor White
Write-Host ""
Write-Host "  To trust this certificate on any Windows machine:" -ForegroundColor Cyan
Write-Host "  Run PowerShell as Administrator:" -ForegroundColor White
Write-Host "    certutil -addstore -f Root `"$caCrt`"" -ForegroundColor Yellow
Write-Host ""

