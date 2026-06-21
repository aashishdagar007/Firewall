# secure_windows_protocols.ps1
# Requires Run as Administrator

Write-Host "Securing Windows OS Protocols..." -ForegroundColor Cyan

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$protocolsToDisable = @(
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1"
)

$protocolsToEnable = @(
    "TLS 1.2",
    "TLS 1.3"
)

# Function to update registry keys for a protocol
function Set-ProtocolStatus {
    param (
        [string]$Protocol,
        [bool]$Enable
    )

    $protocolPath = "$registryPath\$Protocol"
    $clientPath = "$protocolPath\Client"
    $serverPath = "$protocolPath\Server"

    # Create keys if they don't exist
    if (!(Test-Path $protocolPath)) { New-Item -Path $protocolPath -Force | Out-Null }
    if (!(Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }
    if (!(Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }

    $enabledValue = if ($Enable) { 1 } else { 0 }
    $disabledByDefaultValue = if ($Enable) { 0 } else { 1 }

    # Client
    Set-ItemProperty -Path $clientPath -Name "Enabled" -Value $enabledValue -Type DWord -Force
    Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value $disabledByDefaultValue -Type DWord -Force

    # Server
    Set-ItemProperty -Path $serverPath -Name "Enabled" -Value $enabledValue -Type DWord -Force
    Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value $disabledByDefaultValue -Type DWord -Force

    $status = if ($Enable) { "ENABLED" } else { "DISABLED" }
    $color = if ($Enable) { "Green" } else { "Red" }
    Write-Host "[*] $Protocol has been $status" -ForegroundColor $color
}

Write-Host "`nDisabling vulnerable protocols..." -ForegroundColor Yellow
foreach ($protocol in $protocolsToDisable) {
    Set-ProtocolStatus -Protocol $protocol -Enable $false
}

Write-Host "`nEnabling secure protocols..." -ForegroundColor Yellow
foreach ($protocol in $protocolsToEnable) {
    Set-ProtocolStatus -Protocol $protocol -Enable $true
}

Write-Host "`nDone! Please restart your computer for these changes to take effect." -ForegroundColor Cyan
