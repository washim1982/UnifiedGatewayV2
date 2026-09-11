<#
.SYNOPSIS
  Creates/updates the IIS app pool and an HTTPS-only site for the Unified LLM Gateway, and grants
  the app-pool identity write access to the runtime folders (data, logs).

  TLS is not optional. The site gets one HTTPS binding using a certificate already installed in
  Cert:\LocalMachine\My, and any plain-HTTP binding on the site is removed. -AllowHttpRedirect adds
  an HTTP binding back for browsers only: the gateway redirects the dashboard and refuses every API
  call on it with HTTPS_REQUIRED, so a key sent there is rejected rather than accepted.

  The app pool uses "No Managed Code" (ASP.NET Core runs out-of-band), AlwaysRunning + preload so
  the AWS credential-refresh BackgroundService runs without an incoming request, and no idle
  timeout / periodic recycle so STS credentials keep refreshing.

  Prerequisites on the server:
    - IIS with the "Application Initialization" role service (for preload)
    - .NET 8 Hosting Bundle (ASP.NET Core Module V2)
    - A server-authentication certificate for -HostName, with its private key, in LocalMachine\My
  Run as Administrator, after publish.ps1.
.EXAMPLE
  ./install.ps1 -CertificateThumbprint 3F2A...C9 -HostName gateway.enterprise.internal
.EXAMPLE
  ./install.ps1 -CertificateThumbprint 3F2A...C9 -HostName gateway.enterprise.internal -AllowHttpRedirect -DisableLegacyTls
#>
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,

    [string]$HostName = "",
    [string]$SiteRoot = "C:\inetpub\unified-gateway",
    [string]$SiteName = "unified-gateway",
    [int]$HttpsPort = 443,

    # Adds an HTTP binding so a browser typing http:// is redirected. API calls on it are refused.
    [switch]$AllowHttpRedirect,
    [int]$HttpPort = 80,

    # Disables SSL 3.0, TLS 1.0 and TLS 1.1 for every server application on this host (SCHANNEL).
    # Machine-wide and needs a reboot, so it is opt-in.
    [switch]$DisableLegacyTls
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration

# --- Certificate ---
# Normalise a thumbprint pasted from the certificate dialog, which interleaves spaces and
# prepends an invisible left-to-right mark.
$thumbprint = ($CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
$certificate = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue

if (-not $certificate) { throw "Certificate $thumbprint was not found in Cert:\LocalMachine\My." }
if (-not $certificate.HasPrivateKey) { throw "Certificate $thumbprint has no private key, so IIS cannot terminate TLS with it." }
if ($certificate.NotAfter -le (Get-Date)) { throw "Certificate $thumbprint expired on $($certificate.NotAfter)." }
if ($certificate.NotAfter -le (Get-Date).AddDays(30)) {
    Write-Warning "Certificate $thumbprint expires on $($certificate.NotAfter). Schedule its renewal."
}

$serverAuthentication = "1.3.6.1.5.5.7.3.1"
$usages = @($certificate.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
if ($usages.Count -gt 0 -and $usages -notcontains $serverAuthentication) {
    throw "Certificate $thumbprint is not valid for server authentication (EKU $serverAuthentication)."
}

if ($HostName) {
    $covered = $certificate.DnsNameList | Where-Object {
        $name = $_.Unicode
        ($name -ieq $HostName) -or
        ($name.StartsWith("*.") -and
         $HostName.EndsWith($name.Substring(1), [StringComparison]::OrdinalIgnoreCase) -and
         $HostName.Split('.').Count -eq $name.Split('.').Count)
    }
    if (-not $covered) { throw "Certificate $thumbprint does not cover host name '$HostName'." }
}

# --- App pool ---
if (-not (Test-Path "IIS:\AppPools\$SiteName")) { New-WebAppPool -Name $SiteName | Out-Null }
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ""            # No Managed Code
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name startMode -Value "AlwaysRunning"
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.idleTimeout -Value ([TimeSpan]::Zero)
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name recycling.periodicRestart.time -Value ([TimeSpan]::Zero)

# --- Site: HTTPS only ---
$sslFlags = if ($HostName) { 1 } else { 0 }   # 1 = SNI, so several sites can share port 443
$httpsBindingInfo = "*:${HttpsPort}:$HostName"

if (-not (Test-Path "IIS:\Sites\$SiteName")) {
    New-Website -Name $SiteName -PhysicalPath $SiteRoot -ApplicationPool $SiteName `
        -Port $HttpsPort -HostHeader $HostName -Ssl -SslFlags $sslFlags -Force | Out-Null
} else {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $SiteRoot
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $SiteName

    $existing = Get-WebBinding -Name $SiteName -Protocol https |
        Where-Object { $_.bindingInformation -eq $httpsBindingInfo }
    if (-not $existing) {
        New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostName -SslFlags $sslFlags
    }
}

# An API key sent to a plain-HTTP listener has crossed the network in clear before the gateway
# can refuse it, so the site keeps none unless a browser redirect is asked for explicitly.
Get-WebBinding -Name $SiteName -Protocol http | Remove-WebBinding
if ($AllowHttpRedirect) {
    New-WebBinding -Name $SiteName -Protocol http -Port $HttpPort -HostHeader $HostName
    Write-Warning "HTTP binding on port $HttpPort added for browser redirects only. The gateway refuses API calls on it."
}

# Attach the certificate. A re-run replaces whatever was bound before.
$binding = Get-WebBinding -Name $SiteName -Protocol https |
    Where-Object { $_.bindingInformation -eq $httpsBindingInfo }
try { $binding.RemoveSslCertificate() } catch { }
$binding.AddSslCertificate($thumbprint, "My")

try { Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationDefaults.preloadEnabled -Value $true }
catch { Write-Warning "Preload not set (install the 'Application Initialization' role service)." }

# --- Protocol floor ---
$protocols = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$legacyChanged = $false
foreach ($protocol in "SSL 3.0", "TLS 1.0", "TLS 1.1") {
    $key = "$protocols\$protocol\Server"
    if ($DisableLegacyTls) {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null
        $legacyChanged = $true
    } elseif ((Get-ItemProperty -Path $key -Name Enabled -ErrorAction SilentlyContinue).Enabled -ne 0) {
        Write-Warning "$protocol is not explicitly disabled for server use. Re-run with -DisableLegacyTls, or set it by Group Policy."
    }
}
if ($legacyChanged) {
    Write-Warning "SSL 3.0, TLS 1.0 and TLS 1.1 are disabled in SCHANNEL. Reboot the server for this to take effect."
}

# --- Runtime folder permissions for the app-pool identity ---
$acct = "IIS AppPool\$SiteName"
foreach ($sub in @("data", "logs")) {
    $dir = Join-Path $SiteRoot $sub
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    icacls $dir /grant "${acct}:(OI)(CI)M" /T | Out-Null
}

Start-WebAppPool -Name $SiteName
Start-Website -Name $SiteName

$shownHost = if ($HostName) { $HostName } else { "localhost" }
$portSuffix = if ($HttpsPort -eq 443) { "" } else { ":$HttpsPort" }
Write-Host "Installed. Gateway: https://$shownHost$portSuffix/  (dashboard)   /status   /gateway/health"
Write-Host "Set production config in $SiteRoot\appsettings.Production.json (Roles Anywhere ARNs, break-glass principal, Okta tenant, local model URLs)."
if ($HttpsPort -ne 443) {
    Write-Host "Non-default HTTPS port: set Gateway:Security:HttpsPort to $HttpsPort so browser redirects target it."
}
