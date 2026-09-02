<#
.SYNOPSIS
  Creates/updates the IIS app pool and site for the Unified LLM Gateway and grants the app-pool
  identity write access to the runtime folders (data, dataprotection-keys, logs).

  The app pool uses "No Managed Code" (ASP.NET Core runs out-of-band), AlwaysRunning + preload so
  the AWS credential-refresh BackgroundService runs without an incoming request, and no idle
  timeout / periodic recycle so STS credentials keep refreshing.

  Prerequisites on the server:
    - IIS with the "Application Initialization" role service (for preload)
    - .NET 8 Hosting Bundle (ASP.NET Core Module V2)
  Run as Administrator, after publish.ps1.
.EXAMPLE
  ./install.ps1 -SiteRoot C:\inetpub\unified-gateway -Port 8080
#>
#Requires -RunAsAdministrator
param(
    [string]$SiteRoot = "C:\inetpub\unified-gateway",
    [string]$SiteName = "unified-gateway",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration

# --- App pool ---
if (-not (Test-Path "IIS:\AppPools\$SiteName")) { New-WebAppPool -Name $SiteName | Out-Null }
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name managedRuntimeVersion -Value ""            # No Managed Code
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name startMode -Value "AlwaysRunning"
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name processModel.idleTimeout -Value ([TimeSpan]::Zero)
Set-ItemProperty "IIS:\AppPools\$SiteName" -Name recycling.periodicRestart.time -Value ([TimeSpan]::Zero)

# --- Site ---
if (-not (Test-Path "IIS:\Sites\$SiteName")) {
    New-Website -Name $SiteName -PhysicalPath $SiteRoot -ApplicationPool $SiteName -Port $Port -Force | Out-Null
} else {
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name physicalPath -Value $SiteRoot
    Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationPool -Value $SiteName
}
try { Set-ItemProperty "IIS:\Sites\$SiteName" -Name applicationDefaults.preloadEnabled -Value $true }
catch { Write-Warning "Preload not set (install the 'Application Initialization' role service)." }

# --- Runtime folder permissions for the app-pool identity ---
$acct = "IIS AppPool\$SiteName"
foreach ($sub in @("data", "dataprotection-keys", "logs")) {
    $dir = Join-Path $SiteRoot $sub
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    icacls $dir /grant "${acct}:(OI)(CI)M" /T | Out-Null
}

Start-WebAppPool -Name $SiteName
Start-Website -Name $SiteName

Write-Host "Installed. Gateway: http://localhost:$Port/  (dashboard)   http://localhost:$Port/status   /gateway/health"
Write-Host "Set production config in $SiteRoot\appsettings.Production.json (AWS role, admin key, local model URLs)."
