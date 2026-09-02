<#
.SYNOPSIS
  Removes the Unified LLM Gateway IIS site and app pool. Does not delete published files or data.
#>
#Requires -RunAsAdministrator
param(
    [string]$SiteName = "unified-gateway"
)
$ErrorActionPreference = "SilentlyContinue"
Import-Module WebAdministration

if (Test-Path "IIS:\Sites\$SiteName")    { Remove-Website -Name $SiteName }
if (Test-Path "IIS:\AppPools\$SiteName") { Remove-WebAppPool -Name $SiteName }
Write-Host "Removed IIS site and app pool '$SiteName'."
