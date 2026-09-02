<#
.SYNOPSIS
  Publishes the Unified LLM Gateway (framework-dependent) for IIS hosting and overlays the
  IIS web.config. Run on a build machine (with the .NET 8 SDK), then copy the output to the
  server, or run directly on the server.
.EXAMPLE
  ./publish.ps1 -OutputRoot C:\inetpub\unified-gateway
#>
param(
    [string]$OutputRoot = "C:\inetpub\unified-gateway",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # deploy/iis -> repo root

Write-Host "Publishing UnifiedGateway -> $OutputRoot"
dotnet publish "$repo\UnifiedGatewayV2.csproj" -c $Configuration -o "$OutputRoot"

# Overlay the IIS web.config (in-process hosting + ASPNETCORE_ENVIRONMENT=Production).
Copy-Item "$PSScriptRoot\web.config" "$OutputRoot\web.config" -Force

Write-Host "Done. Next: run install.ps1 (as Administrator) on the server."
