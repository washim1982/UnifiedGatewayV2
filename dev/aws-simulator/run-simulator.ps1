# run-simulator.ps1
# Starts S3Local, KmsLocal, and IamLocal, then opens the dashboard in your default browser.

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       Starting Local AWS Simulator Services      " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

$services = @(
    @{ Name = "IamLocal"; Path = "src/IamLocal/IamLocal.csproj"; Port = 5003 },
    @{ Name = "KmsLocal"; Path = "src/KmsLocal/KmsLocal.csproj"; Port = 5002 },
    @{ Name = "S3Local";  Path = "src/S3Local/S3Local.csproj";   Port = 5001 }
)

$processes = @()

foreach ($s in $services) {
    Write-Host "Starting $($s.Name) on http://localhost:$($s.Port)..." -ForegroundColor Yellow
    $p = Start-Process -FilePath "dotnet" -ArgumentList "run --project $($s.Path) --urls http://localhost:$($s.Port)" -PassThru -NoNewWindow
    $processes += $p
}

Start-Sleep -Seconds 3

$dashboardUrl = "http://localhost:5003/"
Write-Host "`nOpening Dashboard UI at $dashboardUrl in your browser..." -ForegroundColor Green
Start-Process $dashboardUrl

Write-Host "`nAll services are running!" -ForegroundColor Green
Write-Host "  - S3Local:     http://localhost:5001" -ForegroundColor Gray
Write-Host "  - KmsLocal:    http://localhost:5002" -ForegroundColor Gray
Write-Host "  - IamLocal:    http://localhost:5003" -ForegroundColor Gray
Write-Host "  - Dashboard:   $dashboardUrl" -ForegroundColor Cyan
Write-Host "`nPress Enter to stop all services..." -ForegroundColor Yellow

[void][System.Console]::ReadLine()

Write-Host "Shutting down simulator services..." -ForegroundColor Yellow
Stop-Process -Name IamLocal, KmsLocal, S3Local -Force -ErrorAction SilentlyContinue
foreach ($p in $processes) {
    if (-not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "All services stopped." -ForegroundColor Green
