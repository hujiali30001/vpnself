# Furun VPN Build Script
# Usage: .\build.ps1 [-Target client|server|all]
param([string]$Target = "all")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
function Build-Target($spec, $name) {
    Write-Host "=== Building $name ===" -ForegroundColor Cyan
    python -m PyInstaller --noconfirm $spec
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $name" }
    Write-Host "=== $name OK ===" -ForegroundColor Green
}
if ($Target -eq "client" -or $Target -eq "all") { Build-Target "client.spec" "FurunVPN" }
if ($Target -eq "server" -or $Target -eq "all") { Build-Target "server_console.spec" "FurunVPNServer" }
Write-Host "Build complete." -ForegroundColor Green
