# Build Punchd VPN MSI installer
# Prerequisites:
#   - WiX Toolset v4+ (dotnet tool install --global wix)
#   - wix extension: wix extension add WixToolset.UI.wixext
#   - Rust cross-compiled exe already built

param(
    [string]$ExePath = "..\target\x86_64-pc-windows-gnu\release\punchd-vpn.exe",
    [string]$ConfigPath = "",
    [string]$Version = "1.0.0",
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"

# Verify exe exists
if (-not (Test-Path $ExePath)) {
    Write-Error "Exe not found: $ExePath"
    Write-Host "Build it first: cargo build --release --target x86_64-pc-windows-gnu --bin punchd-vpn"
    exit 1
}

$ExeFullPath = (Resolve-Path $ExePath).Path

# Create a dummy config if none provided (WiX needs the source file to exist)
$tempConfig = $false
if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
    $ConfigPath = Join-Path $env:TEMP "vpn-config-placeholder.toml"
    Set-Content -Path $ConfigPath -Value "# Placeholder - configure after install"
    $tempConfig = $true
}

$ConfigFullPath = (Resolve-Path $ConfigPath).Path

Write-Host "Building Punchd VPN MSI..."
Write-Host "  Exe: $ExeFullPath"
Write-Host "  Version: $Version"

# Build MSI using WiX v4
wix build main.wxs `
    -d "ExePath=$ExeFullPath" `
    -d "ConfigPath=$ConfigFullPath" `
    -ext WixToolset.UI.wixext `
    -o "$OutputDir\punchd-vpn-$Version.msi"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "MSI built: $OutputDir\punchd-vpn-$Version.msi" -ForegroundColor Green
    Write-Host ""
    Write-Host "Install: msiexec /i punchd-vpn-$Version.msi"
    Write-Host "Silent:  msiexec /i punchd-vpn-$Version.msi /qn"
    Write-Host "With config: msiexec /i punchd-vpn-$Version.msi VPNCONFIGSOURCE=C:\path\to\vpn-config.toml"
} else {
    Write-Error "WiX build failed"
}

# Cleanup temp
if ($tempConfig -and (Test-Path $ConfigPath)) {
    Remove-Item $ConfigPath
}
