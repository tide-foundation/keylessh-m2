@echo off
echo Building Punchd VPN MSI...
powershell -ExecutionPolicy Bypass -File "%~dp0build-msi.ps1"
pause
