@echo off
setlocal

REM ---------------------------------------------------------------
REM  Build TideSSP MSI installer
REM
REM  Prerequisites:
REM    - Visual Studio Build Tools (cl.exe on PATH)
REM    - WiX Toolset v4+  (dotnet tool install --global wix)
REM    - Run from a "Developer Command Prompt" or after vcvarsall.bat
REM ---------------------------------------------------------------

set ROOT=%~dp0..
set BUILD=%ROOT%\build
set INSTALLER=%~dp0
set OUTDIR=%INSTALLER%\out

echo === Step 1: Build TideSSP and TideSubAuth DLLs ===
cmake -B "%BUILD%" -S "%ROOT%" -A x64
if errorlevel 1 goto :fail
cmake --build "%BUILD%" --config Release
if errorlevel 1 goto :fail

echo.
echo === Step 2: Build custom action DLL ===
cl /nologo /W4 /O2 /LD /DUNICODE /D_UNICODE ^
   "%INSTALLER%\CustomActions.c" ^
   /Fe:"%BUILD%\Release\TideCA.dll" ^
   /link msi.lib advapi32.lib netapi32.lib /DEF:"%INSTALLER%\CustomActions.def"
if errorlevel 1 goto :fail

echo.
echo === Step 3: Build MSI ===
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

REM WiX v4 CLI
wix build "%INSTALLER%\Product.wxs" ^
    -ext WixToolset.UI.wixext ^
    -bindpath BinDir="%BUILD%\Release" ^
    -bindpath InstallerDir="%INSTALLER%" ^
    -o "%OUTDIR%\TideSSP.msi"
if errorlevel 1 goto :fail

echo.
echo === Success ===
echo MSI output: %OUTDIR%\TideSSP.msi
goto :eof

:fail
echo.
echo === BUILD FAILED ===
exit /b 1
