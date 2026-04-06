@echo off
setlocal

REM ---------------------------------------------------------------
REM  Build PunchdEndpoint MSI (TideSSP + Punchd Gateway service)
REM
REM  Expects the repository root at C:\src:
REM    C:\src\tide-ssp\                   TideSSP driver (C, built with MSVC)
REM    C:\src\bridges\punchd-bridge-rs\   Punchd Gateway (Rust, built with GNU)
REM
REM  Prerequisites (provided by the Docker image):
REM    - Visual Studio Build Tools (MSVC for TideSSP)
REM    - CMake, Ninja
REM    - WiX Toolset v6+
REM    - Rust with x86_64-pc-windows-gnu target
REM    - MinGW-w64
REM ---------------------------------------------------------------

set "TIDESSP=%~dp0.."
set "PUNCHD=C:\src\bridges\punchd-bridge-rs"
set "BUILD=%TIDESSP%\build"
set "OUTDIR=%TIDESSP%\out"

echo === Step 1: Build TideSSP DLLs with MSVC (TideSSP, TideSubAuth, TideCA) ===
cmake -B "%BUILD%" -S "%TIDESSP%" -A x64
if %errorlevel% neq 0 goto :fail
cmake --build "%BUILD%" --config Release
if %errorlevel% neq 0 goto :fail

echo.
echo === Step 2: Build punchd-bridge-rs with GNU (static binary, no vcruntime) ===
if not exist "%PUNCHD%\Cargo.toml" (
    echo ERROR: %PUNCHD%\Cargo.toml not found.
    echo Mount the repository root at C:\src.
    goto :fail
)
pushd "%PUNCHD%"
cargo build --release --target x86_64-pc-windows-gnu --bin punchd-bridge-rs
if %errorlevel% neq 0 (popd & goto :fail)

REM Copy binary to target\release for WiX bindpath
if not exist target\release mkdir target\release
copy /Y target\x86_64-pc-windows-gnu\release\punchd-bridge-rs.exe target\release\punchd-bridge-rs.exe
popd

echo.
echo === Step 3: Build combined MSI ===
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

wix build "%TIDESSP%\installer\WorkstationProduct.wxs" ^
    -arch x64 ^
    -bindpath BinDir="%BUILD%\Release" ^
    -bindpath InstallerDir="%TIDESSP%\installer" ^
    -bindpath PunchdDir="%PUNCHD%\target\release" ^
    -o "%OUTDIR%\PunchdEndpoint.msi"
if %errorlevel% neq 0 goto :fail
if not exist "%OUTDIR%\PunchdEndpoint.msi" (
    echo ERROR: MSI was not produced.
    goto :fail
)

echo.
echo === Success ===
echo MSI output: %OUTDIR%\PunchdEndpoint.msi
goto :eof

:fail
echo.
echo === BUILD FAILED ===
exit /b 1
