@echo off
REM ============================================================================
REM PrivGuard.bat - Launcher / elevation bootstrapper ONLY.
REM
REM All application logic (menus, registry/task/service handling, backup,
REM rollback, monitoring, logs, settings) lives in PrivGuard.ps1. This file's
REM only job is: confirm PrivGuard.ps1 exists next to it, ensure the process
REM is elevated, then hand off to PowerShell. Keeping logic in exactly one
REM place (the .ps1) avoids the .bat and .ps1 drifting out of sync.
REM ============================================================================
setlocal EnableExtensions
title PrivGuard Launcher

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%PrivGuard.ps1"

if not exist "%PS1%" (
    echo.
    echo [!] Cannot find PrivGuard.ps1 next to this launcher.
    echo     Expected: %PS1%
    echo     Make sure PrivGuard.bat and PrivGuard.ps1 are in the same folder.
    echo.
    pause
    exit /b 1
)

where powershell >nul 2>nul
if errorlevel 1 (
    echo.
    echo [!] powershell.exe was not found on your PATH.
    echo     PrivGuard requires Windows PowerShell 5.1 or later.
    echo.
    pause
    exit /b 1
)

REM ---------------------------------------------------------------------------
REM Elevation check. If not elevated, relaunch elevated and let this instance
REM exit; the elevated instance picks up from here and proceeds to launch the
REM PowerShell UI.
REM ---------------------------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo [!] Administrator privileges are required. Relaunching elevated...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%PS1%\"' -Verb RunAs"
    exit /b
)

REM ---------------------------------------------------------------------------
REM Already elevated: hand off to the PowerShell UI and mirror its exit code.
REM ---------------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "EXIT_CODE=%ERRORLEVEL%"
exit /b %EXIT_CODE%
