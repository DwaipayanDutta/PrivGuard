@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Windows Privacy Hardening

:: ============================================================================
:: Windows-Privacy-Hardening.bat
:: No third-party software. Windows 10/11.
::
:: Modes:
::   1 = SAFE       Supported Windows policies/settings; minimal disruption
::   2 = AGGRESSIVE More telemetry reduction; disables selected tasks/services
::   3 = MONITOR    Observe outbound Microsoft connections; no blocking/changes
::   4 = ROLLBACK   Restore settings from the backup created by this script
::
:: Run as Administrator.
::
:: Fix log (vs. earlier version):
::   - Backup/rollback now covers CloudContent, InputPersonalization, and
::     Speech_OneCore registry keys (previously modified but never backed up).
::   - Service start-type backup is now actually read back and restored,
::     including Delayed Auto-Start, instead of being hardcoded on rollback.
::   - Scheduled-task backup covers every task either mode can disable, and
::     rollback restores each task to its ACTUAL previous state rather than
::     always force-enabling.
::   - Removed dead WIN_MAJOR/WIN_MINOR capture and the redundant CurrentBuild
::     registry query.
:: ============================================================================

set "SCRIPT_NAME=Windows-Privacy-Hardening"
set "BASE=%ProgramData%\%SCRIPT_NAME%"
set "BACKUP=%BASE%\Backup"
set "LOG=%BASE%\%SCRIPT_NAME%.log"
set "REG=%BACKUP%\registry"
set "TASKS=%BACKUP%\tasks"
set "SERVICES=%BACKUP%\services"

if not exist "%BASE%" mkdir "%BASE%" >nul 2>&1
if not exist "%BACKUP%" mkdir "%BACKUP%" >nul 2>&1
if not exist "%REG%" mkdir "%REG%" >nul 2>&1
if not exist "%TASKS%" mkdir "%TASKS%" >nul 2>&1
if not exist "%SERVICES%" mkdir "%SERVICES%" >nul 2>&1

call :is_admin
if errorlevel 1 (
    echo.
    echo [!] Administrator privileges are required.
    echo     Relaunching elevated...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call :detect_windows

:MENU
cls
echo ============================================================
echo              WINDOWS PRIVACY HARDENING
echo ============================================================
echo.
echo Detected: %WIN_NAME% %WIN_BUILD% ^(%ARCH%^)
echo.
echo  1. SAFE       - recommended
echo  2. AGGRESSIVE - stronger telemetry reduction
echo  3. MONITOR    - observe Microsoft outbound connections
echo  4. ROLLBACK   - restore this script's backup
echo  5. STATUS     - show current policy state
echo  6. EXIT
echo.
choice /C 123456 /N /M "Select [1-6]: "
if errorlevel 6 exit /b
if errorlevel 5 goto STATUS
if errorlevel 4 goto ROLLBACK
if errorlevel 3 goto MONITOR
if errorlevel 2 goto AGGRESSIVE
if errorlevel 1 goto SAFE

:SAFE
call :init_log "SAFE mode"
call :backup
call :apply_common
call :apply_safe
call :finish "SAFE"
goto END

:AGGRESSIVE
call :init_log "AGGRESSIVE mode"
call :backup
call :apply_common
call :apply_safe
call :apply_aggressive
call :finish "AGGRESSIVE"
goto END

:ROLLBACK
call :init_log "ROLLBACK"
call :rollback
goto END

:STATUS
cls
echo ============================================================
echo                     PRIVACY STATUS
echo ============================================================
echo.
echo Windows: %WIN_NAME% %WIN_BUILD%
echo.
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDumpCollection 2>nul
echo.
echo Tailored experiences:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled 2>nul
echo.
echo Advertising ID:
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled 2>nul
echo.
echo Activity history:
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities 2>nul
echo.
echo Consumer features / Spotlight:
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures 2>nul
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures 2>nul
echo.
echo DiagTrack / dmwappushservice start type:
sc qc DiagTrack 2>nul | findstr /I "START_TYPE"
sc qc dmwappushservice 2>nul | findstr /I "START_TYPE"
echo.
pause
goto MENU

:MONITOR
call :init_log "MONITOR mode"
call :monitor
goto END

:: ---------------------------------------------------------------------------
:: FUNCTIONS
:: ---------------------------------------------------------------------------

:is_admin
net session >nul 2>&1
if errorlevel 1 exit /b 1
exit /b 0

:detect_windows
for /f "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2^>nul ^| find "ProductName"') do set "WIN_NAME=%%b"
for /f "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2^>nul ^| find "CurrentBuildNumber"') do set "WIN_BUILD=%%b"
if "%WIN_NAME%"=="" set "WIN_NAME=Windows"
if "%WIN_BUILD%"=="" set "WIN_BUILD=Unknown"
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (set "ARCH=x64") else if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" (set "ARCH=ARM64") else (set "ARCH=x86")
exit /b

:init_log
echo.>>"%LOG%"
echo ============================================================>>"%LOG%"
echo %date% %time% - %~1>>"%LOG%"
echo Windows: %WIN_NAME% %WIN_BUILD% %ARCH%>>"%LOG%"
echo ============================================================>>"%LOG%"
exit /b

:log
echo [%time%] %~1>>"%LOG%"
echo [%time%] %~1
exit /b

:backup
call :log "Creating registry backup..."
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "%REG%\DataCollection.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "%REG%\SystemPolicy.reg" /y >nul 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" "%REG%\UserPrivacy.reg" /y >nul 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "%REG%\AdvertisingInfo.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "%REG%\CloudContent.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" "%REG%\InputPersonalization.reg" /y >nul 2>&1
reg export "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" "%REG%\SpeechOneCore.reg" /y >nul 2>&1

call :log "Backing up scheduled-task states..."
call :backup_task "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
call :backup_task "Microsoft\Windows\Application Experience\ProgramDataUpdater"
call :backup_task "Microsoft\Windows\Autochk\Proxy"
call :backup_task "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
call :backup_task "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
call :backup_task "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
call :backup_task "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
call :backup_task "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll"
call :backup_task "Microsoft\Windows\Application Experience\StartupAppTask"
call :backup_task "Microsoft\Windows\Application Experience\MareBackup"

call :log "Backing up service start types..."
call :backup_service "DiagTrack"
call :backup_service "dmwappushservice"

call :log "Backup completed."
exit /b

:backup_task
set "TNAME=%~1"
set "SAFE_NAME=%TNAME:\=__%"
schtasks /Query /TN "%TNAME%" /FO LIST /V > "%TASKS%\%SAFE_NAME%.txt" 2>&1
exit /b

:backup_service
set "SVC=%~1"
set "ST="
for /f "tokens=3" %%S in ('sc qc "%SVC%" 2^>nul ^| findstr /I "START_TYPE"') do set "ST=%%S"
set "DELAYED=0"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\%SVC%" /v DelayedAutostart 2>nul | findstr /I "0x1" >nul 2>&1
if not errorlevel 1 set "DELAYED=1"
>"%SERVICES%\%SVC%.state" (
    echo START_TYPE=%ST%
    echo DELAYED=%DELAYED%
)
exit /b

:apply_common
call :log "Applying supported diagnostic-data policies..."

:: 1 = Required diagnostic data on editions where policy is honored.
:: Microsoft documents 0 as Diagnostic data off (Security) for eligible
:: managed editions and 1 as Required. We deliberately use 1 for broad
:: Windows 10/11 compatibility and to preserve Windows servicing diagnostics.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDiagnosticLogCollection /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitDumpCollection /t REG_DWORD /d 1 /f >nul

:: Prevent the diagnostic-data opt-in UI from being used to raise the policy.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableTelemetryOptInSettingsUx /t REG_DWORD /d 1 /f >nul

:: Reduce tailored experiences based on diagnostic data.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f >nul

:: Disable Windows Advertising ID for the current user.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul

:: Disable Windows consumer features / suggested content policy.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f >nul

:: Disable Windows Spotlight suggestions/consumer experiences where supported.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f >nul

:: Activity history: prevent publishing/uploading activity to Microsoft.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f >nul

:: Disable online speech recognition policy.
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v HasAccepted /t REG_DWORD /d 0 /f >nul

call :log "Common privacy policies applied."
exit /b

:apply_safe
call :log "Applying SAFE scheduled-task reductions..."

:: These are telemetry/CEIP-related tasks. Do not disable Windows Update,
:: Defender, Time Service, licensing, authentication, or core networking.
call :disable_task "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
call :disable_task "Microsoft\Windows\Application Experience\ProgramDataUpdater"
call :disable_task "Microsoft\Windows\Autochk\Proxy"
call :disable_task "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
call :disable_task "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
call :disable_task "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"

call :log "SAFE mode completed."
exit /b

:apply_aggressive
call :log "Applying AGGRESSIVE telemetry reductions..."

:: Disable telemetry service. Windows can recreate/adjust telemetry behavior
:: after servicing; the policy settings above remain the primary control.
call :set_service_disabled "DiagTrack"
call :set_service_disabled "dmwappushservice"

:: Additional CEIP/telemetry scheduled tasks commonly present on Windows 10/11.
call :disable_task "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
call :disable_task "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll"

:: Disable Application Experience tasks if present.
call :disable_task "Microsoft\Windows\Application Experience\StartupAppTask"
call :disable_task "Microsoft\Windows\Application Experience\MareBackup"

call :log "AGGRESSIVE mode completed."
call :log "NOTE: Firewall endpoint blocking is intentionally NOT enabled."
call :log "Blocking Microsoft-wide domains can break Update, Defender, Store, authentication and other services."
exit /b

:monitor
cls
echo ============================================================
echo                    MONITOR MODE
echo ============================================================
echo.
echo This mode DOES NOT block or disable anything.
echo It correlates each active connection to its owning process
echo and remote hostname, and classifies the destination against
echo known Microsoft telemetry endpoints.
echo.
echo Resolving hostnames, this can take a little while...
echo.

if not exist "%BASE%\Monitor" mkdir "%BASE%\Monitor" >nul 2>&1
set "MSTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%"
set "MSTAMP=%MSTAMP: =0%"
set "MON=%BASE%\Monitor\Microsoft-Monitor_%MSTAMP%.txt"
set "MTMP=%BASE%\Monitor\tmp"
if exist "%MTMP%" rmdir /s /q "%MTMP%" >nul 2>&1
mkdir "%MTMP%" >nul 2>&1

:: ---- Collect ESTABLISHED TCP connections (Proto,Local,Foreign,State,PID) ---
if exist "%MTMP%\ips_raw.txt" del "%MTMP%\ips_raw.txt"
if exist "%MTMP%\pids_raw.txt" del "%MTMP%\pids_raw.txt"
if exist "%MTMP%\pairs_raw.txt" del "%MTMP%\pairs_raw.txt"
if exist "%MTMP%\conns.csv" del "%MTMP%\conns.csv"

for /f "tokens=1,2,3,4,5" %%a in ('netstat -ano ^| findstr /I "ESTABLISHED"') do call :mon_collect "%%b" "%%c" "%%e"

call :mon_dedupe "%MTMP%\ips_raw.txt" "%MTMP%\ips_unique.txt"
call :mon_dedupe "%MTMP%\pids_raw.txt" "%MTMP%\pids_unique.txt"
call :mon_dedupe "%MTMP%\pairs_raw.txt" "%MTMP%\pairs_unique.txt"

:: ---- Resolve each unique remote IP via nslookup, classify hostname --------
if exist "%MTMP%\resolved.txt" del "%MTMP%\resolved.txt"
for /f "delims=" %%I in ('type "%MTMP%\ips_unique.txt" 2^>nul') do call :mon_resolve_ip "%%I"

:: ---- Resolve each unique PID to a process name -----------------------------
if exist "%MTMP%\procs.txt" del "%MTMP%\procs.txt"
for /f "delims=" %%P in ('type "%MTMP%\pids_unique.txt" 2^>nul') do call :mon_proc_name "%%P"

:: ---- Write report -----------------------------------------------------------
echo Windows Privacy Hardening - MONITOR MODE > "%MON%"
echo Started: %date% %time% >> "%MON%"
echo Windows: %WIN_NAME% %WIN_BUILD% %ARCH% >> "%MON%"
echo. >> "%MON%"
echo ============================================================ >> "%MON%"
echo SUMMARY >> "%MON%"
echo ============================================================ >> "%MON%"
for %%C in ("Known Microsoft telemetry endpoint" "Microsoft-owned domain (general)" "Non-Microsoft / Unclassified") do (
    set "CNT=0"
    for /f %%N in ('findstr /C:"%%~C" "%MTMP%\resolved.txt" 2^>nul ^| find /c /v ""') do set "CNT=%%N"
    echo   %%~C: !CNT!>> "%MON%"
)
echo. >> "%MON%"
echo ============================================================ >> "%MON%"
echo PROCESS / DESTINATION CORRELATION ^(established connections^) >> "%MON%"
echo ============================================================ >> "%MON%"
echo Classification legend: >> "%MON%"
echo   Known Microsoft telemetry endpoint - documented Windows diagnostic-data host >> "%MON%"
echo   Microsoft-owned domain ^(general^)   - Microsoft-operated, not necessarily telemetry >> "%MON%"
echo                                         ^(covers Update, Defender cloud, auth, Office, etc.^) >> "%MON%"
echo   Non-Microsoft / Unclassified        - does not match either list above >> "%MON%"
echo. >> "%MON%"
echo PID     PROCESS                  REMOTE_IP          HOSTNAME >> "%MON%"
echo ------------------------------------------------------------------------------------------- >> "%MON%"
for /f "tokens=1,2 delims=|" %%A in ('type "%MTMP%\pairs_unique.txt" 2^>nul') do call :mon_emit_row "%%A" "%%B"
echo. >> "%MON%"

echo ============================================================ >> "%MON%"
echo RAW ACTIVE TCP CONNECTIONS ^(all states^) >> "%MON%"
echo ============================================================ >> "%MON%"
netstat -ano >> "%MON%" 2>&1
echo. >> "%MON%"
echo ============================================================ >> "%MON%"
echo DNS CACHE - MICROSOFT RELATED ENTRIES >> "%MON%"
echo ============================================================ >> "%MON%"
ipconfig /displaydns | findstr /I /C:"microsoft" /C:"windowsupdate" /C:"windows.com" /C:"office.com" /C:"live.com" /C:"azure" /C:"bing.com" >> "%MON%" 2>&1
echo. >> "%MON%"
echo ============================================================ >> "%MON%"
echo ACTIVE PROCESSES >> "%MON%"
echo ============================================================ >> "%MON%"
tasklist /FO TABLE >> "%MON%" 2>&1
echo. >> "%MON%"
echo LIMITATIONS >> "%MON%"
echo ============================================================ >> "%MON%"
echo PTR ^(reverse DNS^) records are set by the address owner and can be >> "%MON%"
echo absent, generic, or occasionally misleading. Classification is a >> "%MON%"
echo best-effort hostname match, not proof of ownership. >> "%MON%"
echo Microsoft services may share IP ranges/CDN infrastructure with others. >> "%MON%"
echo This is NOT packet capture and does not inspect transmitted data - >> "%MON%"
echo it shows who a process is connected to, not what data is exchanged. >> "%MON%"
echo IPv6 remote addresses are not correlated ^(IPv4 only^); see the raw >> "%MON%"
echo netstat section above for the complete connection list. >> "%MON%"
echo No firewall, registry, service, or task changes were made. >> "%MON%"

rmdir /s /q "%MTMP%" >nul 2>&1
call :log "Monitor report created: %MON%"
echo.
echo Monitor report created:
echo   %MON%
echo.
type "%MON%" | findstr /C:"Known Microsoft" /C:"Microsoft-owned domain" /C:"Non-Microsoft"
echo.
echo For repeated monitoring, run MONITOR periodically.
echo.
pause
exit /b

:mon_collect
set "LOCAL=%~1"
set "REMOTE=%~2"
set "PID=%~3"
:: IPv4 only: take the part before the last colon as the IP. IPv6 addresses
:: (which contain multiple colons) are intentionally skipped here; they still
:: appear in the raw netstat dump later in the report.
for /f "tokens=1,2 delims=." %%z in ("%REMOTE%") do set "ISV4=1"
echo %REMOTE% | findstr /R "^\[" >nul 2>&1
if not errorlevel 1 goto :mon_collect_skip
for /f "delims=:" %%R in ("%REMOTE%") do set "RIP=%%R"
echo %RIP% | findstr /R "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul 2>&1
if errorlevel 1 goto :mon_collect_skip
echo %RIP%>>"%MTMP%\ips_raw.txt"
echo %PID%>>"%MTMP%\pids_raw.txt"
echo %PID%^|%RIP%>>"%MTMP%\pairs_raw.txt"
:mon_collect_skip
exit /b

:mon_dedupe
set "INFILE=%~1"
set "OUTFILE=%~2"
if exist "%OUTFILE%" del "%OUTFILE%"
if not exist "%INFILE%" exit /b
set "PREV="
for /f "delims=" %%L in ('sort "%INFILE%" 2^>nul') do (
    if /i not "%%L"=="!PREV!" (
        echo %%L>>"%OUTFILE%"
        set "PREV=%%L"
    )
)
exit /b

:mon_resolve_ip
set "IP=%~1"
set "HOSTNAME="
for /f "tokens=2 delims=:" %%N in ('nslookup %IP% 2^>nul ^| findstr /I "Name:"') do set "HOSTNAME=%%N"
if defined HOSTNAME (
    for /f "tokens=* delims= " %%T in ("!HOSTNAME!") do set "HOSTNAME=%%T"
) else (
    set "HOSTNAME=(no PTR record)"
)
call :mon_classify "!HOSTNAME!"
echo %IP%^|!HOSTNAME!^|!CLASS!>>"%MTMP%\resolved.txt"
exit /b

:mon_classify
set "H=%~1"
set "CLASS=Non-Microsoft / Unclassified"
echo %H% | findstr /I "v10.events.data.microsoft.com v20.events.data.microsoft.com watson.telemetry.microsoft.com settings-win.data.microsoft.com self.events.data.microsoft.com" >nul 2>&1
if not errorlevel 1 (
    set "CLASS=Known Microsoft telemetry endpoint"
    exit /b
)
echo %H% | findstr /I /C:"microsoft.com" /C:"azure.com" /C:"windows.com" /C:"office.com" /C:"live.com" /C:"bing.com" /C:"msftncsi.com" /C:"windowsupdate.com" /C:"azureedge.net" /C:"msedge.net" >nul 2>&1
if not errorlevel 1 (
    set "CLASS=Microsoft-owned domain (general)"
    exit /b
)
exit /b

:mon_proc_name
set "PID=%~1"
set "PNAME=(unknown)"
for /f "tokens=1 delims=," %%N in ('tasklist /FI "PID eq %PID%" /FO CSV /NH 2^>nul') do set "PNAME=%%~N"
echo %PID%^|%PNAME%>>"%MTMP%\procs.txt"
exit /b

:mon_emit_row
set "PID=%~1"
set "RIP=%~2"
set "PNAME=(unknown)"
for /f "tokens=1,2 delims=|" %%X in ('findstr /B "%PID%|" "%MTMP%\procs.txt" 2^>nul') do set "PNAME=%%Y"
set "HOSTNAME=(unresolved)"
set "CLASS=Non-Microsoft / Unclassified"
for /f "tokens=1,2,3 delims=|" %%X in ('findstr /B "%RIP%|" "%MTMP%\resolved.txt" 2^>nul') do (
    set "HOSTNAME=%%Y"
    set "CLASS=%%Z"
)
echo %PID%    !PNAME!    %RIP%    !HOSTNAME! ^(!CLASS!^)>> "%MON%"
exit /b

:disable_task
schtasks /Query /TN "%~1" >nul 2>&1
if errorlevel 1 (
    call :log "Task not present: %~1"
    exit /b
)
schtasks /Change /TN "%~1" /DISABLE >nul 2>&1
if errorlevel 1 (
    call :log "Could not disable task: %~1"
) else (
    call :log "Disabled task: %~1"
)
exit /b

:set_service_disabled
sc query "%~1" >nul 2>&1
if errorlevel 1 (
    call :log "Service not present: %~1"
    exit /b
)
sc config "%~1" start= disabled >nul 2>&1
if errorlevel 1 (
    call :log "Could not disable service: %~1"
) else (
    call :log "Disabled service: %~1"
)
exit /b

:finish
call :log "%~1 mode finished."
echo.
echo ============================================================
echo %~1 MODE COMPLETE
echo ============================================================
echo.
echo Log:
echo   %LOG%
echo.
echo Backup:
echo   %BACKUP%
echo.
echo A restart is recommended.
echo.
choice /C YN /N /M "Restart now? [Y/N]: "
if errorlevel 2 exit /b
shutdown /r /t 10 /c "Windows Privacy Hardening - restart"
exit /b

:rollback
if not exist "%BACKUP%" (
    echo No backup directory exists: %BACKUP%
    pause
    goto MENU
)

call :log "Restoring registry backups where available..."
if exist "%REG%\DataCollection.reg" reg import "%REG%\DataCollection.reg" >nul 2>&1
if exist "%REG%\SystemPolicy.reg" reg import "%REG%\SystemPolicy.reg" >nul 2>&1
if exist "%REG%\UserPrivacy.reg" reg import "%REG%\UserPrivacy.reg" >nul 2>&1
if exist "%REG%\AdvertisingInfo.reg" reg import "%REG%\AdvertisingInfo.reg" >nul 2>&1
if exist "%REG%\CloudContent.reg" reg import "%REG%\CloudContent.reg" >nul 2>&1
if exist "%REG%\InputPersonalization.reg" reg import "%REG%\InputPersonalization.reg" >nul 2>&1
if exist "%REG%\SpeechOneCore.reg" reg import "%REG%\SpeechOneCore.reg" >nul 2>&1

call :log "Restoring service start types from backup..."
call :restore_service "DiagTrack"
call :restore_service "dmwappushservice"

call :log "Restoring scheduled tasks to their previous state..."
call :restore_task "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
call :restore_task "Microsoft\Windows\Application Experience\ProgramDataUpdater"
call :restore_task "Microsoft\Windows\Autochk\Proxy"
call :restore_task "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
call :restore_task "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
call :restore_task "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
call :restore_task "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
call :restore_task "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll"
call :restore_task "Microsoft\Windows\Application Experience\StartupAppTask"
call :restore_task "Microsoft\Windows\Application Experience\MareBackup"

call :log "Rollback completed."
echo.
echo Rollback completed. Some settings may require a restart.
pause
goto MENU

:restore_service
set "SVC=%~1"
set "STATEFILE=%SERVICES%\%SVC%.state"
sc query "%SVC%" >nul 2>&1
if errorlevel 1 (
    call :log "Service not present, skipping restore: %SVC%"
    exit /b
)
if not exist "%STATEFILE%" (
    call :log "No saved state for service %SVC%, leaving as-is."
    exit /b
)
set "ST="
set "DELAYED=0"
for /f "tokens=1,2 delims==" %%A in ('type "%STATEFILE%"') do (
    if /i "%%A"=="START_TYPE" set "ST=%%B"
    if /i "%%A"=="DELAYED" set "DELAYED=%%B"
)
if "%ST%"=="2" (
    if "%DELAYED%"=="1" (
        sc config "%SVC%" start= delayed-auto >nul 2>&1
    ) else (
        sc config "%SVC%" start= auto >nul 2>&1
    )
) else if "%ST%"=="3" (
    sc config "%SVC%" start= demand >nul 2>&1
) else if "%ST%"=="4" (
    sc config "%SVC%" start= disabled >nul 2>&1
) else if "%ST%"=="1" (
    sc config "%SVC%" start= system >nul 2>&1
) else if "%ST%"=="0" (
    sc config "%SVC%" start= boot >nul 2>&1
) else (
    call :log "Unrecognized saved start type '%ST%' for %SVC%, leaving as-is."
    exit /b
)
call :log "Restored service %SVC% to start type %ST% (delayed=%DELAYED%)"
exit /b

:restore_task
set "TNAME=%~1"
set "SAFE_NAME=%TNAME:\=__%"
set "STATEFILE=%TASKS%\%SAFE_NAME%.txt"
schtasks /Query /TN "%TNAME%" >nul 2>&1
if errorlevel 1 (
    call :log "Task not present, skipping restore: %TNAME%"
    exit /b
)
if not exist "%STATEFILE%" (
    REM No saved state: default to enabling, since these tasks ship enabled.
    schtasks /Change /TN "%TNAME%" /ENABLE >nul 2>&1
    call :log "No saved state for task %TNAME%, defaulted to ENABLE."
    exit /b
)
set "WASENABLED=1"
findstr /I /C:"Scheduled Task State:    Disabled" "%STATEFILE%" >nul 2>&1
if not errorlevel 1 set "WASENABLED=0"
if "%WASENABLED%"=="1" (
    schtasks /Change /TN "%TNAME%" /ENABLE >nul 2>&1
    call :log "Restored task to ENABLED: %TNAME%"
) else (
    schtasks /Change /TN "%TNAME%" /DISABLE >nul 2>&1
    call :log "Restored task to DISABLED (was already disabled before this script ran): %TNAME%"
)
exit /b

:END
echo.
echo Press any key to exit...
pause >nul
exit /b
