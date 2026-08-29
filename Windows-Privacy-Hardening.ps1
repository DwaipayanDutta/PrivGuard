#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Privacy Hardening - PowerShell edition with an interactive menu.

.DESCRIPTION
    Uses only documented Microsoft policies, registry values, scheduled tasks,
    and services. No third-party software. Windows 10/11.

    Modes:
      1 = SAFE        Supported policies/settings; minimal disruption
      2 = AGGRESSIVE  More telemetry reduction; disables selected tasks/services
      3 = MONITOR     Observe outbound Microsoft connections; no changes made
      4 = ROLLBACK    Restore settings from this script's own backup
      5 = STATUS      Show current policy state
      6 = EXIT

    Run as Administrator.
#>

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# Self-elevate
# ---------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Administrator privileges are required. Relaunching elevated..." -ForegroundColor Yellow
    $psi = @{
        FilePath     = 'powershell.exe'
        ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        Verb         = 'RunAs'
    }
    Start-Process @psi
    exit
}

# ---------------------------------------------------------------------------
# Paths / state
# ---------------------------------------------------------------------------
$ScriptName = 'Windows-Privacy-Hardening'
$Base       = Join-Path $env:ProgramData $ScriptName
$BackupDir  = Join-Path $Base 'Backup'
$RegDir     = Join-Path $BackupDir 'registry'
$TaskDir    = Join-Path $BackupDir 'tasks'
$SvcDir     = Join-Path $BackupDir 'services'
$MonitorDir = Join-Path $Base 'Monitor'
$LogFile    = Join-Path $Base "$ScriptName.log"

foreach ($dir in @($Base, $BackupDir, $RegDir, $TaskDir, $SvcDir, $MonitorDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# Registry keys touched by this script - single source of truth for
# apply / backup / rollback / status, so nothing gets modified without
# also being backed up (see the earlier batch-file review for why that
# consistency matters).
$RegKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
    'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization',
    'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences'
)

# Scheduled tasks this script may disable (SAFE set + AGGRESSIVE set combined),
# always fully backed up regardless of which mode is chosen.
$AllTasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Autochk\Proxy',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeAll',
    '\Microsoft\Windows\Application Experience\StartupAppTask',
    '\Microsoft\Windows\Application Experience\MareBackup'
)

$SafeTasks = $AllTasks[0..5]
$AggressiveTasks = $AllTasks[6..9]
$Services = @('DiagTrack', 'dmwappushservice')

# Hostname patterns for MONITOR-mode classification. "Known telemetry" is an
# exact/specific match to a documented Windows diagnostic-data endpoint.
# "Microsoft-owned (general)" is a broader suffix match that also covers
# Windows Update, Defender cloud protection, auth, Office, etc. - i.e. NOT
# necessarily telemetry, just Microsoft-operated. Everything else is left
# unclassified rather than guessed at.
$KnownTelemetryHosts = @(
    'v10.events.data.microsoft.com',
    'v20.events.data.microsoft.com',
    'watson.telemetry.microsoft.com',
    'settings-win.data.microsoft.com',
    'self.events.data.microsoft.com'
)
$MicrosoftDomainSuffixes = @(
    'microsoft.com', 'azure.com', 'azureedge.net', 'msedge.net',
    'windows.com', 'windowsupdate.com', 'office.com', 'office365.com',
    'live.com', 'bing.com', 'msftncsi.com', 'msn.com', 'trafficmanager.net'
)

function Get-HostnameClassification {
    param([string]$Hostname)
    if ([string]::IsNullOrWhiteSpace($Hostname) -or $Hostname -eq '(no PTR record)') {
        return 'Unresolved'
    }
    foreach ($h in $KnownTelemetryHosts) {
        if ($Hostname -ieq $h) { return 'Known telemetry endpoint' }
    }
    foreach ($suffix in $MicrosoftDomainSuffixes) {
        if ($Hostname.ToLower().TrimEnd('.').EndsWith($suffix)) { return 'Microsoft-owned (general)' }
    }
    return 'Non-Microsoft / Unclassified'
}

# ---------------------------------------------------------------------------
# Logging / UI helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Host $line -ForegroundColor DarkGray
}

function Write-Section {
    param([string]$Title, [string]$Color = 'Cyan')
    $width = 64
    Write-Host ('=' * $width) -ForegroundColor $Color
    Write-Host ("  {0}" -f $Title.ToUpper()) -ForegroundColor $Color
    Write-Host ('=' * $width) -ForegroundColor $Color
}

function Write-Ok    { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Skip  { param([string]$m) Write-Host "  [--]   $m" -ForegroundColor DarkGray }
function Write-Warn2 { param([string]$m) Write-Host "  [!!]   $m" -ForegroundColor Yellow }
function Write-Info  { param([string]$m) Write-Host "  [i]    $m" -ForegroundColor Cyan }

function Get-WindowsInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    [PSCustomObject]@{
        Name = $os.Caption
        Build = $build
        Arch  = $env:PROCESSOR_ARCHITECTURE
    }
}

function Show-Banner {
    param([Parameter(Mandatory)]$WinInfo)
    Clear-Host
    $box = @(
        '╔══════════════════════════════════════════════════════════╗',
        '║              WINDOWS PRIVACY HARDENING                     ║',
        '╚══════════════════════════════════════════════════════════╝'
    )
    foreach ($l in $box) { Write-Host $l -ForegroundColor Magenta }
    Write-Host ""
    Write-Host ("  Detected: {0} (build {1}, {2})" -f $WinInfo.Name, $WinInfo.Build, $WinInfo.Arch) -ForegroundColor White
    Write-Host ""
}

function Show-Menu {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    $items = @(
        @{ Key = '1'; Label = 'SAFE'       ; Desc = 'recommended - minimal disruption'          ; Color = 'Green'  },
        @{ Key = '2'; Label = 'AGGRESSIVE' ; Desc = 'stronger telemetry reduction'               ; Color = 'Yellow' },
        @{ Key = '3'; Label = 'MONITOR'    ; Desc = 'observe Microsoft outbound connections'     ; Color = 'Cyan'   },
        @{ Key = '4'; Label = 'ROLLBACK'   ; Desc = "restore this script's backup"               ; Color = 'Red'    },
        @{ Key = '5'; Label = 'STATUS'     ; Desc = 'show current policy state'                  ; Color = 'White'  },
        @{ Key = '6'; Label = 'EXIT'       ; Desc = ''                                            ; Color = 'DarkGray' }
    )
    foreach ($item in $items) {
        Write-Host ("   {0}. " -f $item.Key) -NoNewline -ForegroundColor White
        Write-Host ("{0,-11}" -f $item.Label) -NoNewline -ForegroundColor $item.Color
        Write-Host (" {0}" -f $item.Desc) -ForegroundColor DarkGray
    }
    Write-Host ""
    $choice = Read-Host "  Select [1-6]"
    return $choice
}

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------
function Backup-RegistryKeys {
    Write-Log "Creating registry backup..."
    foreach ($key in $RegKeys) {
        if (Test-Path $key) {
            $nativePath = $key -replace '^HKLM:\\', 'HKLM\' -replace '^HKCU:\\', 'HKCU\'
            $fileName = ($key -replace '[:\\]', '_') + '.reg'
            $dest = Join-Path $RegDir $fileName
            & reg.exe export "$nativePath" "$dest" /y *> $null
        }
    }
    Write-Log "Registry backup completed."
}

function Backup-TaskStates {
    Write-Log "Backing up scheduled-task states..."
    foreach ($taskPath in $AllTasks) {
        $splitIndex = $taskPath.LastIndexOf('\')
        $folder = $taskPath.Substring(0, $splitIndex + 1)
        $name   = $taskPath.Substring($splitIndex + 1)
        $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
        $stateFile = Join-Path $TaskDir (($taskPath.TrimStart('\') -replace '[\\]', '__') + '.json')
        if ($task) {
            @{ Exists = $true; State = $task.State.ToString() } | ConvertTo-Json | Set-Content -Path $stateFile
        } else {
            @{ Exists = $false; State = $null } | ConvertTo-Json | Set-Content -Path $stateFile
        }
    }
}

function Backup-ServiceStates {
    Write-Log "Backing up service start types..."
    foreach ($svcName in $Services) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
        $stateFile = Join-Path $SvcDir "$svcName.json"
        if ($svc) {
            $delayed = $false
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
            if (Test-Path $regPath) {
                $val = (Get-ItemProperty -Path $regPath -Name DelayedAutostart -ErrorAction SilentlyContinue).DelayedAutostart
                if ($val -eq 1) { $delayed = $true }
            }
            @{ Exists = $true; StartMode = $svc.StartMode; Delayed = $delayed } | ConvertTo-Json | Set-Content -Path $stateFile
        } else {
            @{ Exists = $false; StartMode = $null; Delayed = $false } | ConvertTo-Json | Set-Content -Path $stateFile
        }
    }
}

function Backup-All {
    Backup-RegistryKeys
    Backup-TaskStates
    Backup-ServiceStates
    Write-Log "Backup completed."
}

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------
function Set-Reg {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Apply-CommonPolicies {
    Write-Log "Applying supported diagnostic-data policies..."

    # 1 = Required diagnostic data on editions where the policy is honored.
    # Microsoft documents 0 as "Diagnostic data off (Security)" for eligible
    # managed editions and 1 as "Required". We deliberately use 1 for broad
    # Windows 10/11 compatibility and to preserve Windows servicing diagnostics.
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDumpCollection' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'DisableTelemetryOptInSettingsUx' 1

    Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled' 0
    Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled' 0

    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableTailoredExperiencesWithDiagnosticData' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 1
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures' 1

    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 0
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 0

    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' 'AllowInputPersonalization' 0
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' 'HasAccepted' 0

    Write-Log "Common privacy policies applied."
}

function Disable-TaskSafe {
    param([string]$TaskPath)
    $splitIndex = $TaskPath.LastIndexOf('\')
    $folder = $TaskPath.Substring(0, $splitIndex + 1)
    $name   = $TaskPath.Substring($splitIndex + 1)
    $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log "Task not present: $TaskPath"
        return
    }
    try {
        Disable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction Stop | Out-Null
        Write-Log "Disabled task: $TaskPath"
    } catch {
        Write-Log "Could not disable task: $TaskPath ($($_.Exception.Message))"
    }
}

function Apply-SafeTasks {
    Write-Log "Applying SAFE scheduled-task reductions..."
    # Telemetry/CEIP-related tasks only. Windows Update, Defender, Time
    # Service, licensing, authentication, and core networking are never touched.
    foreach ($t in $SafeTasks) { Disable-TaskSafe -TaskPath $t }
    Write-Log "SAFE mode completed."
}

function Set-ServiceDisabled {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "Service not present: $Name"
        return
    }
    try {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
        Write-Log "Disabled service: $Name"
    } catch {
        Write-Log "Could not disable service: $Name ($($_.Exception.Message))"
    }
}

function Apply-AggressivePolicies {
    Write-Log "Applying AGGRESSIVE telemetry reductions..."
    foreach ($s in $Services) { Set-ServiceDisabled -Name $s }
    foreach ($t in $AggressiveTasks) { Disable-TaskSafe -TaskPath $t }
    Write-Log "AGGRESSIVE mode completed."
    Write-Log "NOTE: Firewall endpoint blocking is intentionally NOT enabled."
    Write-Log "Blocking Microsoft-wide domains can break Update, Defender, Store, authentication and other services."
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
function Get-RegValueDisplay {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -ne $val) { return $val }
    }
    return '(not set / default)'
}

function Show-Status {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    Write-Section "Privacy Status"
    Write-Host ""

    Write-Info "AllowTelemetry: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry')"
    Write-Info "LimitDiagnosticLogCollection: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDiagnosticLogCollection')"
    Write-Info "LimitDumpCollection: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'LimitDumpCollection')"
    Write-Host ""
    Write-Info "Tailored experiences: $(Get-RegValueDisplay 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' 'TailoredExperiencesWithDiagnosticDataEnabled')"
    Write-Info "Advertising ID enabled: $(Get-RegValueDisplay 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' 'Enabled')"
    Write-Host ""
    Write-Info "Activity history publish: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities')"
    Write-Info "Activity history upload: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities')"
    Write-Host ""
    Write-Info "Consumer features disabled: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures')"
    Write-Info "Spotlight disabled: $(Get-RegValueDisplay 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures')"
    Write-Host ""
    foreach ($svcName in $Services) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Info "$svcName start mode: $($svc.StartMode)  (state: $($svc.State))"
        } else {
            Write-Skip "$svcName not present"
        }
    }
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# Monitor (read-only)
# ---------------------------------------------------------------------------
function Resolve-PtrCached {
    param([string]$IPAddress, [hashtable]$Cache)
    if ($Cache.ContainsKey($IPAddress)) { return $Cache[$IPAddress] }
    $hostname = '(no PTR record)'
    try {
        $result = Resolve-DnsName -Name $IPAddress -Type PTR -ErrorAction Stop -QuickTimeout
        if ($result) {
            $rec = $result | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($rec) { $hostname = $rec.NameHost.TrimEnd('.') }
        }
    } catch {
        # No PTR record, private/unresolvable address, or lookup timeout - leave default.
    }
    $Cache[$IPAddress] = $hostname
    return $hostname
}

function Invoke-Monitor {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    Write-Section "Monitor Mode" 'Cyan'
    Write-Host ""
    Write-Host "  This mode DOES NOT block or disable anything." -ForegroundColor White
    Write-Host "  It records active connections, correlates each one to its" -ForegroundColor White
    Write-Host "  owning process and remote hostname, and classifies the" -ForegroundColor White
    Write-Host "  destination against known Microsoft telemetry endpoints." -ForegroundColor White
    Write-Host ""
    Write-Host "  Resolving hostnames, this can take a few seconds..." -ForegroundColor DarkGray

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $monFile = Join-Path $MonitorDir "Microsoft-Monitor_$stamp.txt"

    # ---- Gather raw connection + process data --------------------------------
    $connections = @()
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1') }
    } catch {
        Write-Warn2 "Get-NetTCPConnection unavailable; correlation table will be limited."
    }

    $dnsCache = @{}
    $procCache = @{}
    $rows = @()

    foreach ($c in $connections) {
        $pid_ = $c.OwningProcess
        if (-not $procCache.ContainsKey($pid_)) {
            $p = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
            $procCache[$pid_] = if ($p) { [PSCustomObject]@{ Name = $p.ProcessName; Path = $p.Path } }
                                 else { [PSCustomObject]@{ Name = '(unknown)'; Path = '' } }
        }
        $hostname = Resolve-PtrCached -IPAddress $c.RemoteAddress -Cache $dnsCache
        $classification = Get-HostnameClassification -Hostname $hostname

        $rows += [PSCustomObject]@{
            PID            = $pid_
            Process        = $procCache[$pid_].Name
            RemoteAddress  = $c.RemoteAddress
            RemotePort     = $c.RemotePort
            Hostname       = $hostname
            Classification = $classification
        }
    }

    # Deduplicate identical PID+RemoteAddress+Port rows that can appear from
    # multiple local sockets to the same destination; keep a count instead.
    $grouped = $rows | Group-Object PID, RemoteAddress, RemotePort | ForEach-Object {
        $first = $_.Group[0]
        [PSCustomObject]@{
            PID            = $first.PID
            Process        = $first.Process
            RemoteAddress  = $first.RemoteAddress
            RemotePort     = $first.RemotePort
            Hostname       = $first.Hostname
            Classification = $first.Classification
            Connections    = $_.Count
        }
    } | Sort-Object Classification, Process

    $summary = $grouped | Group-Object Classification | Select-Object Name, Count

    # ---- Build report ----------------------------------------------------
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Windows Privacy Hardening - MONITOR MODE")
    [void]$sb.AppendLine("Started: $(Get-Date)")
    [void]$sb.AppendLine("Windows: $($WinInfo.Name) $($WinInfo.Build) $($WinInfo.Arch)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("SUMMARY")
    [void]$sb.AppendLine("============================================================")
    foreach ($s in $summary) {
        [void]$sb.AppendLine(("  {0,-32} {1}" -f $s.Name, $s.Count))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("PROCESS / DESTINATION CORRELATION (established connections)")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("Classification legend:")
    [void]$sb.AppendLine("  Known telemetry endpoint   - matches a documented Windows diagnostic-data host")
    [void]$sb.AppendLine("  Microsoft-owned (general)  - Microsoft-operated domain, not necessarily telemetry")
    [void]$sb.AppendLine("                               (covers Update, Defender cloud, auth, Office, etc.)")
    [void]$sb.AppendLine("  Non-Microsoft/Unclassified - does not match either list above")
    [void]$sb.AppendLine("  Unresolved                 - no PTR record returned for the remote IP")
    [void]$sb.AppendLine("")
    $grouped | Format-Table PID, Process, RemoteAddress, RemotePort, Hostname, Classification, Connections -AutoSize |
        Out-String -Width 220 | ForEach-Object { [void]$sb.AppendLine($_) }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("RAW ACTIVE TCP CONNECTIONS (all states)")
    [void]$sb.AppendLine("============================================================")
    try {
        Get-NetTCPConnection -ErrorAction Stop |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Format-Table -AutoSize | Out-String -Width 200 | ForEach-Object { [void]$sb.AppendLine($_) }
    } catch {
        [void]$sb.AppendLine("Get-NetTCPConnection unavailable, falling back to netstat.")
        [void]$sb.AppendLine((netstat -ano | Out-String))
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("DNS CACHE - MICROSOFT RELATED ENTRIES")
    [void]$sb.AppendLine("============================================================")
    try {
        $pattern = 'microsoft|windowsupdate|windows\.com|office\.com|live\.com|azure|bing\.com'
        Get-DnsClientCache -ErrorAction Stop |
            Where-Object { $_.Entry -match $pattern } |
            Format-Table Entry, Data, TimeToLive -AutoSize | Out-String -Width 200 | ForEach-Object { [void]$sb.AppendLine($_) }
    } catch {
        [void]$sb.AppendLine("Get-DnsClientCache unavailable.")
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("ACTIVE PROCESSES")
    [void]$sb.AppendLine("============================================================")
    Get-Process | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String -Width 200 | ForEach-Object { [void]$sb.AppendLine($_) }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("LIMITATIONS")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("PTR (reverse DNS) records are set by the address owner and can be absent,")
    [void]$sb.AppendLine("generic (e.g. a bare CDN/cloud hostname), or occasionally misleading.")
    [void]$sb.AppendLine("Classification is a best-effort hostname match, not proof of ownership.")
    [void]$sb.AppendLine("Microsoft services may share IP ranges/CDN infrastructure with other tenants.")
    [void]$sb.AppendLine("This is NOT packet capture and does not inspect transmitted data - it shows")
    [void]$sb.AppendLine("who a process is connected to, not what data is being exchanged.")
    [void]$sb.AppendLine("No firewall, registry, service, or task changes were made.")

    Set-Content -Path $monFile -Value $sb.ToString()
    Write-Log "Monitor report created: $monFile"

    Write-Host ""
    Write-Ok "Monitor report created:"
    Write-Host "  $monFile" -ForegroundColor White
    Write-Host ""
    Write-Host "  Quick summary:" -ForegroundColor DarkGray
    foreach ($s in $summary) {
        $color = switch ($s.Name) {
            'Known telemetry endpoint'      { 'Yellow' }
            'Microsoft-owned (general)'     { 'Cyan' }
            'Non-Microsoft / Unclassified'  { 'White' }
            default                          { 'DarkGray' }
        }
        Write-Host ("    {0,-32} {1}" -f $s.Name, $s.Count) -ForegroundColor $color
    }
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------
function Restore-RegistryKeys {
    Write-Log "Restoring registry backups where available..."
    Get-ChildItem -Path $RegDir -Filter '*.reg' -ErrorAction SilentlyContinue | ForEach-Object {
        & reg.exe import "$($_.FullName)" *> $null
        Write-Log "Imported: $($_.Name)"
    }
}

function Restore-ServiceStates {
    Write-Log "Restoring service start types from backup..."
    foreach ($svcName in $Services) {
        $stateFile = Join-Path $SvcDir "$svcName.json"
        if (-not (Test-Path $stateFile)) {
            Write-Log "No saved state for service $svcName, leaving as-is."
            continue
        }
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-Log "Service not present, skipping restore: $svcName"
            continue
        }
        if (-not $state.Exists) {
            Write-Log "Service $svcName did not exist at backup time, leaving as-is."
            continue
        }
        switch -Wildcard ($state.StartMode) {
            'Auto' {
                if ($state.Delayed) {
                    & sc.exe config $svcName start= delayed-auto | Out-Null
                } else {
                    Set-Service -Name $svcName -StartupType Automatic
                }
            }
            'Manual'   { Set-Service -Name $svcName -StartupType Manual }
            'Disabled' { Set-Service -Name $svcName -StartupType Disabled }
            'Boot'     { & sc.exe config $svcName start= boot   | Out-Null }
            'System'   { & sc.exe config $svcName start= system | Out-Null }
            default    { Write-Log "Unrecognized saved start mode '$($state.StartMode)' for $svcName, leaving as-is." }
        }
        Write-Log "Restored service $svcName to start mode $($state.StartMode) (delayed=$($state.Delayed))"
    }
}

function Restore-TaskStates {
    Write-Log "Restoring scheduled tasks to their previous state..."
    foreach ($taskPath in $AllTasks) {
        $splitIndex = $taskPath.LastIndexOf('\')
        $folder = $taskPath.Substring(0, $splitIndex + 1)
        $name   = $taskPath.Substring($splitIndex + 1)
        $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log "Task not present, skipping restore: $taskPath"
            continue
        }
        $stateFile = Join-Path $TaskDir (($taskPath.TrimStart('\') -replace '[\\]', '__') + '.json')
        if (-not (Test-Path $stateFile)) {
            # No saved state: default to enabling, since these tasks ship enabled.
            Enable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue | Out-Null
            Write-Log "No saved state for task $taskPath, defaulted to ENABLE."
            continue
        }
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        if (-not $state.Exists) {
            Write-Log "Task $taskPath did not exist at backup time, leaving as-is."
            continue
        }
        if ($state.State -eq 'Disabled') {
            Disable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Restored task to DISABLED (was already disabled before this script ran): $taskPath"
        } else {
            Enable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue | Out-Null
            Write-Log "Restored task to ENABLED: $taskPath"
        }
    }
}

function Invoke-Rollback {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    if (-not (Test-Path $BackupDir)) {
        Write-Warn2 "No backup directory exists: $BackupDir"
        Read-Host "Press Enter to return to the menu"
        return
    }
    Write-Section "Rollback" 'Red'
    Write-Host ""
    Restore-RegistryKeys
    Restore-ServiceStates
    Restore-TaskStates
    Write-Log "Rollback completed."
    Write-Host ""
    Write-Ok "Rollback completed. Some settings may require a restart."
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# Finish / restart prompt
# ---------------------------------------------------------------------------
function Complete-Mode {
    param([string]$ModeName)
    Write-Log "$ModeName mode finished."
    Write-Host ""
    Write-Section "$ModeName Mode Complete" 'Green'
    Write-Host ""
    Write-Host "  Log:" -ForegroundColor DarkGray
    Write-Host "    $LogFile" -ForegroundColor White
    Write-Host "  Backup:" -ForegroundColor DarkGray
    Write-Host "    $BackupDir" -ForegroundColor White
    Write-Host ""
    Write-Host "  A restart is recommended." -ForegroundColor Yellow
    $answer = Read-Host "  Restart now? [y/N]"
    if ($answer -match '^[Yy]') {
        Write-Host "  Restarting in 10 seconds..." -ForegroundColor Yellow
        & shutdown.exe /r /t 10 /c "Windows Privacy Hardening - restart"
    }
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
function Start-InitLog {
    param([string]$Mode)
    $winInfo = Get-WindowsInfo
    Add-Content -Path $LogFile -Value ""
    Add-Content -Path $LogFile -Value ('=' * 60)
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Mode"
    Add-Content -Path $LogFile -Value "Windows: $($winInfo.Name) $($winInfo.Build) $($winInfo.Arch)"
    Add-Content -Path $LogFile -Value ('=' * 60)
}

$winInfo = Get-WindowsInfo

while ($true) {
    $choice = Show-Menu -WinInfo $winInfo
    switch ($choice) {
        '1' {
            Start-InitLog -Mode 'SAFE'
            Backup-All
            Apply-CommonPolicies
            Apply-SafeTasks
            Complete-Mode -ModeName 'SAFE'
        }
        '2' {
            Start-InitLog -Mode 'AGGRESSIVE'
            Backup-All
            Apply-CommonPolicies
            Apply-SafeTasks
            Apply-AggressivePolicies
            Complete-Mode -ModeName 'AGGRESSIVE'
        }
        '3' {
            Start-InitLog -Mode 'MONITOR'
            Invoke-Monitor -WinInfo $winInfo
        }
        '4' {
            Start-InitLog -Mode 'ROLLBACK'
            Invoke-Rollback -WinInfo $winInfo
        }
        '5' {
            Show-Status -WinInfo $winInfo
        }
        '6' {
            exit
        }
        default {
            Write-Warn2 "Invalid choice."
            Start-Sleep -Milliseconds 800
        }
    }
}
