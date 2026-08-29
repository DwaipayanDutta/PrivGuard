#Requires -Version 5.1
<#
.SYNOPSIS
    PrivGuard - Windows Privacy & Telemetry Control

.DESCRIPTION
    Single source of truth for all PrivGuard logic and UI. Launched by
    PrivGuard.bat, which only handles elevation and process hand-off.

    Uses only documented Microsoft policies, registry values, scheduled
    tasks, and services. No third-party software. Windows 10/11.

    Modes:
      1 = SAFE        Supported policies/settings; minimal disruption
      2 = AGGRESSIVE  More telemetry reduction; disables selected tasks/services
      3 = MONITOR     Live view of processes talking to Microsoft endpoints
      4 = ROLLBACK    Restore settings from PrivGuard's own backup
      5 = STATUS      Detailed current privacy configuration
      6 = LOGS        View activity log and past monitor reports
      7 = SETTINGS    Configure PrivGuard
      Q = EXIT

    SAFE and AGGRESSIVE always show a dry-run preview of every change before
    anything is modified, and ask for confirmation before proceeding.

    Run via PrivGuard.bat (handles elevation). Running this file directly
    without elevation will simply tell you to do that.
#>

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# Elevation guard (elevation itself happens in PrivGuard.bat, not here -
# keeping it in one place avoids the two files drifting apart)
# ---------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "[!] PrivGuard needs Administrator privileges." -ForegroundColor Yellow
    Write-Host "    Please run PrivGuard.bat instead of launching this .ps1 directly -" -ForegroundColor Yellow
    Write-Host "    it takes care of elevation for you." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# ---------------------------------------------------------------------------
# Paths / persistent state
# ---------------------------------------------------------------------------
$ScriptName = 'PrivGuard'
$Base       = Join-Path $env:ProgramData $ScriptName
$BackupDir  = Join-Path $Base 'Backup'
$RegDir     = Join-Path $BackupDir 'registry'
$TaskDir    = Join-Path $BackupDir 'tasks'
$SvcDir     = Join-Path $BackupDir 'services'
$MonitorDir = Join-Path $Base 'Monitor'
$LogFile    = Join-Path $Base "$ScriptName.log"
$SettingsFile = Join-Path $Base 'settings.json'

foreach ($dir in @($Base, $BackupDir, $RegDir, $TaskDir, $SvcDir, $MonitorDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# ---------------------------------------------------------------------------
# Settings (persisted). Currently: which AllowTelemetry level SAFE/AGGRESSIVE
# target. 1 = "Required" (broad Windows 10/11 compatibility, preserves
# servicing diagnostics). 0 = "Off (Security)" - only honored on eligible
# managed editions (Enterprise/Education/Server with the right policy
# support); on unmanaged consumer editions Windows may silently fall back to
# a higher level, so this is opt-in rather than default.
# ---------------------------------------------------------------------------
function Get-DefaultSettings { @{ TelemetryLevel = 1 } }

function Load-Settings {
    if (Test-Path $SettingsFile) {
        try {
            $loaded = Get-Content $SettingsFile -Raw | ConvertFrom-Json
            return @{ TelemetryLevel = [int]$loaded.TelemetryLevel }
        } catch {
            return Get-DefaultSettings
        }
    }
    return Get-DefaultSettings
}

function Save-Settings {
    param($Settings)
    $Settings | ConvertTo-Json | Set-Content -Path $SettingsFile
}

$Settings = Load-Settings

# ---------------------------------------------------------------------------
# Registry keys touched by this script - single source of truth for
# apply / backup / rollback / status / dry-run, so nothing gets modified
# without also being backed up and previewable.
# ---------------------------------------------------------------------------
$RegKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
    'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization',
    'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences'
)

# Scheduled tasks this script may disable (SAFE set + AGGRESSIVE set
# combined), always fully backed up regardless of which mode is chosen.
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

# ---------------------------------------------------------------------------
# Hostname classification (used by both STATUS-adjacent summaries and the
# MONITOR screen). Buckets: TELEMETRY, SECURITY, UPDATE, GENERAL, OTHER.
# Rollup for summary counts: TELEMETRY / MICROSOFT SERVICES (SECURITY+UPDATE+
# GENERAL) / OTHER.
# ---------------------------------------------------------------------------
$TelemetryHosts = @(
    'v10.events.data.microsoft.com',
    'v20.events.data.microsoft.com',
    'watson.telemetry.microsoft.com',
    'settings-win.data.microsoft.com',
    'self.events.data.microsoft.com'
)
$SecuritySuffixes = @('wd.microsoft.com', 'smartscreen.microsoft.com', 'wdcp.microsoft.com', 'wdcpalt.microsoft.com')
$UpdateSuffixes   = @('windowsupdate.com', 'delivery.mp.microsoft.com', 'do.dsp.mp.microsoft.com')
$GeneralSuffixes  = @(
    'microsoft.com', 'azure.com', 'azureedge.net', 'msedge.net',
    'windows.com', 'office.com', 'office365.com', 'live.com',
    'bing.com', 'msftncsi.com', 'msn.com', 'trafficmanager.net'
)

function Get-ConnectionType {
    param([string]$Hostname)
    if ([string]::IsNullOrWhiteSpace($Hostname) -or $Hostname -eq '(no PTR record)') { return 'UNRESOLVED' }
    $h = $Hostname.ToLower().TrimEnd('.')
    foreach ($x in $TelemetryHosts)  { if ($h -eq $x) { return 'TELEMETRY' } }
    foreach ($x in $SecuritySuffixes) { if ($h.EndsWith($x)) { return 'SECURITY' } }
    foreach ($x in $UpdateSuffixes)   { if ($h.EndsWith($x)) { return 'UPDATE' } }
    foreach ($x in $GeneralSuffixes)  { if ($h.EndsWith($x)) { return 'GENERAL' } }
    return 'OTHER'
}

function Get-RollupCategory {
    param([string]$Type)
    switch ($Type) {
        'TELEMETRY'  { return 'TELEMETRY' }
        'SECURITY'   { return 'MICROSOFT SERVICES' }
        'UPDATE'     { return 'MICROSOFT SERVICES' }
        'GENERAL'    { return 'MICROSOFT SERVICES' }
        default      { return 'OTHER' }
    }
}

function Format-Destination {
    param([string]$Hostname, [string]$Type)
    if ($Type -eq 'UNRESOLVED') { return '(unresolved)' }
    $h = $Hostname.TrimEnd('.')
    if ($Type -eq 'TELEMETRY') {
        if ($h.Length -gt 22) { return $h.Substring(0, 19) + '...' }
        return $h
    }
    # For everything else, show a compact "*.suffix" form when we matched a
    # known suffix, since the exact subdomain is usually noise (CDN nodes etc).
    $allSuffixes = $SecuritySuffixes + $UpdateSuffixes + $GeneralSuffixes
    foreach ($s in $allSuffixes) {
        if ($h.EndsWith($s)) { return "*.$s" }
    }
    if ($h.Length -gt 22) { return $h.Substring(0, 19) + '...' }
    return $h
}

# ---------------------------------------------------------------------------
# Logging / low-level UI helpers
# ---------------------------------------------------------------------------
function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
    Add-Content -Path $LogFile -Value $line
}

function Write-Ok    { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Skip  { param([string]$m) Write-Host "  [--]   $m" -ForegroundColor DarkGray }
function Write-Warn2 { param([string]$m) Write-Host "  [!!]   $m" -ForegroundColor Yellow }
function Write-Info  { param([string]$m) Write-Host "  [i]    $m" -ForegroundColor Cyan }

function Get-WindowsInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    [PSCustomObject]@{ Name = $os.Caption; Build = $build; Arch = $env:PROCESSOR_ARCHITECTURE }
}

# ---------------------------------------------------------------------------
# Box-drawing UI
# ---------------------------------------------------------------------------
$BoxWidth = 66

function Write-BoxTop    { Write-Host ('╔' + ('═' * $BoxWidth) + '╗') -ForegroundColor Magenta }
function Write-BoxBottom { Write-Host ('╚' + ('═' * $BoxWidth) + '╝') -ForegroundColor Magenta }
function Write-BoxDivider { Write-Host ('╠' + ('═' * $BoxWidth) + '╣') -ForegroundColor Magenta }

function Write-BoxLine {
    param([string]$Text = '', [string]$Color = 'White')
    $pad = $BoxWidth - 2 - $Text.Length
    if ($pad -lt 0) { $Text = $Text.Substring(0, $BoxWidth - 5) + '...'; $pad = 0 }
    Write-Host '║ ' -NoNewline -ForegroundColor Magenta
    Write-Host $Text -NoNewline -ForegroundColor $Color
    Write-Host (' ' * $pad) -NoNewline
    Write-Host ' ║' -ForegroundColor Magenta
}

function Write-BoxTitle {
    param([string]$Text)
    $innerWidth = $BoxWidth
    $padTotal = $innerWidth - $Text.Length
    $padLeft = [Math]::Floor($padTotal / 2)
    $padRight = $innerWidth - $Text.Length - $padLeft
    Write-Host '║' -NoNewline -ForegroundColor Magenta
    Write-Host (' ' * $padLeft) -NoNewline
    Write-Host $Text -NoNewline -ForegroundColor White
    Write-Host (' ' * $padRight) -NoNewline
    Write-Host '║' -ForegroundColor Magenta
}

function Get-PrivacyStatusLines {
    # Returns an array of @{Label; Value; Color} for the four headline
    # indicators shown in the banner and reused in the full STATUS screen.
    $items = @()

    $telemetry = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry
    $tInfo = switch ($telemetry) {
        0       { @{ Label = 'OFF (SECURITY)'; Color = 'Green' } }
        1       { @{ Label = 'REQUIRED'; Color = 'Yellow' } }
        2       { @{ Label = 'ENHANCED'; Color = 'Yellow' } }
        3       { @{ Label = 'FULL'; Color = 'Red' } }
        default { @{ Label = 'DEFAULT (UNMANAGED)'; Color = 'Red' } }
    }
    $items += @{ Label = 'Diagnostic data'; Value = $tInfo.Label; Color = $tInfo.Color }

    $tailored = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' -Name TailoredExperiencesWithDiagnosticDataEnabled -ErrorAction SilentlyContinue).TailoredExperiencesWithDiagnosticDataEnabled
    if ($tailored -eq 0) { $items += @{ Label = 'Tailored experiences'; Value = 'DISABLED'; Color = 'Green' } }
    else { $items += @{ Label = 'Tailored experiences'; Value = 'ENABLED'; Color = 'Yellow' } }

    $ad = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($ad -eq 0) { $items += @{ Label = 'Advertising ID'; Value = 'DISABLED'; Color = 'Green' } }
    else { $items += @{ Label = 'Advertising ID'; Value = 'ENABLED'; Color = 'Yellow' } }

    $pub = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name PublishUserActivities -ErrorAction SilentlyContinue).PublishUserActivities
    $upl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name UploadUserActivities -ErrorAction SilentlyContinue).UploadUserActivities
    if ($pub -eq 0 -and $upl -eq 0) { $items += @{ Label = 'Activity history'; Value = 'BLOCKED'; Color = 'Green' } }
    else { $items += @{ Label = 'Activity history'; Value = 'ALLOWED'; Color = 'Yellow' } }

    return $items
}

function Show-Banner {
    param($WinInfo)
    Clear-Host
    Write-BoxTop
    Write-BoxTitle 'PRIVGUARD'
    Write-BoxTitle 'Windows Privacy & Telemetry Control'
    Write-BoxDivider
    Write-BoxLine ''
    Write-BoxLine 'SYSTEM' 'DarkCyan'
    Write-BoxLine ("{0}     Build {1}     {2}" -f $WinInfo.Name, $WinInfo.Build, $WinInfo.Arch)
    Write-BoxLine ''
    Write-BoxLine 'PRIVACY STATUS' 'DarkCyan'
    foreach ($item in (Get-PrivacyStatusLines)) {
        Write-Host '║ ' -NoNewline -ForegroundColor Magenta
        Write-Host '* ' -NoNewline -ForegroundColor $item.Color
        $line = "{0,-24} {1}" -f $item.Label, $item.Value
        $pad = $BoxWidth - 4 - $line.Length
        if ($pad -lt 0) { $pad = 0 }
        Write-Host $line -NoNewline -ForegroundColor White
        Write-Host (' ' * $pad) -NoNewline
        Write-Host ' ║' -ForegroundColor Magenta
    }
    Write-BoxLine ''
}

function Show-Menu {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    Write-BoxDivider
    Write-BoxLine ''
    $items = @(
        @{ Key = '1'; Label = 'SAFE'       ; Desc = 'Recommended privacy configuration'          ; Color = 'Green'  },
        @{ Key = '2'; Label = 'AGGRESSIVE' ; Desc = 'Maximum reduction without firewall blocking' ; Color = 'Yellow' },
        @{ Key = '3'; Label = 'MONITOR'    ; Desc = 'Inspect processes and Microsoft connections' ; Color = 'Cyan'   },
        @{ Key = '4'; Label = 'ROLLBACK'   ; Desc = 'Restore the previous Windows configuration'  ; Color = 'Red'    },
        @{ Key = '5'; Label = 'STATUS'     ; Desc = 'Detailed privacy configuration'              ; Color = 'White'  },
        @{ Key = '6'; Label = 'LOGS'       ; Desc = 'View activity and monitor reports'           ; Color = 'White'  },
        @{ Key = '7'; Label = 'SETTINGS'   ; Desc = 'Configure PrivGuard'                         ; Color = 'White'  }
    )
    foreach ($item in $items) {
        $line1 = "[{0}] {1}" -f $item.Key, $item.Label
        Write-Host '║   ' -NoNewline -ForegroundColor Magenta
        Write-Host $line1 -NoNewline -ForegroundColor $item.Color
        $pad = $BoxWidth - 4 - $line1.Length
        Write-Host (' ' * [Math]::Max($pad,0)) -NoNewline
        Write-Host ' ║' -ForegroundColor Magenta
        Write-BoxLine ("      {0}" -f $item.Desc) 'DarkGray'
        Write-BoxLine ''
    }
    Write-Host '║   ' -NoNewline -ForegroundColor Magenta
    Write-Host '[Q] EXIT' -NoNewline -ForegroundColor DarkGray
    $pad = $BoxWidth - 4 - 8
    Write-Host (' ' * [Math]::Max($pad,0)) -NoNewline
    Write-Host ' ║' -ForegroundColor Magenta
    Write-BoxLine ''
    Write-BoxBottom
    Write-Host ""
    $choice = Read-Host "Select an option"
    return $choice.Trim().ToUpper()
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
# Dry-run: compute planned changes without applying them
# ---------------------------------------------------------------------------
function Get-RegistryTargets {
    # Single source of truth for what SAFE/AGGRESSIVE set in the registry,
    # shared by both the real apply step and the dry-run preview.
    @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Target = $Settings.TelemetryLevel; Label = 'Diagnostic data level' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'LimitDiagnosticLogCollection'; Target = 1; Label = 'Limit diagnostic log collection' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'LimitDumpCollection'; Target = 1; Label = 'Limit dump collection' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'DisableTelemetryOptInSettingsUx'; Target = 1; Label = 'Lock diagnostic opt-in UI' },
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'TailoredExperiencesWithDiagnosticDataEnabled'; Target = 0; Label = 'Tailored experiences' },
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Target = 0; Label = 'Advertising ID' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsConsumerFeatures'; Target = 1; Label = 'Consumer features' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableTailoredExperiencesWithDiagnosticData'; Target = 1; Label = 'Tailored experiences (CloudContent)' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableSoftLanding'; Target = 1; Label = 'Spotlight soft-landing suggestions' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsSpotlightFeatures'; Target = 1; Label = 'Windows Spotlight features' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'PublishUserActivities'; Target = 0; Label = 'Publish activity history' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'UploadUserActivities'; Target = 0; Label = 'Upload activity history' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'; Name = 'AllowInputPersonalization'; Target = 0; Label = 'Online speech recognition' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences'; Name = 'HasAccepted'; Target = 0; Label = 'Speech data collection accepted' }
    )
}

function Get-PlannedChanges {
    param([string]$Mode)
    $changes = @()

    foreach ($r in (Get-RegistryTargets)) {
        $current = if (Test-Path $r.Path) { (Get-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue).($r.Name) } else { $null }
        $currentDisplay = if ($null -eq $current) { '(not set)' } else { $current }
        $changes += [PSCustomObject]@{
            Category   = 'Registry'
            Target     = $r.Label
            Current    = $currentDisplay
            New        = $r.Target
            WillChange = ($current -ne $r.Target)
        }
    }

    $taskList = if ($Mode -eq 'AGGRESSIVE') { $AllTasks } else { $SafeTasks }
    foreach ($t in $taskList) {
        $splitIndex = $t.LastIndexOf('\')
        $folder = $t.Substring(0, $splitIndex + 1)
        $name   = $t.Substring($splitIndex + 1)
        $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
        if ($task) {
            $cur = $task.State.ToString()
            $changes += [PSCustomObject]@{ Category = 'Scheduled Task'; Target = $name; Current = $cur; New = 'Disabled'; WillChange = ($cur -ne 'Disabled') }
        } else {
            $changes += [PSCustomObject]@{ Category = 'Scheduled Task'; Target = $name; Current = '(not present)'; New = 'Disabled'; WillChange = $false }
        }
    }

    if ($Mode -eq 'AGGRESSIVE') {
        foreach ($s in $Services) {
            $svc = Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue
            if ($svc) {
                $changes += [PSCustomObject]@{ Category = 'Service'; Target = $s; Current = $svc.StartMode; New = 'Disabled'; WillChange = ($svc.StartMode -ne 'Disabled') }
            } else {
                $changes += [PSCustomObject]@{ Category = 'Service'; Target = $s; Current = '(not present)'; New = 'Disabled'; WillChange = $false }
            }
        }
    }

    return $changes
}

function Show-DryRunPreview {
    param([string]$Mode, $WinInfo)
    Show-Banner -WinInfo $WinInfo
    Write-BoxDivider
    Write-BoxTitle "DRY RUN - $Mode"
    Write-BoxBottom
    Write-Host ""
    Write-Host "  Nothing has been changed yet. This is a preview." -ForegroundColor Cyan
    Write-Host ""

    $changes = Get-PlannedChanges -Mode $Mode
    $willChange = $changes | Where-Object { $_.WillChange }
    $noChange   = $changes | Where-Object { -not $_.WillChange }

    Write-Host ("  {0,-16} {1,-38} {2,-16} {3,-10}" -f 'CATEGORY', 'TARGET', 'CURRENT', 'NEW') -ForegroundColor DarkCyan
    Write-Host ('  ' + ('-' * 82)) -ForegroundColor DarkGray
    foreach ($c in $changes) {
        $color = if ($c.WillChange) { 'Yellow' } else { 'DarkGray' }
        $targetDisp = if ($c.Target.Length -gt 36) { $c.Target.Substring(0,33) + '...' } else { $c.Target }
        Write-Host ("  {0,-16} {1,-38} {2,-16} {3,-10}" -f $c.Category, $targetDisp, $c.Current, $c.New) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host ("  {0} setting(s) will change.  {1} already match the target or are not present." -f $willChange.Count, $noChange.Count) -ForegroundColor White
    Write-Host ""

    if ($willChange.Count -eq 0) {
        Write-Ok "System already matches this profile. Nothing to apply."
        Read-Host "Press Enter to return to the menu"
        return $false
    }

    $answer = Read-Host "  Apply these $($willChange.Count) change(s) now? [y/N]"
    return ($answer -match '^[Yy]')
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
    Write-Log "Applying supported diagnostic-data policies (TelemetryLevel=$($Settings.TelemetryLevel))..."
    foreach ($r in (Get-RegistryTargets)) {
        Set-Reg $r.Path $r.Name $r.Target
    }
    Write-Log "Common privacy policies applied."
}

function Disable-TaskSafe {
    param([string]$TaskPath)
    $splitIndex = $TaskPath.LastIndexOf('\')
    $folder = $TaskPath.Substring(0, $splitIndex + 1)
    $name   = $TaskPath.Substring($splitIndex + 1)
    $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
    if (-not $task) { Write-Log "Task not present: $TaskPath"; return }
    try {
        Disable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction Stop | Out-Null
        Write-Log "Disabled task: $TaskPath"
    } catch {
        Write-Log "Could not disable task: $TaskPath ($($_.Exception.Message))"
    }
}

function Apply-SafeTasks {
    Write-Log "Applying SAFE scheduled-task reductions..."
    foreach ($t in $SafeTasks) { Disable-TaskSafe -TaskPath $t }
    Write-Log "SAFE mode completed."
}

function Set-ServiceDisabled {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Log "Service not present: $Name"; return }
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
}

# ---------------------------------------------------------------------------
# STATUS (full view)
# ---------------------------------------------------------------------------
function Show-Status {
    param($WinInfo)
    Show-Banner -WinInfo $WinInfo
    Write-BoxDivider
    Write-BoxTitle 'DETAILED STATUS'
    Write-BoxBottom
    Write-Host ""
    foreach ($item in (Get-PrivacyStatusLines)) {
        Write-Host ("  {0,-26} " -f $item.Label) -NoNewline -ForegroundColor White
        Write-Host $item.Value -ForegroundColor $item.Color
    }
    Write-Host ""
    Write-Host "  Scheduled tasks:" -ForegroundColor DarkCyan
    foreach ($taskPath in $AllTasks) {
        $splitIndex = $taskPath.LastIndexOf('\')
        $folder = $taskPath.Substring(0, $splitIndex + 1)
        $name   = $taskPath.Substring($splitIndex + 1)
        $task = Get-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue
        if ($task) {
            $color = if ($task.State -eq 'Disabled') { 'Green' } else { 'Yellow' }
            Write-Host ("    {0,-55} {1}" -f $name, $task.State) -ForegroundColor $color
        } else {
            Write-Host ("    {0,-55} (not present)" -f $name) -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    Write-Host "  Services:" -ForegroundColor DarkCyan
    foreach ($svcName in $Services) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
        if ($svc) {
            $color = if ($svc.StartMode -eq 'Disabled') { 'Green' } else { 'Yellow' }
            Write-Host ("    {0,-30} {1,-12} (state: {2})" -f $svcName, $svc.StartMode, $svc.State) -ForegroundColor $color
        } else {
            Write-Host ("    {0,-30} (not present)" -f $svcName) -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# MONITOR - live correlation screen
# ---------------------------------------------------------------------------
function Resolve-PtrCached {
    param([string]$IPAddress, [hashtable]$Cache)
    if ($Cache.ContainsKey($IPAddress)) { return $Cache[$IPAddress] }
    $hostname = '(no PTR record)'
    try {
        $result = Resolve-DnsName -Name $IPAddress -Type PTR -ErrorAction Stop
        if ($result) {
            $rec = $result | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($rec) { $hostname = $rec.NameHost.TrimEnd('.') }
        }
    } catch { }
    $Cache[$IPAddress] = $hostname
    return $hostname
}

function Get-MonitorData {
    $connections = @()
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object { $_.RemoteAddress -notin @('127.0.0.1', '::1') }
    } catch { }

    $dnsCache = @{}
    $procCache = @{}
    $rows = @()

    foreach ($c in $connections) {
        $pid_ = $c.OwningProcess
        if (-not $procCache.ContainsKey($pid_)) {
            $p = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
            $procCache[$pid_] = if ($p) { $p.ProcessName } else { '(unknown)' }
        }
        $hostname = Resolve-PtrCached -IPAddress $c.RemoteAddress -Cache $dnsCache
        $type = Get-ConnectionType -Hostname $hostname
        $rows += [PSCustomObject]@{
            Process     = $procCache[$pid_]
            PID         = $pid_
            RemoteAddr  = $c.RemoteAddress
            Hostname    = $hostname
            Type        = $type
            Rollup      = Get-RollupCategory -Type $type
            Destination = Format-Destination -Hostname $hostname -Type $type
        }
    }

    $grouped = $rows | Group-Object PID, RemoteAddr | ForEach-Object { $_.Group[0] } | Sort-Object Rollup, Process
    return $grouped
}

function Show-MonitorScreen {
    param($WinInfo)
    $data = Get-MonitorData

    while ($true) {
        Show-Banner -WinInfo $WinInfo
        Write-BoxDivider
        Write-BoxTitle 'MONITOR'
        Write-BoxBottom
        Write-Host ""
        Write-Host "  Active Microsoft Connections" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host ("  {0,-16} {1,-8} {2,-26} {3,-12}" -f 'PROCESS', 'PID', 'DESTINATION', 'TYPE') -ForegroundColor DarkCyan
        Write-Host ('  ' + ('-' * 64)) -ForegroundColor DarkGray
        foreach ($row in $data) {
            $color = switch ($row.Type) {
                'TELEMETRY' { 'Yellow' }
                'SECURITY'  { 'Green' }
                'UPDATE'    { 'Cyan' }
                'GENERAL'   { 'White' }
                'UNRESOLVED'{ 'DarkGray' }
                default     { 'DarkGray' }
            }
            Write-Host ("  {0,-16} {1,-8} {2,-26} {3,-12}" -f $row.Process, $row.PID, $row.Destination, $row.Type) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host ('  ' + ('-' * 64)) -ForegroundColor DarkGray
        Write-Host ""
        $summary = $data | Group-Object Rollup
        $telemetryCount = ($summary | Where-Object { $_.Name -eq 'TELEMETRY' }).Count
        $msCount        = ($summary | Where-Object { $_.Name -eq 'MICROSOFT SERVICES' }).Count
        $otherCount     = ($summary | Where-Object { $_.Name -eq 'OTHER' }).Count
        Write-Host ("  {0,-24} {1}" -f 'TELEMETRY', $telemetryCount) -ForegroundColor Yellow
        Write-Host ("  {0,-24} {1}" -f 'MICROSOFT SERVICES', $msCount) -ForegroundColor Cyan
        Write-Host ("  {0,-24} {1}" -f 'OTHER', $otherCount) -ForegroundColor White
        Write-Host ""
        Write-Host "  [R] Refresh   [E] Export Report   [B] Back" -ForegroundColor DarkGray
        Write-Host ""

        $key = Read-Host "  Choice"
        switch ($key.Trim().ToUpper()) {
            'R' { $data = Get-MonitorData }
            'E' { Export-MonitorReport -WinInfo $WinInfo -Data $data; Read-Host "Press Enter to continue" }
            'B' { return }
            default { }
        }
    }
}

function Export-MonitorReport {
    param($WinInfo, $Data)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $monFile = Join-Path $MonitorDir "Microsoft-Monitor_$stamp.txt"

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("PrivGuard - MONITOR REPORT")
    [void]$sb.AppendLine("Generated: $(Get-Date)")
    [void]$sb.AppendLine("Windows: $($WinInfo.Name) $($WinInfo.Build) $($WinInfo.Arch)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("SUMMARY")
    [void]$sb.AppendLine("============================================================")
    $summary = $Data | Group-Object Rollup
    foreach ($name in @('TELEMETRY', 'MICROSOFT SERVICES', 'OTHER')) {
        $count = ($summary | Where-Object { $_.Name -eq $name }).Count
        [void]$sb.AppendLine(("  {0,-24} {1}" -f $name, $count))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("PROCESS / DESTINATION CORRELATION")
    [void]$sb.AppendLine("============================================================")
    $Data | Format-Table Process, PID, RemoteAddr, Hostname, Type -AutoSize | Out-String -Width 200 | ForEach-Object { [void]$sb.AppendLine($_) }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("LIMITATIONS")
    [void]$sb.AppendLine("============================================================")
    [void]$sb.AppendLine("PTR records are set by the address owner and can be absent, generic,")
    [void]$sb.AppendLine("or occasionally misleading. Classification is a best-effort hostname")
    [void]$sb.AppendLine("match, not proof of ownership. This is NOT packet capture and does")
    [void]$sb.AppendLine("not inspect transmitted data - it shows who a process is connected")
    [void]$sb.AppendLine("to, not what data is exchanged. No changes were made to the system.")

    Set-Content -Path $monFile -Value $sb.ToString()
    Write-Log "Monitor report exported: $monFile"
    Write-Host ""
    Write-Ok "Report exported to:"
    Write-Host "  $monFile" -ForegroundColor White
}

# ---------------------------------------------------------------------------
# LOGS
# ---------------------------------------------------------------------------
function Show-Logs {
    param($WinInfo)
    while ($true) {
        Show-Banner -WinInfo $WinInfo
        Write-BoxDivider
        Write-BoxTitle 'LOGS'
        Write-BoxBottom
        Write-Host ""
        Write-Host "  Recent activity ($LogFile):" -ForegroundColor DarkCyan
        if (Test-Path $LogFile) {
            Get-Content $LogFile -Tail 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        } else {
            Write-Skip "No activity logged yet."
        }
        Write-Host ""
        Write-Host "  Monitor reports:" -ForegroundColor DarkCyan
        $reports = Get-ChildItem -Path $MonitorDir -Filter '*.txt' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
        if ($reports.Count -eq 0) {
            Write-Skip "No monitor reports yet. Run MONITOR and press [E] to export one."
        } else {
            for ($i = 0; $i -lt $reports.Count; $i++) {
                Write-Host ("    [{0}] {1}  ({2})" -f ($i + 1), $reports[$i].Name, $reports[$i].LastWriteTime) -ForegroundColor White
            }
        }
        Write-Host ""
        Write-Host "  Enter a report number to view it, or [B] to go back." -ForegroundColor DarkGray
        $choice = Read-Host "  Choice"
        if ($choice.Trim().ToUpper() -eq 'B') { return }
        $idx = 0
        if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $reports.Count) {
            Clear-Host
            Get-Content $reports[$idx - 1].FullName | Out-Host -Paging
        }
    }
}

# ---------------------------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------------------------
function Show-Settings {
    param($WinInfo)
    while ($true) {
        Show-Banner -WinInfo $WinInfo
        Write-BoxDivider
        Write-BoxTitle 'SETTINGS'
        Write-BoxBottom
        Write-Host ""
        Write-Host "  Diagnostic data target level (used by SAFE and AGGRESSIVE):" -ForegroundColor DarkCyan
        $current = $Settings.TelemetryLevel
        Write-Host ("    Current: {0} - {1}" -f $current, $(if ($current -eq 0) { 'Off (Security)' } else { 'Required' })) -ForegroundColor White
        Write-Host ""
        Write-Host "    [1] Required (1) - broad Windows 10/11 compatibility, preserves" -ForegroundColor White
        Write-Host "        servicing diagnostics. Recommended default." -ForegroundColor DarkGray
        Write-Host "    [0] Off / Security (0) - only honored on eligible managed editions" -ForegroundColor White
        Write-Host "        (Enterprise/Education/Server with policy support). Unmanaged" -ForegroundColor DarkGray
        Write-Host "        consumer editions may silently fall back to a higher level." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Paths:" -ForegroundColor DarkCyan
        Write-Host "    Backup:  $BackupDir" -ForegroundColor DarkGray
        Write-Host "    Log:     $LogFile" -ForegroundColor DarkGray
        Write-Host "    Reports: $MonitorDir" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  [1] Set level to Required   [0] Set level to Off/Security   [B] Back" -ForegroundColor DarkGray
        $choice = Read-Host "  Choice"
        switch ($choice.Trim().ToUpper()) {
            '1' { $Settings.TelemetryLevel = 1; Save-Settings -Settings $Settings; Write-Ok "Telemetry target set to Required. Re-run SAFE/AGGRESSIVE to apply." ; Start-Sleep -Seconds 1 }
            '0' { $Settings.TelemetryLevel = 0; Save-Settings -Settings $Settings; Write-Warn2 "Telemetry target set to Off/Security. This may not be honored on your edition. Re-run SAFE/AGGRESSIVE to apply."; Start-Sleep -Seconds 2 }
            'B' { return }
            default { }
        }
    }
}

# ---------------------------------------------------------------------------
# ROLLBACK
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
        if (-not (Test-Path $stateFile)) { Write-Log "No saved state for service $svcName, leaving as-is."; continue }
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) { Write-Log "Service not present, skipping restore: $svcName"; continue }
        if (-not $state.Exists) { Write-Log "Service $svcName did not exist at backup time, leaving as-is."; continue }
        switch -Wildcard ($state.StartMode) {
            'Auto' {
                if ($state.Delayed) { & sc.exe config $svcName start= delayed-auto | Out-Null }
                else { Set-Service -Name $svcName -StartupType Automatic }
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
        if (-not $task) { Write-Log "Task not present, skipping restore: $taskPath"; continue }
        $stateFile = Join-Path $TaskDir (($taskPath.TrimStart('\') -replace '[\\]', '__') + '.json')
        if (-not (Test-Path $stateFile)) {
            Enable-ScheduledTask -TaskName $name -TaskPath $folder -ErrorAction SilentlyContinue | Out-Null
            Write-Log "No saved state for task $taskPath, defaulted to ENABLE."
            continue
        }
        $state = Get-Content $stateFile -Raw | ConvertFrom-Json
        if (-not $state.Exists) { Write-Log "Task $taskPath did not exist at backup time, leaving as-is."; continue }
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
    if (-not (Test-Path $BackupDir) -or (Get-ChildItem $BackupDir -Recurse -File -ErrorAction SilentlyContinue).Count -eq 0) {
        Write-Warn2 "No backup found. Run SAFE or AGGRESSIVE at least once before rolling back."
        Read-Host "Press Enter to return to the menu"
        return
    }
    Write-BoxDivider
    Write-BoxTitle 'ROLLBACK'
    Write-BoxBottom
    Write-Host ""
    $confirm = Read-Host "  Restore all settings from the last backup? [y/N]"
    if ($confirm -notmatch '^[Yy]') { return }
    Restore-RegistryKeys
    Restore-ServiceStates
    Restore-TaskStates
    Write-Log "Rollback completed."
    Write-Host ""
    Write-Ok "Rollback completed. Some settings may require a restart."
    Read-Host "Press Enter to return to the menu"
}

# ---------------------------------------------------------------------------
# Mode completion / restart prompt
# ---------------------------------------------------------------------------
function Complete-Mode {
    param([string]$ModeName)
    Write-Log "$ModeName mode finished."
    Write-Host ""
    Write-Ok "$ModeName mode complete."
    Write-Host "  Log:    $LogFile" -ForegroundColor DarkGray
    Write-Host "  Backup: $BackupDir" -ForegroundColor DarkGray
    Write-Host ""
    $answer = Read-Host "  A restart is recommended. Restart now? [y/N]"
    if ($answer -match '^[Yy]') {
        Write-Host "  Restarting in 10 seconds..." -ForegroundColor Yellow
        & shutdown.exe /r /t 10 /c "PrivGuard - restart"
    }
    Read-Host "Press Enter to return to the menu"
}

function Start-InitLog {
    param([string]$Mode, $WinInfo)
    Add-Content -Path $LogFile -Value ""
    Add-Content -Path $LogFile -Value ('=' * 60)
    Add-Content -Path $LogFile -Value "$(Get-Date) - $Mode"
    Add-Content -Path $LogFile -Value "Windows: $($WinInfo.Name) $($WinInfo.Build) $($WinInfo.Arch)"
    Add-Content -Path $LogFile -Value ('=' * 60)
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
$winInfo = Get-WindowsInfo

while ($true) {
    $choice = Show-Menu -WinInfo $winInfo
    switch ($choice) {
        '1' {
            if (Show-DryRunPreview -Mode 'SAFE' -WinInfo $winInfo) {
                Start-InitLog -Mode 'SAFE' -WinInfo $winInfo
                Backup-All
                Apply-CommonPolicies
                Apply-SafeTasks
                Complete-Mode -ModeName 'SAFE'
            }
        }
        '2' {
            if (Show-DryRunPreview -Mode 'AGGRESSIVE' -WinInfo $winInfo) {
                Start-InitLog -Mode 'AGGRESSIVE' -WinInfo $winInfo
                Backup-All
                Apply-CommonPolicies
                Apply-SafeTasks
                Apply-AggressivePolicies
                Complete-Mode -ModeName 'AGGRESSIVE'
            }
        }
        '3' { Show-MonitorScreen -WinInfo $winInfo }
        '4' { Invoke-Rollback -WinInfo $winInfo }
        '5' { Show-Status -WinInfo $winInfo }
        '6' { Show-Logs -WinInfo $winInfo }
        '7' { Show-Settings -WinInfo $winInfo }
        'Q' { exit }
        default { }
    }
}
