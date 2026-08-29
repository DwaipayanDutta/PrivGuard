# 🐕‍🦺 PrivGuard — Windows Privacy & Telemetry Control

<p align="center">
  <img src="logo_wordmark.png" alt="PrivGuard - Windows Privacy & Telemetry Control" width="560"/>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg">
  <img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE.svg">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg">
</p>

> No third-party software. No firewall blocking. Just documented Windows policies, applied and reversed cleanly.

PrivGuard reduces what Windows 10/11 sends to Microsoft using only settings Microsoft itself documents and supports — Group Policy–style registry values, scheduled tasks, and services. Every change it makes is backed up first and can be undone with one command.

Named after the dog on the logo: a Doberman, because that's what this tool is — a guard dog for your system's privacy settings, not a battering ram.

---

## ✨ Features

- 🔍 **Dry-run by default** — SAFE and AGGRESSIVE always show you exactly what will change (current value → new value) and ask for confirmation before touching anything
- 🔒 **Documented settings only** — registry policies, scheduled tasks, and services that Microsoft publishes; no undocumented hacks, no DRM/auth bypass, no firewall-level domain blocking
- ↩️ **Full backup + rollback** — every registry key, task, and service touched is backed up before modification and can be restored to its *actual* prior state, not just re-enabled by assumption
- 📡 **MONITOR mode** — a live, read-only view correlating each active connection to its owning process and destination, classified as Telemetry / Microsoft Services / Other
- 📋 **LOGS** — browse past activity and exported monitor reports from within the app
- ⚙️ **SETTINGS** — configure the diagnostic-data target level PrivGuard applies
- 🪟 **Single source of truth** — one PowerShell script contains all logic; the batch file is a thin launcher, nothing more (see [Architecture](#-architecture))

---

## 🚀 Quick Start

1. Download or clone this repository.
2. Double-click **`PrivGuard.bat`**.
3. Approve the UAC elevation prompt.
4. Use the menu — `1` for SAFE (recommended), `3` for MONITOR, `5` for STATUS, and so on.

That's it. `PrivGuard.ps1` never needs to be run directly.

---

## 🏗️ Architecture

```
PrivGuard.bat
       │
       └── launches (elevated)
              │
              ▼
       PrivGuard.ps1
              │
       ┌──────┼────────┐
       ▼      ▼        ▼
     SAFE  MONITOR  AGGRESSIVE
       │      │        │
       └──────┼────────┘
              ▼
        Backup / Logs
              │
              ▼
           Rollback
```

**`PrivGuard.bat`** does exactly one job: confirm `PrivGuard.ps1` exists, make sure the process is elevated (relaunching itself with `Start-Process -Verb RunAs` if not), then hand off to PowerShell. It contains no application logic.

**`PrivGuard.ps1`** is the single source of truth for everything else: the menu, registry/task/service handling, backup, dry-run preview, rollback, the MONITOR correlation engine, logs, and settings. Keeping all logic in one file means there's nothing to keep in sync between two implementations — the batch file can't drift out of date with the PowerShell logic because it doesn't duplicate any of it.

If you ever see the PowerShell window ask you to "run PrivGuard.bat instead," that means `PrivGuard.ps1` was launched directly without elevation — elevation is intentionally handled in exactly one place.

---

## 📋 Requirements

- Windows 10 or 11
- Windows PowerShell 5.1+ (included by default on all supported Windows 10/11 builds)
- Administrator rights (PrivGuard will prompt for elevation automatically)

---

## 🕹️ Modes

| Mode | What it does |
|---|---|
| **SAFE** | Sets documented diagnostic-data, tailored-experience, advertising-ID, activity-history, and Spotlight/consumer-feature policies; disables telemetry/CEIP-related scheduled tasks. Does not touch Windows Update, Defender, licensing, or core networking. |
| **AGGRESSIVE** | Everything in SAFE, plus disables the `DiagTrack` and `dmwappushservice` services and a few additional Application Experience tasks. Still does **not** enable any firewall rules or block any domains. |
| **MONITOR** | Read-only. Shows active connections correlated to process name, PID, resolved hostname, and classification (Telemetry / Security / Update / General / Other). Nothing is changed. Press `[E]` to export a report, `[R]` to refresh. |
| **ROLLBACK** | Restores every registry key, task, and service PrivGuard has ever touched to its state at the time of the last backup — not a guess, the actual recorded prior state. |
| **STATUS** | Full current-state dump of every policy, task, and service PrivGuard manages. |
| **LOGS** | View recent activity log entries and browse/open past exported MONITOR reports. |
| **SETTINGS** | Currently configures the diagnostic-data (`AllowTelemetry`) target level SAFE/AGGRESSIVE apply. |

### Dry-run preview

Selecting **SAFE** or **AGGRESSIVE** always shows a table like this before anything is touched:

```
CATEGORY         TARGET                                 CURRENT          NEW
----------------------------------------------------------------------------------
Registry         Diagnostic data level                  3                1
Registry         Tailored experiences                   1                0
Scheduled Task   Consolidator                            Ready            Disabled
Scheduled Task   UsbCeip                                 Disabled         Disabled
...

4 setting(s) will change.  2 already match the target or are not present.

Apply these 4 change(s) now? [y/N]:
```

Nothing is modified until you type `y`. If everything already matches the target profile, PrivGuard tells you there's nothing to do and returns you to the menu.

---

## 📁 What gets backed up, and where

All state lives under:

```
%ProgramData%\PrivGuard\
├── PrivGuard.log          Activity log across all runs
├── settings.json          Your saved PrivGuard settings
├── Backup\
│   ├── registry\*.reg     Exported registry keys, importable directly
│   ├── tasks\*.json       Prior scheduled-task state
│   └── services\*.json    Prior service start-type state
└── Monitor\*.txt          Exported MONITOR reports
```

Rollback reads these files to restore the exact prior state — including whether a scheduled task was *already* disabled before PrivGuard ran, and whether a service used Delayed Auto-Start rather than plain Automatic.

---

## ⚠️ What PrivGuard deliberately does NOT do

- **No firewall rules or domain blocking.** Blocking Microsoft-wide IP ranges or domains can break Windows Update, Defender cloud protection, Store, licensing, and authentication. PrivGuard sticks to policy-level controls that Microsoft explicitly supports toggling.
- **No DRM, license, or access-control circumvention.**
- **No packet inspection.** MONITOR mode uses `Get-NetTCPConnection`/`Resolve-DnsName`, the same category of information any built-in tool like Resource Monitor can show you. It cannot see encrypted payload contents.

---

## 🔎 Understanding MONITOR output

| Classification | Meaning |
|---|---|
| **Telemetry** | Exact match to a documented Windows diagnostic-data endpoint (e.g. `v10.events.data.microsoft.com`) |
| **Security** | Microsoft Defender / SmartScreen cloud-protection endpoints |
| **Update** | Windows Update / Delivery Optimization endpoints |
| **General** | Other Microsoft-operated domains (Bing, Office, MSN, Azure CDN, etc.) — not necessarily telemetry |
| **Other** | Does not match any Microsoft domain pattern |
| **Unresolved** | No PTR record returned for the remote IP |

Classification is a best-effort hostname match, not proof of ownership — reverse DNS records are set by the address owner and can be missing, generic, or occasionally misleading. Microsoft services also share CDN/cloud infrastructure with other tenants in some cases.

---

## 🛠️ Development

```bash
git clone https://github.com/DwaipayanDutta/PrivGuard.git
cd PrivGuard
```

There's no build step — `PrivGuard.bat` and `PrivGuard.ps1` run as-is. When adding functionality:

- Add new registry targets to `Get-RegistryTargets` (used by both `Apply-CommonPolicies` and the dry-run preview automatically).
- Add new scheduled tasks to `$SafeTasks` or `$AggressiveTasks` (both are backed up regardless of which mode runs, so rollback always has state to restore from).
- Never modify a setting that isn't first captured by `Backup-All` — the dry-run/backup/rollback triangle is the whole point of the design.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

## 🙏 Credits

Built entirely on built-in Windows/PowerShell cmdlets and documented Microsoft Group Policy registry values. No external dependencies.
