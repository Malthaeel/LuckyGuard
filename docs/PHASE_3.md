# Phase 3 — Windows process and persistence scanner

Phase 3 keeps LuckyGuard read-only and adds the first endpoint/system-inspection layer.

## Process coverage

- running-process inventory
- parent PID mapping through Toolhelp snapshot
- full image-path resolution
- read-only command-line retrieval
- Authenticode trust verification
- Windows system-name masquerading detection
- LuckyWare-style timestamp executable heuristic
- command-line LuckyWare C2 / shell-download-obfuscation correlation

A Windows process name such as `svchost.exe`, `SndVol.exe`, `dispdiag.exe`, or `isoburn.exe` is never considered malicious by name alone.

## Persistence coverage

- HKCU/HKLM Run and RunOnce, 32-bit and 64-bit views
- current-user and common Startup folders
- `.lnk` target inspection where COM resolution is available
- Scheduled Task executable actions
- Services ImagePath
- IFEO Debugger values, 32-bit and 64-bit views
- Winlogon Shell/Userinit
- AppInit_DLLs
- WMI CommandLineEventConsumer / ActiveScriptEventConsumer / bindings

## Safety

- no process termination
- no Registry writes
- no task/service changes
- no WMI changes
- no PowerShell execution
- no project execution
- no credential/token/cookie access

Subsystem-level task/WMI access failures are reported as incomplete coverage instead of CLEAN.

## Commands

```powershell
.\scripts\run.cmd scan processes
.\scripts\run.cmd scan persistence
.\scripts\run.cmd scan system
```

`scan system` composes the SDK/toolchain, process, and persistence scanners. Network/C2 connection correlation is deliberately deferred to Phase 4.
