# Phase 7 — Realtime Guard

Phase 7 adds a foreground, alert-only realtime protection layer. It does not auto-delete, auto-kill, or auto-quarantine.

## Watched surfaces

Default watch roots are normalized and nested roots are collapsed to avoid duplicate watcher coverage:

- `%USERPROFILE%\Downloads`
- `%APPDATA%` (includes user Startup)
- `%LOCALAPPDATA%` (includes the normal user TEMP location on many systems)
- Common Startup when available

Additional developer/project roots can be added with repeated `--watch <path>` arguments.

Interesting file types include executable/driver/install/script/archive surfaces plus Visual Studio/MSBuild/source files. Events are filtered before scanning.

## Runtime safety

- `FileSystemWatcher` is notification-only; LuckyGuard never executes changed files.
- Bounded event queue prevents unbounded memory growth.
- Per-path debounce collapses save/copy bursts.
- File stability checks wait briefly before opening newly copied files.
- Duplicate alert suppression prevents repeated identical findings from flooding the terminal/log.
- Watcher overflow/error emits a diagnostic warning; it is never silently treated as clean coverage.
- Network polling reuses the signed IOC store and Phase 4 TCP/DNS correlation.
- Phase 7 is alert-only. Cleaner mutations remain separate and confirmation-gated.

## Commands

```powershell
LuckyGuard guard status
LuckyGuard guard roots
LuckyGuard guard run
LuckyGuard guard run --watch "C:\Projects" --network-seconds 20
LuckyGuard guard run --no-network --watch "C:\Projects"
LuckyGuard guard run --verbose
```

Stop the foreground guard with `Ctrl+C`.

Alerts are also written as JSON Lines to:

```text
%LOCALAPPDATA%\LuckyGuard\Guard\guard.jsonl
```

The JSONL log does not contain browser cookies, Discord tokens, passwords, or other credential extraction data.

## Developer focused scanning

A changed `.cpp/.h/.props/.targets/.rsp` file is analyzed directly instead of forcing a full recursive project scan. `.sln/.slnx` changes still use solution graph analysis; supported project files use the project scanner.

## Not yet included

- Windows Service/background host
- automatic quarantine policy
- archive content extraction/scanning
- official hosted LuckyGuard IOC endpoint
