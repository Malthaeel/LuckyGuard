# Phase 2 — PE, SUO, SDK/MSVC scanning

Phase 2 keeps LuckyGuard read-only and adds binary/toolchain inspection.

## Added

- PE parser for `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`
- community-reported LuckyWare `.rcd*` section detection
- critical verdict when the PE entry point resolves inside `.rcd*`
- generic RWX section heuristic
- `.suo` OLE Compound File signature validation and LuckyWare marker inspection
- `.vs` / `.suo` recursive discovery for solution/project/path scans
- Windows SDK include-root discovery
- Visual Studio MSVC include-root discovery
- read-only SDK/toolchain marker scanning
- `scan file`
- `scan sdk`
- Phase 1 xUnit analyzer-warning cleanup

## Safety properties

- no file deletion
- no PE patching
- no `.vs` deletion
- no SDK/header modification
- no project execution
- no MSBuild execution
- no credential/token/cookie access

## Scope limitation

A CLEAN Phase 2 result applies only to the supported developer, PE, SUO and SDK surfaces. Process, persistence, network and full IOC correlation arrive in later phases.
