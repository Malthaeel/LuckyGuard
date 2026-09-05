# Phase 8 — Windows Service Guard + bounded archive scanner

Phase 8 moves LuckyGuard's alert-only realtime Guard from foreground-only operation to an optional Windows Service host and adds bounded deep inspection for ZIP-compatible archives.

## Windows Service host

Service name: `LuckyGuardGuard`

The service uses the native Windows Service Control Manager contract (`StartServiceCtrlDispatcher`, `RegisterServiceCtrlHandlerEx`, `SetServiceStatus`) without third-party hosting packages. Service installation/removal is explicit and Administrator-only.

Commands:

```text
LuckyGuard guard service status
LuckyGuard guard service install --confirm INSTALL [--watch <path>] [--network-seconds N] [--no-network]
LuckyGuard guard service start
LuckyGuard guard service stop
LuckyGuard guard service uninstall --confirm UNINSTALL
```

The install command deploys the service host into `%ProgramData%\LuckyGuard\Service` and captures the current user's default Guard roots into `%ProgramData%\LuckyGuard\Guard\service-config.json`. The service runs alert-only and writes JSONL alerts to `%ProgramData%\LuckyGuard\Guard\guard-service.jsonl`.

Uninstall preserves logs/config for audit and recovery. No realtime auto-delete or auto-quarantine is enabled in Phase 8.

## Archive scanner

Deep-scanned formats:

- ZIP
- JAR
- NUPKG

Observed but not decompressed in Phase 8:

- RAR
- 7Z

The scanner never uses archive-provided entry paths for extraction. It reads bounded entry streams and applies:

- max entry count
- max declared total uncompressed bytes
- max per-entry scan bytes
- extreme compression-ratio cutoff
- max nested ZIP depth
- traversal-like path detection
- source-marker scanning inside text/source entries
- PE `.rcd*` analysis directly from archive entry bytes
- verified IOC filename and SHA-256 matching inside archive entries

A direct `scan archive` / `scan file` of RAR/7Z returns incomplete coverage; directory scans count and note opaque archives without pretending they were deep-inspected.

## Realtime hardening

- JAR/NUPKG are now realtime-inspected.
- LuckyGuard's own `%LocalAppData%\LuckyGuard` and `%ProgramData%\LuckyGuard` state/log paths are excluded from realtime file events to avoid self-trigger loops.
- The service reads an explicit root list rather than inheriting the LocalSystem profile's default folders.

## Safety

Phase 8 service monitoring remains alert-only. Existing remediation continues to require an explicit plan, live revalidation, elevation where necessary, and confirmation tokens.


## Public distribution pipeline

Phase 8 is code-signing ready rather than bundling a certificate. `scripts/release.ps1` publishes self-contained `win-x64` CLI and service payloads, signs only LuckyGuard-owned PE files when signing is enabled, verifies Authenticode signatures immediately, validates the embedded IOC feed, creates a portable ZIP, optionally compiles `release/LuckyGuard.iss`, signs the final installer, and writes SHA-256 package hashes.

Supported signing modes:

- `None` — local/dev release only
- `CertStore` — a code-signing certificate available through the Windows certificate store (including compatible hardware-backed providers)
- `ArtifactSigning` — Microsoft Artifact Signing SignTool/dlib integration using an external metadata JSON and Azure authentication

The repository never stores a private key, certificate password, token PIN, or Azure client secret. The Inno Setup installer can install/start the existing alert-only Windows Service and removes the service during uninstall while intentionally preserving `%ProgramData%\LuckyGuard` audit/quarantine state.
