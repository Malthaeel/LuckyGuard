# Architecture

Core scanner contracts live in `LuckyGuard.Core`. Scanner implementations depend on Core and never on the CLI, allowing the later real-time Guard service to reuse the same engines.

```text
LuckyGuard.Cli
  -> LuckyGuard.Core
  -> LuckyGuard.Detection -> LuckyGuard.Core
  -> LuckyGuard.Ioc       -> LuckyGuard.Core
  -> LuckyGuard.Reporting -> LuckyGuard.Core
  -> LuckyGuard.Solution  -> Core / MSBuild / Source
  -> LuckyGuard.PE        -> Core
  -> LuckyGuard.Suo       -> Core
  -> LuckyGuard.SDK       -> Core
  -> LuckyGuard.Windows   -> Core
```

## Read-only composition

- developer scans compose baseline + solution/MSBuild/source + PE + SUO
- `scan sdk` composes SDK/toolchain scanning
- `scan processes` composes Windows process scanning
- `scan persistence` composes Windows persistence scanning
- `scan system` composes SDK + processes + persistence

No Phase 3 scanner has mutation authority.


## Phase 8 modules

- `LuckyGuard.Archive`: bounded ZIP/JAR/NUPKG container inspection, nested archive limits, entry-level source/PE/IOC correlation.
- `LuckyGuard.Service`: native Windows Service Control Manager host for the alert-only realtime Guard.

Service configuration/log state is stored under `%ProgramData%\LuckyGuard\Guard`. Realtime monitoring never treats its own LuckyGuard state directories as scan-triggering content.
