# LuckyGuard Phase 1 — Developer Project Scanner

Phase 1 adds the first real read-only LuckyWare-oriented detection modules.

## Scope

- `.sln` and `.slnx` discovery/parsing
- `.vcxproj`, `.csproj`, `.fsproj`, `.vbproj`
- `.props`, `.targets`, `.user`
- `Directory.Build.props`, `Directory.Build.targets`, `Directory.Build.rsp`
- `Directory.Solution.props`, `Directory.Solution.targets`
- `before/after.*.sln(.x).targets`
- recursive local MSBuild imports with loop/depth limits
- suspicious build-event / `Exec` / `Command` analysis
- suspicious `UsingTask` analysis
- remote/UNC import detection
- C/C++ source marker scanning
- `imgui_impl_win32.cpp` escaped-hex blob heuristic

## Safety properties

- no MSBuild execution
- no `dotnet build`, `devenv`, PowerShell or project command execution during scanning
- no deletion
- no quarantine yet
- no registry/firewall/process mutation
- XML DTD processing disabled
- XML size limit
- import recursion and import-count limits
- reparse points skipped during directory discovery

## Verdict semantics

`CLEAN` in Phase 1 means only that the supported developer-project surfaces were scanned without findings.
It is **not** a full Windows malware-free verdict.

## Commands

```powershell
.\scripts\run.cmd status
.\scripts\run.cmd scan solution .\LuckyGuard.sln
.\scripts\run.cmd scan project .\src\LuckyGuard.Cli\LuckyGuard.Cli.csproj
.\scripts\run.cmd scan path "C:\Projects"
.\scripts\run.cmd scan solution .\LuckyGuard.sln --format json --output .\scan.json
```
