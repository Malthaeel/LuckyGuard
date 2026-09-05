# LuckyGuard

[![CI](https://github.com/Malthaeel/LuckyGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Malthaeel/LuckyGuard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Malthaeel/LuckyGuard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Malthaeel/LuckyGuard/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/Malthaeel/LuckyGuard)](LICENSE)
[![Windows](https://img.shields.io/badge/platform-Windows%20x64-0078D4)](#requirements)

**LuckyGuard is a terminal-first Windows security toolkit focused on detecting, containing and recovering from LuckyWare-related compromise.**

> Current source release candidate: **1.0.0-rc.6**  
> Stable signed binary release: **not published yet**  
> Official repository: **https://github.com/Malthaeel/LuckyGuard**

LuckyGuard follows a conservative security model: **scan first, explain the evidence, and mutate only after an explicit remediation plan and confirmation**. Realtime protection is alert-only. Cleanup is journaled, backup-oriented and designed for verification/rollback.

```text
  LuckyGuard 1.0
  ─────────────────────────────────────────────
  IOC feed           VERIFIED
  Defender           ON / realtime active
  Realtime service   RUNNING
  Mutation            GATED

  luckyguard >
```

## Why LuckyGuard exists

LuckyWare has been associated with developer-project poisoning, credential-stealing workflows, suspicious persistence and loader-style behavior. LuckyGuard was built to inspect the Windows and developer surfaces relevant to those behaviors without turning the security tool itself into a credential extractor or an opaque "one-click cleaner".

LuckyGuard **does not decrypt, display or export Discord tokens, browser cookies, passwords or other credentials**.

## Status

The source tree is public and testable. The final `1.0.0` installer will only be presented as an official public binary after the following release gates are satisfied:

- trusted Authenticode publisher configured;
- all LuckyGuard-owned PE files signed and timestamped;
- signed installer signature re-verified;
- SHA-256 manifest generated;
- GitHub release asset digests re-verified after upload;
- final signed artifacts submitted to VirusTotal and report links published;
- release regression suite passes.

**Do not treat unsigned RC binaries or third-party mirrors as official stable releases.**

## Installation

### Stable release (after 1.0.0 signing gate)

The convenience installer will be:

```powershell
irm https://raw.githubusercontent.com/Malthaeel/LuckyGuard/main/install.ps1 | iex
```

The bootstrap is intentionally strict. Before elevation it verifies the GitHub release source, local SHA-256, GitHub's release-asset digest, Authenticode validity and the exact configured publisher identity.

For the most inspectable path, download `LuckyGuard-Setup-win-x64.exe` directly from the repository's **Releases** page, verify it, and then run it.

### Build the current RC from source

```powershell
git clone https://github.com/Malthaeel/LuckyGuard.git
cd LuckyGuard
.\scripts\build.cmd
.\scripts\test.cmd
.\scripts\run.cmd status
```

## Verify an official release

Never rely on the filename alone. Verify the exact bytes you downloaded.

### 1. SHA-256

Each release contains `SHA256SUMS.txt` and `release-manifest.json`.

```powershell
Get-FileHash .\LuckyGuard-Setup-win-x64.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The values must match exactly.

### 2. Authenticode

```powershell
Get-AuthenticodeSignature .\LuckyGuard-Setup-win-x64.exe |
  Format-List Status,StatusMessage,SignerCertificate
```

For stable public releases, `Status` must be `Valid`, and the signer subject must match the publisher documented in that release.

### 3. GitHub release asset integrity

LuckyGuard's publication script re-reads every uploaded release asset through the GitHub API and compares GitHub's returned `sha256:` digest with the local release file before publication is considered complete.

### 4. VirusTotal transparency

The **final signed artifacts** are the files that matter. Signing changes the file hash, so LuckyGuard does not publish misleading VirusTotal links for pre-signing builds.

Each stable release will include `TRUST-EVIDENCE.md`, containing the SHA-256 of every published package and its deterministic VirusTotal lookup URL:

```text
https://www.virustotal.com/gui/file/<SHA256>
```

A VirusTotal result is a transparency signal, **not a mathematical certificate that software is safe**. Security tools can receive heuristic detections because they enumerate processes, persistence, services, network state and security configuration. Always compare the report against the official hash, Authenticode signer and GitHub release.

See [Trust, verification and false positives](docs/TRUST_AND_VERIFICATION.md).

## Why an antivirus might inspect LuckyGuard closely

LuckyGuard performs operations that security products reasonably watch:

- enumerates processes, command lines and signatures;
- inspects registry persistence, scheduled tasks and Windows services;
- reads active TCP/DNS state;
- scans executable structures and developer project files;
- integrates with Microsoft Defender;
- installs an optional Windows Service for alert-only monitoring;
- quarantines/remediates only after explicit confirmation.

Those behaviors are expected for a defensive endpoint tool, but they can overlap with generic heuristic rules. LuckyGuard does **not** disable Defender, add antivirus exclusions, hide itself, inject into processes, dump credentials or silently remove findings.

If an official signed build is incorrectly classified, report the exact SHA-256 and vendor detection. The maintainer can submit the signed artifact to the relevant vendor for false-positive review; Microsoft also provides a file-submission process for files believed to be incorrectly detected.

## What LuckyGuard covers

### Developer and source infection surfaces

- `.sln` / `.slnx` projects and recursive MSBuild imports;
- `.csproj`, `.vcxproj`, `.props`, `.targets`, `.user` and build events;
- response files and suspicious build commands;
- C/C++ source poisoning indicators relevant to known/community LuckyWare research;
- Visual Studio `.suo/.vs` and installed Windows SDK/MSVC source poisoning indicators.

### Windows executable and persistence surfaces

- PE files: `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`;
- suspicious `.rcd*` sections, entry-point correlation and risky permissions;
- Run/RunOnce, Startup, Scheduled Tasks, Services, IFEO, Winlogon, AppInit and WMI;
- process image path, command-line and Authenticode correlation;
- active TCP and DNS observations correlated with the signed IOC feed.

### Archive inspection

- bounded ZIP/JAR/NUPKG scanning;
- path traversal detection;
- nesting, expanded-size, entry-count and compression-ratio limits;
- PE/source/IOC inspection inside supported archives;
- unsupported archive types are reported as unsupported/incomplete rather than falsely clean.

### Recovery and defense integration

- Microsoft Defender status, quick/full scan and confirmation-gated offline scan;
- SHA-256 verified quarantine;
- remediation plans with explicit APPLY tokens;
- live revalidation before mutation;
- registry/task/service backup and rollback journal;
- alert-only realtime Guard and optional `LuckyGuardGuard` Windows Service.

## Common commands

```powershell
luckyguard status
luckyguard scan system
luckyguard verify system
luckyguard defender status
luckyguard defender quick
luckyguard guard status
luckyguard ioc verify
luckyguard update check
```

Administrator-only / mutation operations remain explicitly gated, for example:

```powershell
luckyguard ioc update
luckyguard clean plan system
luckyguard clean apply <plan> --confirm APPLY
luckyguard clean rollback <execution-id> --confirm ROLLBACK
```

Run `luckyguard` with no arguments to open the terminal dashboard.

## Detection confidence

LuckyGuard separates stronger and weaker evidence instead of treating every heuristic as confirmed malware.

- **Confirmed / reversed evidence** can drive high-confidence findings and narrowly scoped remediation policy.
- **Community / heuristic evidence** is surfaced for review and correlation.
- A suspicious Windows process **name alone is never sufficient**; path, command line, signature, network and other context are considered.

A `CLEAN` verdict means no finding was produced on the implemented surfaces with the loaded rules/IOC feed. It does **not** guarantee the absence of unknown malware, kernel/rootkit compromise or firmware-level compromise.

## IOC trust model

LuckyGuard ships a signed IOC feed and a public verification key. The public key's SPKI SHA-256 is pinned in code, so replacing both the feed and adjacent key file is insufficient to establish trust.

IOC updates use:

- HTTPS only;
- same-host policy;
- redirects disabled;
- bounded download sizes;
- ECDSA P-256 / SHA-256 verification;
- staged activation;
- timestamp/version anti-rollback checks;
- ProgramData storage for system-wide verified updates.

See [IOC feed documentation](docs/IOC_FEED.md).

## Requirements

- Windows 10/11 x64;
- PowerShell for development/release scripts;
- .NET 9 SDK only when building from source;
- self-contained public builds do not require users to install the .NET runtime separately.

Optional release-maintainer tooling:

- Inno Setup 7;
- Windows SDK SignTool;
- GitHub CLI.

## Repository security

This repository includes:

- Windows CI/build/test workflow;
- CodeQL analysis;
- dependency review;
- Dependabot configuration;
- private-key and credential guards in release/bootstrap tooling;
- strict public-release gates;
- a `SECURITY.md` coordinated disclosure policy.

Private signing keys, PFX/P12 files, local credentials, logs, generated release output and machine-local LuckyGuard data are intentionally excluded from version control.

## Development

```powershell
.\scripts\build.cmd
.\scripts\test.cmd
```

Current RC regression target: **156 xUnit tests**, plus release-tooling smoke tests.

Useful documentation:

- [Architecture](docs/ARCHITECTURE.md)
- [IOC feed](docs/IOC_FEED.md)
- [Trust and verification](docs/TRUST_AND_VERIFICATION.md)
- [Public release process](docs/PUBLIC_RELEASE.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Security reports

Please do **not** publish exploitable security vulnerabilities as normal GitHub issues. Follow [SECURITY.md](SECURITY.md) and use GitHub's private vulnerability reporting flow when available.

## License

See [LICENSE](LICENSE).
