# LuckyGuard

**Terminal-first Windows protection focused on LuckyWare detection, containment and recovery.**

> Current release candidate: **1.0.0-rc.4**  
> Platform: Windows x64 Â· .NET 9 self-contained public builds

LuckyGuard was built around a conservative rule: **scan first, explain findings, mutate only after an explicit plan and confirmation**. Realtime protection is alert-only; cleanup operations are journaled and rollback-oriented.

```text
  â–ˆâ–ˆâ•—     â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•—  â–ˆâ–ˆâ•—â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
  â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•‘ â–ˆâ–ˆâ•”â•â•šâ–ˆâ–ˆâ•— â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•”â•â•â•â•â• â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—
  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•‘   â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•

  LuckyWare Protection Toolkit

  IOC feed           VERIFIED
  Defender           ON / realtime active
  Realtime service   RUNNING

  luckyguard >
```

## Install

After the repository and trusted publisher are configured, the convenience terminal install is:

```powershell
irm https://raw.githubusercontent.com/Malthaeel/LuckyGuard/main/install.ps1 | iex
```

The bootstrap downloads the latest stable GitHub installer and verifies **SHA-256 from the release manifest, GitHub's own release-asset SHA-256 digest, Authenticode trust, and the exact configured publisher identity** before elevation.

For the strongest bootstrap path, download `LuckyGuard-Setup-win-x64.exe` directly from GitHub Releases and inspect its Authenticode publisher before running it.

After installation, open a new terminal:

```powershell
luckyguard
```

Or run commands directly:

```powershell
luckyguard scan system
luckyguard verify system
luckyguard guard status
luckyguard defender status
luckyguard ioc verify
# Administrator terminal for system-wide IOC refresh
luckyguard ioc update
luckyguard update check
```

## What LuckyGuard covers

- Developer infection surfaces: `.sln/.slnx`, MSBuild imports/targets, project build events, response files and C/C++ source markers.
- PE inspection: `.exe/.dll/.sys/.scr/.cpl`, suspicious `.rcd*` sections, entry-point correlation and risky section permissions.
- Visual Studio `.suo/.vs` and Windows SDK/MSVC poisoning indicators.
- Processes, Run/RunOnce, Startup, scheduled tasks, services, IFEO, Winlogon, AppInit and WMI persistence surfaces.
- Active TCP/DNS correlation with the signed LuckyWare IOC feed.
- Bounded ZIP/JAR/NUPKG inspection with path-traversal, decompression-size, nesting, entry-count and compression-ratio protections.
- Microsoft Defender status plus quick/full/offline scan integration.
- SHA-256 verified quarantine, confirmation-gated remediation and rollback journals.
- Alert-only realtime filesystem/network Guard and optional `LuckyGuardGuard` Windows Service.

## Trust model

LuckyGuard's IOC feed is ECDSA P-256/SHA-256 signed. The public key is not merely stored beside the feed: its SPKI fingerprint is pinned in the application. The online IOC updater keeps HTTPS/same-host/no-redirect limits, bounded downloads, signature verification, staged activation and signed anti-rollback timestamps.

Public application releases are expected to be Authenticode-signed. Release scripts refuse a trusted-public build when signing is disabled and re-verify signatures after signing. GitHub publication also verifies the hashes returned by GitHub for the uploaded assets.

## Safety model

Scanning, verification and realtime Guard monitoring are read-only. Cleanup requires PLAN â†’ explicit confirmation â†’ live revalidation â†’ backup/journal â†’ APPLY â†’ VERIFY. Community/heuristic persistence findings remain review-only unless a stronger dedicated policy explicitly allows remediation.

LuckyGuard does **not** decrypt or display Discord tokens, browser cookies, passwords or other credentials.

A `CLEAN` result means no findings were detected on the implemented surfaces with the loaded IOC feed. It is not a mathematical guarantee that a machine contains no unknown/rootkit-level malware.

## GitHub repository bootstrap

Repository setup and Authenticode signing are intentionally separate. After installing and authenticating GitHub CLI, a fresh public repository can be created with:

```powershell
winget install --id GitHub.cli -e
gh auth login
.\scripts\github-bootstrap.cmd -Confirm CREATE_PUBLIC_REPO
```

The bootstrap detects the authenticated GitHub login, configures official IOC URLs, refuses known signing/private-key files, initializes Git, creates the `LuckyGuard` public repository, and pushes the initial commit. Stable release publication remains blocked until a trusted publisher identity is configured and the installer is validly signed.


## Build from source

```powershell
.\scripts\build.cmd
.\scripts\test.cmd
```

Public release documentation:

- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md)
- [`docs/PUBLIC_RELEASE.md`](docs/PUBLIC_RELEASE.md)
- [`docs/IOC_FEED.md`](docs/IOC_FEED.md)
- [`SECURITY.md`](SECURITY.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

See [`LICENSE`](LICENSE).

