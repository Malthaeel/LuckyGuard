# LuckyGuard public release model

LuckyGuard 1.0.0-rc.6 is the final public-release candidate before the stable 1.0 tag.

## Public-ready gates

Do **not** label a release stable/public-trusted until all of these pass on a clean Windows x64 machine:

1. `scripts\build.cmd` — zero errors/warnings.
2. `scripts\test.cmd` — all tests pass.
3. Windows Service install/start/status/stop/uninstall regression passes.
4. Archive regression passes.
5. `scripts\release-public.cmd` produces a signed installer.
6. `Get-AuthenticodeSignature` reports `Valid` for `LuckyGuard-Setup-win-x64.exe`.
7. `SHA256SUMS.txt` and `release-manifest.json` match every final signed package.
8. `TRUST-EVIDENCE.md` is generated from the frozen package hashes and contains Authenticode + VirusTotal hash lookup evidence.
9. The final signed installer/portable artifacts are submitted to VirusTotal; links resolve to the exact SHA-256 published by LuckyGuard.
10. `install.ps1` is configured with the exact GitHub repository and expected Authenticode publisher subject.
11. Fresh-VM install/uninstall test passes.

Until the signing identity is configured, LuckyGuard should be described as a **development/public-beta candidate**, not a trusted public release.

## End-user experience

After installation, the installer adds `C:\Program Files\LuckyGuard` to the machine PATH. A new terminal can run:

```powershell
luckyguard
```

With no arguments, LuckyGuard opens an interactive terminal dashboard. Existing CLI commands still work directly:

```powershell
luckyguard scan system
luckyguard guard status
luckyguard defender status
luckyguard quarantine list
```

## GitHub loader

The repository-root `install.ps1` resolves the latest published GitHub Release, downloads the Windows installer and `SHA256SUMS.txt`, checks SHA-256, requires GitHub release-asset sha256 digest metadata, requires a valid Authenticode signature for public installs, verifies the exact configured publisher subject, launches the installer elevated, refreshes PATH for the current terminal, and starts the LuckyGuard dashboard.

Configure the GitHub repository first; the signing identity can be attached later:

```powershell
.\scripts\configure-public.cmd -Repository "Malthaeel/LuckyGuard"
```

After a trusted code-signing certificate or service is available, attach its exact Authenticode subject without changing the repository metadata:

```powershell
.\scripts\configure-public.cmd `
  -Repository "Malthaeel/LuckyGuard" `
  -PublisherSubject "CN=YOUR VERIFIED PUBLISHER NAME"
```

For a fresh public repository, `scripts\github-bootstrap.cmd` can detect the authenticated GitHub account, configure repository-derived URLs, run a signing-secret guard, initialize Git, commit, create the public repository, and push. Creation requires the exact token `CREATE_PUBLIC_REPO`. Review the diff before running that confirmed step.

Convenience install command after configuration:

```powershell
irm https://raw.githubusercontent.com/Malthaeel/LuckyGuard/main/install.ps1 | iex
```

### Trust warning

`irm | iex` trusts the current content served by the repository before the loader can verify the signed installer. The installer itself is still required to pass SHA-256 + Authenticode + publisher checks, but a compromised repository could alter the loader logic. For users who want the strongest bootstrap chain, publish and document a direct `releases/latest/download/LuckyGuard-Setup-win-x64.exe` route and have them verify Authenticode before execution, or distribute through a package manager whose manifest pins the installer hash.

## Stable release asset

The release pipeline produces both a versioned installer and a stable latest-release alias:

- `LuckyGuard-Setup-<version>-win-x64.exe`
- `LuckyGuard-Setup-win-x64.exe`

GitHub supports direct links to an asset on the latest release using `/releases/latest/download/<asset-name>`. The stable alias exists specifically for that flow.

## Publishing to GitHub

After a signed local release is built:

```powershell
.\scripts\publish-github.cmd -Repository "Malthaeel/LuckyGuard"
```

This requires the GitHub CLI (`gh`) to already be authenticated. The publish script refuses to upload a public installer whose Authenticode status is not `Valid`.

## Recommended channels

- GitHub Releases: canonical signed binaries + hashes.
- `install.ps1`: convenience terminal bootstrap.
- Inno Setup installer: normal Windows install/uninstall and optional realtime service.
- Portable ZIP: advanced/manual use.
- Later: WinGet package for a stronger familiar install path (`winget install ...`).


## Phase 8.1.3 installer compatibility

Start Menu shortcut command-line quoting uses Inno Setup doubled-quote syntax and is compatible with Inno Setup 7.x.


## 1.0 repository security

The public repository also includes CodeQL v4, dependency review, Dependabot, private-security-report guidance, an RC/stable publish guard, stale-artifact cleanup, and post-upload GitHub asset digest verification.


## Antivirus transparency

Do not submit unsigned/pre-signing builds as the canonical VirusTotal evidence for a stable release. Authenticode signing changes the executable hash. Generate release evidence only after final packaging/signing, submit those exact bytes to VirusTotal, and publish the resulting SHA-256 lookup in `TRUST-EVIDENCE.md`.

VirusTotal is an additional transparency signal, not a substitute for SHA-256, Authenticode, source review or GitHub release digest verification.
