# Changelog

## 1.0.0-rc.6

- Hotfixed `ReleaseToolingScriptTests.cs` so the public-repository PEM ignore regression checks the `*.pem` ignore rule directly instead of embedding a newline-sensitive string literal.
- Restores test-project compilation after the RC5 repository-hygiene changes.
- No production detection/remediation behavior changed; this is a test/release-quality hotfix.

## 1.0.0-rc.5

- Hardened `.gitignore` for generated output, IDE state, diagnostics, credentials, signing containers and stale phase-plan artifacts.
- Added `.gitattributes` to normalize line endings and remove mass LF/CRLF noise on Windows.
- Rebuilt the public README around trust, release verification, transparent antivirus/false-positive handling and official distribution boundaries.
- Added `docs/TRUST_AND_VERIFICATION.md`.
- Added release-time `TRUST-EVIDENCE.md` generation with final SHA-256, Authenticode status and VirusTotal hash lookup URLs.
- GitHub publisher now uploads and digest-verifies `TRUST-EVIDENCE.md` with each release.
- Added public-repository sanitize tooling for accidentally tracked ignored/local artifacts such as legacy `phase*-plan.json` files.
- Added a structured antivirus false-positive issue template.

## 1.0.0-rc.4

- Fixed `github-bootstrap.ps1` under Windows PowerShell 5.1 + StrictMode when a PowerShell child script succeeds without ever creating `$LASTEXITCODE`.
- PowerShell child-script success checks now use `$?` / terminating exceptions; `$LASTEXITCODE` is reserved for native executables.
- Hardened the same distinction in payload and installer signing calls inside `release.ps1`.
- Added xUnit and release-tooling regression coverage for the PowerShell-script exit-state path.

## 1.0.0-rc.3

- Fixed GitHub bootstrap preview on Windows PowerShell 5.1: an expected missing-repository probe no longer becomes a terminating `NativeCommandError` under `$ErrorActionPreference = Stop`.
- Added non-throwing native command probes for GitHub auth, repository existence, and git-origin readiness checks.
- Bootstrap now distinguishes an expected missing repository from real GitHub/network/auth failures before allowing creation.
- Added release-tooling regression coverage for the native probe path.

## 1.0.0-rc.2

- Repository and signing configuration are now decoupled; GitHub setup no longer requires a placeholder publisher identity.
- Added confirmation-gated `scripts/github-bootstrap.cmd` for authenticated public repository creation and initial push.
- Added private-key/signing-secret pre-push guard.
- Public readiness now checks GitHub authentication, matching `origin`, and official IOC URLs separately.
- Added repository-only configuration regression coverage.
- Fixed `release.ps1 -RequireSigned` initialization order so the stable signed path can read public configuration safely.
- Release private-key guard now also blocks `.snk` files.

Public release candidate.

- Windows installer + PATH command (`luckyguard`) and optional persistent `LuckyGuardGuard` service.
- Self-contained win-x64 portable release.
- Signed LuckyWare IOC trust root and configurable official IOC endpoint; mutable system-wide feed state lives in ProgramData while the pinned trust root remains bundled.
- `luckyguard update check` stable GitHub release check.
- GitHub installer requires SHA-256 manifest, GitHub release asset digest and exact Authenticode publisher match.
- GitHub publish script validates local hashes and re-verifies uploaded GitHub asset digests.
- CodeQL, dependency review, Dependabot and hardened public issue templates.
- Release output directory is cleaned before every build to prevent stale-version assets from leaking into a release.

See `docs/RELEASE_CHECKLIST.md` before publishing.
