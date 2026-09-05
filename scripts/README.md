# LuckyGuard scripts

Prefer the `.cmd` launchers on Windows; they invoke the repository PowerShell helpers without requiring a machine-wide execution-policy change.

```bat
scripts\run.cmd --version
scripts\run.cmd status
scripts\run.cmd scan system
scripts\run.cmd verify system
scripts\build.cmd
scripts\test.cmd
```

Public release tooling:

```bat
scripts\check-release-tools.cmd
scripts\public-readiness.cmd
scripts\configure-public.cmd -Repository "Malthaeel/LuckyGuard" -PublisherSubject "CN=EXACT PUBLISHER SUBJECT"
scripts\release-public.cmd -SigningMode CertStore -CertificateThumbprint "THUMBPRINT"
scripts\publish-github.cmd -Repository "Malthaeel/LuckyGuard" -Prerelease
```

`publish-github.cmd -Prerelease` is mandatory while the source version contains an RC/alpha/beta/preview suffix. The script refuses unsigned packages, stale manifest mismatches, repository/publisher mismatches and post-upload GitHub asset digest mismatches.

Mutation is never performed by a launcher itself. Cleaner/service/restore operations still require their exact confirmation tokens.

## GitHub bootstrap and repository hygiene (1.0 RC5)

Repository setup is independent from code signing.

```powershell
winget install --id GitHub.cli -e
gh auth login
.\scripts\github-bootstrap.cmd -Confirm CREATE_PUBLIC_REPO
```

The bootstrap refuses to overwrite an existing repository and scans the source tree for common private signing-key artifacts before staging/pushing. A trusted Authenticode publisher is still required before stable release publication.


Repository hygiene / trust helpers:

```bat
scripts\public-repo-sanitize.cmd
scripts\public-repo-sanitize.cmd -Apply
scripts\generate-trust-evidence.cmd
```

`public-repo-sanitize` identifies files that are already tracked but should now be ignored (for example legacy `phase*-plan.json` files). `-Apply` removes them from Git tracking while leaving ignored local files on disk, then renormalizes text according to `.gitattributes`.

`generate-trust-evidence` reads the final release manifest and creates `TRUST-EVIDENCE.md` with SHA-256, Authenticode status and deterministic VirusTotal SHA-256 lookup links. Stable evidence should be generated only after final signing.
