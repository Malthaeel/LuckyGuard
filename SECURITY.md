# LuckyGuard Security Policy

LuckyGuard is a defensive Windows security tool. Scanning is read-only; remediation is explicit, confirmation-gated and rollback-oriented.

## Scan guarantees

- No process termination.
- No registry, firewall, hosts, service, task, or file mutation during `scan`, `verify`, `ioc status/verify`, or `clean plan`.
- No credential, cookie, browser-secret, or Discord-token extraction.
- No untrusted project execution (`msbuild`, `dotnet build`, `devenv`) during scans.
- IOC domains are never contacted to test whether they are alive.

## Phase 6 mutation guarantees

- `clean apply` requires the exact `--confirm APPLY` token.
- Auto-eligible plan actions are live revalidated immediately before mutation.
- File quarantine uses copy → SHA-256 verification → source re-check → original removal. A failed verification leaves the original intact.
- Existing original paths are never overwritten during restore.
- Registry-value deletion captures original value, type, hive and exact 32/64-bit registry view before deletion.
- Scheduled Task deletion is limited to strong Reversed/Confirmed findings, exports XML first, and refuses password-backed logon types because LuckyGuard does not collect rollback credentials.
- Service deletion is even stricter: only CRITICAL Reversed/Confirmed service-command findings, elevation required, service must already be stopped, and its Services registry key is exported before deletion.
- Task/service backup files are SHA-256 checked and rollback rejects path traversal, unexpected backup filenames, hash mismatch, or overwrite conflicts.
- Remediation journals are created before the first mutation and atomically persisted after each successful action.
- Heuristic/community persistence remains review-only unless an explicitly documented stronger rule applies.

## IOC update trust guarantees

- The local ECDSA public key must match a SubjectPublicKeyInfo SHA-256 fingerprint compiled into LuckyGuard.
- Update URLs must be HTTPS, use the same host, and redirects are refused.
- Downloads have hard size limits.
- The downloaded feed must verify before staging, after staging, and after activation.
- Older signed feeds are rejected to reduce signed replay/rollback risk.
- Update failure leaves or restores the previously verified feed.
- Public installs write mutable IOC feed/signature state to ProgramData only from an elevated update command; the bundled public key remains under the installed application and must still match the compiled SPKI pin.
- The bundled verified feed is copied as the initial ProgramData anti-rollback baseline before the first online update.

## Defender integration

LuckyGuard invokes Microsoft Defender's built-in PowerShell cmdlets. It does not disable Defender, change execution policy, or suppress Defender remediation. Defender Offline requires explicit `--confirm REBOOT` and an elevated terminal.

Do not submit live malware samples to the repository. Use inert/synthetic fixtures for tests.


## Release signing guarantees

- No code-signing private key, PFX, password, token PIN, Azure client secret, or signing credential belongs in the repository.
- Public releases should use a trusted Authenticode identity through a hardware-backed/provider-backed Windows certificate-store certificate or Microsoft Artifact Signing.
- The release pipeline signs LuckyGuard-owned executables/assemblies before packaging, verifies every resulting signature, then signs and verifies the final installer separately.
- SHA-256 package hashes are generated only after package/installer signing is complete.
- Unsigned output is explicitly labeled as a development release by the release script.


## Public bootstrap and GitHub release guarantees

- Stable/public bootstrap requires the GitHub release asset to expose a `sha256:` digest and requires it to match the downloaded installer.
- `SHA256SUMS.txt` is checked independently against the downloaded installer.
- The installer Authenticode signature must be trusted and the signer Subject must exactly match the configured publisher Subject.
- Release output is cleaned before each build so stale packages from older versions cannot be accidentally published.
- GitHub publishing uploads only files named by the current release manifest, then reads the release back and verifies every GitHub asset digest against the local file.
- RC versions cannot be accidentally published as a stable GitHub release by the provided publish script.
