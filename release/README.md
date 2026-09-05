# LuckyGuard release and code signing

Phase 8 includes a public-distribution-ready release pipeline. It does **not** contain a signing certificate, private key, Azure credential, or signing secret.

## Release outputs

`scripts\release.cmd` / `scripts\release.ps1`:

1. restore + Release build + tests
2. self-contained `win-x64` publish for the CLI and Windows Service host
3. stage the service host under `service\` so the installer/portable package can locate it
4. optionally Authenticode-sign LuckyGuard-owned `.exe` / `.dll` files
5. verify every signature after signing
6. validate `LuckyGuard --version` and the signed IOC feed
7. create a portable ZIP
8. optionally compile an Inno Setup installer
9. sign and verify the installer when signing is enabled
10. generate `SHA256SUMS.txt` and `release-manifest.json`

The self-contained package carries the .NET runtime, so end users don't need to install .NET 9 separately.

## Unsigned development release

```powershell
.\scripts\release.cmd
```

This is useful for local testing. Do not present an unsigned build as a trusted public release.

## Public signing with a certificate in the Windows certificate store

This works with providers/tokens that expose the code-signing certificate through the Windows certificate store.

```powershell
.\scripts\release-public.cmd -SigningMode CertStore -CertificateThumbprint "YOUR_CERT_THUMBPRINT"
```

Equivalent full PowerShell form:

```powershell
.\scripts\release.ps1 `
  -RequireSigned `
  -Installer Required `
  -SigningMode CertStore `
  -CertificateThumbprint "YOUR_CERT_THUMBPRINT"
```

The pipeline uses SHA-256 for the file digest and RFC 3161 timestamp digest. Override `-TimestampUrl` if your CA requires a different timestamp service.

## Microsoft Artifact Signing

Create metadata from `release\artifact-signing.metadata.example.json`, then configure the official Artifact Signing client tools and authenticate to Azure.

```powershell
.\scripts\release.ps1 `
  -RequireSigned `
  -Installer Required `
  -SigningMode ArtifactSigning `
  -ArtifactSigningMetadata "C:\secure\metadata.json" `
  -ArtifactSigningDlib "C:\Program Files (x86)\Microsoft\ArtifactSigningClientTools\bin\x64\Azure.CodeSigning.Dlib.dll"
```

Artifact Signing mode defaults to Microsoft's Artifact Signing RFC 3161 timestamp endpoint. The metadata file identifies the account/profile; Azure credentials are resolved by the Artifact Signing client and must never be committed to this repository.

## Installer

The repository contains `release\LuckyGuard.iss` for Inno Setup 7 or 6. `-Installer Auto` builds Setup.exe when `ISCC.exe` is installed; `-Installer Required` fails the release if Inno Setup is unavailable; `-Installer Skip` creates only the portable ZIP.

The installer:

- installs under `C:\Program Files\LuckyGuard`
- optionally installs/starts the alert-only `LuckyGuardGuard` Windows Service
- registers LuckyGuard in Windows App Paths
- removes the service during uninstall
- preserves `%ProgramData%\LuckyGuard` logs/quarantine/config by design

## Key handling rules

- Never commit a `.pfx`, private key, HSM PIN, token PIN, Azure client secret, or signing credential.
- Prefer HSM/hardware-token backed certificates or Artifact Signing for public releases.
- Sign binaries **before** packaging; sign the final installer **after** installer compilation.
- Do not modify signed files after signing.
- Always timestamp public releases and verify signatures with `signtool verify /pa /all`.
- Publish `SHA256SUMS.txt` next to every release.
