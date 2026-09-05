# LuckyGuard 1.0 release checklist

## Source gates

- [ ] `scripts\build.cmd` succeeds with zero warnings/errors.
- [ ] `scripts\test.cmd` passes all xUnit tests and release-tooling smoke tests.
- [ ] GitHub CI, CodeQL and dependency review pass.
- [ ] `config/public-release.json` has the final repository and exact Authenticode publisher subject.
- [ ] No private signing material exists anywhere in the repository.

## Windows integration gates

- [ ] Clean installer install succeeds.
- [ ] `where luckyguard` resolves to `C:\Program Files\LuckyGuard\LuckyGuard.exe` in a new terminal.
- [ ] `luckyguard` opens the terminal dashboard.
- [ ] `LuckyGuardGuard` is RUNNING after install and after reboot.
- [ ] IOC verification reports VERIFIED.
- [ ] Uninstall removes the service, installation directory and PATH entry while preserving ProgramData audit/quarantine state.

## Trust/release gates

- [ ] Produce with `scripts\release-public.cmd` using CertStore or ArtifactSigning.
- [ ] `Get-AuthenticodeSignature` is `Valid` for the stable installer alias.
- [ ] Timestamp is present and valid.
- [ ] `SHA256SUMS.txt` and `release-manifest.json` match the final signed artifacts.
- [ ] `TRUST-EVIDENCE.md` is generated from the final package bytes.
- [ ] Final signed installer and portable package are submitted to VirusTotal; published report links correspond to the exact release SHA-256 values.
- [ ] Suspected false positives are submitted to affected vendors (Microsoft Security Intelligence for Defender detections) before/alongside stable announcement when practical.
- [ ] Publish through `scripts\publish-github.cmd` and require its post-upload GitHub digest verification to pass.
- [ ] Test `install.ps1` from a clean Windows VM/user profile.
- [ ] Test `luckyguard update check` and `luckyguard ioc update` against the public repository.

Only after every item passes should an RC suffix be removed and `1.0.0` be tagged stable.
