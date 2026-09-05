# LuckyGuard signed IOC feed

LuckyGuard separates application releases from LuckyWare IOC updates.

The repository publishes:

- `rules/luckyware/ioc-feed.json`
- `rules/luckyware/ioc-feed.sig`
- `rules/luckyware/ioc-public-key.pem`

The public key is additionally fingerprint-pinned inside the application. Replacing all three repository files is therefore insufficient to introduce an unauthorized feed: the key itself must still match the compiled pin and the ECDSA signature must verify.

After `scripts/configure-public.cmd` sets the repository, users can run from an **elevated Administrator terminal**:

```powershell
luckyguard ioc update
```

The immutable bundled trust root remains under Program Files. Updated feed/signature state is stored system-wide under `C:\ProgramData\LuckyGuard\Rules\luckyware`, so both the CLI and Windows Service consume the same verified feed without modifying installed binaries. The shipped verified feed is seeded as the first anti-rollback baseline before the first online update.

The configured official endpoint uses `raw.githubusercontent.com` for both the feed and signature. The updater still enforces HTTPS, same-host URLs, no redirects, size limits, signature verification, staging verification and signed anti-rollback timestamps.

## Updating the feed

Do not store the private IOC signing key in the repository or GitHub Actions secrets unless a deliberately designed hardware/provider-backed signing system is introduced. Prefer offline signing and commit only the new feed + detached signature.
