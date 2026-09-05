# LuckyGuard rules

`rules/luckyware/ioc-feed.json` is the Phase 4 LuckyWare IOC baseline.

The feed is authenticated with a detached ECDSA P-256/SHA-256 signature:

- `ioc-feed.json` — feed bytes
- `ioc-feed.sig` — Base64 DER ECDSA signature
- `ioc-public-key.pem` — pinned public verification key

The private signing key is not distributed with LuckyGuard.

IOC confidence is part of the rule model. Community indicators are not promoted to confirmed indicators simply because they match.
