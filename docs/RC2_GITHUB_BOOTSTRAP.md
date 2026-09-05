# LuckyGuard 1.0.0-rc.2 — GitHub bootstrap

RC2 separates public repository setup from trusted Authenticode signing.

## Why

A GitHub repository and official IOC URLs can be configured before the project has acquired a public code-signing identity. The stable installer remains locked until the publisher subject is configured and the installer signature validates.

## Fresh repository flow

```powershell
winget install --id GitHub.cli -e
gh auth login
.\scripts\github-bootstrap.cmd -Confirm CREATE_PUBLIC_REPO
```

The bootstrap:

- reads the authenticated GitHub login via `gh api user`;
- configures `OWNER/REPOSITORY` and official IOC URLs;
- leaves `PUBLISHER_SUBJECT` pending if no signing identity exists;
- refuses common private signing-key file extensions and PEM private-key material;
- initializes Git on `main` if needed;
- stages and commits the source tree;
- refuses to overwrite an existing GitHub repository;
- creates a **public** repository only with the exact `CREATE_PUBLIC_REPO` confirmation token;
- adds `origin` and pushes the initial commit.

Run `scripts\public-readiness.cmd` afterwards. GitHub-specific gates should become PASS while signing gates can remain BLOCK until the trusted signing identity is attached.
