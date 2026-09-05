# Contributing to LuckyGuard

LuckyGuard is a defensive Windows security project. Keep contributions reproducible and safe.

## Development

Requirements: Windows x64 and .NET 9 SDK.

```powershell
.\scripts\build.cmd
.\scripts\test.cmd
```

Every feature change should add or update regression tests. Do not make scanners execute untrusted projects or samples.

## Test data

Use inert synthetic fixtures. Never commit live malware, stolen credentials, tokens, cookies, private signing keys, PFX/P12 files, or IOC-feed signing private keys.

## Remediation changes

Changes that mutate files, registry, tasks or services must preserve LuckyGuard's PLAN → explicit APPLY → journal/backup → VERIFY model and default to the least-destructive reversible action.

Security vulnerabilities should be reported privately through GitHub Security Advisories rather than public issues.
