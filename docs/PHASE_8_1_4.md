# Phase 8.1.4

Public release candidate hardening.

- Fixes single-file `sign-artifacts.ps1` target handling under PowerShell StrictMode by forcing the resolved target set to an array.
- Adds a release-tooling smoke test that exercises an unsigned single-file installer target.
- Keeps signing policy unchanged: public releases still require a trusted Authenticode signing mode.
