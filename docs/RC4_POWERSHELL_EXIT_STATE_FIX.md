# LuckyGuard 1.0.0-rc.4 — PowerShell exit-state hardening

RC4 fixes a Windows PowerShell 5.1 + `Set-StrictMode` edge case discovered during the confirmation-gated GitHub bootstrap.

## Root cause

`configure-public.ps1` is a PowerShell child script, not a native executable. A successful PowerShell script is not required to create or update the automatic `$LASTEXITCODE` variable. Reading an unset `$LASTEXITCODE` under StrictMode throws `VariableIsUndefined`.

## Fix

- PowerShell child-script calls use `$?` and terminating exceptions for success/failure.
- Native executables continue to use native exit codes.
- The same correction is applied to `sign-artifacts.ps1` calls in the release pipeline.
- Regression checks prevent reintroducing `$LASTEXITCODE` immediately after PowerShell child-script calls.

No repository is created unless `-Confirm CREATE_PUBLIC_REPO` is supplied.
