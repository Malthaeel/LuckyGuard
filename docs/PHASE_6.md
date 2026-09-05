# Phase 6 — Defender, signed IOC update, task/service rollback

Phase 6 extends LuckyGuard's containment/remediation trust model.

## Defender bridge

- `defender status` reads Microsoft Defender state.
- `defender quick` invokes `Start-MpScan -ScanType QuickScan`.
- `defender full` invokes `Start-MpScan -ScanType FullScan`.
- `defender offline --confirm REBOOT` invokes `Start-MpWDOScan` and requires an elevated terminal.

No PowerShell script file is created and LuckyGuard does not change the machine execution policy.

## IOC update trust chain

1. Local ECDSA public key must match the SPKI SHA-256 fingerprint compiled into LuckyGuard.
2. Feed and signature URLs must both be HTTPS and use the same host.
3. Redirects are refused.
4. Feed/signature sizes are bounded.
5. ECDSA signature is checked before staging.
6. Staged files are parsed and verified from disk.
7. Empty feeds, implausible future timestamps and rollback to an older signed feed are refused.
8. Existing files are backed up before activation.
9. The final activated pair is verified again.

## Scheduled Tasks

Only HIGH/CRITICAL Reversed/Confirmed task-command findings can become auto-eligible. The task XML is exported first. Password-backed logon types are refused because LuckyGuard does not collect the secret required for reliable rollback.

## Services

Only CRITICAL Reversed/Confirmed service-command findings can become auto-eligible. The service must be STOPPED. LuckyGuard exports its `HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>` registry key before `sc.exe delete`. Rollback imports the backed-up key; SCM refresh or a reboot can be required.

## Journal safety

The rollback journal is created before the first mutation and is atomically rewritten after each successful action. Task/service backup files carry SHA-256 hashes and rollback refuses path traversal, unexpected backup filenames, hash mismatch, or overwrite conflicts.

## Phase 6.1 hotfix
- Malformed or non-PEM IOC public keys are rejected as an invalid pin instead of throwing.
- LuckyGuard.Cli and LuckyGuard.Tests explicitly declare the Windows platform contract, eliminating CA1416 noise for Windows-only remediation APIs.
