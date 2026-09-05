# Phase 5 — Quarantine, remediation planning, rollback and verify

Phase 5 is LuckyGuard's first mutation-capable phase. The default scanner remains read-only.

## Workflow

```text
scan
  ↓
clean plan        (read-only)
  ↓
JSON plan
  ↓
live revalidation
  ↓
clean apply       (explicit APPLY token)
  ↓
quarantine / backed-up registry cleanup
  ↓
verify
```

## Auto-eligible evidence

Current automatic remediation is intentionally narrow:

- exact LuckyWare SHA-256 IOC file match
- Critical `.rcd*` PE entry-point infection signal
- Reversed/Confirmed HIGH+ suspicious Run/RunOnce or IFEO registry-value command with exact Registry32/Registry64 evidence

Other findings are emitted as `ReviewOnly` actions. Detection severity alone is not sufficient to authorize mutation.

## Tampered/stale plan protection

A remediation JSON is not trusted as evidence. Before any apply, LuckyGuard re-scans each eligible file or the persistence surface and requires the same detection ID, target, severity and confidence to still be present. Any mismatch aborts the entire apply before mutation.

## Quarantine

Default root:

```text
%ProgramData%\LuckyGuard\Quarantine\<id>\
  payload.lgq
  metadata.json
```

The source file is copied, the quarantine copy is SHA-256 verified, metadata is written, and only then is the original removed. Restore never overwrites an occupied original path.

## Rollback journal

Default root:

```text
%ProgramData%\LuckyGuard\Remediation\<execution-id>\journal.json
```

The journal records quarantine IDs and backed-up registry values. `clean rollback` restores registry values and then quarantined files.

## Deferred mutation surfaces

Service deletion, Scheduled Task deletion, WMI persistence deletion, process termination and network blocking remain disabled until their backup/rollback and live-correlation rules are implemented and tested.
