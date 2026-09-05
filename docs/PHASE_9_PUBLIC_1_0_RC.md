# Phase 9 — LuckyGuard 1.0 public release candidate

Version: `1.0.0-rc.4`

Adds the final public distribution controls: official configurable IOC endpoint, stable-release update check, exact publisher matching, mandatory GitHub asset digest verification, stale artifact cleanup, post-upload digest verification, CodeQL/dependency review/Dependabot, repository templates, and a stable release checklist.

This RC must not be tagged `1.0.0` until trusted Authenticode signing is configured and the full clean-machine install/reboot/uninstall/bootstrap checklist passes.

## RC2 repository bootstrap delta

RC2 decouples GitHub repository setup from Authenticode publisher configuration. A fresh public repository can be created with `scripts\github-bootstrap.cmd -Confirm CREATE_PUBLIC_REPO` after `gh auth login`. Stable publication remains blocked until the expected publisher and a valid signed installer are present.


## RC3 native-probe hardening

RC3 fixes Windows PowerShell 5.1 native stderr handling in GitHub bootstrap/readiness probes. Expected missing-repository and missing-origin states are captured through non-throwing process probes, while unexpected GitHub/auth/network failures remain blocking.
