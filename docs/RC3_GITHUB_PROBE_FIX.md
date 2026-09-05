# LuckyGuard 1.0.0-rc.3 — GitHub probe hardening

Windows PowerShell 5.1 can promote native stderr to a terminating error when `$ErrorActionPreference = Stop`. The GitHub bootstrap previously used `gh repo view` as an existence probe and therefore aborted during the expected pre-creation `repository not found` state.

RC3 routes expected native command probes through `System.Diagnostics.Process` and inspects exit code/stdout/stderr explicitly. Missing repositories are accepted only when GitHub returns a recognizable not-found response; authentication, transport, and unexpected API failures still stop the bootstrap.
