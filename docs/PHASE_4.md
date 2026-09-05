# Phase 4 — Network/C2 correlation and signed IOC baseline

Phase 4 keeps LuckyGuard read-only and adds active network correlation plus a cryptographically verified IOC baseline.

## Added

- IPv4/IPv6 TCP owner-PID enumeration via `GetExtendedTcpTable`.
- Process path and Authenticode context for active connections.
- Windows DNS client cache inspection through `MSFT_DNSClientCache` in `root\\StandardCimv2`.
- Domain-to-IP correlation without contacting suspicious domains.
- Verified IOC matching for domains, IP addresses, SHA-256 values, and filenames.
- ECDSA P-256 / SHA-256 detached signature verification for the local IOC feed.
- `LuckyGuard ioc status` and `LuckyGuard ioc verify`.
- `LuckyGuard scan network`.
- File SHA-256 IOC matching during file/path/solution/project scans.
- Regression fix for stale `cpuz###` temporary driver service entries.

## Evidence policy

- `Confirmed`: independent runtime/sandbox evidence.
- `Reversed`: strong reverse-engineering evidence.
- `Community`: community-maintained IOC requiring correlation.
- `Heuristic`: behavioral signal only.

A DNS-cache-only match is intentionally lower severity than an active TCP connection. A community IP or filename is never treated as equivalent to a confirmed C2-domain connection.

## Safety

Phase 4 does not kill processes, close sockets, alter DNS, edit hosts/firewall rules, delete services, quarantine files, or contact IOC domains.
