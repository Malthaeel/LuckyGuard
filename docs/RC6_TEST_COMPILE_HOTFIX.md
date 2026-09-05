# RC6 test compile hotfix

RC5 introduced two public-release regression tests. One assertion intended to search for the literal `*.pem\n` pattern was generated with a physical newline inside a normal C# string literal, causing `CS1010` and related parser errors before xUnit could run.

RC6 changes that assertion to check the `*.pem` pattern directly and bumps the release candidate version. Production scanner, guard, cleaner, IOC, service, and release behavior are otherwise unchanged.

Expected Windows validation:

```text
Build succeeded
Test summary: total: 156, failed: 0, succeeded: 156
```
