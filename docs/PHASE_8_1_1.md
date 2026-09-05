# Phase 8.1.1

Hotfix for the Phase 8.1 public candidate.

- Fixes `ArchivePathPolicy` compilation by using the string `StartsWith` overload when passing `StringComparison.Ordinal`.
- Adds regression coverage for rooted backslash and UNC-style archive entry paths.
- No runtime policy relaxation: rooted/traversal-like archive entries remain rejected.
