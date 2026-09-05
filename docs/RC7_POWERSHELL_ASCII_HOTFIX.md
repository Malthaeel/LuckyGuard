# RC7 - Windows PowerShell 5.1 ASCII hotfix

RC6 reached successful Inno Setup compilation but the release pipeline stopped while parsing `scripts/generate-trust-evidence.ps1` in Windows PowerShell 5.1. The UTF-8 em dash in an executable PowerShell string was decoded through the legacy code page and broke tokenization.

RC7 keeps public/release PowerShell entrypoints ASCII-only and adds regression coverage so the same class of parser failure cannot silently return.
