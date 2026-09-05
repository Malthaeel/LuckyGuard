param([Parameter(ValueFromRemainingArguments=$true)][string[]]$LuckyGuardArgs)
$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    dotnet run --project .\src\LuckyGuard.Cli -- @LuckyGuardArgs
} finally { Pop-Location }
