$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    dotnet restore .\LuckyGuard.sln
    dotnet build .\LuckyGuard.sln -c Release --no-restore
} finally { Pop-Location }
