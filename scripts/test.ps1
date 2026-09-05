$ErrorActionPreference = "Stop"
Push-Location (Join-Path $PSScriptRoot "..")
try {
    dotnet test .\LuckyGuard.sln -c Release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & (Join-Path $PSScriptRoot 'test-release-tooling.ps1')
} finally { Pop-Location }
