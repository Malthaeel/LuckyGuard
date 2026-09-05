$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("LuckyGuard-release-smoke-" + [Guid]::NewGuid().ToString('N'))
$dummy = Join-Path $tempRoot 'LuckyGuard-Setup-test.exe'

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    [System.IO.File]::WriteAllBytes($dummy, [byte[]](0x4D,0x5A))

    $output = & (Join-Path $PSScriptRoot 'sign-artifacts.ps1') -Path $dummy -SigningMode None 6>&1 | Out-String
    if ($output -notmatch 'Signing disabled\. 1 LuckyGuard-owned signable file\(s\) left unsigned\.') {
        throw "Single-file signing helper regression failed. Output: $output"
    }
    Write-Host 'Release tooling smoke test: PASS (single-file unsigned signing target)'

    # Validate public configuration against a throwaway repo copy so the real source tree is never mutated by tests.
    $fakeRoot = Join-Path $tempRoot 'public-config-repo'
    New-Item -ItemType Directory -Path (Join-Path $fakeRoot 'scripts'),(Join-Path $fakeRoot 'config'),(Join-Path $fakeRoot '.github\ISSUE_TEMPLATE') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'configure-public.ps1') -Destination (Join-Path $fakeRoot 'scripts\configure-public.ps1')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1') -Destination (Join-Path $fakeRoot 'install.ps1')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'README.md') -Destination (Join-Path $fakeRoot 'README.md')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'config\public-release.json') -Destination (Join-Path $fakeRoot 'config\public-release.json')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.github\ISSUE_TEMPLATE\config.yml') -Destination (Join-Path $fakeRoot '.github\ISSUE_TEMPLATE\config.yml')

    # Repository configuration must be usable before a signing identity exists.
    & (Join-Path $fakeRoot 'scripts\configure-public.ps1') -Repository 'luckyguard-test/LuckyGuard'
    $configured = Get-Content -LiteralPath (Join-Path $fakeRoot 'config\public-release.json') -Raw | ConvertFrom-Json
    if ($configured.repository -ne 'luckyguard-test/LuckyGuard') { throw 'configure-public repository regression failed.' }
    if ($configured.publisherSubject -ne 'PUBLISHER_SUBJECT') { throw 'Repository-only configuration must preserve the pending publisher placeholder.' }
    $loaderText = Get-Content -LiteralPath (Join-Path $fakeRoot 'install.ps1') -Raw
    if ($loaderText -notmatch "Repository\s*=\s*'luckyguard-test/LuckyGuard'") { throw 'configure-public did not update install.ps1 repository.' }
    if ($loaderText -notmatch "ExpectedPublisherSubject\s*=\s*'PUBLISHER_SUBJECT'") { throw 'Repository-only configuration unexpectedly changed install.ps1 publisher.' }
    Write-Host 'Release tooling smoke test: PASS (repository-only public config)'

    # Publisher can be attached independently later without losing repository metadata.
    & (Join-Path $fakeRoot 'scripts\configure-public.ps1') -Repository 'luckyguard-test/LuckyGuard' -PublisherSubject 'CN=LuckyGuard Test Publisher'
    $configured = Get-Content -LiteralPath (Join-Path $fakeRoot 'config\public-release.json') -Raw | ConvertFrom-Json
    if ($configured.publisherSubject -ne 'CN=LuckyGuard Test Publisher') { throw 'configure-public publisher regression failed.' }
    $loaderText = Get-Content -LiteralPath (Join-Path $fakeRoot 'install.ps1') -Raw
    if ($loaderText -notmatch "ExpectedPublisherSubject\s*=\s*'CN=LuckyGuard Test Publisher'") { throw 'configure-public did not update install.ps1 publisher.' }
    Write-Host 'Release tooling smoke test: PASS (publisher attachment + loader rewrite)'

    # RequireSigned used to reference $root before it was initialized. Keep this ordering regression guarded.
    $releaseScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release.ps1') -Raw
    $rootAssignment = $releaseScript.IndexOf('$root = Split-Path -Parent $PSScriptRoot', [StringComparison]::Ordinal)
    $requireSignedBlock = $releaseScript.IndexOf('if ($RequireSigned)', [StringComparison]::Ordinal)
    if ($rootAssignment -lt 0 -or $requireSignedBlock -lt 0 -or $rootAssignment -gt $requireSignedBlock) {
        throw 'release.ps1 must initialize $root before the RequireSigned public-config gate.'
    }
    Write-Host 'Release tooling smoke test: PASS (RequireSigned initialization order)'

    # Native command probes must not use direct PowerShell stderr redirection under ErrorActionPreference=Stop.
    $bootstrapScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'github-bootstrap.ps1') -Raw
    $readinessScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'public-readiness.ps1') -Raw
    if ($bootstrapScript -notmatch 'function Invoke-NativeProbe') { throw 'github-bootstrap.ps1 must define a non-throwing native probe helper.' }
    if ($readinessScript -notmatch 'function Invoke-NativeProbe') { throw 'public-readiness.ps1 must define a non-throwing native probe helper.' }
    if ($bootstrapScript -match 'repo view \$repository --json nameWithOwner \*> \$null') { throw 'Repository existence probe regressed to direct native stderr redirection.' }
    if ($bootstrapScript -match '& \$gh auth status \*> \$null') { throw 'GitHub auth probe regressed to direct native stderr redirection.' }
    if ($readinessScript -match '& \$ghCmd\.Source auth status \*> \$null') { throw 'Readiness auth probe regressed to direct native stderr redirection.' }
    if ($bootstrapScript -notmatch 'NOT FOUND \(expected before creation\)') { throw 'Bootstrap must surface the expected pre-creation repository state.' }
    if ($bootstrapScript -notmatch 'Could not determine whether GitHub repository') { throw 'Bootstrap must distinguish missing repositories from unexpected GitHub failures.' }
    Write-Host 'Release tooling smoke test: PASS (PowerShell 5.1 native probe hardening)'

    # PowerShell child scripts do not guarantee that $LASTEXITCODE exists or changes. StrictMode must not read it after .ps1 calls.
    $configureCall = "& (Join-Path `$PSScriptRoot 'configure-public.ps1') -Repository `$repository"
    $configureIndex = $bootstrapScript.IndexOf($configureCall, [StringComparison]::Ordinal)
    if ($configureIndex -lt 0) { throw 'Bootstrap configure-public invocation was not found.' }
    $configureWindowLength = [Math]::Min(220, $bootstrapScript.Length - $configureIndex)
    $configureWindow = $bootstrapScript.Substring($configureIndex, $configureWindowLength)
    if ($configureWindow.Contains('$LASTEXITCODE')) { throw 'Bootstrap must not read $LASTEXITCODE after configure-public.ps1.' }
    if (-not $configureWindow.Contains('if(-not $?)')) { throw 'Bootstrap must validate configure-public.ps1 with PowerShell command success state.' }

    $releaseScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'release.ps1') -Raw
    if ($releaseScript.Contains('if ($LASTEXITCODE -ne 0) { throw ''Payload signing failed.'' }')) { throw 'Payload signing regressed to $LASTEXITCODE.' }
    if ($releaseScript.Contains('if ($LASTEXITCODE -ne 0) { throw ''Installer signing failed.'' }')) { throw 'Installer signing regressed to $LASTEXITCODE.' }
    if (-not $releaseScript.Contains('if (-not $?) { throw ''Payload signing failed.'' }')) { throw 'Payload signing must use PowerShell command success state.' }
    if (-not $releaseScript.Contains('if (-not $?) { throw ''Installer signing failed.'' }')) { throw 'Installer signing must use PowerShell command success state.' }
    Write-Host 'Release tooling smoke test: PASS (PowerShell child-script exit-state hardening)'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
