[CmdletBinding()]
param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git.exe is required.' }
    if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) { throw 'This directory is not an initialized Git repository.' }

    $forbidden = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike (Join-Path $root '.git\*') -and $_.FullName -notlike (Join-Path $root 'artifacts\*') } |
        Where-Object { $_.Extension -in @('.pfx','.p12','.pvk','.key','.snk','.jks','.keystore') })
    $privatePem = @(Get-ChildItem -LiteralPath $root -Recurse -Filter *.pem -File -ErrorAction SilentlyContinue |
        Where-Object { Select-String -LiteralPath $_.FullName -Pattern 'BEGIN (EC |RSA |ENCRYPTED |OPENSSH )?PRIVATE KEY' -Quiet -ErrorAction SilentlyContinue })
    if ($forbidden.Count -gt 0 -or $privatePem.Count -gt 0) {
        Write-Host 'BLOCK: private/signing material exists in the working tree.' -ForegroundColor Red
        @($forbidden + $privatePem) | ForEach-Object { Write-Host "  $($_.FullName)" }
        throw 'Move private material outside the repository before continuing.'
    }

    $trackedIgnored = @(& git ls-files -ci --exclude-standard 2>$null | Where-Object { $_ })
    $legacyPlans = @(& git ls-files 'phase*-plan.json' 2>$null | Where-Object { $_ })
    $removeFromIndex = @($trackedIgnored + $legacyPlans | Sort-Object -Unique)

    Write-Host 'LuckyGuard public repository sanitize'
    Write-Host '------------------------------------'
    if ($removeFromIndex.Count -eq 0) {
        Write-Host 'Tracked generated/local artifacts : PASS (none found)'
    } else {
        Write-Host "Tracked generated/local artifacts : $($removeFromIndex.Count)"
        $removeFromIndex | ForEach-Object { Write-Host "  $_" }
    }
    Write-Host 'Private/signing material           : PASS'

    if (-not $Apply) {
        Write-Host ''
        Write-Host 'Preview only. Re-run with -Apply to remove listed files from Git tracking while keeping ignored local files on disk.'
        return
    }

    foreach ($item in $removeFromIndex) {
        & git rm --cached --ignore-unmatch -- $item | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "git rm --cached failed for $item" }
    }

    & git add --renormalize . | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'git add --renormalize failed.' }
    Write-Host ''
    Write-Host 'Sanitize staging complete. Review with: git status --short'
}
finally {
    Pop-Location
}
