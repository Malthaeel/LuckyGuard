[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string[]]$Path,
    [ValidateSet('None','CertStore','ArtifactSigning')][string]$SigningMode = 'None',
    [string]$CertificateThumbprint,
    [string]$ArtifactSigningMetadata,
    [string]$ArtifactSigningDlib,
    [string]$SignToolPath,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'

function Resolve-SignTool([string]$Requested) {
    if ($Requested) {
        $resolved = (Resolve-Path -LiteralPath $Requested).Path
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "SignTool not found: $Requested" }
        return $resolved
    }
    if ($env:LUCKYGUARD_SIGNTOOL) { return Resolve-SignTool $env:LUCKYGUARD_SIGNTOOL }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path $kits) {
        $candidate = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw 'SignTool.exe was not found. Install a current Windows SDK or set LUCKYGUARD_SIGNTOOL.'
}

function Resolve-SignTargets([string[]]$InputPaths) {
    $files = foreach ($item in $InputPaths) {
        if (Test-Path -LiteralPath $item -PathType Container) {
            Get-ChildItem -LiteralPath $item -Recurse -File | Where-Object {
                $_.Name -match '^LuckyGuard.*\.(exe|dll)$'
            }
        } elseif (Test-Path -LiteralPath $item -PathType Leaf) {
            Get-Item -LiteralPath $item
        } else {
            throw "Signing target not found: $item"
        }
    }
    @($files | Sort-Object FullName -Unique)
}

$targets = @(Resolve-SignTargets $Path)
if ($SigningMode -eq 'None') {
    Write-Host "Signing disabled. $($targets.Count) LuckyGuard-owned signable file(s) left unsigned."
    return
}
if (-not $targets) { throw 'No signable LuckyGuard artifacts were found.' }

$signtool = Resolve-SignTool $SignToolPath
if (-not $TimestampUrl) {
    $TimestampUrl = if ($SigningMode -eq 'ArtifactSigning') { 'http://timestamp.acs.microsoft.com/' } else { 'http://timestamp.digicert.com' }
}

if ($SigningMode -eq 'CertStore') {
    if (-not $CertificateThumbprint) { $CertificateThumbprint = $env:LUCKYGUARD_CERT_THUMBPRINT }
    if (-not $CertificateThumbprint) { throw 'CertStore signing requires -CertificateThumbprint or LUCKYGUARD_CERT_THUMBPRINT.' }
    $CertificateThumbprint = ($CertificateThumbprint -replace '\s','').ToUpperInvariant()
}

if ($SigningMode -eq 'ArtifactSigning') {
    if (-not $ArtifactSigningMetadata) { $ArtifactSigningMetadata = $env:LUCKYGUARD_ARTIFACT_SIGNING_METADATA }
    if (-not $ArtifactSigningDlib) { $ArtifactSigningDlib = $env:LUCKYGUARD_ARTIFACT_SIGNING_DLIB }
    if (-not $ArtifactSigningMetadata -or -not (Test-Path -LiteralPath $ArtifactSigningMetadata -PathType Leaf)) {
        throw 'ArtifactSigning requires a valid metadata JSON path.'
    }
    if (-not $ArtifactSigningDlib -or -not (Test-Path -LiteralPath $ArtifactSigningDlib -PathType Leaf)) {
        throw 'ArtifactSigning requires Azure.CodeSigning.Dlib.dll.'
    }
    $ArtifactSigningMetadata = (Resolve-Path -LiteralPath $ArtifactSigningMetadata).Path
    $ArtifactSigningDlib = (Resolve-Path -LiteralPath $ArtifactSigningDlib).Path
}

foreach ($target in $targets) {
    Write-Host "Signing $($target.FullName)"
    $args = @('sign','/v','/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256')
    if ($SigningMode -eq 'CertStore') {
        $args += @('/sha1',$CertificateThumbprint)
    } else {
        $args += @('/dlib',$ArtifactSigningDlib,'/dmdf',$ArtifactSigningMetadata)
    }
    $args += $target.FullName
    & $signtool @args
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed for $($target.FullName) with exit code $LASTEXITCODE." }

    & $signtool verify /pa /all /v $target.FullName
    if ($LASTEXITCODE -ne 0) { throw "Signature verification failed for $($target.FullName)." }
}

Write-Host "Signed and verified $($targets.Count) file(s)."
