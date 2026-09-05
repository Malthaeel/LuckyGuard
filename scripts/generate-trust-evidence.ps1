[CmdletBinding()]
param(
    [string]$PackagesDirectory,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
if (-not $PackagesDirectory) { $PackagesDirectory = Join-Path $root 'artifacts\release\packages' }
if (-not $OutputPath) { $OutputPath = Join-Path $PackagesDirectory 'TRUST-EVIDENCE.md' }

$manifestPath = Join-Path $PackagesDirectory 'release-manifest.json'
$configPath = Join-Path $root 'config\public-release.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Release manifest not found: $manifestPath" }
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Public release config not found: $configPath" }

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$repository = [string]$config.repository
$repoConfigured = $repository -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -and $repository -ne 'OWNER/REPOSITORY'
$tag = "v$($manifest.version)"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# LuckyGuard release trust evidence')
$lines.Add('')
$lines.Add("- Version: **$($manifest.version)**")
$lines.Add("- Runtime: **$($manifest.runtime)**")
$lines.Add("- Generated: **$([DateTimeOffset]::UtcNow.ToString('O'))**")
$lines.Add("- Signing mode: **$($manifest.signingMode)**")
if ($manifest.publisherSubject) { $lines.Add("- Authenticode publisher: **$($manifest.publisherSubject)**") }
if ($repoConfigured) { $lines.Add("- Official repository: https://github.com/$repository") }
$lines.Add('')
if ([string]$manifest.signingMode -eq 'None') { $lines.Add('> **Development/RC warning:** this release is unsigned. Do not use these hashes as the canonical trust evidence for a future signed stable release; signing changes executable bytes and SHA-256.') ; $lines.Add('') }
$lines.Add('> VirusTotal links below are hash lookups for the exact packaged bytes. A report appears only after that exact file has been submitted. VirusTotal is transparency evidence, not a safety certificate.')
$lines.Add('')
$lines.Add('| File | SHA-256 | Authenticode | VirusTotal |')
$lines.Add('|---|---|---|---|')

foreach ($pkg in @($manifest.packages)) {
    $path = Join-Path $PackagesDirectory ([string]$pkg.file)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Manifest package is missing: $($pkg.file)" }
    $sha = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -ne ([string]$pkg.sha256).ToLowerInvariant()) { throw "Manifest SHA-256 mismatch while generating trust evidence: $($pkg.file)" }

    $auth = 'n/a'
    if ([System.IO.Path]::GetExtension($path).Equals('.exe',[StringComparison]::OrdinalIgnoreCase)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
            $subject = $subject.Replace('|','\|')
            $auth = "Valid - $subject"
        } else {
            $auth = [string]$sig.Status
        }
    }
    $vt = "https://www.virustotal.com/gui/file/$sha"
    $lines.Add("| ``$($pkg.file)`` | ``$sha`` | $auth | [lookup]($vt) |")
}

$lines.Add('')
$lines.Add('## Local verification')
$lines.Add('')
$lines.Add('```powershell')
$lines.Add('Get-FileHash .\LuckyGuard-Setup-win-x64.exe -Algorithm SHA256')
$lines.Add('Get-AuthenticodeSignature .\LuckyGuard-Setup-win-x64.exe | Format-List Status,SignerCertificate')
$lines.Add('```')
if ($repoConfigured) {
    $lines.Add('')
    $lines.Add('## Official release')
    $lines.Add('')
    $lines.Add("https://github.com/$repository/releases/tag/$tag")
}

$lines | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Host "Trust evidence generated: $OutputPath"
