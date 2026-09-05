[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
    [switch]$Prerelease
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$buildInfo=Join-Path $root 'src\LuckyGuard.Core\BuildInfo.cs'
$m=Select-String -LiteralPath $buildInfo -Pattern 'Version\s*=\s*"([^"]+)"' | Select-Object -First 1
if(-not $m){throw 'Version not found.'}
$version=$m.Matches[0].Groups[1].Value
$isPre = $version -match '-(rc|alpha|beta|preview)[.-]?'
if($isPre -and -not $Prerelease){throw "Version $version is a prerelease. Re-run with -Prerelease; RC builds cannot be published as stable."}
if(-not $isPre -and $Prerelease){Write-Warning "Version $version has no prerelease suffix but -Prerelease was supplied."}

$packages=Join-Path $root 'artifacts\release\packages'
$setup=Join-Path $packages 'LuckyGuard-Setup-win-x64.exe'
$hashes=Join-Path $packages 'SHA256SUMS.txt'
$manifestPath=Join-Path $packages 'release-manifest.json'
if(-not(Test-Path $setup)){throw 'Stable public installer alias is missing. Run signed release-public first.'}
if(-not(Test-Path $hashes) -or -not(Test-Path $manifestPath)){throw 'Release manifest/checksums are missing.'}

$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$publicConfigPath=Join-Path $root 'config\public-release.json'
if(-not(Test-Path -LiteralPath $publicConfigPath)){throw 'config/public-release.json is missing.'}
$publicConfig=Get-Content -LiteralPath $publicConfigPath -Raw | ConvertFrom-Json
if($publicConfig.repository -ne $Repository){throw "Configured repository '$($publicConfig.repository)' does not match requested publish repository '$Repository'."}
if($publicConfig.publisherSubject -eq 'PUBLISHER_SUBJECT'){throw 'Authenticode publisher is not configured.'}
if($manifest.version -ne $version){throw "Manifest version $($manifest.version) does not match source version $version."}
if($manifest.signingMode -eq 'None'){throw 'Manifest says SigningMode=None. Refusing public GitHub publication.'}

$sig=Get-AuthenticodeSignature -LiteralPath $setup
if($sig.Status -ne 'Valid'){throw "Public installer signature is not valid: $($sig.Status)"}
if(-not $sig.SignerCertificate -or -not $sig.SignerCertificate.Subject.Equals([string]$publicConfig.publisherSubject,[StringComparison]::OrdinalIgnoreCase)){throw "Installer signer does not exactly match configured publisher '$($publicConfig.publisherSubject)'."}

# Validate every package in the manifest and only upload the current release files.
$hashMap=@{}
foreach($line in Get-Content -LiteralPath $hashes){
    if($line -match '^([a-fA-F0-9]{64})\s+\*?(.+)$'){$hashMap[$Matches[2].Trim()]=$Matches[1].ToLowerInvariant()}
}
$files=@()
foreach($pkg in @($manifest.packages)){
    $path=Join-Path $packages $pkg.file
    if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "Manifest package missing: $($pkg.file)"}
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if($actual -ne ([string]$pkg.sha256).ToLowerInvariant()){throw "Manifest SHA-256 mismatch: $($pkg.file)"}
    if(-not $hashMap.ContainsKey($pkg.file) -or $hashMap[$pkg.file] -ne $actual){throw "SHA256SUMS mismatch: $($pkg.file)"}
    $files += $path
}
$files += $hashes
$files += $manifestPath
$files=@($files | Sort-Object -Unique)

if(-not(Get-Command gh -ErrorAction SilentlyContinue)){throw 'GitHub CLI (gh) is required.'}
& gh auth status | Out-Host
if($LASTEXITCODE -ne 0){throw 'GitHub CLI is not authenticated.'}
$tag="v$version"
& gh release view $tag --repo $Repository *> $null
if($LASTEXITCODE -eq 0){throw "GitHub release $tag already exists; immutable release tags are not overwritten by this script."}

$args=@('release','create',$tag,'--repo',$Repository,'--title',"LuckyGuard $version",'--generate-notes')
if($Prerelease){$args+='--prerelease'}
$args += $files
& gh @args
if($LASTEXITCODE -ne 0){throw 'gh release create failed.'}

Write-Host 'Verifying uploaded GitHub release asset digests...'
$json=& gh api -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2026-03-10' "repos/$Repository/releases/tags/$tag"
if($LASTEXITCODE -ne 0){throw 'Could not read the newly-created GitHub release.'}
$remote=$json | ConvertFrom-Json
foreach($local in $files){
    $name=Split-Path -Leaf $local
    $asset=@($remote.assets | Where-Object {$_.name -eq $name}) | Select-Object -First 1
    if(-not $asset){throw "Uploaded asset missing from GitHub release: $name"}
    $actual=(Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToLowerInvariant()
    $digestMatch=[regex]::Match([string]$asset.digest,'^sha256:([a-fA-F0-9]{64})$')
    if(-not $digestMatch.Success){throw "GitHub did not return sha256 digest metadata for $name"}
    if($digestMatch.Groups[1].Value.ToLowerInvariant() -ne $actual){throw "GitHub asset digest mismatch after upload: $name"}
    Write-Host "  VERIFIED $name"
}
Write-Host "Published + digest-verified https://github.com/$Repository/releases/tag/$tag"
