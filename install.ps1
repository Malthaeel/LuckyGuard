[CmdletBinding()]
param(
    [string]$Repository = 'Malthaeel/LuckyGuard',
    [string]$ExpectedPublisherSubject = 'PUBLISHER_SUBJECT',
    [switch]$NoService,
    [switch]$NoLaunch,
    [switch]$AllowUnsignedDevelopment
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Lg([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $old = $Host.UI.RawUI.ForegroundColor
    try { $Host.UI.RawUI.ForegroundColor = $Color; Write-Host $Text }
    finally { $Host.UI.RawUI.ForegroundColor = $old }
}
function Step([string]$Text) { Write-Host -NoNewline '  ['; Write-Host -NoNewline '*' -ForegroundColor Cyan; Write-Host "] $Text" }
function Good([string]$Text) { Write-Host -NoNewline '  ['; Write-Host -NoNewline '+' -ForegroundColor Green; Write-Host "] $Text" }
function Fail([string]$Text) { Write-Host -NoNewline '  ['; Write-Host -NoNewline '!' -ForegroundColor Red; Write-Host "] $Text" }

Clear-Host
Write-Lg '   __               __        ______                     __' Magenta
Write-Lg '  / /   __  _______/ /____  / ____/_  ______ __________/ /' Magenta
Write-Lg ' / /   / / / / ___/ //_/ / / / __/ / / / __ `/ ___/ __  / ' Magenta
Write-Lg '/ /___/ /_/ / /__/ ,< / /_/ / /_/ /_/ / /_/ / /  / /_/ /  ' Magenta
Write-Lg '\____/\__,_/\___/_/|_|\__, /\____/\__,_/\__,_/_/   \__,_/   ' Magenta
Write-Lg '                      /____/     Secure GitHub Installer' DarkGray
Write-Host ''

if ($Repository -eq 'OWNER/REPOSITORY' -or $Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'LuckyGuard public installer is not configured yet. Set the GitHub owner/repository in install.ps1 or run scripts\configure-public.ps1.'
}
if (-not $AllowUnsignedDevelopment -and $ExpectedPublisherSubject -eq 'PUBLISHER_SUBJECT') {
    throw 'Public installation is locked until an Authenticode publisher subject is configured.'
}

$api = "https://api.github.com/repos/$Repository/releases/latest"
$headers = @{ 'User-Agent' = 'LuckyGuard-Installer/1.0'; 'Accept' = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2026-03-10' }
$tmpRoot = Join-Path $env:TEMP ("LuckyGuard-Install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null

try {
    Step "Resolving latest GitHub release from $Repository"
    $release = Invoke-RestMethod -Uri $api -Headers $headers
    if ($release.draft -or $release.prerelease) { throw 'Latest GitHub release is not a stable published release.' }
    Good ("Release " + $release.tag_name)

    $installerAsset = @($release.assets | Where-Object { $_.name -eq 'LuckyGuard-Setup-win-x64.exe' }) | Select-Object -First 1
    if (-not $installerAsset) {
        $installerAsset = @($release.assets | Where-Object { $_.name -match '^LuckyGuard-Setup-.*-win-x64\.exe$' }) | Select-Object -First 1
    }
    $hashAsset = @($release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' }) | Select-Object -First 1
    if (-not $installerAsset -or -not $hashAsset) { throw 'Release is missing the Windows installer or SHA256SUMS.txt.' }

    $installer = Join-Path $tmpRoot $installerAsset.name
    $hashFile = Join-Path $tmpRoot 'SHA256SUMS.txt'
    Step ("Downloading " + $installerAsset.name)
    Invoke-WebRequest -Uri $installerAsset.browser_download_url -OutFile $installer -Headers $headers
    Invoke-WebRequest -Uri $hashAsset.browser_download_url -OutFile $hashFile -Headers $headers

    Step 'Verifying SHA-256'
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $hashFile) {
        if ($line -match '^([a-fA-F0-9]{64})\s+\*?(.+)$' -and $Matches[2].Trim() -eq $installerAsset.name) {
            $expected = $Matches[1].ToLowerInvariant(); break
        }
    }
    if (-not $expected) { throw 'Installer SHA-256 was not found in SHA256SUMS.txt.' }
    $actual = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw 'SHA-256 mismatch. Installation aborted.' }
    $installerDigestMatch = [regex]::Match([string]$installerAsset.digest, '^sha256:([a-fA-F0-9]{64})$')
    $hashAssetActual = (Get-FileHash -LiteralPath $hashFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashDigestMatch = [regex]::Match([string]$hashAsset.digest, '^sha256:([a-fA-F0-9]{64})$')
    if (-not $AllowUnsignedDevelopment) {
        if (-not $installerDigestMatch.Success) { throw 'GitHub installer asset is missing the required sha256 digest metadata.' }
        if (-not $hashDigestMatch.Success) { throw 'GitHub SHA256SUMS asset is missing the required sha256 digest metadata.' }
        if ($installerDigestMatch.Groups[1].Value.ToLowerInvariant() -ne $actual) { throw 'GitHub release asset digest does not match the downloaded installer.' }
        if ($hashDigestMatch.Groups[1].Value.ToLowerInvariant() -ne $hashAssetActual) { throw 'GitHub release asset digest does not match SHA256SUMS.txt.' }
    } else {
        if ($installerDigestMatch.Success -and $installerDigestMatch.Groups[1].Value.ToLowerInvariant() -ne $actual) { throw 'GitHub release asset digest does not match the downloaded installer.' }
        if ($hashDigestMatch.Success -and $hashDigestMatch.Groups[1].Value.ToLowerInvariant() -ne $hashAssetActual) { throw 'GitHub release asset digest does not match SHA256SUMS.txt.' }
    }
    Good ("SHA-256 " + $actual.Substring(0,16) + 'â€¦')

    Step 'Verifying Authenticode signature'
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($AllowUnsignedDevelopment) {
        if ($signature.Status -ne 'Valid') { Write-Lg '  [dev] Installer is unsigned/untrusted; allowed only because -AllowUnsignedDevelopment was supplied.' Yellow }
    } else {
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw "Authenticode verification failed: $($signature.Status)" }
        if (-not $signature.SignerCertificate.Subject.Equals($ExpectedPublisherSubject, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unexpected signer. Expected exact publisher '$ExpectedPublisherSubject'; got '$($signature.SignerCertificate.Subject)'."
        }
        Good ("Publisher " + $signature.SignerCertificate.Subject)
    }

    Step 'Launching elevated LuckyGuard installer'
    $taskArg = if ($NoService) { '/TASKS=""' } else { '/TASKS="guardservice"' }
    $proc = Start-Process -FilePath $installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',$taskArg) -Verb RunAs -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "Installer exited with code $($proc.ExitCode)." }

    $installExe = Join-Path $env:ProgramFiles 'LuckyGuard\LuckyGuard.exe'
    if (-not (Test-Path -LiteralPath $installExe)) { throw 'Installer completed but LuckyGuard.exe was not found in Program Files.' }
    Good 'Installed to C:\Program Files\LuckyGuard'

    $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    $env:Path = @($machinePath,$userPath) -join ';'
    $version = & $installExe --version
    Good $version
    if (-not $NoService) {
        $serviceQuery = & sc.exe query LuckyGuardGuard 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -or $serviceQuery -notmatch 'STATE\s*:\s*4\s+RUNNING') {
            throw 'Installer completed but LuckyGuardGuard is not RUNNING.'
        }
        Good 'Realtime Guard service RUNNING'
    }

    Write-Host ''
    Write-Lg '  Installation complete.' Green
    Write-Host '  Open a new terminal and type:'
    Write-Host ''
    Write-Lg '      luckyguard' Magenta
    Write-Host ''
    if (-not $NoLaunch) { & $installExe }
}
catch {
    Fail $_.Exception.Message
    throw
}
finally {
    if (Test-Path -LiteralPath $tmpRoot) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

