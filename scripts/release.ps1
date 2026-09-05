[CmdletBinding()]
param(
    [ValidateSet('win-x64')][string]$Runtime = 'win-x64',
    [ValidateSet('None','CertStore','ArtifactSigning')][string]$SigningMode = 'None',
    [ValidateSet('Auto','Required','Skip')][string]$Installer = 'Auto',
    [string]$CertificateThumbprint,
    [string]$ArtifactSigningMetadata,
    [string]$ArtifactSigningDlib,
    [string]$SignToolPath,
    [string]$TimestampUrl,
    [string]$InnoSetupCompiler,
    [switch]$SkipTests,
    [switch]$RequireSigned
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot

if ($RequireSigned -and $SigningMode -eq 'None') { throw 'Public release requested but SigningMode=None. Choose CertStore or ArtifactSigning.' }

if ($RequireSigned) {
    $publicConfigPath = Join-Path $root 'config\public-release.json'
    if (-not (Test-Path -LiteralPath $publicConfigPath)) { throw 'config/public-release.json is missing.' }
    $publicConfig = Get-Content -LiteralPath $publicConfigPath -Raw | ConvertFrom-Json
    if ($publicConfig.repository -eq 'OWNER/REPOSITORY' -or $publicConfig.publisherSubject -eq 'PUBLISHER_SUBJECT') {
        throw 'Stable/public signed release is locked until scripts/configure-public.cmd configures the repository and exact publisher subject.'
    }
}

$buildInfo = Join-Path $root 'src\LuckyGuard.Core\BuildInfo.cs'
$versionMatch = Select-String -LiteralPath $buildInfo -Pattern 'Version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $versionMatch) { throw 'Could not read LuckyGuard version from BuildInfo.cs.' }
$version = $versionMatch.Matches[0].Groups[1].Value

$artifacts = Join-Path $root 'artifacts\release'
$work = Join-Path $artifacts 'work'
$payload = Join-Path $work 'payload'
$servicePayload = Join-Path $payload 'service'
$packages = Join-Path $artifacts 'packages'

if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
if (Test-Path $packages) { Remove-Item -LiteralPath $packages -Recurse -Force }
New-Item -ItemType Directory -Path $payload,$servicePayload,$packages -Force | Out-Null

$forbiddenSigningFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike (Join-Path $root 'artifacts\*') -and $_.Extension -in @('.pfx','.p12','.pvk','.key','.snk','.jks','.keystore') })
if ($forbiddenSigningFiles.Count -gt 0) {
    throw "Private signing material was found inside the repository. Move it outside the repo before releasing: $($forbiddenSigningFiles[0].FullName)"
}
$privatePem = Get-ChildItem -LiteralPath $root -Recurse -Filter *.pem -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike (Join-Path $root 'artifacts\*') } |
    Where-Object { Select-String -LiteralPath $_.FullName -Pattern 'BEGIN (EC |RSA |OPENSSH |ENCRYPTED )?PRIVATE KEY' -Quiet -ErrorAction SilentlyContinue } |
    Select-Object -First 1
if ($privatePem) { throw "Private-key PEM material was found inside the repository: $($privatePem.FullName)" }

Push-Location $root
try {
    Write-Host "== LuckyGuard $version release / $Runtime =="
    dotnet restore .\LuckyGuard.sln
    if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }
    dotnet build .\LuckyGuard.sln -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
    if (-not $SkipTests) {
        dotnet test .\tests\LuckyGuard.Tests\LuckyGuard.Tests.csproj -c Release --no-build --no-restore
        if ($LASTEXITCODE -ne 0) { throw 'dotnet test failed.' }
    }

    dotnet publish .\src\LuckyGuard.Cli\LuckyGuard.Cli.csproj -c Release -r $Runtime --self-contained true -o $payload -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw 'LuckyGuard CLI publish failed.' }
    dotnet publish .\src\LuckyGuard.Service\LuckyGuard.Service.csproj -c Release -r $Runtime --self-contained true -o $servicePayload -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw 'LuckyGuard Service publish failed.' }

    $serviceExe = Join-Path $servicePayload 'LuckyGuardService.exe'
    $cliExe = Join-Path $payload 'LuckyGuard.exe'
    if (-not (Test-Path -LiteralPath $cliExe)) { throw 'Published LuckyGuard.exe is missing.' }
    if (-not (Test-Path -LiteralPath $serviceExe)) { throw 'Published LuckyGuardService.exe is missing.' }

    Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $root 'SECURITY.md') -Destination $payload
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination $payload

    & (Join-Path $PSScriptRoot 'sign-artifacts.ps1') -Path $payload -SigningMode $SigningMode -CertificateThumbprint $CertificateThumbprint -ArtifactSigningMetadata $ArtifactSigningMetadata -ArtifactSigningDlib $ArtifactSigningDlib -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl
    if (-not $?) { throw 'Payload signing failed.' }

    & $cliExe --version
    if ($LASTEXITCODE -ne 0) { throw 'Published LuckyGuard --version validation failed.' }
    & $cliExe ioc verify
    if ($LASTEXITCODE -ne 0) { throw 'Published IOC feed verification failed.' }

    $portableName = "LuckyGuard-$version-$Runtime-portable.zip"
    $portablePath = Join-Path $packages $portableName
    if (Test-Path $portablePath) { Remove-Item $portablePath -Force }
    Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $portablePath -CompressionLevel Optimal

    function Resolve-Inno([string]$Requested) {
        if ($Requested) {
            if (-not (Test-Path -LiteralPath $Requested -PathType Leaf)) { throw "ISCC.exe not found: $Requested" }
            return (Resolve-Path -LiteralPath $Requested).Path
        }
        if ($env:LUCKYGUARD_ISCC -and (Test-Path -LiteralPath $env:LUCKYGUARD_ISCC -PathType Leaf)) { return (Resolve-Path -LiteralPath $env:LUCKYGUARD_ISCC).Path }
        $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        $candidates = @(
            (Join-Path $env:ProgramFiles 'Inno Setup 7\ISCC.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 7\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
            (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
        return $candidates | Select-Object -First 1
    }

    $installerPath = $null
    if ($Installer -ne 'Skip') {
        $iscc = Resolve-Inno $InnoSetupCompiler
        if (-not $iscc) {
            if ($Installer -eq 'Required') { throw 'Inno Setup compiler (ISCC.exe) is required but was not found. Install Inno Setup 7 (recommended) or 6, or pass -InnoSetupCompiler.' }
            Write-Warning 'Inno Setup compiler was not found. Portable ZIP created; installer skipped.'
        } else {
            $iss = Join-Path $root 'release\LuckyGuard.iss'
            & $iscc "/DMyAppVersion=$version" "/DPayloadDir=$payload" "/DOutputDir=$packages" $iss
            if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }
            $installerPath = Get-ChildItem -LiteralPath $packages -Filter "LuckyGuard-Setup-$version-$Runtime.exe" -File | Select-Object -First 1 -ExpandProperty FullName
            if (-not $installerPath) { throw 'Installer compiler completed but expected Setup.exe was not found.' }
            & (Join-Path $PSScriptRoot 'sign-artifacts.ps1') -Path $installerPath -SigningMode $SigningMode -CertificateThumbprint $CertificateThumbprint -ArtifactSigningMetadata $ArtifactSigningMetadata -ArtifactSigningDlib $ArtifactSigningDlib -SignToolPath $SignToolPath -TimestampUrl $TimestampUrl
            if (-not $?) { throw 'Installer signing failed.' }

            # Create a stable latest-release asset name after signing. Copying preserves the Authenticode signature.
            $stableInstallerPath = Join-Path $packages 'LuckyGuard-Setup-win-x64.exe'
            Copy-Item -LiteralPath $installerPath -Destination $stableInstallerPath -Force
            if ($SigningMode -ne 'None') {
                $stableSignature = Get-AuthenticodeSignature -LiteralPath $stableInstallerPath
                if ($stableSignature.Status -ne 'Valid') { throw "Stable installer alias signature verification failed: $($stableSignature.Status)" }
                $actualPublisherSubject = if ($stableSignature.SignerCertificate) { [string]$stableSignature.SignerCertificate.Subject } else { '<none>' }
                if ($RequireSigned -and -not $actualPublisherSubject.Equals([string]$publicConfig.publisherSubject,[StringComparison]::OrdinalIgnoreCase)) {
                    throw "Signed installer publisher '$actualPublisherSubject' does not match configured publisher '$($publicConfig.publisherSubject)'."
                }
            }
        }
    }

    $packageFiles = @($portablePath)
    if ($installerPath) { $packageFiles += $installerPath; $packageFiles += (Join-Path $packages 'LuckyGuard-Setup-win-x64.exe') }
    $hashLines = foreach ($file in $packageFiles) {
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $(Split-Path -Leaf $file)"
    }
    $hashPath = Join-Path $packages 'SHA256SUMS.txt'
    $hashLines | Set-Content -LiteralPath $hashPath -Encoding ascii

    $releasePublisherSubject = $null
    if ($SigningMode -ne 'None' -and $installerPath) {
        $releaseSig = Get-AuthenticodeSignature -LiteralPath (Join-Path $packages 'LuckyGuard-Setup-win-x64.exe')
        if ($releaseSig.SignerCertificate) { $releasePublisherSubject = [string]$releaseSig.SignerCertificate.Subject }
    }

    $manifest = [ordered]@{
        product = 'LuckyGuard'
        version = $version
        runtime = $Runtime
        selfContained = $true
        signingMode = $SigningMode
        publisherSubject = $releasePublisherSubject
        installer = [bool]$installerPath
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        dotnetSdk = (& dotnet --version).Trim()
        packages = @($packageFiles | ForEach-Object {
            [ordered]@{
                file = Split-Path -Leaf $_
                sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
                bytes = (Get-Item -LiteralPath $_).Length
            }
        })
    }
    $manifestPath = Join-Path $packages 'release-manifest.json'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    & (Join-Path $PSScriptRoot 'generate-trust-evidence.ps1') -PackagesDirectory $packages
    if (-not $?) { throw 'Trust evidence generation failed.' }

    Write-Host ''
    Write-Host 'Release completed.'
    Write-Host "Packages : $packages"
    Write-Host "Signing  : $SigningMode"
    if ($SigningMode -eq 'None') { Write-Warning 'This is an UNSIGNED development release. Do not present it as a trusted public release.' }
    Get-ChildItem -LiteralPath $packages -File | Select-Object Name,Length | Format-Table -AutoSize
}
finally {
    Pop-Location
}
