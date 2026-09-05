$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot

function Invoke-NativeProbe([string]$File,[string[]]$Arguments){
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$File
    $psi.Arguments=($Arguments -join ' ')
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $proc=New-Object System.Diagnostics.Process
    $proc.StartInfo=$psi
    [void]$proc.Start()
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    [pscustomobject]@{
        ExitCode=$proc.ExitCode
        StdOut=$stdout.Trim()
        StdErr=$stderr.Trim()
    }
}

function Check([string]$Name,[bool]$Ok,[string]$Detail){
    $label=if($Ok){'PASS'}else{'BLOCK'}
    $color=if($Ok){'Green'}else{'Yellow'}
    Write-Host ('{0,-24} ' -f $Name) -NoNewline
    Write-Host $label -ForegroundColor $color -NoNewline
    Write-Host "  $Detail"
    return $Ok
}

$configPath=Join-Path $root 'config\public-release.json'
$config=if(Test-Path $configPath){Get-Content $configPath -Raw | ConvertFrom-Json}else{$null}
$repoOk=$null -ne $config -and $config.repository -ne 'OWNER/REPOSITORY' -and [string]$config.repository -match '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
$publisherOk=$null -ne $config -and -not [string]::IsNullOrWhiteSpace([string]$config.publisherSubject) -and $config.publisherSubject -ne 'PUBLISHER_SUBJECT'
$iocOk=$false
$iocDetail='config missing'
if($config){
    try{
        $feed=[Uri][string]$config.iocFeedUrl
        $sig=[Uri][string]$config.iocSignatureUrl
        $iocOk=$repoOk -and $feed.Scheme -eq 'https' -and $sig.Scheme -eq 'https' -and $feed.Host -eq $sig.Host -and
            $feed.AbsoluteUri -eq "https://raw.githubusercontent.com/$($config.repository)/main/rules/luckyware/ioc-feed.json" -and
            $sig.AbsoluteUri -eq "https://raw.githubusercontent.com/$($config.repository)/main/rules/luckyware/ioc-feed.sig"
        $iocDetail=if($iocOk){'official repository endpoints'}else{'URLs do not match configured repository'}
    }catch{$iocDetail='invalid IOC URL'}
}
$innoOk=$null -ne (Get-Command ISCC.exe -ErrorAction SilentlyContinue) -or
    (Test-Path (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe')) -or
    (Test-Path (Join-Path $env:ProgramFiles 'Inno Setup 7\ISCC.exe'))
$ghCmd=Get-Command gh.exe -ErrorAction SilentlyContinue
$ghOk=$null -ne $ghCmd
$ghAuthOk=$false
if($ghOk){
    $ghAuthProbe=Invoke-NativeProbe $ghCmd.Source @('auth','status')
    $ghAuthOk=$ghAuthProbe.ExitCode -eq 0
}
$gitCmd=Get-Command git.exe -ErrorAction SilentlyContinue
$remoteOk=$false
$remoteDetail='git/origin not configured'
if($repoOk -and $gitCmd -and (Test-Path (Join-Path $root '.git'))){
    Push-Location $root
    try{
        $originProbe=Invoke-NativeProbe $gitCmd.Source @('remote','get-url','origin')
        $origin=$originProbe.StdOut
        if($originProbe.ExitCode -eq 0 -and $origin){
            $expected=[regex]::Escape([string]$config.repository)
            $remoteOk=$origin -match "(?:github\.com[:/])$expected(?:\.git)?$"
            $remoteDetail=$origin
        }
    }finally{Pop-Location}
}
$signtoolOk=$null -ne (Get-Command signtool.exe -ErrorAction SilentlyContinue)
if(-not $signtoolOk -and ${env:ProgramFiles(x86)}){
    $kits=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if(Test-Path $kits){$signtoolOk=$null -ne (Get-ChildItem $kits -Filter signtool.exe -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.FullName -match '\\x64\\signtool\.exe$'} | Select-Object -First 1)}
}
$setup=Join-Path $root 'artifacts\release\packages\LuckyGuard-Setup-win-x64.exe'
$setupSigned=$false
$setupDetail='not built yet'
if(Test-Path $setup){
    $sig=Get-AuthenticodeSignature $setup
    $setupSigned=$sig.Status -eq 'Valid'
    $setupDetail="status=$($sig.Status)"
    if($setupSigned -and $publisherOk -and $sig.SignerCertificate){
        if(-not $sig.SignerCertificate.Subject.Equals([string]$config.publisherSubject,[StringComparison]::OrdinalIgnoreCase)){
            $setupSigned=$false
            $setupDetail="valid signature but signer mismatch: $($sig.SignerCertificate.Subject)"
        }
    }
}

Write-Host 'LuckyGuard public-release readiness'
Write-Host '----------------------------------'
$results=@(
    (Check 'Repository configured' $repoOk $(if($config){[string]$config.repository}else{'config missing'})),
    (Check 'Official IOC URLs' $iocOk $iocDetail),
    (Check 'Git origin matches' $remoteOk $remoteDetail),
    (Check 'Publisher configured' $publisherOk $(if($config){[string]$config.publisherSubject}else{'config missing'})),
    (Check 'Inno Setup' $innoOk 'installer compiler'),
    (Check 'SignTool' $signtoolOk 'Windows SDK signing tool'),
    (Check 'GitHub CLI' $ghOk 'gh.exe'),
    (Check 'GitHub auth' $ghAuthOk 'gh auth status'),
    (Check 'Signed installer' $setupSigned $setupDetail)
)
$blocked=@($results | Where-Object {-not $_}).Count
Write-Host ''
if($blocked -eq 0){Write-Host 'PUBLIC RELEASE TOOLING: READY' -ForegroundColor Green; exit 0}
Write-Host "PUBLIC RELEASE TOOLING: $blocked blocker(s) remain" -ForegroundColor Yellow
if($repoOk -and $iocOk -and $remoteOk -and $ghOk -and $ghAuthOk){
    Write-Host 'GitHub repository track: READY. Remaining signing blockers do not prevent RC source publication.' -ForegroundColor Cyan
}
exit 2
