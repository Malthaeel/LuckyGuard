[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]+$')][string]$RepositoryName = 'LuckyGuard',
    [string]$Description = 'LuckyGuard - Windows LuckyWare-focused scanner, cleaner, and realtime guard.',
    [string]$Confirm
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot

function Require-Command([string]$Name,[string]$Hint){
    $cmd=Get-Command $Name -ErrorAction SilentlyContinue
    if(-not $cmd){throw "$Name is required. $Hint"}
    return $cmd.Source
}
function Invoke-Native([string]$File,[string[]]$Arguments){
    & $File @Arguments
    if($LASTEXITCODE -ne 0){throw "$File exited with code $LASTEXITCODE."}
}
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
function Assert-NoSigningSecrets([string]$Path){
    $blockedExtensions=@('.pfx','.p12','.pvk','.key','.snk')
    $skip='\\(\.git|artifacts|bin|obj|\.vs|TestResults)\\'
    $files=@(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notmatch $skip})
    $secretFile=@($files | Where-Object {$blockedExtensions -contains $_.Extension.ToLowerInvariant()} | Select-Object -First 1)
    if($secretFile){throw "Signing/private-key file must not be committed: $($secretFile.FullName)"}
    foreach($file in $files){
        if($file.Length -gt 2MB){continue}
        if($file.Extension -notin @('.ps1','.cmd','.json','.md','.yml','.yaml','.cs','.props','.targets','.xml','.txt','.pem','.iss','.sln','.csproj')){continue}
        try{
            $content=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            if($content -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'){
                throw "PEM private key material must not be committed: $($file.FullName)"
            }
        }catch [System.Management.Automation.RuntimeException]{ throw }
        catch{}
    }
}

$gh=Require-Command 'gh.exe' 'Install it with: winget install --id GitHub.cli -e'
$git=Require-Command 'git.exe' 'Install Git for Windows first.'
$authProbe=Invoke-NativeProbe $gh @('auth','status')
if($authProbe.ExitCode -ne 0){throw 'GitHub CLI is not authenticated. Run: gh auth login'}
$loginProbe=Invoke-NativeProbe $gh @('api','user','--jq','.login')
if($loginProbe.ExitCode -ne 0){
    $detail=if([string]::IsNullOrWhiteSpace($loginProbe.StdErr)){"exit code $($loginProbe.ExitCode)"}else{$loginProbe.StdErr}
    throw "Could not resolve the authenticated GitHub login: $detail"
}
$login=$loginProbe.StdOut.Trim()
if([string]::IsNullOrWhiteSpace($login) -or $login -notmatch '^[A-Za-z0-9_.-]+$'){throw 'Could not resolve the authenticated GitHub login.'}
$repository="$login/$RepositoryName"

Write-Host 'LuckyGuard GitHub bootstrap'
Write-Host '---------------------------'
Write-Host "Account    : $login"
Write-Host "Repository : $repository"
Write-Host 'Visibility : PUBLIC'
Write-Host ''

# Configure repo-derived URLs now; publisher signing can be configured independently later.
& (Join-Path $PSScriptRoot 'configure-public.ps1') -Repository $repository
if(-not $?){throw 'Public repository configuration failed.'}
Assert-NoSigningSecrets $root

$repoProbe=Invoke-NativeProbe $gh @('repo','view',$repository,'--json','nameWithOwner')
if($repoProbe.ExitCode -eq 0){
    throw "GitHub repository $repository already exists. This bootstrap intentionally refuses to overwrite or repurpose an existing repository."
}
$repoMissing=$repoProbe.StdErr -match 'Could not resolve to a Repository|HTTP 404|Not Found'
if(-not $repoMissing){
    $detail=if([string]::IsNullOrWhiteSpace($repoProbe.StdErr)){"exit code $($repoProbe.ExitCode)"}else{$repoProbe.StdErr}
    throw "Could not determine whether GitHub repository $repository exists: $detail"
}
Write-Host 'GitHub repository : NOT FOUND (expected before creation)' -ForegroundColor DarkGray

if($Confirm -ne 'CREATE_PUBLIC_REPO'){
    Write-Host ''
    Write-Host 'Repository metadata is configured locally, but no GitHub repository was created.' -ForegroundColor Yellow
    Write-Host 'Review the diff, then re-run with:'
    Write-Host ''
    Write-Host '  .\scripts\github-bootstrap.cmd -Confirm CREATE_PUBLIC_REPO' -ForegroundColor Cyan
    exit 2
}

Push-Location $root
try{
    if(-not(Test-Path -LiteralPath (Join-Path $root '.git'))){
        Invoke-Native $git @('init','-b','main')
    }

    $nameProbe=Invoke-NativeProbe $git @('config','user.name')
    $name=$nameProbe.StdOut
    if([string]::IsNullOrWhiteSpace($name)){Invoke-Native $git @('config','user.name',$login)}
    $emailProbe=Invoke-NativeProbe $git @('config','user.email')
    $email=$emailProbe.StdOut
    if([string]::IsNullOrWhiteSpace($email)){Invoke-Native $git @('config','user.email',"$login@users.noreply.github.com")}

    Invoke-Native $git @('add','--all')
    $staged=& $git diff --cached --name-only
    if($LASTEXITCODE -ne 0){throw 'Could not inspect staged files.'}
    if(-not [string]::IsNullOrWhiteSpace(($staged | Out-String))){
        Invoke-Native $git @('commit','-m','Prepare LuckyGuard 1.0 public release candidate')
    }else{
        $headProbe=Invoke-NativeProbe $git @('rev-parse','--verify','HEAD')
        if($headProbe.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($headProbe.StdOut)){
            throw 'Nothing is staged and the repository has no commit.'
        }
    }

    Invoke-Native $gh @('repo','create',$repository,'--public','--source=.','--remote=origin','--push','--description',$Description)
    Write-Host ''
    Write-Host "PUBLIC GITHUB REPOSITORY CREATED: https://github.com/$repository" -ForegroundColor Green
    Write-Host 'Code-signing remains intentionally separate; stable publishing is still blocked until a trusted publisher is configured.'
}
finally{Pop-Location}
