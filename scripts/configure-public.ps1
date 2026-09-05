[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
    [string]$PublisherSubject
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $PSScriptRoot
$configPath=Join-Path $root 'config\public-release.json'
$oldRepository='OWNER/REPOSITORY'
$existingPublisher='PUBLISHER_SUBJECT'
if(Test-Path -LiteralPath $configPath){
    try {
        $existing=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        if($existing.repository){$oldRepository=[string]$existing.repository}
        if($existing.publisherSubject){$existingPublisher=[string]$existing.publisherSubject}
    } catch {}
}

$publisherToWrite = if([string]::IsNullOrWhiteSpace($PublisherSubject)){$existingPublisher}else{$PublisherSubject.Trim()}
if([string]::IsNullOrWhiteSpace($publisherToWrite)){$publisherToWrite='PUBLISHER_SUBJECT'}

$loader=Join-Path $root 'install.ps1'
$text=Get-Content -LiteralPath $loader -Raw
$escapedRepo=$Repository.Replace("'","''")
$escapedPublisher=$publisherToWrite.Replace("'","''")
$text=[regex]::Replace($text, '(?m)^\s*\[string\]\$Repository\s*=\s*''[^'']*''', "    [string]`$Repository = '$escapedRepo'", 1)
$text=[regex]::Replace($text, '(?m)^\s*\[string\]\$ExpectedPublisherSubject\s*=\s*''[^'']*''', "    [string]`$ExpectedPublisherSubject = '$escapedPublisher'", 1)
Set-Content -LiteralPath $loader -Value $text -Encoding utf8

foreach($relative in @('README.md','.github\ISSUE_TEMPLATE\config.yml')){
    $target=Join-Path $root $relative
    if(Test-Path -LiteralPath $target){
        $content=Get-Content -LiteralPath $target -Raw
        $content=$content.Replace('OWNER/REPOSITORY',$Repository)
        if($oldRepository -and $oldRepository -ne 'OWNER/REPOSITORY'){$content=$content.Replace($oldRepository,$Repository)}
        Set-Content -LiteralPath $target -Value $content -Encoding utf8
    }
}

$config=[ordered]@{
    repository=$Repository
    publisherSubject=$publisherToWrite
    iocFeedUrl="https://raw.githubusercontent.com/$Repository/main/rules/luckyware/ioc-feed.json"
    iocSignatureUrl="https://raw.githubusercontent.com/$Repository/main/rules/luckyware/ioc-feed.sig"
}
$config | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $configPath -Encoding utf8

Write-Host "Configured public repository metadata for $Repository"
if($publisherToWrite -eq 'PUBLISHER_SUBJECT'){
    Write-Host 'Authenticode publisher: PENDING (repository setup can proceed; stable public release remains blocked)' -ForegroundColor Yellow
}else{
    Write-Host "Expected Authenticode publisher: $publisherToWrite"
}
Write-Host "Official IOC feed: $($config.iocFeedUrl)"
Write-Host 'Review install.ps1 and config/public-release.json before committing.'
