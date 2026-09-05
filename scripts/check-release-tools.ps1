$ErrorActionPreference = 'Stop'

function Find-Iscc {
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

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
$iscc = Find-Iscc

Write-Host 'LuckyGuard release prerequisites'
Write-Host '-------------------------------'
Write-Host ("dotnet : " + $(if ($dotnet) { $dotnet.Source } else { '<missing>' }))
Write-Host ("ISCC   : " + $(if ($iscc) { $iscc } else { '<missing>' }))

if (-not $iscc) {
    Write-Host ''
    Write-Host 'Recommended install command:'
    Write-Host '  winget install --id JRSoftware.InnoSetup.7 -e -s winget -i'
    exit 2
}
