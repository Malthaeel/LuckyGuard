@echo off
setlocal
cd /d "%~dp0.."
dotnet run --project ".\src\LuckyGuard.Cli\LuckyGuard.Cli.csproj" -- %*
exit /b %ERRORLEVEL%
