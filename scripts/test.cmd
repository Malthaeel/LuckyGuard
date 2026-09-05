@echo off
setlocal
cd /d "%~dp0.."
dotnet test ".\LuckyGuard.sln" -c Release
if errorlevel 1 exit /b %ERRORLEVEL%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-release-tooling.ps1"
exit /b %ERRORLEVEL%
