@echo off
setlocal
cd /d "%~dp0.."
dotnet restore ".\LuckyGuard.sln"
if errorlevel 1 exit /b %ERRORLEVEL%
dotnet build ".\LuckyGuard.sln" -c Release --no-restore
exit /b %ERRORLEVEL%
