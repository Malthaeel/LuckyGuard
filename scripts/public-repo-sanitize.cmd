@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0public-repo-sanitize.ps1" %*
exit /b %ERRORLEVEL%
