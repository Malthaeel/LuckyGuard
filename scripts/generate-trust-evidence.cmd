@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0generate-trust-evidence.ps1" %*
exit /b %ERRORLEVEL%
