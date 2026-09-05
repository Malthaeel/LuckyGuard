@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0public-readiness.ps1" %*
exit /b %ERRORLEVEL%
