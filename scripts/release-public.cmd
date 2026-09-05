@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0release.ps1" -RequireSigned -Installer Required %*
exit /b %ERRORLEVEL%
