@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0check-release-tools.ps1"
exit /b %ERRORLEVEL%
