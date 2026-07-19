@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0test-proxy-windows.ps1" %*
exit /b %ERRORLEVEL%

