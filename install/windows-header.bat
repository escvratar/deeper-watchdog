@echo off
rem Deeper Watchdog installer for Windows. The installer itself is the PowerShell part below.
set "DW_BAT=%~f0"
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:DW_BAT,[Text.Encoding]::UTF8); $i=$s.IndexOf('#'+'PS-START'); Invoke-Expression $s.Substring($i)"
exit /b %errorlevel%
#PS-START
