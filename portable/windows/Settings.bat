@echo off
cd /d "%~dp0"
title Deeper Watchdog - settings
set PYTHONUTF8=1
set "DATA_DIR=%~dp0data"
python\python.exe deeper_watchdog.py --setup
python\python.exe winctl.py settings-note
pause
