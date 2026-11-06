@echo off
cd /d "%~dp0"
title Deeper Watchdog
set PYTHONUTF8=1
set "DATA_DIR=%~dp0data"
if not exist ".env" python\python.exe deeper_watchdog.py --setup
if not exist ".env" goto end
python\python.exe winctl.py start-note || goto end
python\python.exe -u deeper_watchdog.py --daemon --open-browser
:end
pause
