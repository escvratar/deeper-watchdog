@echo off
cd /d "%~dp0"
set PYTHONUTF8=1
python\python.exe winctl.py stop
pause
