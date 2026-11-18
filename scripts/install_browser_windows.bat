@echo off
cd /d "%~dp0\.."
if not exist .venv (py -3 -m venv .venv)
if errorlevel 1 goto :fail
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :fail
.venv\Scripts\python.exe -m playwright install chromium
if errorlevel 1 goto :fail
echo Chromium installed for account browser automation.
exit /b 0
:fail
echo Browser installation failed. Check internet access, Python, and disk space.
pause
exit /b 1
