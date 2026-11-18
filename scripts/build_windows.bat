@echo off
cd /d "%~dp0\.."
if not exist .venv py -3 -m venv .venv
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-build.txt
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe build\build.py %*
if errorlevel 1 exit /b 1
echo Windows folder build: dist\VPNConfigDownloader\
