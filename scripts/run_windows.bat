@echo off
cd /d "%~dp0\.."
if not exist .venv (py -3 -m venv .venv)
if errorlevel 1 goto :fail
.venv\Scripts\python.exe -c "import PySide6, playwright, keyring, pyzipper, cryptography" >nul 2>&1
if errorlevel 1 (
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 goto :fail
)
.venv\Scripts\python.exe run.py %*
exit /b %errorlevel%
:fail
echo Python or dependency installation failed. Check internet access and Python 3.11+.
pause
exit /b 1
