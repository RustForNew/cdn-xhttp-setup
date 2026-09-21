@echo off
setlocal
set PYTHONUTF8=1
cd /d "%~dp0"
if exist .venv\Scripts\python.exe goto ready
where py >nul 2>nul
if errorlevel 1 (python -m venv .venv) else (py -3 -m venv .venv)
if errorlevel 1 goto fail
:ready
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m cdn_xhttp %*
exit /b %errorlevel%
:fail
echo Setup failed. Install Python 3.10+ with pip and retry.
exit /b 1
