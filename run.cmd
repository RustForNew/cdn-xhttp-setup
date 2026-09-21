@echo off
setlocal
set PYTHONUTF8=1
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto python
py -3 bootstrap.py %*
exit /b %errorlevel%

:python
where python >nul 2>nul
if errorlevel 1 goto fail
python bootstrap.py %*
exit /b %errorlevel%

:fail
echo Install Python 3.10+ with pip, then run this file again.
exit /b 1
