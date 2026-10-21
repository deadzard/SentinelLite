@echo off
setlocal
cd /d "%~dp0"
title SentinelLite - compile and run
echo ================================================
echo  SentinelLite - compile, test and run (Windows)
echo ================================================

set "PY="
py -3 --version >nul 2>&1
if not errorlevel 1 (
    set "PY=py -3"
    goto :have_python
)
python --version >nul 2>&1
if not errorlevel 1 (
    set "PY=python"
    goto :have_python
)
echo [ERROR] Python 3 was not found. Install Python 3.9+ from https://www.python.org/downloads/
echo         and tick "Add python.exe to PATH", then run this file again.
goto :fail

:have_python
echo [OK] Python found: %PY%

if not exist ".venv\Scripts\python.exe" (
    echo [..] Creating virtual environment ...
    %PY% -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Could not create the virtual environment.
    goto :fail
)
set "VPY=.venv\Scripts\python.exe"

echo [..] Installing dependencies ...
"%VPY%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check your internet connection.
    goto :fail
)

echo.
echo [STEP 1/3] Compiling all Python files ...
"%VPY%" compile_check.py
if errorlevel 1 (
    echo [ERROR] Compilation failed. Fix the errors listed above.
    goto :fail
)

echo.
echo [STEP 2/3] Running automated tests ...
"%VPY%" -m pytest -q
if errorlevel 1 (
    echo [ERROR] Some tests failed, so the app was not started.
    goto :fail
)

echo.
echo [STEP 3/3] Starting SentinelLite at http://localhost:8501  (Ctrl+C to stop)
echo.| "%VPY%" -m streamlit run app.py
goto :end

:fail
echo.
echo Setup did not complete. See the messages above.
pause
exit /b 1

:end
pause
endlocal
