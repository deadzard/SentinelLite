@echo off
setlocal
cd /d "%~dp0"
title SentinelLite launcher
echo ================================================
echo  SentinelLite - setup, test and launch (Windows)
echo ================================================

rem ---- 1. Find Python 3.9+ ---------------------------------------------------
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
echo [ERROR] Python 3 was not found.
echo         Install Python 3.9 or newer from https://www.python.org/downloads/
echo         and tick "Add python.exe to PATH" during installation, then run this file again.
goto :fail

:have_python
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.9 or newer is required. Your version:
    %PY% --version
    goto :fail
)
echo [OK] Python found: %PY%

rem ---- 2. Create the virtual environment if needed ------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo [..] Creating virtual environment in .venv ...
    %PY% -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Could not create the virtual environment.
    goto :fail
)
set "VPY=.venv\Scripts\python.exe"

rem ---- 3. Install dependencies ------------------------------------------------------
echo [..] Installing dependencies (internet needed only for this step) ...
"%VPY%" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check your internet connection and try again.
    goto :fail
)

rem ---- 4. Run the automated tests -------------------------------------------------------
echo [..] Running automated tests ...
"%VPY%" -m pytest -q
if errorlevel 1 (
    echo [ERROR] Some tests failed, so the app was not started. Read the messages above.
    goto :fail
)
echo [OK] All tests passed.

rem ---- 5. Start the dashboard -------------------------------------------------------------
echo [..] Starting SentinelLite. Your browser should open at http://localhost:8501
echo      Press Ctrl+C in this window to stop the server.
echo.
rem The piped blank line answers Streamlit's one-time optional e-mail prompt.
echo.| "%VPY%" -m streamlit run app.py
goto :end

:fail
echo.
echo Setup did not complete. See the messages above.
echo Manual steps:  py -3 -m venv .venv ^&^& .venv\Scripts\activate ^&^& pip install -r requirements.txt ^&^& streamlit run app.py
pause
exit /b 1

:end
pause
endlocal
