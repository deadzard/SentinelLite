#!/usr/bin/env bash
# SentinelLite - compile, test and run (macOS / Linux)
set -u
cd "$(dirname "$0")"
fail() { echo; echo "Setup did not complete. See the messages above."; exit 1; }

if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "[ERROR] Python 3 was not found. Install Python 3.9+."; fail; fi
echo "[OK] Using $($PY --version)"

[ -x ".venv/bin/python" ] || { echo "[..] Creating virtual environment ..."; "$PY" -m venv .venv || { echo "[ERROR] venv creation failed."; fail; }; }
VPY=".venv/bin/python"

echo "[..] Installing dependencies ..."
"$VPY" -m pip install --disable-pip-version-check -r requirements.txt || { echo "[ERROR] Dependency install failed."; fail; }

echo; echo "[STEP 1/3] Compiling all Python files ..."
"$VPY" compile_check.py || { echo "[ERROR] Compilation failed."; fail; }

echo; echo "[STEP 2/3] Running automated tests ..."
"$VPY" -m pytest -q || { echo "[ERROR] Tests failed, app not started."; fail; }

echo; echo "[STEP 3/3] Starting SentinelLite at http://localhost:8501  (Ctrl+C to stop)"
printf '\n' | "$VPY" -m streamlit run app.py
