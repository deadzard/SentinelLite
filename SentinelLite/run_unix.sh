#!/usr/bin/env bash
# SentinelLite - setup, test and launch (macOS / Linux)
set -u
cd "$(dirname "$0")"

fail() {
  echo
  echo "Setup did not complete. See the messages above."
  echo "Manual steps: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && streamlit run app.py"
  exit 1
}

if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else echo "[ERROR] Python 3 was not found. Install Python 3.9+ from https://www.python.org/downloads/"; fail; fi

"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "[ERROR] Python 3.9 or newer is required."; fail; }
echo "[OK] Using $($PY --version)"

if [ ! -x ".venv/bin/python" ]; then
  echo "[..] Creating virtual environment in .venv ..."
  "$PY" -m venv .venv || { echo "[ERROR] Could not create the virtual environment (on Debian/Ubuntu: sudo apt install python3-venv)."; fail; }
fi
VPY=".venv/bin/python"

echo "[..] Installing dependencies (internet needed only for this step) ..."
"$VPY" -m pip install --disable-pip-version-check -r requirements.txt || { echo "[ERROR] Dependency installation failed."; fail; }

echo "[..] Running automated tests ..."
"$VPY" -m pytest -q || { echo "[ERROR] Some tests failed, so the app was not started."; fail; }
echo "[OK] All tests passed."

echo "[..] Starting SentinelLite at http://localhost:8501  (Ctrl+C to stop)"
# the piped blank line answers Streamlit's one-time optional e-mail prompt
printf '\n' | "$VPY" -m streamlit run app.py
