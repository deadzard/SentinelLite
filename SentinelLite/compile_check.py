"""
compile_check.py - byte-compile every Python file in the project and report syntax errors.

Run directly:   python compile_check.py
Exit code 0 = everything compiled, 1 = at least one file has an error.
"""
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKIP_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".git"}


def main() -> int:
    files = sorted(p for p in ROOT.rglob("*.py") if not SKIP_DIRS & set(p.relative_to(ROOT).parts))
    failed = 0
    for path in files:
        name = path.relative_to(ROOT)
        try:
            py_compile.compile(str(path), doraise=True)
            print(f"  compiled OK  {name}")
        except py_compile.PyCompileError as exc:
            failed += 1
            print(f"  ERROR        {name}\n{exc.msg}")
    print(f"\n{len(files) - failed} of {len(files)} files compiled successfully.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
