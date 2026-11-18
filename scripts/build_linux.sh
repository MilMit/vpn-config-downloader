#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# PyInstaller on Linux requires a Python interpreter compiled with --enable-shared.
pick_python() {
    for cand in /usr/bin/python3 python3; do
        if command -v "$cand" >/dev/null 2>&1; then
            if "$cand" -c 'import sys, sysconfig; raise SystemExit(0 if sys.version_info >= (3,11) and sysconfig.get_config_var("Py_ENABLE_SHARED") else 1)' 2>/dev/null; then
                echo "$cand"
                return 0
            fi
        fi
    done
    echo "python3"
}

PY="$(pick_python)"
if [[ ! -x .venv-build/bin/python ]]; then
    "$PY" -m venv .venv-build
fi
. .venv-build/bin/activate
python -m pip install -r requirements.txt -r requirements-build.txt
python build/build.py "$@"
printf 'Linux folder build: dist/VPNConfigDownloader/\n'
