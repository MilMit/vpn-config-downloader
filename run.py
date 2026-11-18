#!/usr/bin/env python3
"""Desktop launcher. Run `python run.py` from the project root."""
import sys
try:
    from app.ui.main import start
except ModuleNotFoundError as exc:
    if exc.name and exc.name.startswith('PySide6'):
        print('PySide6 is missing. Install dependencies with: python -m pip install -r requirements.txt',file=sys.stderr)
        sys.exit(1)
    raise
if __name__=='__main__':
    raise SystemExit(start(sys.argv))
