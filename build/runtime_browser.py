"""PyInstaller runtime hook to point Playwright at bundled browsers."""
import os
import sys
from pathlib import Path
root=Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parent))
folder=root/'.browser-bundle'
if folder.is_dir():
    os.environ['PLAYWRIGHT_BROWSERS_PATH']=str(folder)
