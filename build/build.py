"""Native one-directory installer build for the CURRENT operating system.

Usage:
    python build/build.py                       # Full bundle including Chromium
    python build/build.py --skip-browser-bundle # Lean build (uses user Playwright Chromium cache)

Requires Python 3.11+ and runtime + build dependencies.
PyInstaller is NOT a cross-compiler: run on Windows for Windows .exe and on Linux for Linux ELF.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BROWSERS = ROOT / '.browser-bundle'

# Exclude unused heavy Qt subsystems (~250 MB savings)
EXCLUDED_MODULES = [
    'PySide6.QtWebEngineCore',
    'PySide6.QtWebEngineWidgets',
    'PySide6.QtWebEngineQuick',
    'PySide6.QtQuick',
    'PySide6.QtQml',
    'PySide6.Qt3DCore',
    'PySide6.Qt3DRender',
    'PySide6.QtMultimedia',
    'PySide6.QtMultimediaWidgets',
    'PySide6.QtPdf',
    'PySide6.QtPdfWidgets',
    'PySide6.QtCharts',
    'PySide6.QtDataVisualization',
    'PySide6.QtBluetooth',
    'PySide6.QtPositioning',
    'PySide6.QtSensors',
    'PySide6.QtSerialPort',
]


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description='Build native VPN Config Downloader package.')
    parser.add_argument(
        '--skip-browser-bundle',
        action='store_true',
        help='Build without embedding Chromium inside dist/ (uses Playwright cache at runtime).',
    )
    args = parser.parse_args(argv)

    if sys.version_info < (3, 11):
        raise SystemExit('Python 3.11+ required.')
    if os.name != 'nt' and not sysconfig.get_config_var('Py_ENABLE_SHARED'):
        raise SystemExit(
            'PyInstaller on Linux/macOS requires a Python built with --enable-shared (libpython*.so). '
            'Use the system /usr/bin/python3 (or a shared Python build).'
        )
    try:
        import PyInstaller.__main__
    except ImportError:
        raise SystemExit('Install build requirements: pip install -r requirements-build.txt')
    try:
        import PySide6, playwright, keyring, pyzipper, cryptography  # noqa: F401
    except ImportError:
        raise SystemExit('Install runtime requirements first: pip install -r requirements.txt')

    bundle_browser = not args.skip_browser_bundle
    if bundle_browser:
        env = os.environ.copy()
        env['PLAYWRIGHT_BROWSERS_PATH'] = str(BROWSERS)
        if not (BROWSERS.is_dir() and any(BROWSERS.iterdir())):
            print('Installing bundled Chromium into', BROWSERS)
            subprocess.run([sys.executable, '-m', 'playwright', 'install', 'chromium'], check=True, env=env, cwd=ROOT)
        else:
            print('Reusing existing Chromium bundle in', BROWSERS)
        if not BROWSERS.is_dir() or not any(BROWSERS.iterdir()):
            raise SystemExit('Chromium bundle missing; cannot build a browser-bundled app.')

    os.chdir(ROOT)
    separator = ';' if os.name == 'nt' else ':'
    pyinstaller_args = [
        '--noconfirm',
        '--clean',
        '--onedir',
        '--windowed',
        '--name', 'VPNConfigDownloader',
        '--collect-submodules', 'app',
        '--collect-all', 'playwright',
        '--collect-all', 'keyring',
        '--collect-all', 'pyzipper',
        '--hidden-import', 'cryptography.hazmat.primitives.asymmetric.x25519',
        '--hidden-import', 'keyring.backends.SecretService',
        '--hidden-import', 'keyring.backends.Windows',
        '--runtime-hook', str(ROOT / 'build' / 'runtime_browser.py'),
    ]
    for mod in EXCLUDED_MODULES:
        pyinstaller_args.extend(['--exclude-module', mod])
    if bundle_browser:
        pyinstaller_args.extend(['--add-data', str(BROWSERS) + separator + '.browser-bundle'])
    pyinstaller_args.append(str(ROOT / 'run.py'))

    PyInstaller.__main__.run(pyinstaller_args)
    exe_name = 'VPNConfigDownloader.exe' if os.name == 'nt' else 'VPNConfigDownloader'
    built_exe = ROOT / 'dist' / 'VPNConfigDownloader' / exe_name
    if not built_exe.is_file():
        raise SystemExit(f'Expected executable was not produced: {built_exe}')
    print(f'Generated native package: {built_exe.parent} (executable: {built_exe.name})')


if __name__ == '__main__':
    main()
