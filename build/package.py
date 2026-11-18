"""Package a native PyInstaller build, including Chromium and file permissions."""
from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def package_application(application: Path, output: Path, *, version: str,
                        system: str, architecture: str) -> Path:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}', version):
        raise ValueError('Version must contain only letters, numbers, dots, underscores and hyphens.')
    if system not in ('Linux', 'Windows'):
        raise ValueError('Native packages are supported on Linux and Windows.')
    architecture = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(architecture.lower(), architecture.lower())
    if architecture not in ('x86_64', 'aarch64'):
        raise ValueError('Unsupported package architecture.')
    executable = application / ('VPNConfigDownloader.exe' if system == 'Windows' else 'VPNConfigDownloader')
    if not executable.is_file():
        raise FileNotFoundError('Build the native application before packaging.')
    if system == 'Linux' and not os.access(executable, os.X_OK):
        raise ValueError('Linux application is missing executable permissions.')
    browser_name = 'chrome.exe' if system == 'Windows' else 'chrome'
    browser_root = application / '_internal' / '.browser-bundle'
    browsers = [p for p in browser_root.rglob(browser_name) if p.is_file()]
    if not browsers:
        raise ValueError('Release packages require bundled Chromium. Build without --skip-browser-bundle.')

    shutil.copy2(ROOT / 'LICENSE', application / 'LICENSE.txt')
    shutil.copy2(ROOT / 'KNOWN_ISSUES.md', application / 'KNOWN_ISSUES.md')
    output.mkdir(parents=True, exist_ok=True)
    prefix = output / f'VPNConfigDownloader-{version}-{system.lower()}-{architecture}'
    archive = Path(shutil.make_archive(str(prefix), 'zip' if system == 'Windows' else 'gztar',
                                      root_dir=application.parent, base_dir=application.name))
    executable_member = f'{application.name}/{executable.name}'
    browser_members = {f'{application.name}/{p.relative_to(application).as_posix()}' for p in browsers}
    if system == 'Windows':
        with zipfile.ZipFile(archive) as packed:
            names = set(packed.namelist())
            if executable_member not in names or not browser_members.issubset(names):
                raise ValueError('Release ZIP is missing the application or bundled Chromium.')
    else:
        with tarfile.open(archive, 'r:gz') as packed:
            names = set(packed.getnames())
            if executable_member not in names or not browser_members.issubset(names):
                raise ValueError('Release archive is missing the application or bundled Chromium.')
            if not packed.getmember(executable_member).mode & 0o111:
                raise ValueError('Release archive lost Linux executable permissions.')
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description='Package VPN Config Downloader with its bundled browser.')
    parser.add_argument('--version', default='snapshot', help='Version label, e.g. v4.1.0-beta.1')
    args = parser.parse_args()
    archive = package_application(ROOT / 'dist' / 'VPNConfigDownloader', ROOT / 'release',
                                  version=args.version, system=platform.system(), architecture=platform.machine())
    print(f'Verified release package: {archive}')


if __name__ == '__main__':
    main()
