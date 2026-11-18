"""Account sessions and manual-protocol secrets for VPN Config Downloader.

A browser *profile* is a persistent local Chromium profile. This retains login
cookies while they are valid; it is NOT guaranteed encrypted at rest, so protect
your OS user account and disk. The application does not capture account passwords.

OpenVPN service credentials, if the user enters them, are kept by the OS keyring;
there is deliberately no plaintext fallback or export by default.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

PROVIDER_URLS = {
    'windscribe': 'https://windscribe.com/myaccount/config-generator',
    'surfshark': 'https://my.surfshark.com/vpn/manual-setup/main',
    'proton': 'https://account.protonvpn.com/downloads',
}
WIREGUARD_REGISTRATION_URLS = {
    'windscribe': 'https://windscribe.com/myaccount/config-generator#wireguard',
    'surfshark': 'https://my.surfshark.com/vpn/manual-setup/main/wireguard',
    'proton': 'https://account.protonvpn.com/downloads#wireguard-configuration',
}
# Keep legacy storage identifiers so the product rename preserves saved accounts.
SERVICE_ID = 'MultiVPN-Config-Manager.ProtocolVault-v4'
LEGACY_SERVICE_ID = 'MultiVPN-Config-Manager.OpenVPN-v3'


def state_root() -> Path:
    explicit = os.environ.get('MULTIVPN_STATE_DIR', '').strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    if os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))
    elif os.uname().sysname == 'Darwin':
        base = Path.home() / 'Library' / 'Application Support'
    else:
        base = Path(os.environ.get('XDG_DATA_HOME') or (Path.home() / '.local' / 'share'))
    return base / 'MultiVPN-Config-Manager'


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        if os.name != 'nt':
            os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def profile_dir(provider: str, *, base: Path | None = None, create: bool = False, account: str = 'default') -> Path:
    if provider not in PROVIDER_URLS:
        raise ValueError('Unknown VPN provider')
    from .account_registry import validate_account
    validate_account(provider, account)
    root = Path(base) if base is not None else state_root()
    path = root / 'browser_profiles' / (provider if account == 'default' else provider+'--'+account)
    if create:
        _private_dir(root)
        _private_dir(root / 'browser_profiles')
        _private_dir(path)
    return path


def harden_profile_tree(path: Path) -> None:
    """Restrict existing Chromium profile files to the current Unix user.

    This is permissions hardening, NOT cryptographic encryption. Skip symlinks.
    Windows ACLs are managed by the OS/browser, not chmod here.
    """
    if os.name == 'nt' or not path.is_dir() or path.is_symlink():
        return
    for directory, dirs, files in os.walk(path, followlinks=False):
        for filename in files:
            file = Path(directory) / filename
            try:
                if not file.is_symlink():
                    file.chmod(0o600)
            except OSError:
                pass
        for sub in dirs:
            folder = Path(directory) / sub
            try:
                if not folder.is_symlink():
                    folder.chmod(0o700)
            except OSError:
                pass
        try:
            Path(directory).chmod(0o700)
        except OSError:
            pass


def has_session_profile(provider: str, *, base: Path | None = None, account: str = 'default') -> bool:
    p = profile_dir(provider, base=base, account=account)
    # This proves browser state was written, NOT that the account is authenticated.
    return p.is_dir() and any((p / marker).exists() for marker in ('Local State', 'Default', 'Profile 1'))


def forget_profile(provider: str, *, base: Path | None = None, account: str = 'default') -> None:
    p = profile_dir(provider, base=base, account=account)
    if p.is_symlink():
        raise ValueError('Refusing to delete a symbolic-link profile')
    if p.exists():
        shutil.rmtree(p)


def _system_chromium_candidates() -> list[dict]:
    """Return fallback Playwright launch kwargs for already-installed system Chrome/Edge/Chromium."""
    candidates: list[dict] = []
    # Prefer official Playwright channels first (works cross-platform on Windows/Linux/macOS)
    if shutil.which('google-chrome') or shutil.which('google-chrome-stable') or os.name == 'nt':
        candidates.append({'channel': 'chrome'})
    if os.name == 'nt' or shutil.which('microsoft-edge'):
        candidates.append({'channel': 'msedge'})
    for binary in ('google-chrome-stable', 'google-chrome', 'chromium', 'chromium-browser', 'brave-browser'):
        exe = shutil.which(binary)
        if exe:
            candidates.append({'executable_path': exe})
    return candidates


def launch_browser_context(pw, path: Path, *, headless: bool = False, accept_downloads: bool = True):
    """Launch a persistent Chromium context compatible with native desktop browser profiles.

    On real Playwright runs, prefers system Chrome/Edge WITHOUT Playwright's
    `--password-store=basic` / `--use-mock-keychain` overrides so cookies encrypted
    by the user's native browser during manual login (GNOME Keyring / macOS Keychain
    / Windows DPAPI) remain readable. Falls back cleanly to Playwright's bundled
    Chromium if no system browser is available.
    """
    base_kwargs = {'headless': headless, 'accept_downloads': accept_downloads}
    is_real_pw = type(pw).__module__.startswith('playwright.')

    if is_real_pw:
        native_kwargs = {
            **base_kwargs,
            'ignore_default_args': ['--password-store=basic', '--use-mock-keychain'],
        }
        last_exc: Exception | None = None
        for extra in _system_chromium_candidates():
            try:
                return pw.chromium.launch_persistent_context(str(path), **native_kwargs, **extra)
            except Exception as exc:
                last_exc = exc
        try:
            return pw.chromium.launch_persistent_context(str(path), **base_kwargs)
        except Exception as fallback_exc:
            raise RuntimeError(
                'Chromium browser is not installed for Playwright and no usable system Chrome/Edge/Chromium was found. '
                'Run ./install_browser_linux.sh (or install_browser_windows.bat) to download Chromium.'
            ) from (last_exc or fallback_exc)

    try:
        return pw.chromium.launch_persistent_context(str(path), **base_kwargs)
    except Exception as primary_exc:
        msg = str(primary_exc)
        missing_browser = any(
            hint in msg.lower()
            for hint in ("executable doesn't exist", 'please run the following command', 'playwright install', 'no such file')
        )
        if not missing_browser:
            raise
        last_exc = primary_exc
        for extra in _system_chromium_candidates():
            try:
                return pw.chromium.launch_persistent_context(str(path), **base_kwargs, **extra)
            except Exception as fallback_exc:
                last_exc = fallback_exc
        raise RuntimeError(
            'Chromium browser is not installed for Playwright and no usable system Chrome/Edge/Chromium was found. '
            'Run ./install_browser_linux.sh (or install_browser_windows.bat) to download Chromium.'
        ) from last_exc


def _find_native_browser() -> str | None:
    """Locate the user's unmodified desktop Chrome/Edge/Chromium binary for interactive manual login."""
    if os.name == 'nt':
        candidates = [
            Path(os.environ.get('PROGRAMFILES', r'C:\Program Files')) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe',
            Path(os.environ.get('PROGRAMFILES(X86)', r'C:\Program Files (x86)')) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe',
            Path(os.environ.get('LOCALAPPDATA', '')) / 'Google' / 'Chrome' / 'Application' / 'chrome.exe',
            Path(os.environ.get('PROGRAMFILES(X86)', r'C:\Program Files (x86)')) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe',
            Path(os.environ.get('PROGRAMFILES', r'C:\Program Files')) / 'Microsoft' / 'Edge' / 'Application' / 'msedge.exe',
        ]
        for cand in candidates:
            if cand.is_file():
                return str(cand)
        return shutil.which('chrome') or shutil.which('msedge')
    for name in ('google-chrome-stable', 'google-chrome', 'microsoft-edge', 'chromium', 'chromium-browser', 'brave-browser'):
        found = shutil.which(name)
        if found:
            return found
    return None


def _manual_login_native_browser(
    browser_exe: str,
    provider: str,
    path: Path,
    *,
    stop=None,
    emit=None,
    max_seconds: int = 900,
) -> str:
    """Open the user's real unmodified desktop browser with an isolated --user-data-dir.

    No automation driver, no DOM manipulation, and no spoofing: the user completes
    sign-in, CAPTCHA, and 2FA directly in their own normal browser window.
    """
    send = emit or (lambda s: None)
    cmd = [
        browser_exe,
        f'--user-data-dir={path}',
        '--no-first-run',
        '--no-default-browser-check',
        PROVIDER_URLS[provider],
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if provider == 'proton':
        send('Your regular browser is open for Proton. IMPORTANT: check "Keep me signed in" before logging in, then close the browser window when done.')
    else:
        send('Your regular browser is open with an isolated profile. Complete sign-in/2FA, then close that browser window.')
    deadline = time.monotonic() + max_seconds
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if stop is not None and stop.is_set():
                send('Session browser closed by user.')
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                break
            time.sleep(0.4)
    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:
                pass
        harden_profile_tree(path)
    return 'Browser profile saved locally (authentication not verified).'


def manual_login(provider: str, *, stop=None, emit=None, max_seconds: int = 900,
                 playwright_factory=None, account: str = 'default') -> str:
    """Open the official page in a persisted browser; user completes sign in.

    Prefers launching the user's unmodified desktop browser with an isolated
    user-data-dir (since manual sign-in requires no browser automation). Falls
    back to Playwright if no system browser is installed or when a custom factory
    is supplied.
    """
    if provider not in PROVIDER_URLS:
        raise ValueError('Unknown VPN provider')
    path = profile_dir(provider, create=True, account=account)
    if playwright_factory is None:
        native = _find_native_browser()
        if native:
            return _manual_login_native_browser(
                native, provider, path, stop=stop, emit=emit, max_seconds=max_seconds
            )
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError('Playwright is required; run install_browser_linux.sh / .bat') from exc
        playwright_factory = sync_playwright
    send = emit or (lambda s: None)
    with playwright_factory() as pw:
        try:
            context = launch_browser_context(pw, path, headless=False, accept_downloads=True)
        except Exception as exc:
            detail = str(exc).splitlines()[0][:180]
            raise RuntimeError(f'Cannot launch browser: {detail}') from exc
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(PROVIDER_URLS[provider], wait_until='domcontentloaded', timeout=45000)
            send('The official sign-in page is open. Complete any 2FA, then close this browser window.')
            deadline = time.monotonic() + max_seconds
            while time.monotonic() < deadline:
                if stop is not None and stop.is_set():
                    send('Session browser was closed by the user.')
                    break
                try:
                    if not any(not x.is_closed() for x in context.pages):
                        break
                except Exception:
                    break
                try:
                    page.wait_for_timeout(450)
                except Exception:
                    break
            return 'Browser profile saved locally (authentication not verified).'
        finally:
            try:
                context.close()
            except Exception:
                pass
            harden_profile_tree(path)


def windscribe_cookie(*, base: Path | None = None, playwright_factory=None, account: str = 'default') -> str:
    """Read only the existing Windscribe website session token; never log it.

    Checks both browser cookies and Windscribe's 2026 localStorage key
    (`ws_session_auth_hash`). Caller must handle an expired session.
    """
    if not has_session_profile('windscribe', base=base, account=account):
        return ''
    if playwright_factory is None:
        from playwright.sync_api import sync_playwright
        playwright_factory = sync_playwright
    path = profile_dir('windscribe', base=base, account=account)
    with playwright_factory() as pw:
        context = launch_browser_context(pw, path, headless=True, accept_downloads=False)
        try:
            for item in context.cookies('https://windscribe.com'):
                if item.get('name') == 'ws_session_auth_hash' and item.get('value'):
                    token = str(item['value']).strip()
                    if re.fullmatch(r'[^;\s\r\n]+', token):
                        return token
            # Windscribe 2026 also stores ws_session_auth_hash in localStorage.
            try:
                page = context.pages[0] if context.pages else context.new_page()
                if hasattr(page, 'evaluate'):
                    page.goto('https://windscribe.com/myaccount/config-generator', wait_until='domcontentloaded', timeout=15000)
                    token = page.evaluate('() => window.localStorage.getItem("ws_session_auth_hash") || ""')
                    if isinstance(token, str):
                        token = token.strip()
                        if token and re.fullmatch(r'[^;\s\r\n]+', token):
                            return token
            except Exception:
                pass
            return ''
        finally:
            context.close()
            harden_profile_tree(path)


class VaultUnavailable(RuntimeError):
    pass


class ProtocolVault:
    """OS keyring for user-provided OpenVPN service credentials only.

    There is no file-based / obscured / base64 fallback: a keyring error means
    the caller must explicitly keep credentials in memory or install a backend.
    """
    def __init__(self, backend=None):
        self._backend = backend

    def _keyring(self):
        if self._backend is not None:
            return self._backend
        try:
            import keyring
            from keyring.errors import KeyringError, NoKeyringError
        except ImportError as exc:
            raise VaultUnavailable('Install the keyring package to save protocol credentials.') from exc
        try:
            backend = keyring.get_keyring()
            if getattr(backend, 'priority', 0) <= 0:
                raise VaultUnavailable('No secure OS keyring is available. Configure Secret Service / Windows Credential Manager.')
            return keyring
        except VaultUnavailable:
            raise
        except Exception as exc:
            raise VaultUnavailable('Secure OS keyring is unavailable.') from exc

    @staticmethod
    def _keys(provider: str, account: str = 'default'):
        if provider not in PROVIDER_URLS:
            raise ValueError('Unknown VPN provider')
        from .account_registry import validate_account
        validate_account(provider, account)
        return f'{provider}:{account}:openvpn:username', f'{provider}:{account}:openvpn:password'

    def put_openvpn(self, provider: str, username: str, password: str, account: str = 'default') -> None:
        if not username or not password or any(c in username+password for c in '\r\n\x00'):
            raise ValueError('OpenVPN username and password must be nonempty single lines.')
        u, p = self._keys(provider, account)
        backend = self._keyring()
        try:
            backend.set_password(SERVICE_ID, u, username)
            backend.set_password(SERVICE_ID, p, password)
        except Exception as exc:
            raise VaultUnavailable('Could not save credentials to the secure OS keyring.') from exc

    def get_openvpn(self, provider: str, account: str = 'default') -> tuple[str, str] | None:
        u, p = self._keys(provider, account)
        backend = self._keyring()
        try:
            username = backend.get_password(SERVICE_ID, u)
            password = backend.get_password(SERVICE_ID, p)
            if account == 'default' and not (username and password):
                # Read old v3 secrets without silently copying them into v4.
                username = backend.get_password(LEGACY_SERVICE_ID, f'{provider}:openvpn:username')
                password = backend.get_password(LEGACY_SERVICE_ID, f'{provider}:openvpn:password')
        except Exception as exc:
            raise VaultUnavailable('Could not read the secure OS keyring.') from exc
        return (username, password) if username and password else None

    def delete_openvpn(self, provider: str, account: str = 'default') -> None:
        u, p = self._keys(provider, account)
        backend = self._keyring()
        for key in (u, p):
            try:
                backend.delete_password(SERVICE_ID, key)
            except Exception:
                pass
        if account == 'default':
            for key in (f'{provider}:openvpn:username', f'{provider}:openvpn:password'):
                try: backend.delete_password(LEGACY_SERVICE_ID,key)
                except Exception:pass

    def put_wireguard(self, provider: str, private_key: str, account: str = 'default') -> str:
        """Store *user's provider-registered* WireGuard private key in keyring."""
        from .account_registry import validate_account
        from .security import public_from_private
        validate_account(provider,account)
        public = public_from_private(private_key)
        try:
            self._keyring().set_password(SERVICE_ID, f'{provider}:{account}:wireguard:private',private_key.strip())
        except Exception as exc:
            raise VaultUnavailable('Could not save WireGuard key in OS keyring.') from exc
        return public

    def get_wireguard(self, provider: str, account: str = 'default') -> str | None:
        from .account_registry import validate_account
        validate_account(provider,account)
        try:
            return self._keyring().get_password(SERVICE_ID,f'{provider}:{account}:wireguard:private')
        except Exception as exc:
            raise VaultUnavailable('Could not read WireGuard key from OS keyring.') from exc

    def delete_wireguard(self, provider: str, account: str = 'default') -> None:
        from .account_registry import validate_account
        validate_account(provider, account)
        try:
            self._keyring().delete_password(SERVICE_ID, f'{provider}:{account}:wireguard:private')
        except Exception:
            pass

    def put_session_token(self, provider: str, token: str, account: str = 'default') -> None:
        """Persist a provider session token securely in OS keyring (never plaintext on disk)."""
        from .account_registry import validate_account
        validate_account(provider, account)
        clean = token.strip()
        if not clean or any(c in clean for c in '\r\n;\x00 '):
            raise ValueError('Session token must be a non-empty single token without spaces or semicolons.')
        try:
            self._keyring().set_password(SERVICE_ID, f'{provider}:{account}:session:token', clean)
        except Exception as exc:
            raise VaultUnavailable('Could not save session token in OS keyring.') from exc

    def get_session_token(self, provider: str, account: str = 'default') -> str | None:
        from .account_registry import validate_account
        validate_account(provider, account)
        try:
            return self._keyring().get_password(SERVICE_ID, f'{provider}:{account}:session:token')
        except Exception as exc:
            raise VaultUnavailable('Could not read session token from OS keyring.') from exc

    def delete_session_token(self, provider: str, account: str = 'default') -> None:
        from .account_registry import validate_account
        validate_account(provider, account)
        try:
            self._keyring().delete_password(SERVICE_ID, f'{provider}:{account}:session:token')
        except Exception:
            pass
