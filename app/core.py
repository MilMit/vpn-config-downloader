"""Provider-independent metadata, validation and secret-safe file management."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile

from .security import safe_zip_entries

PROTOCOLS = ('wireguard', 'udp', 'tcp', 'ikev2', 'stealth', 'wstunnel')

# Standardized user-facing capability statuses required across providers & UI.
CAPABILITY_STATUS_MAP = {
    'direct': 'Supported',
    'supported': 'Supported',
    'browser': 'Requires Manual Action',
    'import': 'Requires Manual Action',
    'manual': 'Requires Manual Action',
    'experimental': 'Experimental',
    'unsupported': 'Unsupported',
}


@dataclass(frozen=True)
class Location:
    key: str
    country: str
    name: str
    tier: str = 'unknown'
    extras: dict = field(default_factory=dict)

    @property
    def city(self) -> str:
        c = self.extras.get('city') or self.extras.get('location') or ''
        if c:
            return str(c)
        if ' - ' in self.name:
            return self.name.split(' - ', 1)[0].strip()
        return self.name


@dataclass(frozen=True)
class Capability:
    protocol: str
    level: str  # 'direct', 'browser', 'import', 'experimental', 'unsupported'
    explanation: str

    @property
    def status(self) -> str:
        """Human-readable status: Supported | Requires Manual Action | Experimental | Unsupported."""
        return CAPABILITY_STATUS_MAP.get(self.level.lower(), 'Unsupported')


@dataclass
class Credentials:
    website_cookie: str = ''
    wireguard_public_key: str = ''
    wireguard_private_key_file: str = ''
    wireguard_private_key_data: str = ''
    ikev2_credentials_file: str = ''
    ikev2_auth_hash: str = ''
    ikev2_hostnames_file: str = ''
    transport_endpoints_file: str = ''


@dataclass
class Options:
    output: str
    protocols: list[str]
    ports: dict[str, list[str]] = field(default_factory=lambda: {'udp': ['443'], 'tcp': ['54783'], 'wireguard': ['65142']})
    delay: float = 3.0
    timeout: int = 25
    retries: int = 2
    overwrite: bool = False
    archive: bool = True
    browser_limit: int = 60  # per-run safety cap for account-only downloads
    account: str = 'default'
    concurrency: int = 2
    selected_keys: list[str] = field(default_factory=list)


@dataclass
class Event:
    kind: str
    message: str
    current: int = 0
    total: int = 0


def safe_filename(text: str) -> str:
    v = re.sub(r'[^a-zA-Z0-9._-]+', '-', str(text)).strip('._-')
    return v[:100] or 'unknown'


def valid_profile(protocol: str, content: bytes | str) -> bool:
    # Reject unexpected HTML/login pages and binaries even if they include keywords.
    try:
        s = content.decode('utf-8') if isinstance(content, bytes) else content
    except UnicodeDecodeError:
        return False
    if len(s) < 30 or len(s) > 2_000_000 or '\x00' in s:
        return False
    low = s.lower()
    if '<html' in low or '<!doctype' in low:
        return False
    if protocol == 'wireguard':
        return ('[Interface]' in s and '[Peer]' in s and
                bool(re.search(r'(?mi)^\s*Endpoint\s*=\s*\S+', s)) and
                bool(re.search(r'(?mi)^\s*PublicKey\s*=\s*\S+', s)))
    if protocol in ('tcp', 'udp', 'openvpn'):
        return (bool(re.search(r'(?mi)^\s*(client|tls-client)\s*$', s)) and
                bool(re.search(r'(?mi)^\s*remote\s+\S+', s)))
    return False


def profile_kind(name: str, content: bytes) -> str | None:
    ext = Path(name).suffix.lower()
    if ext == '.conf' and valid_profile('wireguard', content):
        return 'wireguard'
    if ext == '.ovpn' and valid_profile('openvpn', content):
        s = content.decode('utf-8').lower()
        if re.search(r'(?mi)^\s*proto\s+(tcp|tcp-client|tcp4|tcp6)\b', s):
            return 'tcp'
        if re.search(r'(?mi)^\s*proto\s+(udp|udp4|udp6)\b', s):
            return 'udp'
        return 'openvpn'
    return None


def extract_server_metadata(name: str, content: bytes | str) -> dict:
    """Extract non-secret country/city/server hints from a profile name or endpoint."""
    stem = Path(name).stem
    country = ''
    city = ''
    server = ''
    # Surfshark style: us-nyc.prod.surfshark.com_udp or al-tia.prod.surfshark.com_tcp
    m_ss = re.match(r'^([a-z]{2})-([a-z0-9]+)\.prod\.surfshark\.com', stem, re.I)
    if m_ss:
        country = m_ss.group(1).upper()
        city = m_ss.group(2).upper()
        server = f'{m_ss.group(1).lower()}-{m_ss.group(2).lower()}.prod.surfshark.com'
    else:
        # Proton style: nl-free-01.protonvpn.udp or US-CA#12
        m_pr = re.match(r'^([a-z]{2})[-_]([a-z0-9-]+)', stem, re.I)
        if m_pr:
            country = m_pr.group(1).upper()
            city = m_pr.group(2)
    try:
        text = content.decode('utf-8') if isinstance(content, bytes) else content
        if not server:
            m_rem = re.search(r'(?mi)^\s*remote\s+(\S+)', text)
            if m_rem:
                server = m_rem.group(1)
            else:
                m_ep = re.search(r'(?mi)^\s*Endpoint\s*=\s*([^\s:]+)', text)
                if m_ep:
                    server = m_ep.group(1)
    except Exception:
        pass
    return {'country': country or 'General', 'city': city or '', 'server': server}


def safe_store(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if os.name != 'nt':
            os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = data.encode('utf-8') if isinstance(data, str) else data
    # Atomic replace avoids half-written configs on interruption.
    fd, tmp = tempfile.mkstemp(prefix='.part-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(payload)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        try:
            if os.name != 'nt':
                os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_report(root: Path, payload: dict) -> Path:
    dest = root / 'report.json'
    safe_store(dest, json.dumps(payload, ensure_ascii=False, indent=2))
    return dest


def export_archive(root: Path) -> Path:
    """Create an unencrypted ZIP; callers must warn about private keys."""
    root = root.resolve()
    out = root.parent / (root.name + '.zip')
    fd, tmp = tempfile.mkstemp(prefix='.zip-tmp-', dir=str(root.parent))
    try:
        with os.fdopen(fd, 'wb') as buffer:
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
                for p in sorted(root.rglob('*')):
                    if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root):
                        z.write(p, p.relative_to(root.parent))
        try:
            if os.name != 'nt':
                os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return out


def file_entries(path: Path):
    """Yield (display_name, bytes) from folder or ZIP, with ZIP-bomb & traversal controls."""
    if path.is_dir():
        for p in sorted(path.rglob('*')):
            if p.is_symlink() or not p.is_file() or p.suffix.lower() not in ('.conf', '.ovpn'):
                continue
            if p.stat().st_size > 2_000_000:
                continue
            yield str(p.relative_to(path)), p.read_bytes()
    elif path.is_file() and path.suffix.lower() == '.zip':
        yield from safe_zip_entries(path, allowed_suffixes=('.conf', '.ovpn'))
    elif path.is_file() and path.suffix.lower() in ('.conf', '.ovpn') and path.stat().st_size <= 2_000_000:
        yield path.name, path.read_bytes()
    else:
        raise ValueError('Choose a folder, .zip archive, or .conf/.ovpn file.')


def import_profiles(source: Path, output: Path, *, on_progress: Callable[[Event], None], stop=None, pause=None) -> dict:
    """Import only valid OpenVPN/WireGuard from user-owned files."""
    if not source.exists():
        raise FileNotFoundError(str(source))
    records = []
    count = 0
    skipped = 0
    hashes = set()
    if source.is_dir():
        # Snapshot only file paths; don't load every profile into RAM.
        total = sum(1 for p in source.rglob('*')
                    if p.is_file() and p.suffix.lower() in ('.conf', '.ovpn')
                    and not p.is_symlink() and p.stat().st_size <= 2_000_000)
    elif source.suffix.lower() == '.zip':
        with zipfile.ZipFile(source) as z:
            total = sum(1 for x in z.infolist()
                        if not x.is_dir() and 30 <= x.file_size <= 2_000_000
                        and Path(x.filename).suffix.lower() in ('.conf', '.ovpn'))
    else:
        total = 1
    if total > 5000:
        raise ValueError('Input has more than 5000 profiles; split into smaller batches.')
    for i, (display_name, content) in enumerate(file_entries(source), 1):
        if stop is not None and stop.is_set():
            break
        if pause is not None:
            while not pause.wait(.2):
                if stop is not None and stop.is_set():
                    break
        kind = profile_kind(display_name, content)
        digest = hashlib.sha256(content).hexdigest()
        if not kind or digest in hashes:
            skipped += 1
            on_progress(Event('skip', f'Skipped invalid/duplicate: {display_name}', i, total))
            continue
        hashes.add(digest)
        ext = '.conf' if kind == 'wireguard' else '.ovpn'
        name = safe_filename(Path(display_name).stem) + '-' + digest[:8] + ext
        dst = output / ('WireGuard' if kind == 'wireguard' else 'OpenVPN-' + kind.upper()) / name
        status = 'reused' if dst.is_file() and dst.read_bytes() == content else 'imported'
        if status == 'imported':
            safe_store(dst, content)
        records.append({'source': display_name, 'status': status, 'protocol': kind, 'file': str(dst.relative_to(output))})
        if status == 'imported':
            count += 1
        on_progress(Event('success', f'{status}: {safe_filename(display_name)} → {kind}', i, total))
    return {'imported': count, 'skipped': skipped, 'records': records, 'scanned': total}


def provider_output_dir(options: Options, provider: str) -> Path:
    """Separate outputs by account; keep historical default output path."""
    from .account_registry import validate_account
    validate_account(provider, options.account)
    leaf = provider if options.account == 'default' else f'{provider}--{options.account}'
    return Path(options.output).expanduser().resolve() / leaf
