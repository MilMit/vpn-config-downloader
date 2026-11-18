"""AES-256 encrypted ZIP output, secure profile key management, ZIP safety and secret redaction.

Password-based encrypted ZIP uses pyzipper AESZipFile, NOT legacy ZipCrypto.
Encryption protects only the ZIP; plain staging files may exist until removed.
"""
from __future__ import annotations

import base64
import io
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable

DEFAULT_MAX_ZIP_ENTRIES = 6000
DEFAULT_MAX_ZIP_TOTAL_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_ZIP_ENTRY_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 100.0

_SECRET_PATTERNS = (
    (re.compile(r'(?mi)(^\s*PrivateKey\s*=\s*)(\S+)'), r'\1[REDACTED]'),
    (re.compile(r'(?mi)(^\s*PresharedKey\s*=\s*)(\S+)'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(ws_session_auth_hash\s*=\s*)([^;\s\r\n]+)'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(Authorization\s*:\s*(?:Bearer\s+)?)([^\r\n]+)'), r'\1[REDACTED]'),
    (re.compile(r'(?s)(<key>)(.*?)(</key>)'), r'\1\n[REDACTED]\n\3'),
    (re.compile(r'(?s)(<tls-auth>)(.*?)(</tls-auth>)'), r'\1\n[REDACTED]\n\3'),
    (re.compile(r'(?s)(<tls-crypt>)(.*?)(</tls-crypt>)'), r'\1\n[REDACTED]\n\3'),
    (re.compile(r'(?mi)(^\s*secret\s*=\s*")([^"]*)(")'), r'\1[REDACTED]\3'),
)


def redact_secrets(text: str, secrets: Iterable[str] = ()) -> str:
    """Remove known secret patterns and runtime secret tokens from logs/reports."""
    if not text:
        return ''
    out = str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, '[REDACTED]')
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def make_keypair() -> tuple[str, str]:
    """Generate valid X25519 WireGuard private/public raw keys in base64."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    private = X25519PrivateKey.generate()
    priv = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def public_from_private(private_key: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    try:
        raw = base64.b64decode(private_key.strip(), validate=True)
    except Exception as exc:
        raise ValueError('WireGuard private key is not base64') from exc
    if len(raw) != 32:
        raise ValueError('WireGuard private key must be 32 bytes')
    key = X25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def is_valid_wireguard_key(key: str) -> bool:
    """Return True if key is a valid 32-byte base64 WireGuard key."""
    if not isinstance(key, str) or not key.strip():
        return False
    try:
        raw = base64.b64decode(key.strip(), validate=True)
        return len(raw) == 32
    except Exception:
        return False


def verify_wireguard_key_match(config_text: str, expected_private_key: str) -> dict:
    """Verify whether a WireGuard .conf's PrivateKey matches expected_private_key.

    Never returns raw private keys.
    """
    expected_pub = public_from_private(expected_private_key)
    match = re.search(r'(?mi)^\s*PrivateKey\s*=\s*(\S+)\s*$', config_text)
    if not match:
        return {
            'has_private_key': False,
            'matches': False,
            'expected_public_key': expected_pub,
            'config_public_key': None,
            'status': 'missing_private_key',
        }
    found = match.group(1).strip()
    if not is_valid_wireguard_key(found):
        return {
            'has_private_key': True,
            'matches': False,
            'expected_public_key': expected_pub,
            'config_public_key': None,
            'status': 'invalid_private_key',
        }
    found_pub = public_from_private(found)
    matched = found_pub == expected_pub
    return {
        'has_private_key': True,
        'matches': matched,
        'expected_public_key': expected_pub,
        'config_public_key': found_pub,
        'status': 'matched' if matched else 'mismatch',
    }


def is_safe_zip_member_name(name: str) -> bool:
    """Reject Unix/Windows path traversal, absolute paths, drive letters, and null bytes."""
    if not name or '\x00' in name:
        return False
    normalized = name.replace('\\', '/')
    if normalized.startswith('/') or normalized.startswith('~'):
        return False
    # Reject Windows drive letters like C:/foo or C:foo
    if re.match(r'^[A-Za-z]:', normalized):
        return False
    parts = [p for p in normalized.split('/') if p]
    if not parts or any(p in ('..', '.') for p in parts):
        return False
    return True


def safe_zip_entries(
    source: Path | bytes,
    *,
    allowed_suffixes: tuple[str, ...] = ('.conf', '.ovpn'),
    max_entries: int = DEFAULT_MAX_ZIP_ENTRIES,
    max_total_size: int = DEFAULT_MAX_ZIP_TOTAL_BYTES,
    max_entry_size: int = DEFAULT_MAX_ZIP_ENTRY_BYTES,
    min_entry_size: int = 30,
    max_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
):
    """Yield (member_name, data) safely from a ZIP path or bytes with ZIP-bomb & traversal defenses.

    Raises ValueError on archive-level attacks (too many entries, expanded size bomb, high ratio).
    Skips unsafe individual entries (traversal, symlinks, disallowed extensions).
    """
    handle = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
    with zipfile.ZipFile(handle, 'r') as z:
        infos = z.infolist()
        if len(infos) > max_entries:
            raise ValueError(f'Archive exceeds maximum entry limit ({max_entries}).')
        declared_total = sum(max(0, i.file_size) for i in infos)
        if declared_total > max_total_size:
            raise ValueError('Archive exceeds expanded-size safety limit (possible ZIP bomb).')
        actual_total = 0
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:  # symlink
                continue
            if not is_safe_zip_member_name(name):
                continue
            if allowed_suffixes and Path(name).suffix.lower() not in allowed_suffixes:
                continue
            if info.file_size < min_entry_size or info.file_size > max_entry_size:
                continue
            if info.compress_size > max_entry_size * 5:
                continue
            if info.compress_size > 0 and (info.file_size / info.compress_size) > max_ratio:
                raise ValueError('Archive entry exceeds safe compression ratio (possible ZIP bomb).')
            # Stream-read with hard cap in case header file_size was forged
            with z.open(info, 'r') as member_stream:
                data = member_stream.read(max_entry_size + 1)
            if len(data) < min_entry_size or len(data) > max_entry_size:
                raise ValueError('Archive entry exceeded declared size limit (possible ZIP bomb).')
            actual_total += len(data)
            if actual_total > max_total_size:
                raise ValueError('Archive actual expanded size exceeded safety limit (possible ZIP bomb).')
            yield name, data


def aes_zip(root: Path, password: str) -> Path:
    """Produce password-protected AES-256 ZIP atomically. No plaintext fallback."""
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError('Use a ZIP password of at least 12 characters.')
    try:
        import pyzipper
    except ImportError as exc:
        raise RuntimeError('AES ZIP encryption unavailable: install pyzipper. Refusing an unencrypted fallback.') from exc
    root = root.resolve()
    if not root.is_dir():
        raise ValueError('Export folder not found.')
    files = [p for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root)]
    if not files:
        raise ValueError('No export files available to encrypt.')
    output = root.parent / (root.name + '-AES256.zip')
    fd, tmp = tempfile.mkstemp(prefix='.encrypted-zip-', dir=str(root.parent))
    try:
        with os.fdopen(fd, 'wb') as target:
            with pyzipper.AESZipFile(target, 'w', compression=pyzipper.ZIP_DEFLATED,
                                      encryption=pyzipper.WZ_AES) as z:
                z.setpassword(password.encode('utf-8'))
                z.setencryption(pyzipper.WZ_AES, nbits=256)
                for p in files:
                    z.write(p, arcname=str(p.relative_to(root.parent)))
        # Verify real decryption of every single entry before atomic commit.
        verify_aes_zip(Path(tmp), password)
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, output)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return output


def verify_aes_zip(archive: Path, password: str) -> dict:
    """Verify that an AES-256 encrypted ZIP archive can actually be decrypted with password."""
    if not isinstance(password, str) or not password:
        raise ValueError('Password is required to verify encrypted archive.')
    try:
        import pyzipper
    except ImportError as exc:
        raise RuntimeError('pyzipper is required to verify AES-256 ZIP archives.') from exc
    archive = Path(archive)
    if not archive.is_file():
        raise FileNotFoundError(str(archive))
    entries = 0
    total_bytes = 0
    with pyzipper.AESZipFile(archive, 'r') as z:
        infos = z.infolist()
        if not infos:
            raise ValueError('Encrypted archive contains no files.')
        # Ensure entries are actually encrypted (flag_bits & 0x1)
        unencrypted = [i.filename for i in infos if not i.is_dir() and not (i.flag_bits & 0x1)]
        if unencrypted:
            raise ValueError('Archive contains unencrypted entries; refusing to verify as encrypted.')
        z.setpassword(password.encode('utf-8'))
        for member in infos:
            if member.is_dir():
                continue
            if not is_safe_zip_member_name(member.filename):
                raise ValueError(f'Unsafe archive member path detected: {member.filename}')
            with z.open(member, 'r') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > DEFAULT_MAX_ZIP_TOTAL_BYTES:
                        raise ValueError('Archive exceeds verification size safety limit.')
            entries += 1
    return {'verified': True, 'entries': entries, 'total_bytes': total_bytes, 'archive': str(archive)}


def remove_plaintext_tree(root: Path, *, archive: Path) -> None:
    """Remove staging folder after successful export; not secure flash-media erasure."""
    root = root.resolve()
    archive = archive.resolve()
    if not archive.is_file() or not archive.parent == root.parent or root.is_symlink():
        raise ValueError('Verified encrypted archive beside staging folder is required.')
    if root.is_dir():
        shutil.rmtree(root)
