"""Explicit opt-in to include OpenVPN *service* login in portable output.

The result contains a plaintext username/password file. This MUST be the user's
explicit decision, never a default. No account website passwords are accepted.
"""
from __future__ import annotations

import re
from pathlib import Path
from .core import safe_store


def add_openvpn_auth_files(provider_output: Path, username: str, password: str) -> dict:
    if not username or not password or any(c in username+password for c in '\r\n\x00'):
        raise ValueError('Invalid service credential line.')
    root = provider_output.resolve()
    added = 0
    skipped = 0
    groups: set[Path] = set()
    for ovpn in sorted(root.rglob('*.ovpn')):
        if ovpn.is_symlink() or not ovpn.is_file():
            continue
        if not ovpn.resolve().is_relative_to(root):
            continue
        text = ovpn.read_text(encoding='utf-8')
        if 'auth-user-pass openvpn_auth.txt' in text:
            added += 1
            groups.add(ovpn.parent)
            continue
        matches = list(re.finditer(r'(?mi)^[ \t]*auth-user-pass(?:[ \t]+([^\r\n#]+))?[ \t]*$', text))
        # Respect existing custom auth-user-pass paths, so we do not invalidate
        # profiles using something we do not understand.
        if len(matches) > 1 or (matches and (matches[0].group(1) or '').strip()):
            skipped += 1
            continue
        if matches:
            text = text[:matches[0].start()] + 'auth-user-pass openvpn_auth.txt' + text[matches[0].end():]
        else:
            text = text.rstrip('\r\n') + '\nauth-user-pass openvpn_auth.txt\n'
        safe_store(ovpn, text)
        groups.add(ovpn.parent)
        added += 1
    for group in groups:
        safe_store(group / 'openvpn_auth.txt', f'{username}\n{password}\n')
    return {'profiles_linked': added, 'profiles_skipped': skipped, 'auth_files': len(groups),
            'warning': 'PLAINTEXT OpenVPN service credentials are included in this export.'}
