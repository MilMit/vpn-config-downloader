"""Non-secret metadata/preflight of downloaded VPN configuration files.

Never include passwords, private keys, website cookies, preshared keys or
whole configuration lines in the JSON/CSV reports. This is structural
inspection only and does NOT prove the tunnel connects successfully.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import Path

from .core import safe_store, profile_kind, extract_server_metadata
from .security import is_valid_wireguard_key

MAX = 2_000_000


def _directive(text: str, key: str) -> str:
    pattern = r'(?mi)^[ \t]*' + re.escape(key) + r'[ \t]*=[ \t]*([^#\r\n]*)'
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ''


def analyze_profile(name: str, data: bytes) -> dict | None:
    kind = profile_kind(name, data)
    if kind is None:
        return None
    text = data.decode('utf-8')
    meta = extract_server_metadata(name, data)
    rec = {
        'kind': kind,
        'sha256': hashlib.sha256(data).hexdigest()[:16],
        'structurally_valid': True,
        'vpn_connection_tested': False,
        'required_actions': [],
        'warnings': [],
        'server': '',
        'port': None,
        'country': meta['country'],
        'city': meta['city'],
    }
    if kind == 'wireguard':
        endpoint = _directive(text, 'Endpoint')
        # IPv6 bracketed endpoints allowed; just take the trailing number.
        m = re.fullmatch(r'(.+):(\d{1,5})', endpoint)
        rec['server'] = m.group(1).strip('[]') if m else endpoint
        rec['port'] = int(m.group(2)) if m else None
        priv_val = _directive(text, 'PrivateKey')
        pub_val = _directive(text, 'PublicKey')
        rec['has_private_key'] = bool(priv_val)
        rec['private_key_format_valid'] = is_valid_wireguard_key(priv_val) if priv_val else False
        rec['public_key_format_valid'] = is_valid_wireguard_key(pub_val)
        rec['has_interface_address'] = bool(_directive(text, 'Address'))
        rec['has_dns'] = bool(_directive(text, 'DNS'))
        rec['has_allowed_ips'] = bool(_directive(text, 'AllowedIPs'))
        if not rec['has_private_key']:
            rec['required_actions'].append('Add the matching account-generated WireGuard private key before connecting')
        elif not rec['private_key_format_valid']:
            rec['warnings'].append('WireGuard PrivateKey is not a standard 32-byte Base64 X25519 key')
        if not rec['public_key_format_valid']:
            rec['warnings'].append('Peer PublicKey is not a standard 32-byte Base64 X25519 key')
        if not rec['has_interface_address']:
            rec['required_actions'].append('Review interface address from provider')
        if not rec['has_allowed_ips']:
            rec['warnings'].append('AllowedIPs missing; client may not route tunnel traffic')
    else:
        m = re.search(r'(?mi)^\s*remote\s+(\S+)(?:\s+(\d{1,5}))?', text)
        if m:
            rec['server'] = m.group(1)
            rec['port'] = int(m.group(2)) if m.group(2) else None
        if rec['port'] is None:
            m_port = re.search(r'(?mi)^\s*port\s+(\d{1,5})\b', text)
            if m_port:
                rec['port'] = int(m_port.group(1))
        has_inline_ca = bool(re.search(r'(?is)<ca>\s*-----BEGIN CERTIFICATE-----.*?</ca>', text))
        has_file_ca = bool(re.search(r'(?mi)^\s*ca\s+\S+', text))
        rec['has_ca_cert'] = has_inline_ca or has_file_ca
        rec['has_tls_auth'] = bool(re.search(r'(?is)<tls-(auth|crypt|crypt-v2)>', text) or
                                   re.search(r'(?mi)^\s*tls-(auth|crypt|crypt-v2)\s+\S+', text))
        rec['has_remote_cert_tls'] = bool(re.search(r'(?mi)^\s*remote-cert-tls\s+server\b', text))
        cipher_m = re.search(r'(?mi)^\s*(?:data-ciphers|cipher)\s+([^\r\n#]+)', text)
        rec['cipher'] = cipher_m.group(1).strip() if cipher_m else ''
        if not rec['has_ca_cert']:
            rec['warnings'].append('Missing CA certificate (<ca> block or ca file directive)')
        if not rec['has_remote_cert_tls']:
            rec['warnings'].append('Missing remote-cert-tls server verification directive')
        auth = re.search(r'(?mi)^[ \t]*auth-user-pass(?:[ \t]+([^\s#]+))?', text)
        rec['has_auth_directive'] = bool(auth)
        if auth and auth.group(1):
            # The caller checks the existence in the filesystem, not here.
            rec['auth_file_reference'] = True
        else:
            rec['auth_file_reference'] = False
            rec['required_actions'].append('OpenVPN manual service username and password needed at connection time')
    return rec


def build_manifest(root: Path) -> dict:
    root = root.resolve()
    rows = []
    for file in sorted(root.rglob('*')):
        if not file.is_file() or file.is_symlink() or file.suffix.lower() not in ('.ovpn', '.conf'):
            continue
        if not file.resolve().is_relative_to(root) or file.stat().st_size > MAX:
            continue
        try:
            data = file.read_bytes()
            rec = analyze_profile(file.name, data)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        if rec is None:
            continue
        rec['file'] = str(file.relative_to(root))
        if rec.get('auth_file_reference'):
            # Scan only the fixed filename that the program itself generates.
            if 'auth-user-pass openvpn_auth.txt' in data.decode('utf-8'):
                if not (file.parent / 'openvpn_auth.txt').is_file():
                    rec['required_actions'].append('Referenced OpenVPN auth file is missing')
            else:
                rec['required_actions'].append('Review custom OpenVPN auth file reference')
        rows.append(rec)
    summary = {
        'total_structurally_valid': len(rows),
        'wireguard': sum(r['kind'] == 'wireguard' for r in rows),
        'openvpn_tcp': sum(r['kind'] == 'tcp' for r in rows),
        'openvpn_udp': sum(r['kind'] == 'udp' for r in rows),
        'other_openvpn': sum(r['kind'] == 'openvpn' for r in rows),
        'missing_actions': sum(bool(r['required_actions']) for r in rows),
        'with_warnings': sum(bool(r.get('warnings')) for r in rows),
        'live_connections_verified': 0,
    }
    payload = {
        'schema_version': 2,
        'summary': summary,
        'warning': 'Structural validation only; never interpreted as VPN connection success.',
        'profiles': rows,
    }
    safe_store(root / 'manifest.json', json.dumps(payload, indent=2, ensure_ascii=False))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['file', 'protocol', 'country', 'city', 'server', 'port', 'structurally_valid', 'required_actions', 'warnings'])
    for row in rows:
        writer.writerow([
            row['file'],
            row['kind'],
            row.get('country', ''),
            row.get('city', ''),
            row['server'],
            row['port'] or '',
            'yes',
            '; '.join(row['required_actions']),
            '; '.join(row.get('warnings', [])),
        ])
    safe_store(root / 'manifest.csv', output.getvalue())
    return summary
