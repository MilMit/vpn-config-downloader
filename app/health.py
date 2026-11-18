"""Three-stage Configuration Health Checker.

Provides three independent verification states:
1. Syntax Validation: structural & directive validation of .ovpn / .conf files.
2. Endpoint Reachability: DNS resolution and TCP socket probe (never claims VPN health).
3. VPN Connection Verification: optional, explicitly consented, non-routing isolated client check;
   reports 'Not Tested' whenever consent, compatible client, or isolated conditions are absent.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable

from .protocol_manifest import analyze_profile
from .security import redact_secrets


def _syntax_section(info: dict | None, error_reason: str = '') -> dict:
    if not info:
        return {
            'status': 'invalid',
            'label': 'Invalid',
            'protocol': None,
            'required_actions': [],
            'warnings': [error_reason or 'Invalid config structure'],
        }
    warnings = list(info.get('warnings') or [])
    required = list(info.get('required_actions') or [])
    status = 'valid_with_warnings' if (warnings or required) else 'valid'
    label = 'Valid (Action Required)' if required else ('Valid (Warnings)' if warnings else 'Valid')
    return {
        'status': status,
        'label': label,
        'protocol': info['kind'],
        'server': info.get('server') or '',
        'port': info.get('port'),
        'required_actions': required,
        'warnings': warnings,
    }


def _client_binary(protocol: str | None) -> str | None:
    if protocol == 'wireguard':
        return shutil.which('wg')
    if protocol in ('udp', 'tcp', 'openvpn'):
        return shutil.which('openvpn')
    return None


def verify_vpn_connection_isolated(
    path: Path,
    *,
    user_consent: bool = False,
    timeout: float = 12.0,
    auth_file: Path | None = None,
) -> dict:
    """Optional, strictly non-routing VPN client check.

    NEVER modifies system default routes or network interfaces.
    Returns 'Not Tested' unless user_consent=True AND a compatible client is available.
    """
    path = Path(path)
    if not user_consent:
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': False,
            'reason': 'Requires explicit user consent for isolated VPN client verification.',
        }
    if not path.is_file() or path.suffix.lower() not in ('.ovpn', '.conf'):
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': False,
            'reason': 'Invalid or missing configuration file.',
        }
    info = analyze_profile(path.name, path.read_bytes())
    if not info:
        return {
            'status': 'failed',
            'label': 'Invalid Config',
            'vpn_verified': False,
            'client_available': False,
            'reason': 'Configuration failed syntax validation before client check.',
        }
    protocol = info['kind']
    binary = _client_binary(protocol)
    if not binary:
        needed = 'wg (wireguard-tools)' if protocol == 'wireguard' else 'openvpn'
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': False,
            'reason': f'Compatible VPN client binary ({needed}) is not installed on this system.',
        }

    if protocol == 'wireguard':
        # WireGuard handshake verification requires creating a kernel/userspace interface (root/CAP_NET_ADMIN).
        # We never alter system networking or routes here; perform safe key/config check only and keep Not Tested for tunnel.
        if not info.get('has_private_key') or not info.get('private_key_format_valid'):
            return {
                'status': 'not_tested',
                'label': 'Not Tested',
                'vpn_verified': False,
                'client_available': True,
                'reason': 'WireGuard PrivateKey missing or invalid; cannot perform live handshake.',
            }
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': True,
            'reason': 'WireGuard live tunnel verification requires an isolated network namespace (CAP_NET_ADMIN); not modifying host routing.',
        }

    # OpenVPN non-routing handshake probe (--route-noexec --ifconfig-noexec --nobind --dev null)
    # Using --dev null and --route-noexec guarantees host interfaces and routing tables are NEVER touched.
    if info.get('has_auth_directive') and not info.get('auth_file_reference') and auth_file is None:
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': True,
            'reason': 'OpenVPN profile requires service credentials; live tunnel check skipped (Not Tested).',
        }
    cmd = [
        binary,
        '--config', str(path.resolve()),
        '--dev', 'null',
        '--route-noexec',
        '--ifconfig-noexec',
        '--nobind',
        '--connect-retry-max', '1',
        '--connect-timeout', str(max(3, min(15, int(timeout)))),
        '--verb', '3',
    ]
    if auth_file is not None and Path(auth_file).is_file():
        cmd.extend(['--auth-user-pass', str(Path(auth_file).resolve())])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5.0, float(timeout)),
            check=False,
        )
        combined = redact_secrets((proc.stdout or '') + '\n' + (proc.stderr or ''))
        if 'Initialization Sequence Completed' in combined:
            return {
                'status': 'verified',
                'label': 'Verified (Isolated)',
                'vpn_verified': True,
                'client_available': True,
                'reason': 'OpenVPN TLS/auth handshake succeeded using non-routing --dev null isolation.',
            }
        if 'AUTH_FAILED' in combined:
            return {
                'status': 'failed',
                'label': 'Auth Failed',
                'vpn_verified': False,
                'client_available': True,
                'reason': 'OpenVPN server rejected authentication (AUTH_FAILED).',
            }
        if 'Options error' in combined:
            return {
                'status': 'failed',
                'label': 'Options Error',
                'vpn_verified': False,
                'client_available': True,
                'reason': 'OpenVPN rejected configuration directives (Options error).',
            }
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': True,
            'reason': 'Isolated OpenVPN check did not complete handshake within timeout.',
        }
    except subprocess.TimeoutExpired:
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': True,
            'reason': 'Isolated OpenVPN probe timed out without establishing tunnel.',
        }
    except OSError as exc:
        return {
            'status': 'not_tested',
            'label': 'Not Tested',
            'vpn_verified': False,
            'client_available': False,
            'reason': f'Could not invoke OpenVPN client ({type(exc).__name__}).',
        }


def probe_profile(
    path: Path,
    *,
    timeout: float = 2.5,
    resolver=None,
    connector=None,
    verify_vpn: bool = False,
    user_consent: bool = False,
    auth_file: Path | None = None,
) -> dict:
    """Run three independent checks: Syntax Validation, Endpoint Reachability, and optional VPN Verification.

    By default, no VPN tunnel is started, no route is changed, and vpn_verified is always False.
    """
    path = Path(path)
    if not path.is_file() or path.suffix.lower() not in ('.ovpn', '.conf') or path.stat().st_size > 2_000_000:
        reason = 'Unsupported, missing, or oversized file'
        return {
            'state': 'invalid',
            'reason': reason,
            'vpn_verified': False,
            'syntax_validation': _syntax_section(None, reason),
            'endpoint_reachability': {'status': 'not_tested', 'label': 'Not Tested', 'dns': 'not_tested', 'tcp': 'not_tested', 'resolved_ips': [], 'elapsed_ms': None},
            'vpn_connection_verification': {'status': 'not_tested', 'label': 'Not Tested', 'vpn_verified': False, 'client_available': False, 'reason': reason},
        }
    info = analyze_profile(path.name, path.read_bytes())
    if not info:
        reason = 'Invalid config structure'
        return {
            'state': 'invalid',
            'reason': reason,
            'vpn_verified': False,
            'syntax_validation': _syntax_section(None, reason),
            'endpoint_reachability': {'status': 'not_tested', 'label': 'Not Tested', 'dns': 'not_tested', 'tcp': 'not_tested', 'resolved_ips': [], 'elapsed_ms': None},
            'vpn_connection_verification': {'status': 'not_tested', 'label': 'Not Tested', 'vpn_verified': False, 'client_available': False, 'reason': reason},
        }

    host = info.get('server') or ''
    port = info.get('port')
    syntax = _syntax_section(info)
    reach = {
        'status': 'not_tested',
        'label': 'Not Tested',
        'dns': 'not_tested',
        'tcp': 'not_tested',
        'resolved_ips': [],
        'elapsed_ms': None,
    }
    vpn_check = {
        'status': 'not_tested',
        'label': 'Not Tested',
        'vpn_verified': False,
        'client_available': _client_binary(info['kind']) is not None,
        'reason': 'Not Tested: live VPN tunnel check requires explicit user consent and isolated client execution.',
    }
    result = {
        'file': path.name,
        'state': 'unknown',
        'protocol': info['kind'],
        'host': host,
        'port': port,
        'dns': 'not_tested',
        'tcp': 'not_tested',
        'vpn_verified': False,
        'elapsed_ms': None,
        'reason': 'A reachable host is NOT proof of VPN authentication or tunnel.',
        'syntax_validation': syntax,
        'endpoint_reachability': reach,
        'vpn_connection_verification': vpn_check,
    }

    if not host or not port or not 1 <= int(port) <= 65535:
        result['reason'] = 'Missing endpoint or port in profile.'
        reach['status'] = 'invalid'
        reach['label'] = 'Missing Endpoint'
        return result

    if len(host) > 253 or any(c in host for c in ' /\\\n\r\t@#?%'):
        result['state'] = 'invalid'
        result['reason'] = 'Malformed endpoint hostname'
        reach['status'] = 'invalid'
        reach['label'] = 'Invalid Hostname'
        return result

    resolver = resolver or socket.getaddrinfo
    try:
        infos = resolver(host, int(port), type=socket.SOCK_STREAM)
        result['dns'] = 'resolved'
        reach['dns'] = 'resolved'
        ips = []
        for entry in infos:
            try:
                sockaddr = entry[4]
                if isinstance(sockaddr, tuple) and sockaddr:
                    ip = str(sockaddr[0])
                    if ip not in ips:
                        ips.append(ip)
            except Exception:
                pass
        reach['resolved_ips'] = ips[:5]
    except (OSError, ValueError) as exc:
        result['dns'] = 'failed'
        reach['dns'] = 'failed'
        reach['status'] = 'dns_failed'
        reach['label'] = 'DNS Failed'
        result['reason'] = type(exc).__name__
        return result

    if info['kind'] in ('wireguard', 'udp'):
        result['state'] = 'dns_only'
        result['reason'] = 'UDP protocol: DNS resolved; a TCP probe cannot validate UDP or VPN handshake.'
        reach['status'] = 'dns_only'
        reach['label'] = 'DNS Resolved (UDP)'
    else:
        connector = connector or socket.create_connection
        start = time.monotonic()
        try:
            conn = connector((host, int(port)), timeout=timeout)
            conn.close()
            elapsed = round((time.monotonic() - start) * 1000, 1)
            result['tcp'] = 'reachable'
            result['state'] = 'tcp_reachable'
            result['elapsed_ms'] = elapsed
            reach['tcp'] = 'reachable'
            reach['status'] = 'tcp_reachable'
            reach['label'] = f'TCP Reachable ({elapsed} ms)'
            reach['elapsed_ms'] = elapsed
        except OSError as exc:
            result['tcp'] = 'failed'
            result['state'] = 'unreachable'
            result['reason'] = type(exc).__name__
            reach['tcp'] = 'failed'
            reach['status'] = 'unreachable'
            reach['label'] = f'Unreachable ({type(exc).__name__})'

    if verify_vpn:
        vpn_res = verify_vpn_connection_isolated(path, user_consent=user_consent, auth_file=auth_file)
        result['vpn_connection_verification'] = vpn_res
        result['vpn_verified'] = bool(vpn_res.get('vpn_verified'))

    return result


def batch_validate(
    root: Path,
    *,
    check_reachability: bool = False,
    timeout: float = 2.0,
    stop=None,
    on_progress: Callable[[int, int, dict], None] | None = None,
) -> list[dict]:
    """Validate all .ovpn and .conf files inside a directory."""
    root = Path(root).resolve()
    files = [
        p for p in sorted(root.rglob('*'))
        if p.is_file() and not p.is_symlink()
        and p.suffix.lower() in ('.ovpn', '.conf')
        and p.resolve().is_relative_to(root)
    ]
    total = len(files)
    results = []
    for idx, file_path in enumerate(files, 1):
        if stop is not None and stop.is_set():
            break
        if check_reachability:
            rec = probe_profile(file_path, timeout=timeout)
        else:
            info = analyze_profile(file_path.name, file_path.read_bytes()) if file_path.stat().st_size <= 2_000_000 else None
            syntax = _syntax_section(info, 'Invalid or oversized config file')
            rec = {
                'file': str(file_path.relative_to(root)),
                'state': 'syntax_valid' if info else 'invalid',
                'protocol': info['kind'] if info else None,
                'host': info.get('server', '') if info else '',
                'port': info.get('port') if info else None,
                'dns': 'not_tested',
                'tcp': 'not_tested',
                'vpn_verified': False,
                'elapsed_ms': None,
                'reason': 'Syntax validation only; endpoint reachability and VPN connection not tested.',
                'syntax_validation': syntax,
                'endpoint_reachability': {'status': 'not_tested', 'label': 'Not Tested', 'dns': 'not_tested', 'tcp': 'not_tested', 'resolved_ips': [], 'elapsed_ms': None},
                'vpn_connection_verification': {'status': 'not_tested', 'label': 'Not Tested', 'vpn_verified': False, 'client_available': _client_binary(info['kind'] if info else None) is not None, 'reason': 'Not Tested'},
            }
        rec['file'] = str(file_path.relative_to(root))
        results.append(rec)
        if on_progress:
            on_progress(idx, total, rec)
    return results
