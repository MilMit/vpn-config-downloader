#!/usr/bin/env python3
"""Windscribe bulk exporter, v3 experimental, stdlib-only, account-owned access.

Downloads only valid OpenVPN/WireGuard configs. Extracts IKEv2 account
credentials where authorized, distinguishes candidate hostnames from official
IKEv2 hostnames. Generates *experimental* Stealth/WSTunnel connection kits.
No VPN connectivity or Windscribe API compatibility is implied by output.
"""
from __future__ import annotations
import argparse
import base64
import csv
import getpass
import io
import json
import os
import subprocess
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

UA = 'Windscribe-Bulk-Exporter/4.1 (+account-owned manual VPN configs)'
ASSETS = 'https://assets.windscribe.com/serverlist/mob-v2/{tier}/0'
UPSTREAM_TS = 'https://raw.githubusercontent.com/whizzzkid/windscribe-fetch-config/main/config.ts'
BASE = 'https://windscribe.com/getconfig'
API_BASE = 'https://api.windscribe.com'
API_SERVER_CONFIGS = API_BASE + '/ServerConfigs'
API_WG_CONFIGS = API_BASE + '/WgConfigs/permanent'
API_DATACENTERS = API_BASE + '/ServerDatacenters'
API_CREDENTIALS = API_BASE + '/ServerCredentials?type=ikev2'
PROTOCOLS = ['udp', 'tcp', 'wireguard', 'ikev2', 'stealth', 'wstunnel']


def parse_ports(ports: str) -> list[str]:
    out = list(dict.fromkeys(x.strip() for x in ports.split(',') if x.strip()))
    if not out or any(not x.isascii() or not x.isdecimal() or not 1 <= int(x) <= 65535 for x in out):
        raise ValueError('Port list must be comma-separated integers in range 1..65535')
    return out


def is_valid_profile(kind: str, body: str) -> bool:
    if '<html' in body.lower() or '<!doctype' in body.lower():
        return False
    if kind == 'wireguard':
        return '[Interface]' in body and '[Peer]' in body and bool(re.search(r'(?m)^\s*Endpoint\s*=', body))
    return bool(re.search(r'(?m)^\s*(client|tls-client)\s*$', body)) and bool(re.search(r'(?m)^\s*remote\s+\S+', body))


def retry_fetch_bytes(url: str, *, retries: int = 3, **kwargs) -> bytes:
    for attempt in range(retries + 1):
        try:
            return fetch_bytes(url, **kwargs)
        except urllib.error.HTTPError as ex:
            if ex.code not in (429, 500, 502, 503, 504) or attempt >= retries:
                raise
            delay = min(30.0, 2.0 * (2 ** attempt))
            header = ex.headers.get('Retry-After') if ex.headers else None
            if header and header.isascii() and header.isdecimal():
                delay = min(60.0, max(delay, float(header)))
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError):
            if attempt >= retries:
                raise
            time.sleep(min(30.0, 2.0 * (2 ** attempt)))
    raise RuntimeError('Retry loop unexpectedly completed')


def read_wireguard_private_key(path: str) -> tuple[str, str]:
    """Read a private key from a local file; derive public key via X25519 (or wg fallback)."""
    if not path:
        return '', ''
    key_path = Path(path).expanduser()
    key = key_path.read_text(encoding='utf-8').strip()
    try:
        raw = base64.b64decode(key, validate=True)
    except (ValueError, base64.binascii.Error) as ex:
        raise ValueError('Invalid WireGuard private key format') from ex
    if len(raw) != 32:
        raise ValueError('WireGuard private key should decode to 32 bytes')
    try:
        from ..security import public_from_private
        public = public_from_private(key)
    except Exception:
        try:
            proc = subprocess.run(['wg', 'pubkey'], input=key+'\n', text=True, capture_output=True, check=True, timeout=8)
            public = proc.stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as ex:
            raise ValueError('Install cryptography or wireguard-tools to derive a WireGuard public key') from ex
    if len(base64.b64decode(public, validate=True)) != 32:
        raise ValueError('Derived an invalid WireGuard public key')
    return key, public


def make_wireguard_portable(profile: str, private_key: str) -> str:
    if not private_key:
        return profile
    match = re.search(r'(?mi)^\s*PrivateKey\s*=\s*(\S+)\s*$', profile)
    if match:
        if match.group(1) != private_key:
            raise ValueError('Generated WireGuard profile has a different private key')
        return profile
    return re.sub(r'(?m)^\[Interface\]\s*$', '[Interface]\nPrivateKey = '+private_key, profile, count=1)


def read_ikev2_credentials_file(path: str) -> tuple[str, str]:
    record = json.loads(Path(path).expanduser().read_text(encoding='utf-8'))
    user, password = record.get('username'), record.get('password')
    if not isinstance(user, str) or not isinstance(password, str) or not user or not password:
        raise ValueError('IKEv2 credentials file must be JSON with username and password')
    return user, password


def read_transport_endpoints(path: str) -> dict[tuple[str, str], dict]:
    """Optional CSV of endpoints *independently verified by the user*."""
    if not path:
        return {}
    result = {}
    with open(path, encoding='utf-8', newline='') as f:
        for row in csv.DictReader(f):
            loc, mode = (row.get('location_id') or '').strip(), (row.get('mode') or '').strip().lower()
            host = (row.get('host') or '').strip()
            port = (row.get('port') or '443').strip()
            backend = (row.get('backend_port') or '').strip()
            if not loc.isdecimal() or mode not in ('stealth','wstunnel') or not re.fullmatch(r'[A-Za-z0-9.-]{3,253}',host) or '..' in host:
                raise ValueError(f'Invalid transport endpoint row: {row!r}')
            if not port.isdecimal() or not 1 <= int(port) <= 65535:
                raise ValueError(f'Invalid port: {port}')
            if mode == 'wstunnel' and (not backend.isdecimal() or not 1 <= int(backend) <= 65535):
                raise ValueError('WStunnel requires a real backend_port')
            result[(loc, mode)] = {'remote_host': host, 'remote_port': int(port), 'backend_port': int(backend) if backend else None,
                                   'verification': 'USER_SUPPLIED_NOT_LIVE_TESTED'}
    return result

def safe_name(s: str) -> str:
    result = re.sub(r'[^0-9A-Za-z._-]+', '-', str(s).strip()).strip('-._')[:95]
    return result or 'unknown'


def fetch_bytes(url: str, *, headers: dict | None = None, method: str = 'GET', data: bytes | None = None, timeout: int = 25) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': UA, **(headers or {})}, data=data, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read(5_000_001)


def locations_from_json(data: dict) -> list[dict]:
    """Public server list from Windscribe (not a guarantee of account access)."""
    items = data.get('data', [])
    if not isinstance(items, list):
        raise ValueError('server list data is not an array')
    out = []
    ids = set()
    for region in items:
        if region.get('status', 1) != 1:
            continue
        for group in region.get('groups', []):
            loc_id = group.get('id')
            if not isinstance(loc_id, int) or loc_id in ids:
                continue
            ids.add(loc_id)
            city, nickname = group.get('city') or '', group.get('nick') or ''
            label = f'{city} - {nickname}'.strip(' -')
            nodes = group.get('nodes') if isinstance(group.get('nodes'), list) else []
            first_node = nodes[0] if nodes and isinstance(nodes[0], dict) else {}
            out.append({'id': str(loc_id), 'label': label, 'country': region.get('country_code') or '',
                        'pro': bool(group.get('pro', region.get('premium_only', False))),
                        'ikev2_candidate_hostname': region.get('dns_hostname') or '',
                        'openvpn_hostname': group.get('ovpn_x509') or '',
                        'node_ip3': first_node.get('ip3') or '',
                        'node_hostname': first_node.get('hostname') or ''})
    if not out:
        raise ValueError('No locations found in server list')
    return out


def locations_from_ts(data: str) -> list[dict]:
    match = re.search(r'export\s+const\s+locations\s*=\s*\[(.*?)\];', data, re.S)
    if not match:
        raise ValueError('No locations array in upstream config.ts')
    matches = re.findall(r"['\"](\d+):([^'\"\r\n]+)['\"]", match.group(1))
    return [{'id': i, 'label': name, 'country': '', 'pro': None,
             'ikev2_candidate_hostname': '', 'openvpn_hostname': ''} for i, name in dict(matches).items()]


def load_locations(source: str, timeout: int) -> list[dict]:
    if source == 'live':
        by_id = {}
        failures = []
        for tier in (0, 1):
            try:
                obj = json.loads(retry_fetch_bytes(ASSETS.format(tier=tier), timeout=timeout, retries=2))
                for loc in locations_from_json(obj):
                    by_id.setdefault(loc['id'], loc)
            except (ValueError, OSError, urllib.error.URLError, TimeoutError) as ex:
                failures.append(f'{tier}: {ex}')
        if not by_id:
            raise ValueError('Could not load Windscribe public server list: '+'; '.join(failures))
        return sorted(by_id.values(), key=lambda loc: (loc['country'], loc['label'], int(loc['id'])))
    if source == 'legacy':
        return locations_from_ts(fetch_bytes(UPSTREAM_TS, timeout=timeout).decode('utf-8'))
    path = Path(source)
    if not path.is_file():
        raise ValueError('Source must be live, legacy, or a local JSON/config.ts file')
    raw = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.json':
        return locations_from_json(json.loads(raw))
    return locations_from_ts(raw)


def secure_write(dest: Path, content: str | bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content.encode('utf-8') if isinstance(content, str) else content)


def _decode_maybe_base64_ovpn(raw_text: str) -> str:
    """Windscribe /ServerConfigs returns OpenVPN profiles Base64-encoded."""
    compact = re.sub(r'\s+', '', raw_text.strip())
    if compact and len(compact) % 4 != 1 and re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', compact):
        try:
            decoded = base64.b64decode(compact, validate=True).decode('utf-8')
            if 'dev tun' in decoded or 'remote ' in decoded:
                return decoded
        except Exception:
            pass
    return raw_text


def _assemble_wg_conf_from_api(cfg: dict, fallback_private_key: str = '') -> str:
    """Format Windscribe /WgConfigs/permanent data.config JSON object into standard WireGuard .conf."""
    priv = str(cfg.get('PrivateKey') or fallback_private_key or '').strip()
    addr = str(cfg.get('Address') or '').strip()
    addr_v6 = str(cfg.get('AddressV6') or '').strip()
    if addr_v6:
        addr = f'{addr}, {addr_v6}' if addr else addr_v6
    dns = str(cfg.get('DNS') or '').strip()
    pub = str(cfg.get('PublicKey') or '').strip()
    allowed = str(cfg.get('AllowedIPs') or '0.0.0.0/0').strip()
    endpoint = str(cfg.get('Endpoint') or '').strip()
    psk = str(cfg.get('PresharedKey') or '').strip()

    lines = ['[Interface]']
    if priv:
        lines.append(f'PrivateKey = {priv}')
    if addr:
        lines.append(f'Address = {addr}')
    if dns:
        lines.append(f'DNS = {dns}')
    lines.append('')
    lines.append('[Peer]')
    if pub:
        lines.append(f'PublicKey = {pub}')
    if psk:
        lines.append(f'PresharedKey = {psk}')
    if allowed:
        lines.append(f'AllowedIPs = {allowed}')
    if endpoint:
        lines.append(f'Endpoint = {endpoint}')
    return '\n'.join(lines) + '\n'


def _extract_api_error(raw_text: str) -> str:
    try:
        obj = json.loads(raw_text)
        if isinstance(obj, dict):
            msg = obj.get('errorMessage') or obj.get('errorDescription') or obj.get('error')
            code = obj.get('errorCode')
            if msg:
                return f'{msg} (code {code})' if code else str(msg)
    except Exception:
        pass
    return ''


def get_manual_config(kind: str, cookie: str, loc: dict, port: str, timeout: int, wg_pub: str = '', retries: int = 3) -> str:
    """Fetch OpenVPN or WireGuard config via Windscribe's official 2026 REST API (api.windscribe.com)."""
    token = cookie.strip()
    auth_header = token if token.lower().startswith('bearer ') else f'Bearer {token}'
    raw_token = token.split(' ', 1)[1].strip() if token.lower().startswith('bearer ') else token

    if kind == 'wireguard':
        payload = {
            'session_auth_hash': raw_token,
            'datacenter_id': str(loc['id']),
            'port': str(port),
        }
        if wg_pub:
            payload['wg_pubkey'] = wg_pub.strip()
        raw_bytes = retry_fetch_bytes(
            API_WG_CONFIGS,
            retries=retries,
            data=urllib.parse.urlencode(payload).encode('utf-8'),
            method='POST',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': auth_header,
                'Accept': 'application/json',
            },
            timeout=timeout,
        )
        raw_text = raw_bytes.decode('utf-8', 'replace')
        err = _extract_api_error(raw_text)
        if err:
            raise ValueError(f'Windscribe WireGuard API error: {err}')
        try:
            obj = json.loads(raw_text)
            cfg = (obj.get('data') or {}).get('config') if isinstance(obj, dict) else None
            if isinstance(cfg, dict):
                body = _assemble_wg_conf_from_api(cfg)
            else:
                body = raw_text
        except json.JSONDecodeError:
            body = raw_text
    else:
        params = urllib.parse.urlencode({
            'datacenter_id': str(loc['id']),
            'protocol': kind.lower(),
            'port': str(port),
            'config_version': '3b',
        })
        url = f'{API_SERVER_CONFIGS}?{params}'
        raw_bytes = retry_fetch_bytes(
            url,
            retries=retries,
            method='GET',
            headers={
                'Authorization': auth_header,
                'Accept': 'text/plain, application/json, */*',
            },
            timeout=timeout,
        )
        raw_text = raw_bytes.decode('utf-8', 'replace')
        err = _extract_api_error(raw_text)
        if err:
            raise ValueError(f'Windscribe OpenVPN API error: {err}')
        body = _decode_maybe_base64_ovpn(raw_text)

    if not is_valid_profile(kind, body):
        raise ValueError(f'{kind} profile failed structural validation (check Windscribe Pro subscription and session token)')
    return body


def get_official_ikev2_hostnames(auth_hash: str, timeout: int) -> dict[str, str]:
    """Fetch official datacenter_id -> ike_hostname mapping from Windscribe /ServerDatacenters."""
    if not auth_hash:
        return {}
    tok = auth_hash.strip()
    header = tok if tok.lower().startswith('bearer ') else f'Bearer {tok}'
    raw = fetch_bytes(API_DATACENTERS, headers={'Authorization': header, 'Accept': 'application/json'}, timeout=timeout)
    result = json.loads(raw)
    data = result.get('data') if isinstance(result, dict) else None
    if isinstance(data, dict) and isinstance(data.get('datacenters'), list):
        items = data['datacenters']
    elif isinstance(data, list):
        items = data
    else:
        return {}
    mapping: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        dc_id = item.get('dc_id') if item.get('dc_id') is not None else item.get('id')
        ike_host = str(item.get('ike_hostname') or '').strip().lower()
        if dc_id is not None and ike_host and re.fullmatch(r'[a-z0-9.-]{3,253}', ike_host) and '..' not in ike_host:
            mapping[str(dc_id)] = ike_host
    return mapping


def _get_server_credentials(cred_type: str, auth_hash: str, timeout: int) -> tuple[str, str]:
    if not auth_hash:
        raise ValueError(f'API auth hash required for {cred_type} credentials')
    tok = auth_hash.strip()
    header = tok if tok.lower().startswith('bearer ') else f'Bearer {tok}'
    url = f'{API_BASE}/ServerCredentials?type={urllib.parse.quote(cred_type)}'
    raw = fetch_bytes(url, headers={'Authorization': header, 'Accept': 'application/json'}, timeout=timeout)
    result = json.loads(raw)
    err = _extract_api_error(raw.decode('utf-8', 'replace'))
    if err:
        raise ValueError(f'Windscribe {cred_type} credentials API error: {err}')
    if not isinstance(result.get('data'), dict):
        raise ValueError(f'Unexpected {cred_type} credentials API response')
    data = result['data']
    try:
        raw_u = str(data['username'])
        raw_p = str(data['password'])
        try:
            user = base64.b64decode(raw_u, validate=True).decode('utf-8')
            passwd = base64.b64decode(raw_p, validate=True).decode('utf-8')
        except Exception:
            user, passwd = raw_u, raw_p
    except (KeyError, ValueError, UnicodeDecodeError) as ex:
        raise ValueError(f'Could not decode {cred_type} credentials') from ex
    if not user or not passwd or len(user) > 200 or len(passwd) > 500:
        raise ValueError(f'Invalid {cred_type} credentials')
    return user, passwd


def get_ikev2_credentials(auth_hash: str, timeout: int) -> tuple[str, str]:
    return _get_server_credentials('ikev2', auth_hash, timeout)


def get_openvpn_credentials(auth_hash: str, timeout: int = 20) -> tuple[str, str]:
    return _get_server_credentials('openvpn', auth_hash, timeout)


def read_verified_ike_hosts(path: str) -> dict[str, str]:
    """Opt-in exact hostnames copied from official IKEv2 generator.
    CSV columns: location_id,hostname. No guessed hostnames are promoted to verified.
    """
    if not path:
        return {}
    ret = {}
    with open(path, encoding='utf-8', newline='') as f:
        for row in csv.DictReader(f):
            location_id = (row.get('location_id') or '').strip()
            hostname = (row.get('hostname') or '').strip().lower()
            if not re.fullmatch(r'\d+', location_id) or not re.fullmatch(r'[a-z0-9.-]{3,253}', hostname) or '..' in hostname:
                raise ValueError(f'Bad verified hostname CSV row: {row!r}')
            ret[location_id] = hostname
    return ret


def make_ikev2_conf(host: str, username: str, password: str, identifier: str) -> tuple[str, str]:
    # StrongSwan swanctl syntax. Certificate validation deliberately kept enabled.
    if re.search(r'["\\\r\n]', username + password):
        raise ValueError('Credentials contain unsupported quote/backslash; use manual IKEv2 setup')
    conn = f'''connections {{
  {identifier} {{
    version = 2
    remote_addrs = {host}
    local_addrs = %any
    local {{
      auth = eap-mschapv2
      eap_id = "{username}"
    }}
    remote {{
      auth = pubkey
      id = {host}
    }}
    children {{
      vpn {{
        local_ts = dynamic
        remote_ts = 0.0.0.0/0
      }}
    }}
  }}
}}
'''
    secrets = f'''secrets {{
  eap-{identifier} {{
    id = "{username}"
    secret = "{password}"
  }}
}}
'''
    return conn, secrets


def make_local_ovpn(src: str, port: int = 65479) -> str:
    # Keep all certs and auth options, change only OpenVPN TCP transport/remote.
    lines = src.splitlines()
    result = []
    for line in lines:
        striped = line.strip()
        key = striped.split(' ', 1)[0].lower() if striped else ''
        if key in ('remote', 'remote-random', 'proto', 'proto-force'):
            continue
        result.append(line)
    result.insert(0, '# EXPERIMENTAL: requires separate Windscribe tunnel proxy; untested')
    result.insert(1, 'remote 127.0.0.1 ' + str(port))
    result.insert(2, 'proto tcp-client')
    return '\n'.join(result) + '\n'


def make_kit(loc: dict, ovpn: str, folder: Path, mode: str, base_name: str, verified_endpoint: dict | None = None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    profile_path = folder / f'{base_name}.ovpn'
    secure_write(profile_path, make_local_ovpn(ovpn))
    remote = re.search(r'(?m)^\s*remote\s+(\S+)\s+(\d+)', ovpn)
    # The OpenVPN host need not be a valid WSTunnel TLS host. USER MUST VERIFY.
    kit = {
        'mode': mode, 'status': 'EXPERIMENTAL_NOT_VERIFIED', 'location': f'{loc["id"]}:{loc["label"]}',
        'ovpn_local_profile': profile_path.name, 'transport_host_candidate': remote.group(1) if remote else '',
        'transport_port_candidate': 443, 'backend_port': None,
        'instructions': 'Use official Windscribe/wstunnel CLI. Verify remote TLS host and backend port in Windscribe implementation. Do NOT assume this config works as-is.',
        'reference': 'https://github.com/Windscribe/wstunnel',
    }
    if verified_endpoint:
        kit.update(verified_endpoint)
        kit['status'] = 'USER_ENDPOINT_SUPPLIED_NOT_LIVE_TESTED'
    meta = folder / f'{base_name}.kit.json'
    secure_write(meta, json.dumps(kit, indent=2, ensure_ascii=False) + '\n')
    return meta


def csv_string(headers: list[str], rows: list[list]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Experimental bulk Windscribe config exporter: OpenVPN, WireGuard, IKEv2 metadata, Stealth/WSTunnel kits')
    p.add_argument('--source', default='live', help='live (current public assets list), legacy, or local JSON/config.ts')
    p.add_argument('--output', default='Windscribe-Export')
    p.add_argument('--protocols', default='all', help='all or comma-separated: udp,tcp,wireguard,ikev2,stealth,wstunnel')
    p.add_argument('--limit', type=int, help='process only first N locations (test)')
    p.add_argument('--delay', type=float, default=4.0, help='seconds between web config requests')
    p.add_argument('--timeout', type=int, default=25)
    p.add_argument('--tcp-ports', default='54783', help='comma separated TCP ports, e.g. 443,54783')
    p.add_argument('--udp-ports', default='443', help='comma separated UDP ports')
    p.add_argument('--wireguard-ports', default='65142', help='comma separated WireGuard ports')
    p.add_argument('--retries', type=int, default=3, help='retries for transient network / HTTP 429 errors')
    p.add_argument('--force', action='store_true', help='redownload existing valid OpenVPN/WireGuard profiles')
    p.add_argument('--wireguard-private-key-file', default='', help='local wg private key file (not passed as CLI argument)')
    p.add_argument('--ikev2-credentials-file', default='', help='local JSON username/password as alternative to API fetch')
    p.add_argument('--transport-endpoints', default='', help='optional VERIFIED BY YOU CSV: location_id,mode,host,port,backend_port')
    p.add_argument('--wireguard-public-key', default='', help='PUBLIC key only (not a secret)')
    p.add_argument('--ikev2-hostnames', default='', help='CSV of official verified IKEv2 hostnames: location_id,hostname')
    p.add_argument('--no-zip', action='store_true')
    p.add_argument('--offline-demo', action='store_true', help='dry-run: no credentials/config requests (live location source still needs network)')
    args = p.parse_args(argv)
    try:
        protocols = PROTOCOLS[:] if args.protocols.lower() == 'all' else list(dict.fromkeys(x.strip().lower() for x in args.protocols.split(',') if x.strip()))
        if not protocols or set(protocols) - set(PROTOCOLS):
            p.error('Allowed protocols: ' + ','.join(PROTOCOLS))
        if args.delay < 0 or args.timeout < 1 or args.retries < 0 or args.retries > 10 or (args.limit is not None and args.limit < 1):
            p.error('Invalid delay/timeout/limit')
        ports = {'udp': parse_ports(args.udp_ports), 'tcp': parse_ports(args.tcp_ports), 'wireguard': parse_ports(args.wireguard_ports)}
        locs = load_locations(args.source, args.timeout)
        if args.limit:
            locs = locs[:args.limit]
        out = Path(args.output).expanduser().resolve()
        if args.offline_demo:
            print(f'Parsed {len(locs)} locations, selected: {", ".join(protocols)}; first: {locs[0]["label"]}')
            return 0
        out.mkdir(parents=True, exist_ok=True)
        os.chmod(out, 0o700)
        print(f'{len(locs)} locations. Source: {args.source}. Not a guarantee of account access.')
        needs_web = bool(set(protocols) & {'udp', 'tcp', 'wireguard', 'stealth', 'wstunnel'})
        cookie = getpass.getpass('Windscribe website ws_session_auth_hash (hidden; only local): ').strip() if needs_web else ''
        if needs_web and (not cookie or any(c in cookie for c in '\r\n; ')):
            raise ValueError('Website session cookie missing/invalid')
        wg_private, from_private_public = read_wireguard_private_key(args.wireguard_private_key_file)
        if args.wireguard_public_key and from_private_public and args.wireguard_public_key != from_private_public:
            raise ValueError('WireGuard public key does not match the supplied private key')
        wg_pub = from_private_public or args.wireguard_public_key or (input('WireGuard PUBLIC key (Enter=skip WG): ').strip() if 'wireguard' in protocols else '')
        if 'wireguard' in protocols and not wg_pub:
            print('WireGuard SKIPPED: public key not supplied')
        verified_hosts = read_verified_ike_hosts(args.ikev2_hostnames)
        transport_endpoints = read_transport_endpoints(args.transport_endpoints)
        api_hash = ''
        if 'ikev2' in protocols and not args.ikev2_credentials_file:
            api_hash = getpass.getpass('Windscribe API auth_hash for IKEv2 (Enter=try website cookie): ').strip() or cookie
        # no-credential storage unless requested; IKEv2 bundle requires own account credential, stored as 0600
        results, stats = [], {'downloaded_configs': 0, 'reused_configs': 0, 'wireguard_portable': 0, 'wireguard_missing_private_key': 0, 'ikev2_credentials': False, 'ikev2_verified_profiles': 0, 'ikev2_candidate_profiles': 0, 'experimental_transport_kits': 0}
        ike_creds = None
        if 'ikev2' in protocols:
            try:
                ike_creds = read_ikev2_credentials_file(args.ikev2_credentials_file) if args.ikev2_credentials_file else get_ikev2_credentials(api_hash, args.timeout)
                secure_write(out / 'IKEv2' / 'credentials.json', json.dumps({'username': ike_creds[0], 'password': ike_creds[1], 'warning': 'PRIVATE. Do not share.'}, indent=2) + '\n')
                stats['ikev2_credentials'] = True
                print('IKEv2: downloaded account credentials (PRIVATE)')
            except (urllib.error.URLError, ValueError, TimeoutError, OSError, json.JSONDecodeError) as ex:
                print(f'IKEv2 credentials unavailable: {ex}', file=sys.stderr)
                results.append({'protocol': 'ikev2', 'status': 'credentials_failed', 'error': str(ex)[:180]})
        candidate_rows = []
        for idx, loc in enumerate(locs, 1):
            base = f'{safe_name(loc["country"] or "XX")}-{loc["id"]}-{safe_name(loc["label"])}'
            location = f'{loc["id"]}:{loc["label"]}'
            if 'ikev2' in protocols:
                candidate_rows.append([loc['id'], loc['label'], loc['country'], loc['ikev2_candidate_hostname'],
                                       'UNVERIFIED: compare with official IKEv2 generator'])
                if ike_creds and loc['id'] in verified_hosts:
                    try:
                        name = f'ws_{loc["id"]}'
                        conf, secret = make_ikev2_conf(verified_hosts[loc['id']], *ike_creds, name)
                        secure_write(out / 'IKEv2' / 'Verified-StrongSwan' / f'{base}.swanctl.conf', conf)
                        secure_write(out / 'IKEv2' / 'Verified-StrongSwan' / f'{base}.secrets.conf', secret)
                        stats['ikev2_verified_profiles'] += 1
                        results.append({'protocol': 'ikev2', 'location': location, 'status': 'generated_from_user_verified_hostname', 'hostname': verified_hosts[loc['id']]})
                    except ValueError as ex:
                        results.append({'protocol': 'ikev2', 'location': location, 'status': 'failed', 'error': str(ex)})
            for kind in ('udp', 'tcp', 'wireguard'):
                if kind not in protocols and not (kind == 'tcp' and ('stealth' in protocols or 'wstunnel' in protocols)):
                    continue
                if kind == 'wireguard' and not wg_pub:
                    continue
                for port in ports[kind]:
                    ext = 'conf' if kind == 'wireguard' else 'ovpn'
                    dest = out / ('WireGuard' if kind == 'wireguard' else f'OpenVPN-{kind.upper()}') / f'{base}-p{port}.{ext}'
                    # Transport-only TCP profiles are also cached privately for resumability.
                    if kind == 'tcp' and kind not in protocols:
                        dest = out / '_TransportSourceTCP' / f'{base}-p{port}.ovpn'
                    status = 'downloaded'
                    try:
                        if not args.force and dest.is_file() and is_valid_profile(kind, dest.read_text(encoding='utf-8')):
                            config = dest.read_text(encoding='utf-8')
                            status = 'reused'
                            stats['reused_configs'] += 1
                        else:
                            config = get_manual_config(kind, cookie, loc, port, args.timeout, wg_pub, args.retries)
                            if kind == 'wireguard':
                                config = make_wireguard_portable(config, wg_private)
                            secure_write(dest, config)
                            stats['downloaded_configs'] += 1
                        if kind == 'wireguard':
                            has_private = bool(re.search(r'(?mi)^\s*PrivateKey\s*=', config))
                            if has_private:
                                stats['wireguard_portable'] += 1
                            else:
                                stats['wireguard_missing_private_key'] += 1
                                secure_write(out / 'WireGuard' / 'README_PRIVATEKEY_REQUIRED.txt',
                                    'WireGuard profiles in this directory are incomplete without the matching private key.\n'
                                    'To export portable profiles use --wireguard-private-key-file /path/to/privatekey.\n'
                                    'Do not share the key or the exported ZIP.\n')
                        results.append({'protocol': kind, 'port': port, 'location': location, 'status': status,
                                        'file': str(dest.relative_to(out)), 'portable': (bool(re.search(r'(?mi)^\s*PrivateKey\s*=',config)) if kind == 'wireguard' else True)})
                        if kind == 'tcp':
                            for mode in ('stealth', 'wstunnel'):
                                if mode in protocols:
                                    make_kit(loc, config, out / mode.capitalize() / base, mode, f'{base}-p{port}',
                                             verified_endpoint=transport_endpoints.get((loc['id'], mode)))
                                    stats['experimental_transport_kits'] += 1
                                    results.append({'protocol': mode, 'location': location, 'status': 'EXPERIMENTAL_KIT_ONLY_NOT_TESTED',
                                                    'endpoint_user_supplied': (loc['id'], mode) in transport_endpoints})
                        print(f'[{idx}/{len(locs)}] {status.upper()} {kind:<10} p{port} {loc["label"]}')
                    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as ex:
                        print(f'[{idx}/{len(locs)}] FAILED {kind:<10} p{port} {loc["label"]}: {ex}', file=sys.stderr)
                        results.append({'protocol': kind, 'port': port, 'location': location, 'status': 'failed', 'error': str(ex)[:180]})
                    if status != 'reused' and args.delay:
                        time.sleep(args.delay)
        if 'ikev2' in protocols:
            secure_write(out / 'IKEv2' / 'hostname_candidates_UNVERIFIED.csv', csv_string(
                ['location_id', 'location', 'country_code', 'candidate_region_dns', 'validation'], candidate_rows))
            # Region names historically used by Windscribe's IKEv2 generator, but
            # do not promote a current server-list DNS entry to verified IKEv2 status.
            if ike_creds:
                unique_regions = {}
                for loc in locs:
                    hostname = loc.get('ikev2_candidate_hostname', '')
                    if hostname and re.fullmatch(r'[a-z0-9.-]{3,253}', hostname):
                        unique_regions[hostname] = loc['country']
                for i, (hostname, country) in enumerate(sorted(unique_regions.items())):
                    name = f'ws_candidate_{i}'
                    try:
                        conf, secret = make_ikev2_conf(hostname, *ike_creds, name)
                        base = safe_name(country + '-' + hostname)
                        secure_write(out / 'IKEv2' / 'Candidate-StrongSwan-UNVERIFIED' / f'{base}.swanctl.conf', conf)
                        secure_write(out / 'IKEv2' / 'Candidate-StrongSwan-UNVERIFIED' / f'{base}.secrets.conf', secret)
                        stats['ikev2_candidate_profiles'] += 1
                    except ValueError:
                        pass
            secure_write(out / 'IKEv2' / 'HOW_TO_VERIFY.txt',
              'Candidates are NOT official IKEv2 profile hostnames.\n'
              'Visit https://windscribe.com/myaccount/config-generator#ikev2\n'
              'For each location use Get Profile Details; copy exact hostname.\n'
              'Create CSV: location_id,hostname\n'
              'Run exporter again with --ikev2-hostnames /path/to/official_hosts.csv\n'
              'Verified StrongSwan templates are generated only for those hosts.\n')
        if 'stealth' in protocols or 'wstunnel' in protocols:
            secure_write(out / 'TRANSPORT_KITS_README.txt',
                'Stealth/WSTunnel files are EXPERIMENTAL KITS, NOT ready-to-use standalone profiles.\n'
                'They contain valid downloaded OpenVPN TCP material re-pointed to localhost, plus metadata.\n'
                'Actual remote transport needs a separate compatible Windscribe/wstunnel tunnel proxy binary.\n'
                'See https://github.com/Windscribe/wstunnel (build_desktop.sh)\n'
                'For WSTunnel: wss://REMOTE:443/tcp/127.0.0.1/BACKEND_PORT  (tunnelType=1)\n'
                'For Stealth: https://REMOTE:443 (tunnelType=2)\n'
                'REMOTE/port/BACKEND_PORT are NOT validated. Do not assume candidate values work.\n'
                'After you start the transport proxy listening on 127.0.0.1:65479, open the .ovpn\n'
                'with your OpenVPN client. No executable binary is included in this package.\n')
        secure_write(out / 'report.json', json.dumps({'source': args.source, 'tested_against_live_account': False, 'version': 3,
            'notes': ['Credentials and VPN profiles are private', 'IKEv2 candidate hosts must not be used without verification',
                      'Stealth/WSTunnel kits do not prove working independent VPN connection'],
            'summary': stats, 'results': results}, ensure_ascii=False, indent=2) + '\n')
        if not args.no_zip:
            archive = out.parent / (out.name + '.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
                for f in out.rglob('*'):
                    if f.is_file():
                        z.write(f, f.relative_to(out.parent))
            os.chmod(archive, 0o600)
            print(f'PRIVATE unencrypted ZIP: {archive}')
        print('Summary:', json.dumps(stats))
        return 0 if any([stats['downloaded_configs'], stats['reused_configs'], stats['ikev2_credentials']]) else 2
    except (ValueError, urllib.error.URLError, TimeoutError, OSError) as ex:
        print(f'ERROR: {ex}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
