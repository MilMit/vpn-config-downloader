"""Official configuration acquisition (not the VPN client or an unofficial login API).

Surfshark publishes a public OpenVPN archive and a public server cluster catalog.
Other account-only downloads are driven in a visible browser where the owner signs
in directly. No passwords, 2FA tokens, browser cookies, or storage state are exported.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from ..core import (
    Event,
    Location,
    extract_server_metadata,
    profile_kind,
    safe_filename,
    safe_store,
)
from ..security import safe_zip_entries

# Current official Surfshark bulk OpenVPN ZIP endpoints (prioritize active API endpoints
# ahead of the legacy Zendesk attachment, which may be outdated).
SURFSHARK_OPENVPN_URLS = (
    'https://my.surfshark.com/vpn/api/v1/server/configurations',
    'https://api.surfshark.com/v1/server/configurations',
    'https://surfshark.zendesk.com/hc/article_attachments/360018527519/configurations.zip',
)

SURFSHARK_CLUSTERS_URLS = (
    ('generic', 'https://api.surfshark.com/v4/server/clusters/generic'),
    ('static', 'https://api.surfshark.com/v4/server/clusters/static'),
)
SURFSHARK_CLUSTERS_FALLBACK_URL = 'https://my.surfshark.com/vpn/api/v1/server/clusters/generic'

# Documented Surfshark manual WireGuard defaults (used with live server pubKey + connectionName:51820).
SURFSHARK_WG_ADDRESS = '10.14.0.2/16'
SURFSHARK_WG_DNS = '162.252.172.57, 149.154.159.92'
SURFSHARK_WG_PORT = 51820

MAX_ARCHIVE = 85 * 1024 * 1024
MAX_PROFILE = 2 * 1024 * 1024
MAX_ENTRIES = 6000


def _parse_surfshark_cluster_list(data: list, cluster_type: str, seen: set[str]) -> list[Location]:
    locations: list[Location] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        conn = str(item.get('connectionName') or '').strip()
        if not conn or conn in seen:
            continue
        seen.add(conn)
        country = str(item.get('countryCode') or item.get('country') or '').strip()
        country_name = str(item.get('country') or '').strip()
        city = str(item.get('location') or '').strip()
        load = item.get('load')
        tags = item.get('tags') if isinstance(item.get('tags'), list) else []
        tier_parts = []
        if cluster_type == 'static':
            tier_parts.append('static')
        if isinstance(load, int):
            tier_parts.append(f'load {load}%')
        tier = ' · '.join(tier_parts) or 'standard'
        label = f'{city} ({conn})' if city else conn
        locations.append(
            Location(
                key=conn,
                country=country,
                name=label,
                tier=tier,
                extras={
                    'connectionName': conn,
                    'country_name': country_name,
                    'city': city,
                    'load': load,
                    'tags': tags,
                    'cluster_type': cluster_type,
                    'pubKey': str(item.get('pubKey') or '').strip(),
                },
            )
        )
    return locations


def fetch_surfshark_clusters(*, timeout: int = 20, opener=None, include_static: bool = True) -> list[Location]:
    """Fetch Surfshark's public server cluster catalog (generic + static IP clusters)."""
    if opener is None:
        opener = urllib.request.urlopen
    locations: list[Location] = []
    seen: set[str] = set()
    last_err = 'No cluster endpoint responded'
    targets = SURFSHARK_CLUSTERS_URLS if include_static else (SURFSHARK_CLUSTERS_URLS[0],)
    for cluster_type, url in targets:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'VPNConfigDownloader/4.1 (+manual configuration client)',
                    'Accept': 'application/json',
                },
            )
            with opener(req, timeout=timeout) as resp:
                resolved = resp.geturl()
                host = urlsplit(resolved).hostname or ''
                if urlsplit(resolved).scheme != 'https' or not (host == 'surfshark.com' or host.endswith('.surfshark.com')):
                    raise ValueError('Untrusted redirect refused')
                raw = resp.read(10 * 1024 * 1024)
            data = json.loads(raw.decode('utf-8'))
            if isinstance(data, list) and data:
                locations.extend(_parse_surfshark_cluster_list(data, cluster_type, seen))
        except Exception as exc:
            last_err = type(exc).__name__
    if not locations:
        try:
            req = urllib.request.Request(
                SURFSHARK_CLUSTERS_FALLBACK_URL,
                headers={'User-Agent': 'VPNConfigDownloader/4.1 (+manual configuration client)', 'Accept': 'application/json'},
            )
            with opener(req, timeout=timeout) as resp:
                data = json.loads(resp.read(10 * 1024 * 1024).decode('utf-8'))
            if isinstance(data, list) and data:
                locations.extend(_parse_surfshark_cluster_list(data, 'generic', seen))
        except Exception as exc:
            last_err = type(exc).__name__
    if not locations:
        raise RuntimeError(f'Could not load Surfshark public server catalog ({last_err}).')
    return sorted(locations, key=lambda loc: (loc.country, loc.name))


def generate_surfshark_wireguard_bulk(
    collector: Collected,
    clusters: list[Location],
    *,
    private_key: str,
    emit: Callable[[Event], None],
    stop=None,
    overwrite: bool = False,
) -> int:
    """Generate bulk WireGuard .conf profiles from live Surfshark server clusters + user's registered private key."""
    from ..security import is_valid_wireguard_key, public_from_private
    priv = private_key.strip()
    # Validates private key format via X25519
    public_from_private(priv)
    count = 0
    valid_clusters = [c for c in clusters if is_valid_wireguard_key(str(c.extras.get('pubKey') or ''))]
    total = len(valid_clusters)
    emit(Event('info', f'Generating Surfshark WireGuard configs from {total} live server clusters…'))
    for idx, loc in enumerate(valid_clusters, 1):
        if stop is not None and stop.is_set():
            break
        conn = loc.extras.get('connectionName') or loc.key
        server_pub = loc.extras['pubKey'].strip()
        city = loc.extras.get('city') or ''
        country = loc.country or 'XX'
        conf = (
            f'# Surfshark WireGuard · {country} {city} ({conn})\n'
            f'# Requires your Public Key to be registered at https://my.surfshark.com/vpn/manual-setup/main/wireguard\n'
            f'[Interface]\n'
            f'PrivateKey = {priv}\n'
            f'Address = {SURFSHARK_WG_ADDRESS}\n'
            f'DNS = {SURFSHARK_WG_DNS}\n\n'
            f'[Peer]\n'
            f'PublicKey = {server_pub}\n'
            f'AllowedIPs = 0.0.0.0/0\n'
            f'Endpoint = {conn}:{SURFSHARK_WG_PORT}\n'
            f'PersistentKeepalive = 25\n'
        ).encode('utf-8')
        filename = f'{safe_filename(conn)}.conf'
        if collector.ingest(filename, conf, 'Surfshark live cluster WireGuard', overwrite=overwrite):
            count += 1
            emit(Event('success', f'WireGuard: {country} {city or conn}', idx, total))
    return count


def generate_surfshark_ikev2_bulk(
    root: Path,
    clusters: list[Location],
    *,
    username: str = '',
    password: str = '',
    include_secrets: bool = False,
    selected_hosts: set[str] | None = None,
    emit: Callable[[Event], None],
    stop=None,
) -> list[dict]:
    """Generate StrongSwan IKEv2 profiles from live Surfshark server hostnames.

    Requires Surfshark manual service credentials and surfshark_ikev2.crt from
    https://my.surfshark.com/vpn/manual-setup/main/ikev2.
    """
    records: list[dict] = []
    filtered = clusters
    if selected_hosts:
        low_sel = {s.strip().lower() for s in selected_hosts if s.strip()}
        filtered = [
            c for c in clusters
            if c.key.lower() in low_sel or c.country.lower() in low_sel
        ]
    total = len(filtered)
    emit(Event('info', f'Generating Surfshark IKEv2 StrongSwan configs for {total} live server gateways…'))
    eap_user = username if (include_secrets and username) else 'YOUR_SURFSHARK_MANUAL_USERNAME'
    if any(ch in eap_user for ch in '"\r\n\\'):
        raise ValueError('IKEv2 username contains unsupported characters.')

    for idx, loc in enumerate(filtered, 1):
        if stop is not None and stop.is_set():
            break
        conn = loc.extras.get('connectionName') or loc.key
        country_dir = safe_filename(loc.country or 'XX')
        city = loc.extras.get('city') or ''
        ident = 'ss_' + re.sub(r'[^a-zA-Z0-9_]+', '_', conn)
        swanctl = (
            f'# Surfshark IKEv2 (StrongSwan swanctl) · {loc.country} {city} ({conn})\n'
            f'# Install surfshark_ikev2.crt into /etc/swanctl/x509ca/ (download from my.surfshark.com/vpn/manual-setup/main/ikev2)\n'
            f'connections {{\n'
            f'  {ident} {{\n'
            f'    version = 2\n'
            f'    remote_addrs = {conn}\n'
            f'    local_addrs = %any\n'
            f'    vips = 0.0.0.0\n'
            f'    local {{\n'
            f'      auth = eap-mschapv2\n'
            f'      eap_id = "{eap_user}"\n'
            f'    }}\n'
            f'    remote {{\n'
            f'      auth = pubkey\n'
            f'      id = {conn}\n'
            f'    }}\n'
            f'    children {{\n'
            f'      vpn {{\n'
            f'        remote_ts = 0.0.0.0/0\n'
            f'      }}\n'
            f'    }}\n'
            f'  }}\n'
            f'}}\n'
        )
        dst = root / 'IKEv2' / country_dir / f'{safe_filename(conn)}.swanctl.conf'
        safe_store(dst, swanctl)
        records.append({
            'name': safe_filename(conn),
            'protocol': 'ikev2',
            'country': loc.country,
            'city': city,
            'server': conn,
            'source': 'Surfshark live cluster IKEv2',
            'file': str(dst.relative_to(root)),
            'status': 'downloaded',
        })
        emit(Event('success', f'IKEv2: {loc.country} {city or conn}', idx, total))

    if records:
        readme = (
            'Surfshark Manual IKEv2 Setup Instructions (StrongSwan / macOS / Windows / iOS)\n'
            '==============================================================================\n'
            '1. Download the official Surfshark Root CA certificate (surfshark_ikev2.crt) from:\n'
            '   https://my.surfshark.com/vpn/manual-setup/main/ikev2\n'
            '2. Copy surfshark_ikev2.crt into /etc/swanctl/x509ca/ (or /etc/ipsec.d/cacerts/).\n'
            '3. Use your Surfshark Manual Service Username & Password (NOT your website login).\n'
            '4. Add your EAP secret in /etc/swanctl/conf.d/surfshark.secrets.conf:\n'
            '   secrets {\n'
            '     eap-surfshark {\n'
            '       id = "YOUR_SURFSHARK_MANUAL_USERNAME"\n'
            '       secret = "YOUR_SURFSHARK_MANUAL_PASSWORD"\n'
            '     }\n'
            '   }\n'
        )
        safe_store(root / 'IKEv2' / 'README_SURFSHARK_IKEV2.txt', readme)
    return records


@dataclass
class Collected:
    root: Path
    allowed: set[str] = field(default_factory=set)  # empty means all formats
    selected_hosts: set[str] = field(default_factory=set)  # empty means accept all servers
    downloaded: int = 0
    reused: int = 0
    recognized: int = 0
    ignored: int = 0
    failures: int = 0
    records: list[dict] = field(default_factory=list)
    hashes: set[str] = field(default_factory=set)
    progress: Callable[[Event], None] | None = None

    def _matches_host_filter(self, name: str, raw: bytes) -> bool:
        if not self.selected_hosts:
            return True
        low_name = Path(name).name.lower()
        meta = extract_server_metadata(name, raw)
        server_low = (meta.get('server') or '').lower()
        country_low = (meta.get('country') or '').lower()
        for token in self.selected_hosts:
            t = token.strip().lower()
            if not t:
                continue
            if t == server_low or t == country_low or t in low_name or (server_low and t in server_low):
                return True
        return False

    def ingest(self, name: str, raw: bytes, source: str, *, overwrite: bool = False) -> bool:
        # No raw response, URL query or credentials are written into reports.
        if len(raw) < 30 or len(raw) > MAX_PROFILE:
            self.ignored += 1
            return False
        kind = profile_kind(name, raw)
        if not kind or (self.allowed and kind not in self.allowed):
            self.ignored += 1
            return False
        self.recognized += 1
        if not self._matches_host_filter(name, raw):
            self.ignored += 1
            return False
        digest = hashlib.sha256(raw).hexdigest()
        if digest in self.hashes:
            self.ignored += 1
            return False
        self.hashes.add(digest)
        family = 'WireGuard' if kind == 'wireguard' else 'OpenVPN-' + kind.upper()
        suffix = '.conf' if kind == 'wireguard' else '.ovpn'
        meta = extract_server_metadata(name, raw)
        country_dir = safe_filename(meta['country']) if meta.get('country') and meta['country'] != 'General' else ''
        target_dir = (self.root / family / country_dir) if country_dir else (self.root / family)
        destination = target_dir / (safe_filename(Path(name).stem) + '-' + digest[:10] + suffix)
        if destination.is_file() and not overwrite and destination.read_bytes() == raw:
            self.reused += 1
            state = 'reused'
        else:
            safe_store(destination, raw)
            # Confirm written file is readable and matches content digest
            if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                self.failures += 1
                return False
            self.downloaded += 1
            state = 'downloaded'
        self.records.append({
            'name': safe_filename(Path(name).stem),
            'protocol': kind,
            'country': meta.get('country', ''),
            'city': meta.get('city', ''),
            'server': meta.get('server', ''),
            'source': source,
            'file': str(destination.relative_to(self.root)),
            'status': state,
            'portable': (kind != 'wireguard' or bool(re.search(rb'(?mi)^\s*PrivateKey\s*=', raw))),
        })
        return True

    def ingest_zip(self, content: bytes, source: str, *, overwrite: bool = False) -> int:
        if len(content) > MAX_ARCHIVE or not zipfile.is_zipfile(io.BytesIO(content)):
            raise ValueError('Official endpoint did not return a valid ZIP below the size limit.')
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            total = len(z.infolist())
        count = 0
        yielded = 0
        for index, (entry_name, entry_bytes) in enumerate(
            safe_zip_entries(
                content,
                allowed_suffixes=('.ovpn', '.conf'),
                max_entries=MAX_ENTRIES,
                max_entry_size=MAX_PROFILE,
            ),
            1,
        ):
            yielded += 1
            if self.ingest(entry_name, entry_bytes, source, overwrite=overwrite):
                count += 1
                if self.progress:
                    self.progress(Event('success', f'Validated {safe_filename(Path(entry_name).name)}', index, total))
        # Account for entries skipped by safe_zip_entries (dirs, traversal, symlinks, invalid extensions)
        if total > yielded:
            self.ignored += (total - yielded)
        return count


def fetch_official_surfshark_openvpn(
    collector: Collected,
    *,
    timeout: int,
    emit: Callable[[Event], None],
    stop=None,
    pause=None,
    overwrite: bool = False,
    opener=None,
) -> int:
    """Download Surfshark's documented public OpenVPN ZIP over HTTPS.

    We validate ZIP format, ZIP-bomb bounds, and each member; HTML/login/error pages are rejected.
    The user's account credentials are never sent to these public endpoints.
    """
    if opener is None:
        opener = urllib.request.urlopen
    last = 'No endpoint returned a valid archive'
    for url in SURFSHARK_OPENVPN_URLS:
        if stop and stop.is_set():
            return 0
        if pause:
            while not pause.wait(.25):
                if stop and stop.is_set():
                    return 0
        emit(Event('info', f'Downloading official Surfshark OpenVPN archive ({urlsplit(url).hostname})…'))
        try:
            request = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'VPNConfigDownloader/4.1 (+manual configuration client)',
                    'Accept': 'application/zip,application/octet-stream,*/*',
                },
            )
            with opener(request, timeout=timeout) as response:
                resolved = response.geturl()
                host = urlsplit(resolved).hostname or ''
                if urlsplit(resolved).scheme != 'https' or not (
                    host in ('surfshark.com', 'zendesk.com') or host.endswith(('.surfshark.com', '.zendesk.com'))
                ):
                    raise ValueError('Untrusted redirect refused')
                content = response.read(MAX_ARCHIVE + 1)
            before = collector.recognized
            found = collector.ingest_zip(content, 'Surfshark official OpenVPN ZIP', overwrite=overwrite)
            if collector.recognized == before:
                raise ValueError('ZIP contained no recognized OpenVPN/WireGuard profiles')
            emit(Event('success', f'Surfshark OpenVPN archive processed: {found} new/reused valid profiles'))
            return found
        except Exception as exc:
            last = type(exc).__name__
            emit(Event('info', f'Official archive endpoint not usable ({last}); trying documented fallback.'))
    raise RuntimeError(f'Surfshark public OpenVPN ZIP could not be downloaded ({last}).')


BROWSER_TARGETS = {
    'surfshark': {
        'url': 'https://my.surfshark.com/vpn/manual-setup/main/wireguard',
        'hosts': ('surfshark.com',),
        'protocols': ('wireguard',),
    },
    'proton': {
        'url': 'https://account.protonvpn.com/downloads',
        'hosts': ('protonvpn.com', 'proton.me'),
        'protocols': ('wireguard', 'udp', 'tcp'),
    },
}


def _trusted(url: str, provider: str) -> bool:
    try:
        p = urlsplit(url)
        return p.scheme == 'https' and any(
            p.hostname == h or (p.hostname or '').endswith('.' + h)
            for h in BROWSER_TARGETS[provider]['hosts']
        )
    except Exception:
        return False


def _is_download_action(label: str) -> bool:
    """Only allow non-destructive download actions (no create/regenerate/delete)."""
    s = re.sub(r'\s+', ' ', label).strip().lower()
    return ('download' in s or 'دریافت' in s) and not any(
        x in s for x in ('delete', 'remove', 'revoke', 'regenerate', 'reset', 'sign out')
    )


def _candidate_buttons(page):
    """Return only visible named download controls. Icons without labels need manual click."""
    selectors = (
        'button:visible', 'a:visible', '[role="button"]:visible'
    )
    results = []
    for css in selectors:
        controls = page.locator(css)
        n = min(controls.count(), 500)
        for i in range(n):
            el = controls.nth(i)
            try:
                name = ' '.join(filter(None, (
                    el.inner_text(timeout=400),
                    el.get_attribute('aria-label'),
                    el.get_attribute('title'),
                )))
                if _is_download_action(name):
                    results.append((el, name[:90]))
            except Exception:
                continue
    return results


def _provider_scope(page, provider: str, protocols: set[str]):
    # Proton sections have stable IDs in its account Downloads page. Ignore
    # global app-install links even if they also say 'Download'.
    if provider == 'proton':
        ids = []
        if 'wireguard' in protocols:
            ids.append('#section-wireguard-configuration')
        if protocols & {'udp', 'tcp', 'openvpn'}:
            ids.append('#section-openvpn-configuration-files, #section-openvpn-configuration')
        root = page.locator(','.join(ids))
        if root.count():
            return root
    return page


def _proton_page_ready(page) -> bool:
    """Return True once Proton's authenticated Downloads sections have rendered server accordions or buttons."""
    try:
        if '/login' in (page.url or '').lower():
            return False
        return bool(page.evaluate('''() => {
            const ovpn = document.querySelector('#section-openvpn-configuration-files, #section-openvpn-configuration');
            const wg = document.querySelector('#section-wireguard-configuration');
            if (!ovpn && !wg) return false;
            const hasItems = (el) => !!el && (
                el.querySelectorAll('summary').length > 0 ||
                Array.from(el.querySelectorAll('button')).some(b => /download|create/i.test(b.innerText || ''))
            );
            return hasItems(ovpn) || hasItems(wg);
        }'''))
    except Exception:
        return False


def _click_radio(section, radio_id: str, label_text: str = '') -> bool:
    """Safely select a Proton radio input via its label or element."""
    try:
        lbl = section.locator(f'label[for="{radio_id}"]').first
        if lbl.count():
            lbl.click(timeout=3000)
            return True
    except Exception:
        pass
    try:
        inp = section.locator(f'#{radio_id}').first
        if inp.count():
            inp.click(force=True, timeout=3000)
            return True
    except Exception:
        pass
    if label_text:
        try:
            lbl = section.locator(f'label:has-text("{label_text}")').first
            if lbl.count():
                lbl.click(timeout=3000)
                return True
        except Exception:
            pass
    return False


def _proton_automated_download(
    page,
    requested: set[str],
    *,
    collector: Collected,
    events: list,
    limit: int,
    delay: float,
    emit: Callable[[Event], None],
    stop,
    pause,
    drain_downloads: Callable[[int, int], int],
    active_page_fn: Callable,
    safe_wait_fn: Callable,
) -> tuple[int, bool]:
    """Automate Proton VPN's official Downloads UI for OpenVPN UDP/TCP and WireGuard .conf files.

    Returns (attempts_count, browser_closed_by_user).
    """
    attempts = 0
    closed = False
    pace_ms = int(max(0.35, min(delay, 3.0)) * 1000)

    def _check_alive():
        nonlocal page, closed
        if pause:
            while not pause.wait(0.2):
                if stop.is_set():
                    return False
        if stop.is_set():
            return False
        page = active_page_fn(page)
        if page is None:
            closed = True
            return False
        return True

    # Wait briefly for Proton's async server list <summary> accordions to populate
    for _ in range(16):
        if not _check_alive():
            return attempts, closed
        try:
            has_summaries = page.evaluate('''() => {
                const s = document.querySelectorAll('#section-openvpn-configuration-files summary, #section-wireguard-configuration summary');
                return s.length > 0;
            }''')
            if has_summaries:
                break
        except Exception:
            pass
        if not safe_wait_fn(page, 600):
            if active_page_fn(page) is None:
                return attempts, True

    # 1. OpenVPN UDP and/or TCP
    ovpn_protos = [p for p in ('udp', 'tcp') if p in requested or 'openvpn' in requested]
    if ovpn_protos and _check_alive():
        sec = page.locator('#section-openvpn-configuration-files, #section-openvpn-configuration').first
        if sec.count():
            emit(Event('info', f'proton: automating OpenVPN ({", ".join(p.upper() for p in ovpn_protos)}) on official Downloads page…'))
            _click_radio(sec, 'platform-Linux', 'GNU/Linux')
            safe_wait_fn(page, 500)
            for proto in ovpn_protos:
                if not _check_alive():
                    break
                proto_attempts = 0
                radio_id = 'protocol-radio_0' if proto == 'udp' else 'protocol-radio_1'
                _click_radio(sec, radio_id, proto.upper())
                safe_wait_fn(page, 900)
                before_proto = collector.downloaded

                # Try Proton's "Download all configurations" bulk ZIP button first (Plus/Country tiers)
                try:
                    dl_all = sec.locator('button:visible:has-text("Download all")').first
                    if dl_all.count() and not dl_all.is_disabled():
                        emit(Event('info', f'proton: clicking "Download all configurations" for OpenVPN {proto.upper()}…'))
                        attempts += 1
                        proto_attempts += 1
                        dl_all.click(timeout=5000)
                        for _ in range(12):
                            if not safe_wait_fn(page, 600):
                                break
                            drain_downloads(attempts, limit * max(1, len(requested)))
                            if collector.downloaded > before_proto:
                                break
                except Exception:
                    pass

                # If bulk ZIP already produced multiple configs, move to next protocol
                if collector.downloaded - before_proto >= 3:
                    emit(Event('success', f'proton: OpenVPN {proto.upper()} bulk archive captured ({collector.downloaded - before_proto} configs).'))
                    continue

                # Otherwise expand each country <details><summary> and click visible Download buttons
                summaries = sec.locator('summary')
                scount = summaries.count()
                emit(Event('info', f'proton: scanning {scount} country group(s) for OpenVPN {proto.upper()} (up to {limit})…'))
                for s_idx in range(scount):
                    if not _check_alive() or proto_attempts >= limit:
                        break
                    try:
                        summary = summaries.nth(s_idx)
                        details = summary.locator('xpath=..')
                        is_open = details.evaluate('el => el.hasAttribute("open")')
                        if not is_open:
                            summary.scroll_into_view_if_needed(timeout=3000)
                            summary.click(timeout=3000)
                            safe_wait_fn(page, 450)
                        dl_btns = details.locator('button:visible:has-text("Download")')
                        bcount = dl_btns.count()
                        for b_idx in range(bcount):
                            if not _check_alive() or proto_attempts >= limit:
                                break
                            btn = dl_btns.nth(b_idx)
                            if btn.is_disabled():
                                continue
                            attempts += 1
                            proto_attempts += 1
                            try:
                                btn.scroll_into_view_if_needed(timeout=2500)
                                btn.click(timeout=4000)
                                safe_wait_fn(page, max(500, pace_ms))
                                drain_downloads(proto_attempts, limit)
                            except Exception as exc:
                                if active_page_fn(page) is None:
                                    return attempts, True
                                emit(Event('skip', f'proton: OpenVPN {proto.upper()} button #{proto_attempts} skipped ({type(exc).__name__})', proto_attempts, limit))
                    except Exception:
                        continue

            # Drain any late-arriving OpenVPN downloads before switching to WireGuard
            if _check_alive():
                safe_wait_fn(page, 1200)
                drain_downloads(attempts, limit)

    # 2. WireGuard (.conf)
    if 'wireguard' in requested and _check_alive():
        wg_sec = page.locator('#section-wireguard-configuration').first
        if wg_sec.count():
            def _wg_count() -> int:
                return sum(1 for r in collector.records if r.get('protocol') == 'wireguard')

            wg_limit = min(limit, 20)
            wg_attempts = 0
            emit(Event('info', f'proton: automating WireGuard (.conf) generation & download (up to {wg_limit})…'))
            try:
                name_inp = wg_sec.locator('#certificate-device-name').first
                if name_inp.count() and not (name_inp.input_value() or '').strip():
                    name_inp.fill('VPNConfigDownloader')
            except Exception:
                pass
            _click_radio(wg_sec, 'wg-platform-Linux', 'GNU/Linux')
            safe_wait_fn(page, 600)

            summaries = wg_sec.locator('summary')
            scount = summaries.count()
            consecutive_misses = 0
            emit(Event('info', f'proton: scanning {scount} WireGuard group(s)…'))
            for s_idx in range(scount):
                if not _check_alive() or wg_attempts >= wg_limit or consecutive_misses >= 4:
                    break
                try:
                    summary = summaries.nth(s_idx)
                    sum_text = (summary.inner_text(timeout=2000) or '').strip().lower()
                    details = summary.locator('xpath=..')
                    is_open = details.evaluate('el => el.hasAttribute("open")')
                    if not is_open:
                        summary.scroll_into_view_if_needed(timeout=3000)
                        summary.click(timeout=3000)
                        safe_wait_fn(page, 450)

                    # Existing certificate accordion (has Revoke/Extend/Download — NEVER click Revoke!)
                    if 'revoke' in sum_text or 'expires' in sum_text:
                        dl_existing = details.locator('button:visible:has-text("Download")')
                        for e_idx in range(dl_existing.count()):
                            if not _check_alive() or wg_attempts >= wg_limit:
                                break
                            eb = dl_existing.nth(e_idx)
                            if eb.is_disabled():
                                continue
                            attempts += 1
                            wg_attempts += 1
                            try:
                                eb.scroll_into_view_if_needed(timeout=2500)
                                eb.click(timeout=4000)
                                safe_wait_fn(page, max(600, pace_ms))
                                drain_downloads(wg_attempts, wg_limit)
                            except Exception:
                                pass
                        continue

                    create_btns = details.locator('button:visible:has-text("Create")')
                    bcount = create_btns.count()
                    for b_idx in range(bcount):
                        if not _check_alive() or wg_attempts >= wg_limit or consecutive_misses >= 4:
                            break
                        btn = create_btns.nth(b_idx)
                        if btn.is_disabled():
                            continue
                        attempts += 1
                        wg_attempts += 1
                        before_wg = _wg_count()
                        try:
                            btn.scroll_into_view_if_needed(timeout=2500)
                            btn.click(timeout=4500)
                            # Wait for Proton's generated WireGuard modal & click Download
                            dialog_clicked = False
                            for _ in range(16):
                                if not safe_wait_fn(page, 450):
                                    if active_page_fn(page) is None:
                                        return attempts, True
                                    break
                                drain_downloads(wg_attempts, wg_limit)
                                if _wg_count() > before_wg:
                                    break
                                dlg = page.locator('[role="dialog"]:visible, dialog:visible, .modal-two:visible').first
                                if dlg.count() and not dialog_clicked:
                                    dl_btn = dlg.locator('button:visible:has-text("Download"), a:visible:has-text("Download")').first
                                    if dl_btn.count() and not dl_btn.is_disabled():
                                        dl_btn.click(timeout=4000)
                                        dialog_clicked = True
                                        safe_wait_fn(page, 800)
                                        drain_downloads(wg_attempts, wg_limit)
                                        if _wg_count() > before_wg:
                                            break
                            # Close modal cleanly before next server
                            try:
                                dlg = page.locator('[role="dialog"]:visible, dialog:visible, .modal-two:visible').first
                                if dlg.count():
                                    close_btn = dlg.locator('button[aria-label*="Close" i]:visible, button:visible:has-text("Close"), button:visible:has-text("Done")').first
                                    if close_btn.count():
                                        close_btn.click(timeout=2500)
                                    else:
                                        page.keyboard.press('Escape')
                                    safe_wait_fn(page, 350)
                            except Exception:
                                pass
                            drain_downloads(wg_attempts, wg_limit)
                            if _wg_count() > before_wg:
                                consecutive_misses = 0
                            else:
                                consecutive_misses += 1
                                if consecutive_misses >= 4:
                                    emit(Event('info', 'proton: WireGuard certificate creation limit or dialog change detected; stopping WireGuard loop cleanly.'))
                            safe_wait_fn(page, pace_ms)
                        except Exception as exc:
                            if active_page_fn(page) is None:
                                return attempts, True
                            consecutive_misses += 1
                            emit(Event('skip', f'proton: WireGuard create #{wg_attempts} skipped ({type(exc).__name__})', wg_attempts, wg_limit))
                except Exception:
                    continue

    drain_downloads(attempts, limit)
    return attempts, closed


def _save_browser_download(download, collector: Collected, provider: str, overwrite: bool = False) -> bool:
    """Playwright saves via a local temporary file, without recording URL/cookies."""
    import tempfile
    name = Path(download.suggested_filename).name
    if Path(name).suffix.lower() not in ('.ovpn', '.conf', '.zip'):
        collector.ignored += 1
        return False
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / safe_filename(name)
        download.save_as(str(path))
        if path.stat().st_size > MAX_ARCHIVE:
            collector.ignored += 1
            return False
        raw = path.read_bytes()
    if name.lower().endswith('.zip'):
        return collector.ingest_zip(raw, f'{provider} account download', overwrite=overwrite) > 0
    return collector.ingest(name, raw, f'{provider} account download', overwrite=overwrite)


def browser_account_download(
    provider: str,
    collector: Collected,
    *,
    protocols: list[str],
    limit: int,
    timeout: int,
    delay: float,
    emit: Callable[[Event], None],
    stop,
    pause,
    overwrite: bool = False,
    playwright_factory=None,
    profile_path=None,
) -> dict:
    """Drive the service's own UI after *human* login; no credential API or bypass."""
    if provider not in BROWSER_TARGETS:
        raise ValueError('Unknown provider')
    requested = set(protocols) & set(BROWSER_TARGETS[provider]['protocols'])
    if not requested:
        return {'visited': 0, 'downloaded': 0, 'note': 'No supported browser modes selected.'}
    interactive_real_browser = playwright_factory is None
    if playwright_factory is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise RuntimeError('Browser acquisition needs Playwright. Install with pip install playwright && python -m playwright install chromium') from e
        playwright_factory = sync_playwright
    initial = collector.downloaded
    attempts = 0
    with playwright_factory() as pw:
        browser = None
        try:
            if profile_path is not None:
                from ..accounts import launch_browser_context
                context = launch_browser_context(pw, Path(profile_path), headless=False, accept_downloads=True)
            else:
                browser = pw.chromium.launch(headless=False)
                context = browser.new_context(accept_downloads=True)
        except Exception as exc:
            detail = str(exc).splitlines()[0][:160]
            raise RuntimeError(f'Browser unavailable or profile already open ({detail}).') from exc
        browser_closed_by_user = False
        try:
            events: list = []
            attached_pages: set[int] = set()

            def _attach_page(p) -> None:
                pid = id(p)
                if pid in attached_pages:
                    return
                attached_pages.add(pid)
                try:
                    p.on('download', lambda d: events.append(d))
                except Exception:
                    pass

            def _drain_downloads(cur_step: int = 0, total_step: int = 0) -> int:
                saved = 0
                while events:
                    item = events.pop(0)
                    try:
                        if _save_browser_download(item, collector, provider, overwrite=overwrite):
                            saved += 1
                            emit(Event('success', f'{provider}: downloaded verified {item.suggested_filename}', cur_step, total_step))
                        else:
                            emit(Event('skip', f'{provider}: unsupported/duplicate download ignored', cur_step, total_step))
                    except Exception as exc:
                        collector.failures += 1
                        emit(Event('skip', f'{provider}: could not save download ({type(exc).__name__})'))
                return saved

            def _active_page(current):
                try:
                    if current is not None and not current.is_closed():
                        return current
                except Exception:
                    pass
                try:
                    for p in context.pages:
                        if not p.is_closed():
                            _attach_page(p)
                            return p
                except Exception:
                    pass
                return None

            def _safe_wait(p, ms: int) -> bool:
                """Return False if browser/page closed during wait."""
                try:
                    p.wait_for_timeout(ms)
                    return True
                except Exception:
                    return False

            try:
                context.on('page', _attach_page)
            except Exception:
                pass
            for existing in list(context.pages):
                _attach_page(existing)
            page = context.pages[0] if context.pages else context.new_page()
            _attach_page(page)

            try:
                page.goto(BROWSER_TARGETS[provider]['url'], wait_until='domcontentloaded', timeout=timeout * 1000)
            except Exception as nav_exc:
                if _active_page(page) is None:
                    browser_closed_by_user = True
                else:
                    emit(Event('info', f'{provider}: initial page navigation warning ({type(nav_exc).__name__}); continue in browser.'))

            emit(Event('info', f'{provider}: sign in inside the opened browser (complete MFA yourself). Manual downloads are captured automatically; close the window when done.'))
            end = time.monotonic() + 240
            while time.monotonic() < end and not stop.is_set() and not browser_closed_by_user:
                page = _active_page(page)
                if page is None:
                    browser_closed_by_user = True
                    break
                _drain_downloads()
                try:
                    if _trusted(page.url, provider):
                        if provider == 'proton' and _proton_page_ready(page):
                            break
                        if _candidate_buttons(_provider_scope(page, provider, requested)):
                            break
                except Exception:
                    if _active_page(page) is None:
                        browser_closed_by_user = True
                        break
                if not _safe_wait(page, 900) and _active_page(page) is None:
                    browser_closed_by_user = True
                    break

            _drain_downloads()
            if stop.is_set():
                return {'visited': 0, 'downloaded': collector.downloaded - initial, 'note': 'Stopped by user.'}
            if browser_closed_by_user:
                n = collector.downloaded - initial
                emit(Event('info', f'{provider}: browser window closed by user ({n} verified profile(s) captured).'))
                return {'visited': 0, 'downloaded': n, 'note': f'Browser closed by user; captured {n} verified profile(s).'}

            page = _active_page(page)
            if page is None:
                n = collector.downloaded - initial
                return {'visited': 0, 'downloaded': n, 'note': f'Browser closed by user; captured {n} verified profile(s).'}

            try:
                cur_url = page.url
            except Exception:
                cur_url = ''
            if not _trusted(cur_url, provider):
                raise RuntimeError('Browser navigated away from the official account domain.')

            # Dedicated full-protocol automation for Proton VPN Downloads page (OpenVPN UDP/TCP + WireGuard)
            if provider == 'proton' and _proton_page_ready(page):
                attempts, browser_closed_by_user = _proton_automated_download(
                    page,
                    requested,
                    collector=collector,
                    events=events,
                    limit=limit,
                    delay=delay,
                    emit=emit,
                    stop=stop,
                    pause=pause,
                    drain_downloads=_drain_downloads,
                    active_page_fn=_active_page,
                    safe_wait_fn=_safe_wait,
                )
            else:
                try:
                    has_buttons = bool(_candidate_buttons(_provider_scope(page, provider, requested)))
                except Exception:
                    has_buttons = False
                if not has_buttons:
                    emit(Event('info', 'No download buttons detected. Check login, plan and page selection; manual clicks are still captured.'))
                emit(Event('info', f'Automatic discovery of visible download controls, up to {limit} clicks.'))
                seen = set()
                idle_rounds = 0
                while attempts < limit and idle_rounds < 3 and not stop.is_set():
                    if pause:
                        while not pause.wait(.25):
                            if stop.is_set():
                                break
                    if stop.is_set():
                        break
                    page = _active_page(page)
                    if page is None:
                        browser_closed_by_user = True
                        break
                    _drain_downloads(attempts, limit)
                    try:
                        if not _trusted(page.url, provider):
                            break
                        controls = _candidate_buttons(_provider_scope(page, provider, requested))
                    except Exception:
                        if _active_page(page) is None:
                            browser_closed_by_user = True
                            break
                        controls = []
                    chosen = None
                    for el, label in controls:
                        try:
                            surrounding = el.evaluate('e => (e.closest("tr, li, [role=row]") || e.parentElement)?.innerText?.slice(0,160) || ""')
                            signature = hashlib.sha256((label + '|' + surrounding).encode()).hexdigest()
                            if signature not in seen:
                                chosen = (el, label, signature)
                                break
                        except Exception:
                            continue
                    if not chosen:
                        idle_rounds += 1
                        if not _safe_wait(page, 700) and _active_page(page) is None:
                            browser_closed_by_user = True
                            break
                        continue
                    idle_rounds = 0
                    el, label, signature = chosen
                    seen.add(signature)
                    attempts += 1
                    before = collector.downloaded
                    try:
                        el.click(timeout=4500)
                        _safe_wait(page, 650)
                        if not events:
                            dialog = page.locator('[role="dialog"]:visible, dialog:visible').first
                            if dialog.count():
                                choices = _candidate_buttons(dialog)
                                selected = next(((b, n) for b, n in choices if _is_download_action(n)), None)
                                if selected:
                                    selected[0].click(timeout=4000)
                                    _safe_wait(page, 500)
                        _drain_downloads(attempts, limit)
                    except Exception as exc:
                        if _active_page(page) is None:
                            browser_closed_by_user = True
                            break
                        collector.failures += 1
                        emit(Event('skip', f'{provider}: download control #{attempts} did not yield a profile ({type(exc).__name__})', attempts, limit))
                    if collector.downloaded == before and attempts % 5 == 0:
                        emit(Event('info', f'{provider}: some controls are inaccessible; manual downloads inside this browser will also be captured.'))
                    if delay:
                        if not _safe_wait(page, int(max(0.5, delay) * 1000)) and _active_page(page) is None:
                            browser_closed_by_user = True
                            break
            if not stop.is_set() and not browser_closed_by_user:
                if collector.downloaded > initial:
                    grace_seconds = 3 if interactive_real_browser else 1
                else:
                    grace_seconds = 300 if interactive_real_browser else 12
                    if interactive_real_browser:
                        emit(Event(
                            'info',
                            f'{provider}: no configs captured automatically yet. Download any OpenVPN UDP/TCP ZIP or WireGuard .conf manually — close Chrome (or click Stop) when finished.',
                        ))
                grace = time.monotonic() + grace_seconds
                while time.monotonic() < grace and not stop.is_set():
                    page = _active_page(page)
                    _drain_downloads()
                    if page is None:
                        browser_closed_by_user = True
                        break
                    if not _safe_wait(page, 450) and _active_page(page) is None:
                        browser_closed_by_user = True
                        break
            _drain_downloads()
        finally:
            try:
                context.close()
            except Exception:
                pass
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
            if profile_path is not None:
                from ..accounts import harden_profile_tree
                harden_profile_tree(Path(profile_path))
    return {
        'visited': attempts,
        'downloaded': collector.downloaded - initial,
        'note': 'Browser-download automation depends on the service UI; WireGuard requires valid account-generated keys.',
    }
