"""Windscribe adapter using concurrent DownloadManager + manual-config backend."""
from __future__ import annotations

import re
from pathlib import Path

from . import windscribe_backend_v3 as legacy
from .base import Provider
from ..core import (
    Capability,
    Credentials,
    Event,
    Location,
    Options,
    export_archive,
    provider_output_dir,
    safe_filename,
    safe_store,
    write_report,
)
from ..download_manager import DownloadManager, DownloadTask


class Windscribe(Provider):
    key = 'windscribe'
    label = 'Windscribe'
    official_url = 'https://windscribe.com/myaccount/config-generator'
    description = 'Account-owned bulk OpenVPN, WireGuard & IKEv2 generator via api.windscribe.com (Pro required); Stealth/WStunnel experimental proxy kits.'
    supports_server_discovery = True
    capabilities = (
        Capability('wireguard', 'direct', 'Official /WgConfigs/permanent API (generates registered keypair or uses your Keyring key)'),
        Capability('udp', 'direct', 'Official /ServerConfigs OpenVPN UDP API (Base64-decoded automatically)'),
        Capability('tcp', 'direct', 'Official /ServerConfigs OpenVPN TCP API (Base64-decoded automatically)'),
        Capability('ikev2', 'direct', 'Official /ServerDatacenters ike_hostname + /ServerCredentials StrongSwan profiles'),
        Capability('stealth', 'experimental', 'Experimental OpenVPN-over-TLS proxy kit (requires external stunnel/wstunnel client)'),
        Capability('wstunnel', 'experimental', 'Experimental OpenVPN-over-WebSocket proxy kit (requires external Windscribe wstunnel binary)'),
    )

    def discover(self, *, source: str = 'live') -> list[Location]:
        return [
            Location(
                key=r['id'],
                country=r['country'],
                name=r['label'],
                tier='pro' if r['pro'] else 'free',
                extras=r,
            )
            for r in legacy.load_locations(source, 25)
        ]

    def export(self, *, locations, credentials: Credentials, options: Options, source_path, emit, stop, pause):
        protocols = list(dict.fromkeys(options.protocols))
        if not locations:
            raise ValueError('No Windscribe locations selected. Fetch locations first.')
        web_needed = bool(set(protocols) & {'wireguard', 'udp', 'tcp', 'stealth', 'wstunnel'})
        if web_needed and (not credentials.website_cookie or any(c in credentials.website_cookie for c in '\r\n; ')):
            raise ValueError('Windscribe website session cookie required for OpenVPN/WireGuard requests.')
        root = provider_output_dir(options, self.key)
        root.mkdir(parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass

        # WG keys never appear in logs, command-line arguments or QSettings.
        wg_priv = ''
        wg_pub = credentials.wireguard_public_key.strip()
        if 'wireguard' in protocols and credentials.wireguard_private_key_data:
            from ..security import public_from_private
            wg_priv = credentials.wireguard_private_key_data.strip()
            derived_pub = public_from_private(wg_priv)
            if wg_pub and derived_pub != wg_pub:
                raise ValueError('Provided WireGuard private/public keys do not match.')
            wg_pub = derived_pub
        elif 'wireguard' in protocols and credentials.wireguard_private_key_file:
            wg_priv, derived_pub = legacy.read_wireguard_private_key(credentials.wireguard_private_key_file)
            if wg_pub and derived_pub != wg_pub:
                raise ValueError('Provided WireGuard private/public keys do not match.')
            wg_pub = derived_pub
        if 'wireguard' in protocols and not wg_pub:
            emit(Event('info', 'Windscribe WireGuard: no local key supplied; API will generate a registered keypair.'))

        hosts = legacy.read_verified_ike_hosts(credentials.ikev2_hostnames_file)
        endpoints = legacy.read_transport_endpoints(credentials.transport_endpoints_file)
        creds = None
        if 'ikev2' in protocols:
            ike_token = credentials.ikev2_auth_hash or credentials.website_cookie
            if ike_token and not hosts:
                try:
                    api_hosts = legacy.get_official_ikev2_hostnames(ike_token, options.timeout)
                    if api_hosts:
                        hosts = api_hosts
                        emit(Event('info', f'IKEv2: loaded {len(hosts)} official hostnames from api.windscribe.com/ServerDatacenters.'))
                except Exception as ex:
                    emit(Event('info', f'IKEv2 official datacenter hostnames unavailable ({type(ex).__name__}); checking user CSV.'))
            try:
                if credentials.ikev2_credentials_file:
                    creds = legacy.read_ikev2_credentials_file(credentials.ikev2_credentials_file)
                elif ike_token:
                    creds = legacy.get_ikev2_credentials(ike_token, options.timeout)
                else:
                    emit(Event('info', 'IKEv2: provide Windscribe session token or credentials JSON.'))
            except Exception as ex:
                emit(Event('fail', f'IKEv2 credential retrieval failed: {type(ex).__name__}'))

        output = []
        errors = []
        successes = 0
        reused = 0
        failures = 0
        experimental = 0
        skipped = 0

        # 1. Handle local IKEv2 templates (no per-location HTTP fetch needed)
        if 'ikev2' in protocols:
            for loc in locations:
                if stop.is_set():
                    break
                while not pause.wait(.2):
                    if stop.is_set():
                        break
                if stop.is_set():
                    break
                country_dir = safe_filename(loc.country or 'XX')
                name = f'{country_dir}-{safe_filename(loc.key)}-{safe_filename(loc.name)}'
                if creds and loc.key in hosts:
                    try:
                        conf, sec = legacy.make_ikev2_conf(hosts[loc.key], creds[0], creds[1], f'ws_{loc.key}')
                        c = root / 'IKEv2' / 'Verified-StrongSwan' / country_dir / (name + '.swanctl.conf')
                        s = root / 'IKEv2' / 'Verified-StrongSwan' / country_dir / (name + '.secrets.conf')
                        safe_store(c, conf)
                        safe_store(s, sec)
                        successes += 1
                        output.append({
                            'location': loc.name,
                            'location_key': loc.key,
                            'country': loc.country,
                            'protocol': 'ikev2',
                            'status': 'generated_from_user_supplied_hostname',
                            'file': str(c.relative_to(root)),
                        })
                        emit(Event('success', f'IKEv2 template: {loc.name}'))
                    except Exception as ex:
                        failures += 1
                        errors.append({'location': loc.name, 'protocol': 'ikev2', 'error_type': type(ex).__name__})
                        emit(Event('fail', f'IKEv2 {loc.name}: {type(ex).__name__}'))
                else:
                    skipped += 1
                    emit(Event('skip', f'IKEv2 {loc.name}: official hostname/credentials missing'))

        # 2. Build concurrent DownloadTasks for OpenVPN UDP/TCP & WireGuard
        tasks: list[DownloadTask] = []
        task_loc_map: dict[str, tuple[Location, str, str, Path, str]] = {}
        for loc in locations:
            row = loc.extras
            country_dir = safe_filename(loc.country or 'XX')
            name = f'{country_dir}-{safe_filename(loc.key)}-{safe_filename(loc.name)}'
            for kind in ('udp', 'tcp', 'wireguard'):
                need_tcp = kind == 'tcp' and bool(set(protocols) & {'stealth', 'wstunnel'})
                if kind not in protocols and not need_tcp:
                    continue
                for port in options.ports[kind]:
                    fproto = 'WireGuard' if kind == 'wireguard' else f'OpenVPN-{kind.upper()}'
                    if need_tcp and kind not in protocols:
                        fproto = '_TransportSourceTCP'
                    ext = '.conf' if kind == 'wireguard' else '.ovpn'
                    dst = root / fproto / country_dir / (name + '-p' + port + ext)
                    task_id = f'{loc.key}:{kind}:{port}'
                    label = f'{loc.country} {loc.name} • {kind.upper()}:{port}'

                    def _make_fetcher(k=kind, r=row, p=port):
                        def _fetch():
                            body = legacy.get_manual_config(
                                k, credentials.website_cookie, r, p, options.timeout, wg_pub, retries=0
                            )
                            if k == 'wireguard':
                                body = legacy.make_wireguard_portable(body, wg_priv)
                            return body
                        return _fetch

                    tasks.append(
                        DownloadTask(
                            task_id=task_id,
                            label=label,
                            protocol=kind,
                            destination=dst,
                            fetcher=_make_fetcher(),
                            metadata={'location': loc.name, 'location_key': loc.key, 'country': loc.country, 'port': port},
                        )
                    )
                    task_loc_map[task_id] = (loc, kind, port, dst, name)

        # Execute concurrently via DownloadManager (with rate-limiting, retries, checkpointing & atomic verification)
        manager = DownloadManager(
            root,
            concurrency=max(1, getattr(options, 'concurrency', 2)),
            retries=options.retries,
            delay=options.delay,
            overwrite=options.overwrite,
        )
        outcomes = manager.run(tasks, emit=emit, stop=stop, pause=pause)

        for res in outcomes:
            loc, kind, port, dst, name = task_loc_map[res.task_id]
            if res.status in ('downloaded', 'reused'):
                if res.status == 'downloaded':
                    successes += 1
                else:
                    reused += 1
                try:
                    contents = dst.read_text('utf-8')
                except OSError:
                    contents = ''
                portable = (kind != 'wireguard' or bool(re.search(r'(?mi)^\s*PrivateKey\s*=', contents)))
                output.append({
                    'location': loc.name,
                    'location_key': loc.key,
                    'country': loc.country,
                    'protocol': kind,
                    'port': port,
                    'status': res.status,
                    'portable': portable,
                    'file': res.file,
                })
                if kind == 'tcp' and contents:
                    for transport in ('stealth', 'wstunnel'):
                        if transport not in protocols:
                            continue
                        verified = endpoints.get((loc.key, transport))
                        if not verified:
                            cand_host = (loc.extras.get('node_ip3') or loc.extras.get('node_hostname') or loc.extras.get('openvpn_hostname') or '').strip()
                            if not cand_host:
                                skipped += 1
                                emit(Event('skip', f'{transport} {loc.name}: no candidate or user-supplied remote endpoint available'))
                                continue
                            verified = {
                                'remote_host': cand_host,
                                'remote_port': 443,
                                'backend_port': 1194 if transport == 'wstunnel' else None,
                                'verification': 'EXPERIMENTAL_FROM_LIVE_SERVERLIST_REQUIRES_EXTERNAL_PROXY',
                            }
                        kit_meta = legacy.make_kit(
                            loc.extras,
                            contents,
                            root / 'Experimental-Transports' / transport / safe_filename(loc.country or 'XX') / name,
                            transport,
                            f'{name}-p{port}',
                            verified_endpoint=verified,
                        )
                        experimental += 1
                        output.append({
                            'location': loc.name,
                            'location_key': loc.key,
                            'country': loc.country,
                            'protocol': transport,
                            'port': '443',
                            'status': 'experimental_kit',
                            'file': str(kit_meta.relative_to(root)),
                        })
                        emit(Event('info', f'{transport}: experimental proxy kit generated for {loc.name} (requires external proxy binary)'))
            elif res.status == 'duplicate':
                skipped += 1
                output.append({
                    'location': loc.name,
                    'location_key': loc.key,
                    'country': loc.country,
                    'protocol': kind,
                    'port': port,
                    'status': 'duplicate',
                })
            elif res.status == 'failed':
                failures += 1
                err_rec = {
                    'location': loc.name,
                    'location_key': loc.key,
                    'country': loc.country,
                    'protocol': kind,
                    'port': port,
                    'status': 'failed',
                    'error_type': res.error_type,
                    'error_detail': res.error_detail,
                }
                output.append(err_rec)
                errors.append(err_rec)

        if experimental:
            safe_store(
                root / 'Experimental-Transports' / 'TRANSPORT_KITS_README.txt',
                'Stealth & WStunnel files are EXPERIMENTAL KITS, NOT standalone OpenVPN profiles.\n'
                'Each kit contains a localhost-pointed .ovpn + .kit.json metadata.\n'
                'Start an external compatible Windscribe wstunnel/stunnel proxy listening on 127.0.0.1:65479,\n'
                'then open the local .ovpn in your OpenVPN client.\n'
                'Official Windscribe wstunnel source: https://github.com/Windscribe/wstunnel\n',
            )

        payload = {
            'provider': self.key,
            'status': 'cancelled' if stop.is_set() else 'completed',
            'verified_live_account': False,
            'generated': successes,
            'reused': reused,
            'failed': failures,
            'skipped': skipped,
            'experimental_transport_kits': experimental,
            'checkpoint': str(manager.checkpoint.path.relative_to(root)),
            'checkpoint_summary': manager.checkpoint.summary(),
            'errors': errors,
            'results': output,
            'notes': [
                'Manual-config API compatibility and VPN connectivity are not proven.',
                'Only the GUI/CLI export controller can enable AES-256 ZIP encryption; profiles in the working folder contain sensitive data.',
                'IKEv2 verified label means USER-SUPPLIED hostname, not independently checked.',
                'Stealth/WStunnel kits require independently sourced tunnel executable and real endpoints.',
            ],
        }
        write_report(root, payload)
        if options.archive and (successes or reused or experimental):
            payload['archive'] = str(export_archive(root))
        return payload
