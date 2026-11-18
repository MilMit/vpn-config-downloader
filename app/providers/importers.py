"""Surfshark and Proton VPN providers: automatic official retrieval, bulk cluster generation, or file import."""
from __future__ import annotations

from pathlib import Path

from .base import Provider
from .official_download import (
    Collected,
    browser_account_download,
    fetch_official_surfshark_openvpn,
    fetch_surfshark_clusters,
    generate_surfshark_ikev2_bulk,
    generate_surfshark_wireguard_bulk,
)
from ..accounts import profile_dir
from ..core import Capability, Event, Location, export_archive, import_profiles, provider_output_dir, write_report


class AccountProvider(Provider):
    capabilities = ()

    def _import(self, source: Path, root: Path, *, emit, stop, pause):
        if source.is_dir() and (root == source or root.is_relative_to(source)):
            raise ValueError('Export directory cannot be inside the imported source folder.')
        outcome = import_profiles(source, root, on_progress=emit, stop=stop, pause=pause)
        outcome.update(provider=self.key, mode='local_import', downloaded=0)
        return outcome

    def export(self, *, locations, credentials, options, source_path, emit, stop, pause):
        root = provider_output_dir(options, self.key)
        root.mkdir(parents=True, exist_ok=True)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        # Existing importer deliberately remains supported. Empty source means AUTO.
        if source_path:
            outcome = self._import(
                Path(source_path).expanduser().resolve(),
                root,
                emit=emit,
                stop=stop,
                pause=pause,
            )
        else:
            protocols = set(options.protocols)
            allowed = {'udp', 'tcp'} if 'openvpn' in protocols else set()
            allowed |= protocols & {'wireguard', 'udp', 'tcp'}
            selected_hosts = {loc.key for loc in (locations or []) if getattr(loc, 'key', '')}
            selected_hosts |= set(getattr(options, 'selected_keys', []) or [])
            collector = Collected(root, allowed=allowed, selected_hosts=selected_hosts, progress=emit)
            warnings = []
            errors = []
            extra_records = []
            ikev2_count = 0

            # 1. Surfshark public OpenVPN UDP/TCP bulk ZIP
            if self.key == 'surfshark' and protocols & {'openvpn', 'udp', 'tcp'}:
                try:
                    fetch_official_surfshark_openvpn(
                        collector,
                        timeout=options.timeout,
                        emit=emit,
                        stop=stop,
                        pause=pause,
                        overwrite=options.overwrite,
                    )
                except Exception as e:
                    msg = 'Surfshark public ZIP unavailable (' + type(e).__name__ + ')'
                    warnings.append(msg)
                    errors.append({'protocol': 'openvpn', 'error_type': type(e).__name__, 'message': msg})
                    emit(Event('fail', msg))

            # 2. Surfshark bulk WireGuard & IKEv2 from live cluster catalog
            surfshark_clusters = None
            surfshark_wg_bulk_done = False
            if self.key == 'surfshark' and not stop.is_set():
                wg_priv = (getattr(credentials, 'wireguard_private_key_data', '') or '').strip()
                if not wg_priv and getattr(credentials, 'wireguard_private_key_file', ''):
                    try:
                        from .windscribe_backend_v3 import read_wireguard_private_key
                        wg_priv, _ = read_wireguard_private_key(credentials.wireguard_private_key_file)
                    except Exception as e:
                        warnings.append(f'Could not read WireGuard private key file ({type(e).__name__})')
                need_clusters = ('ikev2' in protocols) or ('wireguard' in protocols and bool(wg_priv))
                if need_clusters:
                    try:
                        surfshark_clusters = list(locations) if locations else fetch_surfshark_clusters(timeout=options.timeout)
                    except Exception as e:
                        msg = 'Surfshark live server cluster catalog unavailable (' + type(e).__name__ + ')'
                        warnings.append(msg)
                        errors.append({'protocol': 'clusters', 'error_type': type(e).__name__, 'message': msg})
                        emit(Event('fail', msg))

                if 'wireguard' in protocols and wg_priv and surfshark_clusters:
                    try:
                        wg_count = generate_surfshark_wireguard_bulk(
                            collector,
                            surfshark_clusters,
                            private_key=wg_priv,
                            emit=emit,
                            stop=stop,
                            overwrite=options.overwrite,
                        )
                        surfshark_wg_bulk_done = True
                        emit(Event('info', f'Surfshark WireGuard bulk generation complete: {wg_count} configs (requires Public Key registered in Surfshark account).'))
                    except Exception as e:
                        msg = 'Surfshark WireGuard generation failed (' + type(e).__name__ + ')'
                        warnings.append(msg)
                        errors.append({'protocol': 'wireguard', 'error_type': type(e).__name__, 'message': msg})
                        emit(Event('fail', msg))
                elif 'wireguard' in protocols and not wg_priv:
                    emit(Event('info', 'Tip: Save your Surfshark-registered WireGuard Private Key in Accounts to bulk-generate ALL 178+ WireGuard configs instantly without browser clicks.'))

                if 'ikev2' in protocols and surfshark_clusters and not stop.is_set():
                    try:
                        ike_recs = generate_surfshark_ikev2_bulk(
                            root,
                            surfshark_clusters,
                            selected_hosts=selected_hosts,
                            emit=emit,
                            stop=stop,
                        )
                        ikev2_count = len(ike_recs)
                        extra_records.extend(ike_recs)
                        emit(Event('info', f'Surfshark IKEv2 StrongSwan configs generated: {ikev2_count} gateways (see IKEv2/README_SURFSHARK_IKEV2.txt).'))
                    except Exception as e:
                        msg = 'Surfshark IKEv2 generation failed (' + type(e).__name__ + ')'
                        warnings.append(msg)
                        errors.append({'protocol': 'ikev2', 'error_type': type(e).__name__, 'message': msg})
                        emit(Event('fail', msg))

            # 3. Browser-assisted account acquisition (Proton, or Surfshark WireGuard when no keyring key stored)
            browser_protocols = set()
            if self.key == 'surfshark' and 'wireguard' in protocols and not surfshark_wg_bulk_done:
                browser_protocols.add('wireguard')
            elif self.key == 'proton':
                browser_protocols = protocols & {'wireguard', 'openvpn', 'udp', 'tcp'}
            if browser_protocols and not stop.is_set():
                try:
                    result = browser_account_download(
                        self.key,
                        collector,
                        protocols=list(browser_protocols),
                        limit=options.browser_limit,
                        timeout=options.timeout,
                        delay=options.delay,
                        emit=emit,
                        stop=stop,
                        pause=pause,
                        overwrite=options.overwrite,
                        profile_path=profile_dir(self.key, create=True, account=options.account),
                    )
                    if result.get('note'):
                        warnings.append(result['note'])
                except Exception as e:
                    msg = 'Authenticated browser acquisition unavailable: ' + type(e).__name__
                    warnings.append(msg)
                    errors.append({'protocol': ','.join(sorted(browser_protocols)), 'error_type': type(e).__name__, 'message': msg})
                    emit(Event('fail', msg))

            outcome = {
                'provider': self.key,
                'mode': 'official_auto',
                'downloaded': collector.downloaded + ikev2_count,
                'reused': collector.reused,
                'ignored': collector.ignored,
                'failed': collector.failures + len(errors),
                'ikev2_generated': ikev2_count,
                'records': collector.records + extra_records,
                'errors': errors,
                'warnings': warnings,
                'status': 'cancelled' if stop.is_set() else 'completed',
            }
        # Avoid putting secrets such as VPN private keys in JSON logs.
        write_report(root, outcome)
        produced = outcome.get('downloaded', 0) + outcome.get('reused', 0) + outcome.get('imported', 0)
        outcome['archive'] = str(export_archive(root)) if options.archive and produced else None
        return outcome


class Surfshark(AccountProvider):
    key = 'surfshark'
    label = 'Surfshark'
    official_url = 'https://my.surfshark.com/vpn/manual-setup/main'
    description = 'AUTO: Official OpenVPN UDP/TCP bulk ZIP + Bulk WireGuard (all 178 live clusters via Keyring key or browser) + Bulk IKEv2 StrongSwan profiles.'
    supports_server_discovery = True
    capabilities = (
        Capability('udp', 'direct', 'Official bulk OpenVPN UDP ZIP (142+ servers; service credentials used at connect time)'),
        Capability('tcp', 'direct', 'Official bulk OpenVPN TCP ZIP (142+ servers; service credentials used at connect time)'),
        Capability('wireguard', 'direct', 'Bulk .conf for all 178 live clusters using your registered Keyring private key, or browser portal download'),
        Capability('ikev2', 'direct', 'Bulk StrongSwan IKEv2 profiles for all 178 live gateways (requires manual credentials + surfshark_ikev2.crt from portal)'),
    )
    unsupported_explanations = {
        'stealth': 'Surfshark Camouflage (obfuscation) is app-only and Shadowsocks was discontinued; no standalone manual config exists.',
        'wstunnel': 'Surfshark does not offer WStunnel.',
    }

    def discover(self, *, source: str = 'live') -> list[Location]:
        return fetch_surfshark_clusters(timeout=20)


class ProtonVPN(AccountProvider):
    key = 'proton'
    label = 'Proton VPN'
    official_url = 'https://account.protonvpn.com/downloads'
    description = 'AUTO: opens official account in visible browser for OpenVPN UDP/TCP (single or Download-All ZIP) and WireGuard (.conf) downloads.'
    supports_server_discovery = False
    capabilities = (
        Capability('udp', 'browser', 'Official Proton Downloads portal — individual .ovpn or "Download all configurations" UDP ZIP'),
        Capability('tcp', 'browser', 'Official Proton Downloads portal — individual .ovpn or "Download all configurations" TCP ZIP'),
        Capability('wireguard', 'browser', 'Official Proton Downloads portal — generate & download per-server WireGuard .conf files'),
    )
    unsupported_explanations = {
        'ikev2': 'Proton VPN officially discontinued and removed IKEv2 support in favor of WireGuard and OpenVPN.',
        'stealth': 'Proton Stealth (WireGuard-over-TLS) is proprietary and available only inside official Proton VPN apps; no manual config export exists.',
        'wstunnel': 'Proton VPN does not offer WStunnel.',
    }
