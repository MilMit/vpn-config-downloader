"""Non-blocking QThread workers for network, browser, validation, and scheduling tasks."""
from __future__ import annotations

from pathlib import Path
from threading import Event as ThreadEvent

from PySide6.QtCore import QThread, Signal

from ..accounts import ProtocolVault, VaultUnavailable, manual_login, windscribe_cookie
from ..auth_export import add_openvpn_auth_files
from ..core import Event as CoreEvent, export_archive, provider_output_dir
from ..credential_discovery import discover_openvpn_credentials
from ..health import batch_validate, probe_profile
from ..protocol_manifest import build_manifest
from ..scheduler import ConfigScheduler, ScheduleJobSpec
from ..security import aes_zip, public_from_private, redact_secrets, remove_plaintext_tree
from ..session_check import check_account_session


class DiscoveryThread(QThread):
    result = Signal(object)
    failed = Signal(str)

    def __init__(self, provider, source: str = 'live'):
        super().__init__()
        self.provider = provider
        self.source = source

    def run(self):
        try:
            self.result.emit(self.provider.discover(source=self.source))
        except Exception as ex:
            self.failed.emit(redact_secrets(f'{type(ex).__name__}: {str(ex)[:200]}'))


class WorkThread(QThread):
    event = Signal(object)
    result = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        provider,
        locations,
        creds,
        opts,
        source,
        embed_auth: bool = False,
        zip_password: str = '',
        keep_plaintext: bool = True,
    ):
        super().__init__()
        self.provider = provider
        self.locations = locations
        self.creds = creds
        self.opts = opts
        self.source = source
        self.embed_auth = embed_auth
        self.zip_password = zip_password
        self.keep_plaintext = keep_plaintext
        self.stop_event = ThreadEvent()
        self.pause_event = ThreadEvent()
        self.pause_event.set()

    def run(self):
        try:
            if (
                self.provider.key == 'windscribe'
                and not self.creds.website_cookie
                and bool(set(self.opts.protocols) & {'wireguard', 'udp', 'tcp', 'stealth', 'wstunnel'})
            ):
                try:
                    saved_tok = ProtocolVault().get_session_token('windscribe', self.opts.account)
                except VaultUnavailable:
                    saved_tok = None
                if saved_tok:
                    self.event.emit(CoreEvent('info', f'Using saved Windscribe session token from OS keyring ({self.opts.account})…'))
                    self.creds.website_cookie = saved_tok
                else:
                    self.event.emit(CoreEvent('info', 'Reading your Windscribe session from the saved browser profile…'))
                    self.creds.website_cookie = windscribe_cookie(account=self.opts.account)
                if not self.creds.website_cookie:
                    raise RuntimeError(
                        'Windscribe login session is unavailable/expired. Use Accounts → Login or Visual Guide to save your session.'
                    )
            # A private key in the vault is never copied to QSettings or logs.
            if self.provider.key in ('windscribe', 'surfshark') and 'wireguard' in self.opts.protocols and not self.creds.wireguard_private_key_file:
                try:
                    key = ProtocolVault().get_wireguard(self.provider.key, self.opts.account)
                except VaultUnavailable:
                    key = None
                if key:
                    self.creds.wireguard_private_key_data = key
                    public = public_from_private(key)
                    if self.creds.wireguard_public_key and self.creds.wireguard_public_key != public:
                        raise ValueError('The public key differs from the selected account key in keyring')
                    self.creds.wireguard_public_key = public

            # Disable provider's legacy plaintext ZIP until finalized and validated.
            requested_archive = self.opts.archive
            self.opts.archive = False
            outcome = self.provider.export(
                locations=self.locations,
                credentials=self.creds,
                options=self.opts,
                source_path=self.source,
                emit=self.event.emit,
                stop=self.stop_event,
                pause=self.pause_event,
            )
            if self.embed_auth and not self.stop_event.is_set():
                stored = ProtocolVault().get_openvpn(self.provider.key, self.opts.account)
                if not stored:
                    raise RuntimeError('OpenVPN service credentials are missing from the OS keyring.')
                root = provider_output_dir(self.opts, self.provider.key)
                details = add_openvpn_auth_files(root, *stored)
                outcome['openvpn_auth_export'] = {k: v for k, v in details.items() if k != 'warning'}
                self.event.emit(CoreEvent('info', details['warning']))
            if not self.stop_event.is_set():
                root = provider_output_dir(self.opts, self.provider.key)
                summary = build_manifest(root)
                outcome['config_inventory'] = summary
                self.event.emit(
                    CoreEvent(
                        'info',
                        f'Inventory: {summary["total_structurally_valid"]} valid file structures; {summary["missing_actions"]} require attention.',
                    )
                )
                has_config = bool(summary['total_structurally_valid']) or bool(list(root.rglob('*.swanctl.conf')))
                if requested_archive and has_config:
                    if self.zip_password:
                        final = aes_zip(root, self.zip_password)
                        outcome['archive'] = str(final)
                        outcome['archive_encrypted'] = True
                        if not self.keep_plaintext:
                            remove_plaintext_tree(root, archive=final)
                            outcome['plaintext_removed'] = True
                    else:
                        outcome['archive'] = str(export_archive(root))
                        outcome['archive_encrypted'] = False
            self.result.emit(outcome)
        except Exception as ex:
            extra = ' No secure OS keyring is available.' if isinstance(ex, VaultUnavailable) else ''
            self.failed.emit(
                redact_secrets(
                    f'{type(ex).__name__}: operation failed. Check account state, credentials and network.{extra}',
                    secrets=(self.zip_password, self.creds.website_cookie, self.creds.wireguard_private_key_data),
                )
            )
        finally:
            self.zip_password = ''
            self.creds.website_cookie = ''
            self.creds.wireguard_private_key_data = ''

    def stop(self):
        self.stop_event.set()
        self.pause_event.set()

    def toggle_pause(self) -> bool:
        if self.pause_event.is_set():
            self.pause_event.clear()
            return True
        self.pause_event.set()
        return False


class AccountLoginThread(QThread):
    info = Signal(str)
    finished_info = Signal(str)
    failed = Signal(str)

    def __init__(self, provider: str, account: str = 'default'):
        super().__init__()
        self.provider = provider
        self.account = account
        self.cancel = ThreadEvent()

    def run(self):
        try:
            result = manual_login(self.provider, account=self.account, stop=self.cancel, emit=self.info.emit)
            self.finished_info.emit(result)
        except Exception as ex:
            msg = redact_secrets(str(ex)).splitlines()[0][:240]
            self.failed.emit(f'{type(ex).__name__}: {msg or "browser sign-in could not be completed."}')


class AccountCheckThread(QThread):
    result = Signal(object)

    def __init__(self, provider: str, account: str):
        super().__init__()
        self.provider = provider
        self.account = account

    def run(self):
        self.result.emit(check_account_session(self.provider, self.account))


class HealthThread(QThread):
    result = Signal(object)

    def __init__(self, path: str, *, verify_vpn: bool = False, user_consent: bool = False):
        super().__init__()
        self.path = path
        self.verify_vpn = verify_vpn
        self.user_consent = user_consent

    def run(self):
        try:
            self.result.emit(
                probe_profile(
                    Path(self.path),
                    verify_vpn=self.verify_vpn,
                    user_consent=self.user_consent,
                )
            )
        except Exception as e:
            self.result.emit({
                'state': 'error',
                'reason': type(e).__name__,
                'vpn_verified': False,
                'syntax_validation': {'status': 'invalid', 'label': 'Error', 'warnings': [type(e).__name__], 'required_actions': []},
                'endpoint_reachability': {'status': 'not_tested', 'label': 'Not Tested', 'dns': 'not_tested', 'tcp': 'not_tested'},
                'vpn_connection_verification': {'status': 'not_tested', 'label': 'Not Tested', 'vpn_verified': False, 'reason': type(e).__name__},
            })


class BatchHealthThread(QThread):
    progress = Signal(int, int, object)
    finished_results = Signal(object)
    failed = Signal(str)

    def __init__(self, folder: str, *, check_reachability: bool = False):
        super().__init__()
        self.folder = folder
        self.check_reachability = check_reachability
        self.stop_event = ThreadEvent()

    def run(self):
        try:
            results = batch_validate(
                Path(self.folder),
                check_reachability=self.check_reachability,
                stop=self.stop_event,
                on_progress=lambda cur, tot, rec: self.progress.emit(cur, tot, rec),
            )
            self.finished_results.emit(results)
        except Exception as ex:
            self.failed.emit(f'{type(ex).__name__}: {str(ex)[:180]}')

    def stop(self):
        self.stop_event.set()


class CredentialReadThread(QThread):
    result = Signal(object)
    failed = Signal(str)

    def __init__(self, provider: str, account: str, session_token: str = ''):
        super().__init__()
        self.provider = provider
        self.account = account
        self.session_token = session_token

    def run(self):
        try:
            self.result.emit(
                discover_openvpn_credentials(
                    self.provider,
                    self.account,
                    session_token=self.session_token,
                )
            )
        except Exception as exc:
            self.failed.emit(f'Could not read OpenVPN credentials ({type(exc).__name__}). Copy them from the official portal.')


class ScheduledRefreshThread(QThread):
    event = Signal(object)
    finished_record = Signal(object)

    def __init__(self, spec: ScheduleJobSpec):
        super().__init__()
        self.spec = spec
        self.stop_event = ThreadEvent()
        self.pause_event = ThreadEvent()
        self.pause_event.set()

    def run(self):
        scheduler = ConfigScheduler()
        rec = scheduler.run_once(
            self.spec,
            emit=self.event.emit,
            stop=self.stop_event,
            pause=self.pause_event,
        )
        self.finished_record.emit(rec)

    def stop(self):
        self.stop_event.set()
        self.pause_event.set()
