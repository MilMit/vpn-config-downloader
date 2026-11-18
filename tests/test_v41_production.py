"""Comprehensive v4.1 test suite: DownloadManager, 3-stage Validator, Security/ZIP-bomb,
Plugin Registry, Surfshark discovery/filtering, Scheduler, Session metadata, and CLI.
"""
from __future__ import annotations

import base64
import io
import json
import threading
import time
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from app.account_registry import AccountRegistry
from app.cli import main as cli_main
from app.core import CAPABILITY_STATUS_MAP, Capability, Credentials, Location, Options, safe_store
from app.download_manager import DownloadManager, DownloadTask, RateLimitError, TransientDownloadError
from app.health import batch_validate, probe_profile, verify_vpn_connection_isolated
from app.protocol_manifest import analyze_profile
from app.providers import ProviderRegistry, load_providers, register_provider, unregister_provider
from app.providers.base import Provider
from app.providers.importers import Surfshark
from app.providers.official_download import Collected, fetch_surfshark_clusters
from app.providers.windscribe_backend_v3 import read_wireguard_private_key
from app.scheduler import ConfigScheduler, ScheduleJobSpec, validate_unattended_spec
from app.security import (
    aes_zip,
    is_safe_zip_member_name,
    make_keypair,
    public_from_private,
    redact_secrets,
    safe_zip_entries,
    verify_aes_zip,
    verify_wireguard_key_match,
)
from app.session_check import check_account_session

VALID_OVPN = b"""client
dev tun
proto tcp
remote de-fra.prod.surfshark.com 443
remote-cert-tls server
cipher AES-256-GCM
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestcertdata123456
-----END CERTIFICATE-----
</ca>
"""

VALID_OVPN_UDP = b"""client
dev tun
proto udp
remote us-nyc.prod.surfshark.com 1194
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestcertdata654321
-----END CERTIFICATE-----
</ca>
"""

INCOMPLETE_OVPN = b"""client
dev tun
proto udp
remote example.org 1194
"""


def _make_wg_conf(priv: str, pub: str) -> bytes:
    return (
        f"[Interface]\nPrivateKey = {priv}\nAddress = 10.66.0.2/32\nDNS = 1.1.1.1\n"
        f"[Peer]\nPublicKey = {pub}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n"
    ).encode('utf-8')


# ---------- 1. Plugin-based Provider Registry & Protocol Capability Matrix ----------

def test_plugin_provider_registry():
    class CustomVPN(Provider):
        key = 'custom_test_vpn'
        label = 'Custom Test VPN'
        official_url = 'https://example.invalid'
        capabilities = (
            Capability('wireguard', 'direct', 'Direct WG'),
            Capability('ikev2', 'unsupported', 'No IKEv2'),
        )

        def export(self, *, locations, credentials, options, source_path, emit, stop, pause):
            return {'provider': self.key, 'status': 'completed'}

    register_provider(CustomVPN)
    try:
        provs = load_providers()
        assert 'custom_test_vpn' in provs
        matrix = {row['protocol']: row['status'] for row in provs['custom_test_vpn'].protocol_matrix()}
        assert matrix['wireguard'] == 'Supported'
        assert matrix['ikev2'] == 'Unsupported'
        assert matrix['stealth'] == 'Unsupported'
        assert set(matrix.values()).issubset(set(CAPABILITY_STATUS_MAP.values()))
    finally:
        unregister_provider('custom_test_vpn')
    assert 'custom_test_vpn' not in load_providers()


def test_builtin_providers_standardized_statuses():
    allowed = {'Supported', 'Requires Manual Action', 'Experimental', 'Unsupported'}
    for key, prov in load_providers().items():
        mat = prov.protocol_matrix()
        assert len(mat) == 6
        for row in mat:
            assert row['status'] in allowed, f'{key}:{row}'


# ---------- 2. Surfshark Live Schema Parsing & Server Filter ----------

def test_surfshark_clusters_parsing_and_host_filter(tmp_path):
    sample = [
        {
            'country': 'Germany',
            'countryCode': 'DE',
            'location': 'Frankfurt',
            'connectionName': 'de-fra.prod.surfshark.com',
            'load': 18,
            'tags': ['p2p'],
            'pubKey': 'abc=',
        },
        {
            'country': 'United States',
            'countryCode': 'US',
            'location': 'New York',
            'connectionName': 'us-nyc.prod.surfshark.com',
            'load': 25,
            'tags': [],
            'pubKey': 'def=',
        },
    ]

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def geturl(self): return 'https://api.surfshark.com/v4/server/clusters/generic'
        def read(self, n): return json.dumps(sample).encode('utf-8')

    locs = fetch_surfshark_clusters(opener=lambda req, timeout: FakeResp())
    assert len(locs) == 2
    assert locs[0].country == 'DE'
    assert locs[0].city == 'Frankfurt'
    assert locs[0].key == 'de-fra.prod.surfshark.com'

    # Now filter archive to only Germany
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('de-fra.prod.surfshark.com_tcp.ovpn', VALID_OVPN)
        z.writestr('us-nyc.prod.surfshark.com_udp.ovpn', VALID_OVPN_UDP)
    col = Collected(tmp_path, selected_hosts={'de-fra.prod.surfshark.com'})
    count = col.ingest_zip(buf.getvalue(), 'test')
    assert count == 1
    assert col.downloaded == 1
    assert col.records[0]['country'] == 'DE'
    assert (tmp_path / 'OpenVPN-TCP' / 'DE').is_dir()


# ---------- 3. Pure-Python WireGuard Private Key File Derivation (Cross-Platform) ----------

def test_read_wireguard_private_key_without_wg_binary(tmp_path):
    priv, pub = make_keypair()
    key_file = tmp_path / 'wg.key'
    key_file.write_text(priv + '\n', encoding='utf-8')
    with patch('subprocess.run', side_effect=FileNotFoundError('wg not installed')):
        got_priv, got_pub = read_wireguard_private_key(str(key_file))
    assert got_priv == priv
    assert got_pub == pub


# ---------- 4. Professional Download Manager ----------

def test_download_manager_concurrency_retry_dedupe_and_checkpoint(tmp_path):
    attempts = {'t2': 0, 't3': 0}
    lock = threading.Lock()

    def ok_fetcher(i):
        return lambda: VALID_OVPN.replace(b'de-fra', f'node-{i}'.encode())

    def retry_then_ok():
        with lock:
            attempts['t2'] += 1
            n = attempts['t2']
        if n == 1:
            raise RateLimitError('429 slow down', retry_after=0.05)
        return VALID_OVPN.replace(b'de-fra', b'retry-ok')

    def always_fail():
        with lock:
            attempts['t3'] += 1
        raise TransientDownloadError('simulated outage')

    tasks = [
        DownloadTask('t1', 'Node 1', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n1.ovpn', ok_fetcher(1)),
        DownloadTask('t1_dup', 'Node 1 Dup', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n1_dup.ovpn', ok_fetcher(1)),
        DownloadTask('t2', 'Node 2 (429 retry)', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n2.ovpn', retry_then_ok),
        DownloadTask('t3', 'Node 3 (fail)', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n3.ovpn', always_fail),
        DownloadTask('t4', 'Node 4 (invalid HTML)', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n4.ovpn', lambda: b'<html>login</html>'),
    ]
    events = []
    stop = threading.Event()
    pause = threading.Event()
    pause.set()

    mgr = DownloadManager(tmp_path, concurrency=3, retries=1, delay=0.0, base_backoff=0.05, jitter=False)
    outcomes = mgr.run(tasks, emit=events.append, stop=stop, pause=pause)
    by_id = {o.task_id: o for o in outcomes}

    assert {by_id['t1'].status, by_id['t1_dup'].status} == {'downloaded', 'duplicate'}
    assert by_id['t2'].status == 'downloaded'
    assert by_id['t2'].attempts == 2
    assert by_id['t3'].status == 'failed'
    assert by_id['t4'].status == 'failed'
    assert (tmp_path / 'checkpoint.json').is_file()
    assert mgr.checkpoint.failed_ids() == {'t3', 't4'}

    # Now retry ONLY failed tasks from checkpoint, with t3 fixed
    fixed_tasks = [
        DownloadTask('t1', 'Node 1', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n1.ovpn', ok_fetcher(1)),
        DownloadTask('t3', 'Node 3 (fixed)', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n3.ovpn', ok_fetcher(3)),
        DownloadTask('t4', 'Node 4 (fixed)', 'tcp', tmp_path / 'OpenVPN-TCP' / 'n4.ovpn', ok_fetcher(4)),
    ]
    retry_outcomes = mgr.run(fixed_tasks, emit=events.append, stop=stop, pause=pause, only_failed_from_checkpoint=True)
    assert {o.task_id for o in retry_outcomes} == {'t3', 't4'}
    assert all(o.status == 'downloaded' for o in retry_outcomes)
    assert mgr.checkpoint.failed_ids() == set()


def test_download_manager_cancel_interrupts_backoff(tmp_path):
    stop = threading.Event()
    pause = threading.Event()
    pause.set()

    def trigger_backoff():
        # Schedule stop right after throwing 429 with huge 30s Retry-After
        threading.Timer(0.1, stop.set).start()
        raise RateLimitError('long cooldown', retry_after=30.0)

    mgr = DownloadManager(tmp_path, concurrency=1, retries=2, delay=0.0, base_backoff=10.0)
    t0 = time.monotonic()
    outcomes = mgr.run(
        [DownloadTask('slow', 'Slow', 'tcp', tmp_path / 's.ovpn', trigger_backoff)],
        emit=lambda e: None,
        stop=stop,
        pause=pause,
    )
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0  # Proves stop interrupts long backoff immediately
    assert outcomes[0].status == 'cancelled'


# ---------- 5. 3-Stage Configuration Health Checker ----------

def test_three_stage_health_checker_and_batch(tmp_path):
    good = tmp_path / 'good.ovpn'
    good.write_bytes(VALID_OVPN)
    inc = tmp_path / 'incomplete.ovpn'
    inc.write_bytes(INCOMPLETE_OVPN)
    bad = tmp_path / 'bad.ovpn'
    bad.write_bytes(b'<html>not a config</html>')

    class FakeSock:
        def close(self): pass

    res = probe_profile(
        good,
        resolver=lambda h, p, type: [(2, 1, 6, '', ('198.51.100.10', p))],
        connector=lambda addr, timeout: FakeSock(),
    )
    assert res['syntax_validation']['status'] == 'valid_with_warnings'  # requires openvpn service login
    assert res['endpoint_reachability']['status'] == 'tcp_reachable'
    assert res['endpoint_reachability']['resolved_ips'] == ['198.51.100.10']
    assert res['vpn_connection_verification']['status'] == 'not_tested'
    assert res['vpn_connection_verification']['label'] == 'Not Tested'
    assert res['vpn_verified'] is False

    # Incomplete OpenVPN warns about missing CA cert and remote-cert-tls
    inc_info = analyze_profile('incomplete.ovpn', INCOMPLETE_OVPN)
    assert inc_info is not None
    assert inc_info['has_ca_cert'] is False
    assert any('CA certificate' in w for w in inc_info['warnings'])

    # Consent guard for isolated VPN check
    no_consent = verify_vpn_connection_isolated(good, user_consent=False)
    assert no_consent['status'] == 'not_tested'
    assert no_consent['vpn_verified'] is False

    # Batch validation
    batch = batch_validate(tmp_path, check_reachability=False)
    assert len(batch) == 3
    by_name = {r['file']: r for r in batch}
    assert by_name['good.ovpn']['syntax_validation']['status'] != 'invalid'
    assert by_name['bad.ovpn']['syntax_validation']['status'] == 'invalid'
    assert all(r['vpn_connection_verification']['label'] == 'Not Tested' for r in batch)


# ---------- 6. Security: ZIP Bomb, Windows Path Traversal, AES Verify, Key Match, Redaction ----------

def test_zip_bomb_and_windows_path_traversal_defenses(tmp_path):
    assert is_safe_zip_member_name('OpenVPN/de.ovpn') is True
    assert is_safe_zip_member_name('../evil.ovpn') is False
    assert is_safe_zip_member_name('a\\..\\..\\evil.ovpn') is False
    assert is_safe_zip_member_name('C:\\Windows\\evil.ovpn') is False
    assert is_safe_zip_member_name('D:relative.conf') is False
    assert is_safe_zip_member_name('/etc/passwd.ovpn') is False

    # Build a high-compression-ratio ZIP bomb (e.g. 500 KB of spaces -> ~600 bytes compressed, ratio > 500x)
    bomb_path = tmp_path / 'bomb.zip'
    with zipfile.ZipFile(bomb_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('bomb.ovpn', b' ' * 500_000)
    with pytest.raises(ValueError, match='ZIP bomb'):
        list(safe_zip_entries(bomb_path, max_ratio=50.0))


def test_aes_zip_verification_wrong_password_and_plaintext_rejection(tmp_path):
    root = tmp_path / 'export_dir'
    safe_store(root / 'OpenVPN-TCP' / 'de.ovpn', VALID_OVPN)
    arc = aes_zip(root, 'StrongPassphrase#2026!')
    ok = verify_aes_zip(arc, 'StrongPassphrase#2026!')
    assert ok['verified'] is True
    assert ok['entries'] == 1

    with pytest.raises(Exception):
        verify_aes_zip(arc, 'WrongPassphrase#2026!')

    # Unencrypted ZIP must be rejected by verify_aes_zip
    plain_zip = tmp_path / 'plain.zip'
    with zipfile.ZipFile(plain_zip, 'w') as z:
        z.writestr('de.ovpn', VALID_OVPN)
    with pytest.raises(ValueError, match='unencrypted'):
        verify_aes_zip(plain_zip, 'StrongPassphrase#2026!')


def test_wireguard_key_match_and_secret_redaction():
    priv1, pub1 = make_keypair()
    priv2, pub2 = make_keypair()
    conf = _make_wg_conf(priv1, pub2).decode('utf-8')

    m_ok = verify_wireguard_key_match(conf, priv1)
    assert m_ok['matches'] is True
    assert m_ok['status'] == 'matched'
    assert m_ok['expected_public_key'] == pub1

    m_bad = verify_wireguard_key_match(conf, priv2)
    assert m_bad['matches'] is False
    assert m_bad['status'] == 'mismatch'

    raw_log = f"Error with PrivateKey = {priv1} and Cookie: ws_session_auth_hash=tok12345; Authorization: Bearer secretjwt"
    cleaned = redact_secrets(raw_log, secrets=(priv1,))
    assert priv1 not in cleaned
    assert 'tok12345' not in cleaned
    assert 'secretjwt' not in cleaned
    assert '[REDACTED]' in cleaned


# ---------- 7. Session Check Status Persistence ----------

def test_session_check_expired_and_accessible_persistence(tmp_path):
    from app.accounts import profile_dir

    p = profile_dir('windscribe', base=tmp_path, account='work', create=True)
    (p / 'Local State').write_text('state')

    class FakeLocator:
        def __init__(self, count_val): self._c = count_val
        def count(self): return self._c

    class FakePage:
        def __init__(self, url, pw_inputs=0, text=''):
            self.url = url
            self._pw = pw_inputs
            self._text = text
        def goto(self, url, **kw): pass
        def wait_for_timeout(self, ms): pass
        def locator(self, sel): return FakeLocator(self._pw)
        def evaluate(self, js): return self._text

    class FakeCtx:
        def __init__(self, page): self.pages = [page]
        def close(self): pass

    class FakePW:
        def __init__(self, page): self._page = page
        def __enter__(self): return self
        def __exit__(self, *a): pass
        @property
        def chromium(self): return self
        def launch_persistent_context(self, path, **kw): return FakeCtx(self._page)

    # 1. Expired redirect
    r_exp = check_account_session(
        'windscribe', 'work',
        factory=lambda: FakePW(FakePage('https://windscribe.com/login')),
        base=tmp_path,
    )
    assert r_exp.state == 'expired'
    reg = AccountRegistry(tmp_path)
    assert reg.get_status('windscribe', 'work')['state'] == 'expired'

    # 2. Portal accessible + plan hint
    r_ok = check_account_session(
        'windscribe', 'work',
        factory=lambda: FakePW(FakePage('https://windscribe.com/myaccount/config-generator', 0, 'My Account Pro Unlimited')),
        base=tmp_path,
    )
    assert r_ok.state == 'portal_accessible'
    assert 'Pro' in r_ok.plan_hint
    assert reg.get_status('windscribe', 'work')['plan_hint'] == r_ok.plan_hint


# ---------- 8. Automatic Scheduler ----------

def test_scheduler_policy_change_detection_and_history(tmp_path):
    # Policy: refuse interactive providers / protocols
    with pytest.raises(ValueError, match='interactive'):
        validate_unattended_spec(ScheduleJobSpec(provider='proton', protocols=('udp',)))
    with pytest.raises(ValueError, match='interactive'):
        validate_unattended_spec(ScheduleJobSpec(provider='windscribe', protocols=('udp',)))
    with pytest.raises(ValueError, match='manual'):
        validate_unattended_spec(ScheduleJobSpec(provider='surfshark', protocols=('wireguard',)))

    # Authorized Surfshark OpenVPN scheduled run with change detection
    class StubSurfshark(Provider):
        key = 'surfshark'
        label = 'Surfshark'
        def __init__(self): self.runs = 0
        def export(self, *, locations, credentials, options, source_path, emit, stop, pause):
            self.runs += 1
            out = Path(options.output) / 'surfshark' / 'OpenVPN-TCP'
            safe_store(out / 'de.ovpn', VALID_OVPN)
            if self.runs >= 2:
                safe_store(out / 'us.ovpn', VALID_OVPN_UDP)
            return {'provider': 'surfshark', 'downloaded': 1, 'reused': 0, 'failed': 0}

    stub = StubSurfshark()
    sched = ConfigScheduler(base=tmp_path / 'state', provider_loader=lambda: {'surfshark': stub})
    spec = ScheduleJobSpec(provider='surfshark', protocols=('udp', 'tcp'), output=str(tmp_path / 'out'))

    r1 = sched.run_once(spec)
    assert r1['status'] == 'completed'
    assert r1['new_files'] == 1
    assert r1['unchanged_files'] == 0

    r2 = sched.run_once(spec)
    assert r2['status'] == 'completed'
    assert r2['new_files'] == 1
    assert r2['unchanged_files'] == 1

    hist = sched.history.list()
    assert len(hist) == 2
    assert hist[0]['new_files'] == 1
    assert hist[0]['unchanged_files'] == 1


# ---------- 9. CLI ----------

def test_cli_list_providers_and_validate(tmp_path, capsys):
    rc = cli_main(['--list-providers'])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out.keys()) >= {'windscribe', 'surfshark', 'proton'}
    assert len(out['surfshark']['protocols']) == 6

    cfg = tmp_path / 'sample.ovpn'
    cfg.write_bytes(VALID_OVPN)
    rc2 = cli_main(['--validate', str(tmp_path)])
    assert rc2 == 0
    out2 = json.loads(capsys.readouterr().out)
    assert out2['scanned'] == 1
    assert out2['syntax_valid'] == 1
    assert out2['vpn_verified'] == 0


def test_browser_account_download_handles_user_closing_window_gracefully(tmp_path):
    """Closing the browser window mid-session must NOT raise TargetClosedError and must keep captured files."""
    from app.providers.official_download import browser_account_download

    class TargetClosedError(Exception):
        pass

    class FakeDownload:
        suggested_filename = 'proton-nl.ovpn'
        def save_as(self, dst):
            Path(dst).write_bytes(VALID_OVPN)

    class FakeLocator:
        def count(self): return 0

    class FakePage:
        def __init__(self):
            self.url = 'https://account.protonvpn.com/downloads'
            self._closed = False
            self._handlers = {}
            self._waits = 0
        def on(self, event, fn):
            self._handlers[event] = fn
        def goto(self, url, **kw):
            self.url = url
        def is_closed(self):
            return self._closed
        def locator(self, css):
            return FakeLocator()
        def wait_for_timeout(self, ms):
            self._waits += 1
            if self._waits == 1 and 'download' in self._handlers:
                # User manually downloads a config inside the browser
                self._handlers['download'](FakeDownload())
            elif self._waits >= 2:
                # User closes Chrome window
                self._closed = True
                raise TargetClosedError('Target page, context or browser has been closed')

    class FakeContext:
        def __init__(self):
            self.pages = [FakePage()]
        def on(self, event, fn):
            pass
        def close(self):
            pass

    class FakePW:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        @property
        def chromium(self): return self
        def launch_persistent_context(self, path, **kw):
            return FakeContext()

    col = Collected(tmp_path)
    events = []
    pause = threading.Event()
    pause.set()
    res = browser_account_download(
        'proton',
        col,
        protocols=['tcp'],
        limit=5,
        timeout=10,
        delay=0,
        emit=events.append,
        stop=threading.Event(),
        pause=pause,
        playwright_factory=lambda: FakePW(),
        profile_path=tmp_path / 'profile',
    )
    assert res['downloaded'] == 1
    assert col.downloaded == 1
    assert 'closed by user' in res['note'].lower()


def test_surfshark_bulk_wireguard_and_ikev2_generation(tmp_path):
    """Surfshark generates valid bulk WireGuard .conf and StrongSwan IKEv2 profiles from live clusters."""
    user_priv, _ = make_keypair()
    _, srv_pub = make_keypair()
    clusters = [
        Location(
            key='de-fra.prod.surfshark.com',
            country='DE',
            name='Frankfurt (de-fra.prod.surfshark.com)',
            tier='load 12%',
            extras={'connectionName': 'de-fra.prod.surfshark.com', 'city': 'Frankfurt', 'pubKey': srv_pub},
        ),
        Location(
            key='us-nyc.prod.surfshark.com',
            country='US',
            name='New York (us-nyc.prod.surfshark.com)',
            tier='static · load 20%',
            extras={'connectionName': 'us-nyc.prod.surfshark.com', 'city': 'New York', 'pubKey': srv_pub},
        ),
    ]
    pause = threading.Event()
    pause.set()
    opts = Options(output=str(tmp_path), protocols=['wireguard', 'ikev2'], archive=False)
    creds = Credentials(wireguard_private_key_data=user_priv)
    with patch('app.providers.importers.fetch_surfshark_clusters', return_value=clusters):
        res = Surfshark().export(
            locations=[],
            credentials=creds,
            options=opts,
            source_path='',
            emit=lambda e: None,
            stop=threading.Event(),
            pause=pause,
        )
    root = tmp_path / 'surfshark'
    wg_files = list((root / 'WireGuard').rglob('*.conf'))
    ike_files = list((root / 'IKEv2').rglob('*.swanctl.conf'))
    assert len(wg_files) == 2
    assert len(ike_files) == 2
    assert (root / 'IKEv2' / 'README_SURFSHARK_IKEV2.txt').is_file()
    wg_text = wg_files[0].read_text('utf-8')
    assert f'PrivateKey = {user_priv}' in wg_text
    assert f'PublicKey = {srv_pub}' in wg_text
    assert ':51820' in wg_text
    # Ensure report.json never leaks private key
    assert user_priv not in (root / 'report.json').read_text('utf-8')
    assert res['ikev2_generated'] == 2


def test_windscribe_2026_rest_api_openvpn_base64_and_wireguard_json():
    """Windscribe v4.1 REST API decodes Base64 /ServerConfigs and formats /WgConfigs/permanent JSON."""
    from app.providers.windscribe_backend_v3 import get_manual_config

    loc = {'id': '65', 'label': 'Dallas - BBQ'}
    calls = []

    def fake_fetch(url, **kw):
        calls.append((url, kw))
        if '/ServerConfigs' in url:
            assert kw['headers']['Authorization'] == 'Bearer tok-abc'
            assert 'datacenter_id=65' in url and 'protocol=udp' in url and 'config_version=3b' in url
            return base64.b64encode(VALID_OVPN_UDP)
        if '/WgConfigs/permanent' in url:
            assert kw['method'] == 'POST'
            assert kw['headers']['Authorization'] == 'Bearer tok-abc'
            priv, pub = make_keypair()
            return json.dumps({
                'data': {
                    'config': {
                        'PrivateKey': priv,
                        'Address': '100.64.1.2/32',
                        'DNS': '10.255.255.3',
                        'PublicKey': pub,
                        'AllowedIPs': '0.0.0.0/0, ::/0',
                        'Endpoint': 'dal-123.windscribe.com:65142',
                        'PresharedKey': pub,
                    }
                }
            }).encode('utf-8')
        raise AssertionError(f'Unexpected URL: {url}')

    with patch('app.providers.windscribe_backend_v3.retry_fetch_bytes', side_effect=fake_fetch):
        ovpn = get_manual_config('udp', 'tok-abc', loc, '443', 15, retries=0)
        assert 'remote us-nyc.prod.surfshark.com 1194' in ovpn

        wg = get_manual_config('wireguard', 'tok-abc', loc, '65142', 15, retries=0)
        assert '[Interface]' in wg and '[Peer]' in wg
        assert 'Endpoint = dal-123.windscribe.com:65142' in wg
        assert 'PresharedKey =' in wg

    # API JSON error is surfaced cleanly instead of generic structural failure
    err_json = json.dumps({'errorCode': 4000, 'errorMessage': 'Pro subscription required'}).encode('utf-8')
    with patch('app.providers.windscribe_backend_v3.retry_fetch_bytes', return_value=err_json):
        with pytest.raises(ValueError, match='Pro subscription required'):
            get_manual_config('udp', 'tok-abc', loc, '443', 15, retries=0)


def test_windscribe_auto_ikev2_and_experimental_stealth_wstunnel(tmp_path):
    """Windscribe auto-fetches official IKEv2 hostnames from /ServerDatacenters and generates Stealth/WStunnel kits."""
    from app.providers.windscribe import Windscribe

    loc = Location(
        key='86',
        country='US',
        name='Dallas - Ranch',
        tier='pro',
        extras={
            'id': '86',
            'label': 'Dallas - Ranch',
            'country': 'US',
            'pro': True,
            'node_ip3': '198.44.137.29',
            'node_hostname': 'us-central-111.whiskergalaxy.com',
        },
    )
    opts = Options(output=str(tmp_path), protocols=['ikev2', 'stealth', 'wstunnel'], delay=0, archive=False)
    pause = threading.Event()
    pause.set()

    with (
        patch('app.providers.windscribe.legacy.get_official_ikev2_hostnames', return_value={'86': 'us-central.windscribe.com'}),
        patch('app.providers.windscribe.legacy.get_ikev2_credentials', return_value=('ike_user', 'ike_pass')),
        patch('app.providers.windscribe.legacy.get_manual_config', return_value=VALID_OVPN.decode('utf-8')),
    ):
        res = Windscribe().export(
            locations=[loc],
            credentials=Credentials(website_cookie='tok-xyz'),
            options=opts,
            source_path='',
            emit=lambda e: None,
            stop=threading.Event(),
            pause=pause,
        )

    root = tmp_path / 'windscribe'
    assert res['generated'] >= 2  # 1 IKEv2 + 1 _TransportSourceTCP
    assert res['experimental_transport_kits'] == 2  # stealth + wstunnel
    assert list((root / 'IKEv2').rglob('*.swanctl.conf'))
    assert list((root / 'Experimental-Transports' / 'stealth').rglob('*.kit.json'))
    assert list((root / 'Experimental-Transports' / 'wstunnel').rglob('*.kit.json'))
    assert (root / 'Experimental-Transports' / 'TRANSPORT_KITS_README.txt').is_file()


def test_protocol_vault_persists_and_deletes_session_token():
    from app.accounts import ProtocolVault

    class MemKeyring:
        priority = 1
        def __init__(self): self.store = {}
        def set_password(self, svc, key, val): self.store[svc, key] = val
        def get_password(self, svc, key): return self.store.get((svc, key))
        def delete_password(self, svc, key): self.store.pop((svc, key), None)

    v = ProtocolVault(MemKeyring())
    v.put_session_token('windscribe', '123:1:abc:def', 'work')
    assert v.get_session_token('windscribe', 'work') == '123:1:abc:def'
    assert v.get_session_token('windscribe', 'default') is None
    with pytest.raises(ValueError):
        v.put_session_token('windscribe', 'bad token;semi', 'work')
    v.delete_session_token('windscribe', 'work')
    assert v.get_session_token('windscribe', 'work') is None


def test_manual_login_prefers_unmodified_native_browser(tmp_path):
    """Manual login launches the user's unmodified desktop browser with isolated --user-data-dir (no automation flags)."""
    import os
    from app.accounts import manual_login

    captured = {}

    class FakeProc:
        def __init__(self, cmd, **kw):
            captured['cmd'] = cmd
            self._polls = 0
        def poll(self):
            self._polls += 1
            return 0 if self._polls >= 2 else None
        def terminate(self): pass
        def wait(self, timeout=None): pass

    with (
        patch.dict(os.environ, {'MULTIVPN_STATE_DIR': str(tmp_path)}),
        patch('app.accounts._find_native_browser', return_value='/usr/bin/google-chrome'),
        patch('subprocess.Popen', side_effect=FakeProc),
    ):
        res = manual_login('windscribe', account='default', max_seconds=5)

    assert 'saved locally' in res
    cmd = captured['cmd']
    assert cmd[0] == '/usr/bin/google-chrome'
    assert any(arg.startswith('--user-data-dir=') for arg in cmd)
    assert 'https://windscribe.com/myaccount/config-generator' in cmd
    assert not any('automation' in arg.lower() or 'webdriver' in arg.lower() for arg in cmd)


def test_windscribe_openvpn_credentials_api_discovery():
    """discover_openvpn_credentials uses Windscribe's official /ServerCredentials?type=openvpn API."""
    from app.credential_discovery import discover_openvpn_credentials

    payload = json.dumps({
        'data': {
            'username': base64.b64encode(b'ws_ovpn_user').decode(),
            'password': base64.b64encode(b'ws_ovpn_pass').decode(),
        }
    }).encode('utf-8')
    with patch('app.providers.windscribe_backend_v3.fetch_bytes', return_value=payload):
        creds = discover_openvpn_credentials('windscribe', 'default', session_token='tok-123')
    assert creds == ('ws_ovpn_user', 'ws_ovpn_pass')


def test_proton_openvpn_discovery_survives_spa_redirect(tmp_path):
    """Proton OpenVPN discovery must survive transient SPA navigation errors and read revealed credentials."""
    import os
    from app.credential_discovery import discover_openvpn_credentials

    class FakePage:
        def __init__(self):
            self.url = 'https://account.protonvpn.com/vpn/OpenVpnIKEv2'
            self.calls = 0

        def goto(self, url, **kw):
            self.url = url

        def is_closed(self):
            return False

        def wait_for_timeout(self, ms):
            pass

        def evaluate(self, script):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError('Execution context was destroyed, most likely because of a navigation')
            if self.calls == 2:
                self.url = 'https://account.protonvpn.com/u/0/vpn/OpenVpnIKEv2'
                return None
            return {'username': 'proton_ovpn_user', 'password': 'proton_ovpn_password'}

    class FakeCtx:
        def __init__(self, page):
            self.pages = [page]

        def close(self):
            pass

    class FakePW:
        def __init__(self, page):
            self._page = page

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        @property
        def chromium(self):
            return self

        def launch_persistent_context(self, path, **kw):
            return FakeCtx(self._page)

    page = FakePage()
    with patch.dict(os.environ, {'MULTIVPN_STATE_DIR': str(tmp_path)}):
        creds = discover_openvpn_credentials('proton', 'default', factory=lambda: FakePW(page), max_poll_seconds=5.0)
    assert creds == ('proton_ovpn_user', 'proton_ovpn_password')
    assert page.calls == 3
