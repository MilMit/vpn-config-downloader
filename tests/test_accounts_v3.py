import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.accounts import (
    ProtocolVault, VaultUnavailable, profile_dir, has_session_profile, forget_profile,
    manual_login, windscribe_cookie,
)
from app.auth_export import add_openvpn_auth_files
from app.protocol_manifest import analyze_profile, build_manifest
from app.core import export_archive, safe_store

OPENVPN = b'client\nproto udp\nremote de.example.org 1194\nremote-cert-tls server\nauth-user-pass\n'
WG = b'[Interface]\nAddress = 10.1.0.2/32\n[Peer]\nPublicKey = samplekey1234567890abcdefghijkl\nEndpoint = vpn.example.org:51820\n'


class MemoryBackend:
    def __init__(self): self.values = {}
    def set_password(self, service, key, password): self.values[service,key] = password
    def get_password(self, service, key): return self.values.get((service,key))
    def delete_password(self, service, key): self.values.pop((service,key),None)


class FakeBrowser:
    def __init__(self, root, cookies=None):
        self.root = Path(root)
        self._cookies = cookies or []
        self.pages = [FakePage()]
        self.closed = False
    def new_page(self): return self.pages[0]
    def cookies(self, url): return self._cookies
    def close(self): self.closed = True


class FakePage:
    url = 'https://windscribe.com/myaccount/config-generator'
    def __init__(self): self.waits=0
    def goto(self,url,**kwargs): self.url=url
    def is_closed(self): return self.waits>0
    def wait_for_timeout(self,ms): self.waits += 1


class FakePlaywright:
    def __init__(self,cookies=None): self.calls=[]; self.cookies=cookies
    def __enter__(self):return self
    def __exit__(self,*args):pass
    @property
    def chromium(self):return self
    def launch_persistent_context(self, path, **kwargs):
        self.calls.append((path,kwargs))
        Path(path,'Local State').write_text('not real Chrome browser state')
        return FakeBrowser(path,self.cookies)


class AccountsV3(unittest.TestCase):
    def test_provider_isolation_and_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            a=profile_dir('surfshark',base=Path(td),create=True)
            b=profile_dir('proton',base=Path(td),create=True)
            self.assertNotEqual(a,b)
            self.assertEqual(a.stat().st_mode & 0o777,0o700)
            with self.assertRaises(ValueError):profile_dir('../other',base=Path(td),create=True)

    def test_persistent_login_does_not_capture_password_and_saves_profile(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'MULTIVPN_STATE_DIR':td}):
            fake=FakePlaywright()
            result=manual_login('windscribe',playwright_factory=lambda:fake,max_seconds=10)
            self.assertIn('not verified',result)
            self.assertTrue(has_session_profile('windscribe'))
            self.assertEqual(len(fake.calls),1)
            self.assertIs(fake.calls[0][1]['headless'],False)
            self.assertEqual(fake.calls[0][1]['accept_downloads'],True)
            self.assertNotIn('password',str(fake.calls))
            self.assertFalse(has_session_profile('proton'))
            forget_profile('windscribe')
            self.assertFalse(has_session_profile('windscribe'))

    def test_forget_symlink_guard(self):
        with tempfile.TemporaryDirectory() as td:
            path=profile_dir('proton',base=Path(td))
            path.parent.mkdir(parents=True)
            target=Path(td)/'important';target.mkdir()
            path.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):forget_profile('proton',base=Path(td))
            self.assertTrue(target.exists())

    def test_read_windscribe_cookie_keeps_token_out_of_files(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'MULTIVPN_STATE_DIR':td}):
            p=profile_dir('windscribe',create=True)
            (p/'Local State').touch()
            fake=FakePlaywright(cookies=[{'name':'ws_session_auth_hash','value':'top_secret_token'}])
            self.assertEqual(windscribe_cookie(playwright_factory=lambda:fake),'top_secret_token')
            self.assertFalse((p/'cookie.txt').exists())
            self.assertTrue(fake.calls[0][1]['headless'])

    def test_cookie_invalid_chars_refused(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'MULTIVPN_STATE_DIR':td}):
            p=profile_dir('windscribe',create=True);(p/'Local State').touch()
            fake=FakePlaywright(cookies=[{'name':'ws_session_auth_hash','value':'token\r\nunsafe'}])
            self.assertEqual(windscribe_cookie(playwright_factory=lambda:fake),'')

    def test_vault_is_keyring_only(self):
        backend=MemoryBackend();vault=ProtocolVault(backend)
        self.assertIsNone(vault.get_openvpn('surfshark'))
        vault.put_openvpn('surfshark','service-user','service-pass')
        vault.put_openvpn('proton','u2','p2')
        self.assertEqual(vault.get_openvpn('surfshark'),('service-user','service-pass'))
        self.assertEqual(vault.get_openvpn('proton'),('u2','p2'))
        vault.delete_openvpn('surfshark')
        self.assertIsNone(vault.get_openvpn('surfshark'))
        self.assertEqual(vault.get_openvpn('proton'),('u2','p2'))

    def test_vault_rejects_multiline_injection(self):
        v=ProtocolVault(MemoryBackend())
        with self.assertRaises(ValueError):v.put_openvpn('surfshark','u','p\nextra')
        with self.assertRaises(ValueError):v.put_openvpn('foo','u','p')

    def test_auth_files_are_explicit_opt_in_and_zip_contains_them(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'surfshark'
            p=root/'OpenVPN-UDP'/'country.ovpn'
            safe_store(p,OPENVPN)
            self.assertNotIn('service-password',p.read_text())
            result=add_openvpn_auth_files(root,'service-user','service-password')
            self.assertEqual(result['profiles_linked'],1)
            self.assertIn('auth-user-pass openvpn_auth.txt',p.read_text())
            secret=p.parent/'openvpn_auth.txt'
            self.assertEqual(secret.read_text(),'service-user\nservice-password\n')
            self.assertEqual(secret.stat().st_mode & 0o777,0o600)
            archive=export_archive(root)
            self.assertTrue(archive.is_file())

    def test_custom_auth_directive_not_modified(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            p=root/'custom.ovpn'
            original=OPENVPN.replace(b'auth-user-pass\n',b'auth-user-pass /custom/file\n')
            safe_store(p,original)
            out=add_openvpn_auth_files(root,'u','p')
            self.assertEqual(out['profiles_skipped'],1)
            self.assertEqual(p.read_bytes(),original)

    def test_manifest_never_contains_secret(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            safe_store(root/'a.ovpn',OPENVPN)
            key='private-supersecret-string'
            safe_store(root/'b.conf',WG.replace(b'Address =',f'PrivateKey = {key}\nAddress ='.encode()))
            result=build_manifest(root)
            self.assertEqual(result['total_structurally_valid'],2)
            self.assertEqual(result['wireguard'],1)
            raw=(root/'manifest.json').read_text()
            self.assertNotIn(key,raw)
            self.assertNotIn('PrivateKey =',raw)
            self.assertNotIn('service-user',raw)
            self.assertTrue((root/'manifest.csv').is_file())
            self.assertEqual(json.loads(raw)['summary']['live_connections_verified'],0)

    def test_manifest_missing_wireguard_key(self):
        out=analyze_profile('foo.conf',WG)
        self.assertEqual(out['kind'],'wireguard')
        self.assertFalse(out['has_private_key'])
        self.assertGreater(len(out['required_actions']),0)
        self.assertEqual(out['port'],51820)

    def test_manifest_requires_openvpn_login(self):
        out=analyze_profile('file.ovpn',OPENVPN)
        self.assertEqual(out['kind'],'udp')
        self.assertTrue(out['required_actions'])
        self.assertEqual(out['port'],1194)


if __name__=='__main__':unittest.main()
