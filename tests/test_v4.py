import base64
import io
import json
import os
import threading
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from app.account_registry import AccountRegistry, validate_account
from app.accounts import (profile_dir, has_session_profile, forget_profile, ProtocolVault,
                          VaultUnavailable)
from app.core import Options, provider_output_dir, safe_store
from app.health import probe_profile
from app.security import make_keypair, public_from_private, aes_zip, remove_plaintext_tree
from app.session_check import check_account_session

OPENVPN=b'''client
proto tcp
remote example.com 443
remote-cert-tls server
cipher AES-256-GCM
'''
WIREGUARD=b'''[Interface]
PrivateKey = secret
Address = 10.0.0.2/32
[Peer]
PublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0
'''

class MemoryKeyring:
    priority=1
    def __init__(self):self.store={}
    def set_password(self,service,user,password):self.store[service,user]=password
    def get_password(self,service,user):return self.store.get((service,user))
    def delete_password(self,service,user):self.store.pop((service,user),None)


def test_registry_creation(tmp_path):
    a=AccountRegistry(tmp_path)
    assert a.list('proton') == ['default']
    a.add('proton','work');a.add('proton','work')
    assert sorted(a.list('proton')) == ['default','work']
    assert json.loads((tmp_path/'accounts.json').read_text())['proton']==['default','work']
    a.remove('proton','work')
    assert a.list('proton')==['default']
    with pytest.raises(ValueError):a.remove('proton','default')

@pytest.mark.parametrize('name',('..','a/../b',' hello','private account','', 'a'*41,'../../foo','@foo'))
def test_reject_bad_alias(name):
    with pytest.raises(ValueError):validate_account('surfshark',name)


def test_browser_profiles_isolated(tmp_path):
    a=profile_dir('proton',base=tmp_path,account='client1',create=True)
    b=profile_dir('proton',base=tmp_path,account='client2',create=True)
    assert a!=b
    (a/'Local State').write_text('profile1')
    (b/'Local State').write_text('profile2')
    assert has_session_profile('proton',base=tmp_path,account='client1')
    forget_profile('proton',base=tmp_path,account='client1')
    assert not has_session_profile('proton',base=tmp_path,account='client1')
    assert has_session_profile('proton',base=tmp_path,account='client2')


def test_separate_output_by_account(tmp_path):
    a=Options(output=str(tmp_path),protocols=['udp'],account='default')
    b=Options(output=str(tmp_path),protocols=['udp'],account='private')
    assert provider_output_dir(a,'proton')!=provider_output_dir(b,'proton')
    assert provider_output_dir(b,'proton').name=='proton--private'


def test_keypairs_and_keyring():
    priv,pub=make_keypair()
    assert public_from_private(priv)==pub
    assert len(base64.b64decode(priv))==32
    backend=MemoryKeyring();vault=ProtocolVault(backend)
    assert vault.put_wireguard('windscribe',priv,'work')==pub
    assert vault.get_wireguard('windscribe','default') is None
    assert vault.get_wireguard('windscribe','work')==priv
    vault.put_openvpn('windscribe','serviceuser','servicepassword','work')
    assert vault.get_openvpn('windscribe','work')==('serviceuser','servicepassword')
    assert vault.get_openvpn('windscribe') is None
    vault.delete_wireguard('windscribe','work')
    assert vault.get_wireguard('windscribe','work') is None
    vault.delete_openvpn('windscribe','work')
    assert vault.get_openvpn('windscribe','work') is None

@pytest.mark.parametrize('key',('', 'no!', base64.b64encode(b'wrong').decode()))
def test_reject_invalid_wireguard_key(key):
    with pytest.raises(ValueError):public_from_private(key)


def test_plaintext_zip_not_created_on_missing_aes_library(tmp_path):
    dest=tmp_path/'proton';dest.mkdir()
    safe_store(dest/'example.ovpn',OPENVPN)
    with patch.dict('sys.modules',{'pyzipper':None}):
        with pytest.raises(RuntimeError,match='Refusing an unencrypted fallback'):
            aes_zip(dest,'averystrongpassword')
    assert not list(tmp_path.glob('*.zip'))


def test_short_zip_password_rejected(tmp_path):
    with pytest.raises(ValueError):aes_zip(tmp_path,'short')


def test_removal_requires_archive(tmp_path):
    root=tmp_path/'stuff';root.mkdir()
    safe_store(root/'a.ovpn',OPENVPN)
    with pytest.raises(ValueError):remove_plaintext_tree(root,archive=tmp_path/'missing.zip')
    assert (root/'a.ovpn').exists()


def test_dns_only_wireguard(tmp_path):
    p=tmp_path/'node.conf';p.write_bytes(WIREGUARD)
    class Info:
        def __init__(self):self.called=False
    state=Info()
    def resolver(host,port,type):return [(None,None,None,None,('127.0.0.1',port))]
    def connector(*args,**kwargs):
        state.called=True;raise RuntimeError('should not attempt TCP on WireGuard')
    result=probe_profile(p,resolver=resolver,connector=connector)
    assert result['state']=='dns_only'
    assert not result['vpn_verified']
    assert not state.called


def test_tcp_probe_classified_only_as_reachability(tmp_path):
    p=tmp_path/'node.ovpn';p.write_bytes(OPENVPN)
    class Socket:
        def close(self):pass
    result=probe_profile(p,resolver=lambda *a,**k:[(1,2,3,4,5)],connector=lambda *a,**k:Socket())
    assert result['tcp']=='reachable'
    assert result['state']=='tcp_reachable'
    assert not result['vpn_verified']


def test_dns_failure_is_not_vpn_failure(tmp_path):
    p=tmp_path/'node.ovpn';p.write_bytes(OPENVPN)
    def fail(*a,**kw):raise OSError('invalid')
    result=probe_profile(p,resolver=fail)
    assert result['dns']=='failed'
    assert not result['vpn_verified']


def test_session_absent(tmp_path):
    result=check_account_session('surfshark',base=tmp_path)
    assert result.state=='absent'


def test_aes_zip_real_if_installed(tmp_path):
    pytest.importorskip('pyzipper')
    import pyzipper
    root=tmp_path/'surfshark'
    safe_store(root/'OpenVPN-TCP'/'server.ovpn',OPENVPN)
    archive=aes_zip(root,'some-very-strong-password')
    with pyzipper.AESZipFile(archive) as z:
        names=z.namelist()
        assert len(names)==1
        with pytest.raises((RuntimeError,ValueError,Exception)):
            z.read(names[0])
        z.setpassword(b'some-very-strong-password')
        assert z.read(names[0])==OPENVPN
    remove_plaintext_tree(root,archive=archive)
    assert not root.exists()
    assert archive.is_file()


def test_import_second_run_is_reused(tmp_path):
    from app.core import import_profiles
    p=tmp_path/'files';p.mkdir()
    (p/'valid.ovpn').write_bytes(OPENVPN)
    dst=tmp_path/'output'
    events=[]
    a=import_profiles(p,dst,on_progress=events.append)
    b=import_profiles(p,dst,on_progress=events.append)
    assert a['imported']==1
    assert b['imported']==0
    assert b['records'][0]['status']=='reused'


def test_cli_rejects_secret_in_flags():
    # The headless interface intentionally has no '--password' CLI option.
    from app.cli import main
    with pytest.raises(SystemExit) as error:
        main(['--provider','surfshark','--password','secret'])
    assert error.value.code==2


def test_v3_openvpn_credential_backwards_compatibility():
    from app.accounts import LEGACY_SERVICE_ID
    backend=MemoryKeyring()
    backend.set_password(LEGACY_SERVICE_ID,'surfshark:openvpn:username','old-user')
    backend.set_password(LEGACY_SERVICE_ID,'surfshark:openvpn:password','old-pass')
    vault=ProtocolVault(backend)
    assert vault.get_openvpn('surfshark')==('old-user','old-pass')
    vault.delete_openvpn('surfshark')
    assert vault.get_openvpn('surfshark') is None
