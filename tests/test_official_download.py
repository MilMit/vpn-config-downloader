import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from app.core import Credentials, Options
from app.providers.importers import Surfshark,ProtonVPN
from app.providers.official_download import (Collected, fetch_official_surfshark_openvpn,
                                             _trusted, _is_download_action)
WG='''[Interface]\nPrivateKey = abcdefghijklmnopqrstuvwxyz12345=\nAddress = 10.1.1.2/32\n[Peer]\nPublicKey = abcdefghijklmnopqrstuvwxyz12345=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:443\n'''
UDP='''client\ndev tun\nproto udp\nremote de-test.surfshark.com 1194\nremote-cert-tls server\n'''
TCP='''client\ndev tun\nproto tcp\nremote de-test.surfshark.com 443\nremote-cert-tls server\n'''
def archive():
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as f:
        f.writestr('de-test_udp.ovpn',UDP)
        f.writestr('de-test_tcp.ovpn',TCP)
        f.writestr('bad.conf','<html>login</html>')
        f.writestr('../attack.ovpn',UDP)
    return buf.getvalue()

class FakeResponse:
    def __init__(self,b):self.b=b
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def geturl(self):return 'https://surfshark.com/api/v1/server/configurations'
    def read(self,n):return self.b[:n]

class OfficialDownloadTests(unittest.TestCase):
    def test_authoritative_archive_and_dedupe(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);c=Collected(root)
            events=[]
            def opener(request,timeout):return FakeResponse(archive())
            n=fetch_official_surfshark_openvpn(c,timeout=10,emit=events.append,opener=opener)
            self.assertEqual(n,2)
            self.assertEqual(c.downloaded,2)
            self.assertEqual((root/'OpenVPN-UDP').exists(),True)
            self.assertEqual((root/'OpenVPN-TCP').exists(),True)
            again=fetch_official_surfshark_openvpn(c,timeout=10,emit=events.append,opener=opener)
            self.assertEqual(again,0)
            self.assertEqual(c.downloaded,2)
            self.assertGreater(c.ignored,0)
    def test_rejects_login_html_and_bogus_zip(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                fetch_official_surfshark_openvpn(Collected(Path(td)),timeout=10,
                  emit=lambda e:None,opener=lambda req,timeout:FakeResponse(b'<html>sign in</html>'))
    def test_zip_traversal_and_signature(self):
        with tempfile.TemporaryDirectory() as td:
            c=Collected(Path(td));self.assertEqual(c.ingest_zip(archive(),'official'),2)
            self.assertEqual(c.ingest_zip(archive(),'official'),0)
            self.assertFalse((Path(td).parent/'attack.ovpn').exists())
    def test_private_key_portability_flag(self):
        with tempfile.TemporaryDirectory() as td:
            c=Collected(Path(td));self.assertTrue(c.ingest('one.conf',WG.encode(),'mock'))
            self.assertTrue(c.records[0]['portable'])
            no_key=WG.replace('PrivateKey = abcdefghijklmnopqrstuvwxyz12345=\n','')
            self.assertTrue(c.ingest('another.conf',no_key.encode(),'mock'))
            self.assertFalse(c.records[1]['portable'])
    def test_domain_and_click_guard(self):
        self.assertTrue(_trusted('https://account.protonvpn.com/downloads','proton'))
        self.assertFalse(_trusted('https://account.protonvpn.com.evil.org/x','proton'))
        self.assertFalse(_trusted('http://my.surfshark.com/','surfshark'))
        self.assertTrue(_is_download_action('Download WireGuard configuration files'))
        self.assertFalse(_is_download_action('Regenerate key'))
    def test_provider_auto_surfshark_official_mock(self):
        with tempfile.TemporaryDirectory() as td:
            opts=Options(output=td,protocols=['tcp','udp'],archive=True)
            def stub(collector,**kwargs):return collector.ingest_zip(archive(),'official mock')
            with patch('app.providers.importers.fetch_official_surfshark_openvpn',side_effect=stub):
                result=Surfshark().export(locations=[],credentials=Credentials(),options=opts,
                                           source_path='',emit=lambda e:None,stop=Event(),pause=Event())
            self.assertEqual(result['mode'],'official_auto')
            self.assertEqual(result['downloaded'],2)
            self.assertTrue(Path(result['archive']).is_file())
            self.assertNotIn('PrivateKey',Path(td,'surfshark','report.json').read_text())
    def test_proton_browser_injection(self):
        with tempfile.TemporaryDirectory() as td:
            def fake_browser(provider,collector,**kwargs):
                collector.ingest('us-test.conf',WG.encode(),'fake account browser')
                return {'visited':1,'downloaded':1,'note':'simulated'}
            with patch('app.providers.importers.browser_account_download',side_effect=fake_browser):
                res=ProtonVPN().export(locations=[],credentials=Credentials(),
                    options=Options(output=td,protocols=['wireguard'],archive=True),source_path='',
                    emit=lambda e:None,stop=Event(),pause=Event())
            self.assertEqual(res['downloaded'],1)
            self.assertTrue(Path(res['archive']).is_file())

if __name__=='__main__':unittest.main()
