from pathlib import Path
import tempfile
import unittest
import zipfile
from threading import Event
from app.core import (safe_filename, valid_profile, profile_kind, import_profiles,
                      export_archive, safe_store, file_entries)
from app.providers import load_providers
from app.providers.windscribe_backend_v3 import parse_ports,locations_from_json

WG='''[Interface]\nPrivateKey = abcdefghijklmnopqrstuvwxyz12345=\nAddress = 10.1.1.2/32\n[Peer]\nPublicKey = abcdefghijklmnopqrstuvwxyz12345=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:443\n'''
OV='''client\ndev tun\nproto udp\nremote server.example.com 1194\nremote-cert-tls server\n'''

class CoreTests(unittest.TestCase):
    def test_filename(self):
        self.assertEqual(safe_filename('../<evil> Deutschland'), 'evil-Deutschland')
    def test_valid_wg(self):
        self.assertTrue(valid_profile('wireguard',WG))
        self.assertFalse(valid_profile('wireguard','<html>login</html>'))
    def test_detect_openvpn(self):
        self.assertEqual(profile_kind('test.ovpn',OV.encode()),'udp')
        self.assertIsNone(profile_kind('test.ovpn',b'not a VPN profile'))
    def test_port_validation(self):
        self.assertEqual(parse_ports('443,65142,443'),['443','65142'])
        with self.assertRaises(ValueError):parse_ports('0,65536')
    def test_import_folder_and_dedupe(self):
        with tempfile.TemporaryDirectory() as p:
            base=Path(p);source=base/'source';source.mkdir()
            (source/'Germany.conf').write_text(WG)
            (source/'duplicate.conf').write_text(WG)
            (source/'USA.ovpn').write_text(OV)
            (source/'bad.conf').write_text('<html>bad login response</html>')
            out=base/'out';e=[]
            data=import_profiles(source,out,on_progress=e.append,stop=Event())
            self.assertEqual(data['imported'],2)
            self.assertEqual(data['skipped'],2)
            self.assertEqual(len(e),4)
            archive=export_archive(out)
            with zipfile.ZipFile(archive) as z:self.assertEqual(len(z.namelist()),2)
    def test_zip_slip_and_symlink_ignored(self):
        with tempfile.TemporaryDirectory() as p:
            path=Path(p)/'attack.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('../evil.conf',WG)
                z.writestr('/tmp/absolute.conf',WG)
                z.writestr('ok.ovpn',OV)
            self.assertEqual([r[0] for r in file_entries(path)],['ok.ovpn'])
    def test_provider_registration(self):
        p=load_providers()
        self.assertEqual(set(p),{'windscribe','surfshark','proton'})
        self.assertEqual({x.level for x in p['proton'].capabilities},{'browser'})
    def test_sample_location(self):
        sample={'data':[{'status':1,'country_code':'DE','groups':[{'id':12,'city':'Berlin','nick':'Test'}]}]}
        self.assertEqual(locations_from_json(sample)[0]['id'],'12')
    def test_output_mode(self):
        with tempfile.TemporaryDirectory() as p:
            target=Path(p)/'private.conf';safe_store(target,WG)
            self.assertTrue(target.read_text().startswith('[Interface]'))
            self.assertEqual(target.stat().st_mode & 0o777,0o600)

if __name__=='__main__':unittest.main()

class WindscribeMockTests(unittest.TestCase):
    def test_manual_provider_mock_and_resume(self):
        from unittest.mock import patch
        from app.providers.windscribe import Windscribe
        from app.core import Location,Credentials,Options
        sample={'id':'42','label':'Berlin - Test','country':'DE','pro':True}
        loc=Location('42','DE','Berlin - Test','pro',sample)
        events=[]
        with tempfile.TemporaryDirectory() as td:
            opts=Options(output=td,protocols=['udp'],ports={'udp':['443'],'tcp':['54783'],'wireguard':['65142']},delay=0,archive=True)
            with patch('app.providers.windscribe.legacy.get_manual_config',return_value=OV) as mock:
                p=Windscribe()
                result=p.export(locations=[loc],credentials=__import__('app.core',fromlist=['Credentials']).Credentials(website_cookie='demo-token'),
                    options=opts,source_path='',emit=events.append,stop=Event(),pause=self.set_event())
                self.assertEqual(result['generated'],1)
                self.assertEqual(result['failed'],0)
                self.assertTrue(Path(result['archive']).is_file())
                self.assertEqual(mock.call_count,1)
                again=p.export(locations=[loc],credentials=Credentials(website_cookie='demo-token'),
                    options=opts,source_path='',emit=events.append,stop=Event(),pause=self.set_event())
                self.assertEqual(again['reused'],1)
                self.assertEqual(mock.call_count,1)
                self.assertNotIn('demo-token',Path(td,'windscribe','report.json').read_text())
    @staticmethod
    def set_event():
        event=Event();event.set();return event

class ImportMockTests(unittest.TestCase):
    def test_proton_workflow(self):
        from app.core import Credentials,Options
        from app.providers.importers import ProtonVPN
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'vpn-files';src.mkdir()
            (src/'nl-01.ovpn').write_text(OV)
            opts=Options(output=td,protocols=['openvpn'],archive=True)
            events=[]
            result=ProtonVPN().export(locations=[],credentials=Credentials(),options=opts,
                source_path=str(src),emit=events.append,stop=Event(),pause=WindscribeMockTests.set_event())
            self.assertEqual(result['imported'],1)
            self.assertTrue(Path(result['archive']).exists())
            self.assertEqual(result['mode'],'local_import')
