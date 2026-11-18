"""Headless utility for official VPN config acquisition, validation, and AES-256 export.

Passwords are always prompted securely via getpass, NEVER via CLI arguments or config files.
Account-only Proton/Surfshark WireGuard downloads still open the official browser UI.
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
from threading import Event

from .account_registry import validate_account
from .core import Credentials, Options, export_archive, provider_output_dir
from .health import batch_validate, probe_profile
from .protocol_manifest import build_manifest
from .providers import load_providers
from .security import aes_zip, remove_plaintext_tree, verify_aes_zip


def main(argv=None):
    p = argparse.ArgumentParser(description='VPN Config Downloader — download, validate, and securely export user-authorized VPN configs.')
    p.add_argument('--provider', choices=('surfshark', 'proton'), help='Provider to export from')
    p.add_argument('--list-providers', action='store_true', help='Print registered providers and protocol capability matrix')
    p.add_argument('--validate', default='', help='Validate a single .ovpn/.conf file or directory of configs')
    p.add_argument('--check-reachability', action='store_true', help='With --validate, also test DNS/TCP endpoint reachability')
    p.add_argument('--verify-zip', default='', help='Verify decryption of an existing AES-256 ZIP (prompts for password)')
    p.add_argument('--account', default='default', help='Saved account alias (from GUI Accounts)')
    p.add_argument('--protocols', default='udp,tcp,wireguard')
    p.add_argument('--output', default=str(Path.home() / 'Documents' / 'MultiVPN-Configs'))
    p.add_argument('--import-path', default='', help='Import local folder, ZIP, .ovpn, or .conf instead of AUTO')
    p.add_argument('--browser-limit', type=int, default=40)
    p.add_argument('--concurrency', type=int, default=2, help='Concurrent downloads (1..8)')
    p.add_argument('--delay', type=float, default=3)
    p.add_argument('--archive', choices=('none', 'aes256', 'plaintext'), default='none',
                   help='AES-256 ZIP, explicit plain ZIP, or only files (default)')
    p.add_argument('--remove-plaintext', action='store_true', help='Delete staging folder after AES ZIP verification')
    args = p.parse_args(argv)

    if args.list_providers:
        provs = load_providers()
        payload = {
            key: {
                'label': prov.label,
                'official_url': prov.official_url,
                'supports_server_discovery': prov.supports_server_discovery,
                'protocols': prov.protocol_matrix(),
            }
            for key, prov in provs.items()
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if args.verify_zip:
        pw = getpass.getpass('AES-256 ZIP password: ')
        info = verify_aes_zip(Path(args.verify_zip), pw)
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0

    if args.validate:
        target = Path(args.validate).expanduser().resolve()
        if target.is_dir():
            results = batch_validate(target, check_reachability=args.check_reachability)
            summary = {
                'scanned': len(results),
                'syntax_valid': sum(1 for r in results if r['syntax_validation']['status'] != 'invalid'),
                'syntax_invalid': sum(1 for r in results if r['syntax_validation']['status'] == 'invalid'),
                'vpn_verified': sum(1 for r in results if r.get('vpn_verified')),
                'results': results,
            }
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0 if summary['syntax_valid'] else 2
        res = probe_profile(target)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res['syntax_validation']['status'] != 'invalid' else 2

    if not args.provider:
        p.error('--provider is required unless --list-providers, --validate, or --verify-zip is specified.')

    validate_account(args.provider, args.account)
    protos = [s.strip().lower() for s in args.protocols.split(',') if s.strip()]
    if not protos or any(s not in ('udp', 'tcp', 'wireguard', 'openvpn', 'ikev2') for s in protos):
        p.error('Use udp,tcp,wireguard,openvpn,ikev2')
    if not 1 <= args.browser_limit <= 250:
        p.error('--browser-limit must be 1..250')
    if not 1 <= args.concurrency <= 8:
        p.error('--concurrency must be 1..8')
    if args.remove_plaintext and args.archive != 'aes256':
        p.error('--remove-plaintext requires --archive aes256')
    password = ''
    if args.archive == 'aes256':
        password = getpass.getpass('New AES-256 ZIP password (>=12 characters): ')
        confirmation = getpass.getpass('Confirm password: ')
        if len(password) < 12 or confirmation != password:
            p.error('Password too short or mismatch')
    prov = load_providers()[args.provider]
    pause = Event()
    pause.set()
    opts = Options(
        output=args.output,
        protocols=protos,
        browser_limit=args.browser_limit,
        delay=args.delay,
        concurrency=args.concurrency,
        archive=False,
        account=args.account,
    )
    result = prov.export(
        locations=[],
        credentials=Credentials(),
        source_path=args.import_path,
        options=opts,
        emit=lambda e: print(e.kind.upper(), e.message, flush=True),
        stop=Event(),
        pause=pause,
    )
    root = provider_output_dir(opts, prov.key)
    inventory = build_manifest(root)
    result['manifest'] = inventory
    if inventory['total_structurally_valid'] and args.archive != 'none':
        if args.archive == 'aes256':
            file = aes_zip(root, password)
            if args.remove_plaintext:
                remove_plaintext_tree(root, archive=file)
                result['plaintext_removed'] = True
        else:
            print('WARNING: creating a plaintext ZIP that may contain VPN private keys!', flush=True)
            file = export_archive(root)
        result['archive'] = str(file)
    print(json.dumps({k: v for k, v in result.items() if k not in ('records', 'results')}, indent=2))
    return 0 if inventory['total_structurally_valid'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
