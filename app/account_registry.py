"""Minimal local account index; does NOT store passwords, cookies or keys.

Multiple named identities per provider can have independent Chromium profiles
and OS-keyring entries. A browser profile only proves the presence of local
state; never that an online session remains authenticated.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .accounts import state_root, _private_dir
from .core import safe_store

PROVIDERS = ('windscribe', 'surfshark', 'proton')
IDENTITY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$')


def validate_account(provider: str, alias: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError('Unknown provider')
    if not IDENTITY.fullmatch(alias):
        raise ValueError('Account name: 1–40 ASCII letters/numbers/_/-, starting with a letter or number.')
    return alias


class AccountRegistry:
    def __init__(self, base: Path | None = None):
        self.base = Path(base) if base else state_root()
        self.path = self.base / 'accounts.json'
        self.status_path = self.base / 'account_status.json'

    def _read(self) -> dict:
        if not self.path.exists():
            return {p: ['default'] for p in PROVIDERS}
        data = json.loads(self.path.read_text('utf-8'))
        if not isinstance(data, dict):
            raise ValueError('Invalid accounts registry')
        return {p: sorted(set(['default'] + [a for a in data.get(p, [])
                          if isinstance(a, str) and IDENTITY.fullmatch(a)])) for p in PROVIDERS}

    def list(self, provider: str) -> list[str]:
        validate_account(provider, 'default')
        return self._read()[provider]

    def list_all(self) -> dict[str, list[str]]:
        return self._read()

    def add(self, provider: str, alias: str) -> None:
        validate_account(provider, alias)
        data = self._read()
        if alias not in data[provider]:
            data[provider].append(alias)
        self._write(data)

    def remove(self, provider: str, alias: str) -> None:
        validate_account(provider, alias)
        if alias == 'default':
            raise ValueError('The default identity is permanent; you may forget its browser session.')
        data = self._read()
        if alias in data[provider]:
            data[provider].remove(alias)
        self._write(data)
        self.clear_status(provider, alias)

    def _write(self, data: dict) -> None:
        _private_dir(self.base)
        safe_store(self.path, json.dumps(data, indent=2))

    # Non-secret session status tracking (never stores passwords/cookies/keys)
    def _read_status(self) -> dict:
        if not self.status_path.exists():
            return {}
        try:
            raw = json.loads(self.status_path.read_text('utf-8'))
            return raw if isinstance(raw, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def set_status(self, provider: str, alias: str, *, state: str, detail: str, plan_hint: str = '') -> dict:
        validate_account(provider, alias)
        statuses = self._read_status()
        key = f'{provider}:{alias}'
        entry = {
            'state': str(state)[:40],
            'detail': str(detail)[:220],
            'plan_hint': str(plan_hint)[:80],
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }
        statuses[key] = entry
        _private_dir(self.base)
        safe_store(self.status_path, json.dumps(statuses, indent=2, ensure_ascii=False))
        return entry

    def get_status(self, provider: str, alias: str) -> dict | None:
        validate_account(provider, alias)
        return self._read_status().get(f'{provider}:{alias}')

    def clear_status(self, provider: str, alias: str) -> None:
        validate_account(provider, alias)
        statuses = self._read_status()
        key = f'{provider}:{alias}'
        if key in statuses:
            del statuses[key]
            _private_dir(self.base)
            safe_store(self.status_path, json.dumps(statuses, indent=2, ensure_ascii=False))
