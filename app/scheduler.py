"""Automatic Scheduler for authorized, non-interactive configuration refreshes.

Security policy:
- Operations requiring interactive browser login, 2FA, website cookies, private keys,
  or ZIP passphrases are NEVER scheduled unattended.
- Only public, unauthenticated vendor archives (currently Surfshark OpenVPN UDP/TCP)
  are eligible for automatic scheduled refresh.
- Detects config changes via before/after SHA-256 snapshots and keeps persistent
  non-secret run history.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .accounts import state_root, _private_dir
from .core import Credentials, Event, Options, provider_output_dir, safe_store
from .protocol_manifest import build_manifest
from .providers import load_providers
from .security import redact_secrets

# Strict allowlist of provider -> unattended-authorized protocols.
ALLOWED_UNATTENDED_TARGETS: dict[str, set[str]] = {
    'surfshark': {'udp', 'tcp'},
}

MAX_HISTORY_RECORDS = 100


@dataclass(frozen=True)
class ScheduleJobSpec:
    provider: str = 'surfshark'
    protocols: tuple[str, ...] = ('udp', 'tcp')
    output: str = ''
    interval_minutes: int = 1440
    timeout: int = 25
    delay: float = 1.0


def validate_unattended_spec(spec: ScheduleJobSpec) -> None:
    """Enforce that only authorized, non-interactive public downloads can be scheduled."""
    allowed = ALLOWED_UNATTENDED_TARGETS.get(spec.provider)
    if not allowed:
        raise ValueError(
            f'Provider "{spec.provider}" requires interactive authentication/2FA and cannot be scheduled unattended.'
        )
    req = {p.strip().lower() for p in spec.protocols if p.strip()}
    if not req or not req.issubset(allowed):
        disallowed = sorted(req - allowed)
        raise ValueError(
            f'Protocols {disallowed} for "{spec.provider}" require manual/authenticated user action and cannot be scheduled.'
        )
    if spec.interval_minutes < 15 or spec.interval_minutes > 43200:
        raise ValueError('Schedule interval must be between 15 and 43200 minutes.')


def snapshot_config_hashes(root: Path) -> dict[str, str]:
    """Compute relative_path -> sha256 map for all .ovpn/.conf files under root."""
    root = Path(root).resolve()
    if not root.is_dir():
        return {}
    result: dict[str, str] = {}
    for p in sorted(root.rglob('*')):
        if p.is_file() and not p.is_symlink() and p.suffix.lower() in ('.ovpn', '.conf'):
            try:
                if p.resolve().is_relative_to(root):
                    rel = str(p.relative_to(root))
                    result[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
    return result


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    """Compare before/after file hash maps to identify added, changed, unchanged, and removed configs."""
    before_keys = set(before)
    after_keys = set(after)
    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)
    common = before_keys & after_keys
    changed = sorted(k for k in common if before[k] != after[k])
    unchanged = sorted(k for k in common if before[k] == after[k])
    return {
        'new_files': len(added),
        'changed_files': len(changed),
        'unchanged_files': len(unchanged),
        'removed_files': len(removed),
        'added_sample': added[:10],
        'changed_sample': changed[:10],
    }


class SchedulerHistory:
    """Persistent non-secret history of scheduled configuration refreshes."""

    def __init__(self, base: Path | None = None):
        self.base = Path(base) if base else state_root()
        self.path = self.base / 'scheduler_history.json'

    def list(self) -> list[dict]:
        if not self.path.is_file():
            return []
        try:
            raw = json.loads(self.path.read_text('utf-8'))
            return raw if isinstance(raw, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def append(self, record: dict) -> None:
        items = self.list()
        items.insert(0, record)
        items = items[:MAX_HISTORY_RECORDS]
        _private_dir(self.base)
        safe_store(self.path, json.dumps(items, ensure_ascii=False, indent=2))

    def clear(self) -> None:
        _private_dir(self.base)
        safe_store(self.path, '[]')


class ConfigScheduler:
    """Runs authorized scheduled refresh jobs with change detection and history logging."""

    def __init__(self, *, base: Path | None = None, provider_loader=None):
        self.history = SchedulerHistory(base=base)
        self._provider_loader = provider_loader or load_providers

    def run_once(
        self,
        spec: ScheduleJobSpec,
        *,
        emit: Callable[[Event], None] | None = None,
        stop: threading.Event | None = None,
        pause: threading.Event | None = None,
    ) -> dict:
        validate_unattended_spec(spec)
        send = emit or (lambda e: None)
        stop_ev = stop or threading.Event()
        pause_ev = pause or threading.Event()
        if pause is None:
            pause_ev.set()

        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()
        output_root = spec.output or str(Path.home() / 'Documents' / 'MultiVPN-Configs')
        opts = Options(
            output=output_root,
            protocols=list(spec.protocols),
            archive=False,
            account='default',
            timeout=spec.timeout,
            delay=spec.delay,
            overwrite=False,
        )
        target_dir = provider_output_dir(opts, spec.provider)
        before_snap = snapshot_config_hashes(target_dir)

        status = 'completed'
        error_msg = ''
        manifest_summary = {}
        try:
            provider = self._provider_loader()[spec.provider]
            send(Event('info', f'Scheduled refresh started for {provider.label} ({", ".join(spec.protocols)})'))
            outcome = provider.export(
                locations=[],
                credentials=Credentials(),
                options=opts,
                source_path='',
                emit=send,
                stop=stop_ev,
                pause=pause_ev,
            )
            if stop_ev.is_set():
                status = 'cancelled'
            elif outcome.get('failed') and not (outcome.get('downloaded') or outcome.get('reused')):
                status = 'failed'
                warnings = outcome.get('warnings') or []
                error_msg = redact_secrets('; '.join(str(w) for w in warnings))[:200]
            if target_dir.is_dir():
                manifest_summary = build_manifest(target_dir)
        except Exception as exc:
            status = 'failed'
            error_msg = redact_secrets(f'{type(exc).__name__}: {exc}')[:200]
            send(Event('fail', f'Scheduled refresh failed: {type(exc).__name__}'))

        after_snap = snapshot_config_hashes(target_dir)
        changes = diff_snapshots(before_snap, after_snap)
        duration = round(time.monotonic() - t0, 2)

        record = {
            'timestamp': started_at,
            'provider': spec.provider,
            'protocols': list(spec.protocols),
            'status': status,
            'duration_sec': duration,
            'new_files': changes['new_files'],
            'changed_files': changes['changed_files'],
            'unchanged_files': changes['unchanged_files'],
            'total_valid': manifest_summary.get('total_structurally_valid', len(after_snap)),
            'error': error_msg,
        }
        self.history.append(record)
        send(Event(
            'success' if status == 'completed' else 'fail',
            f'Scheduled refresh {status}: +{changes["new_files"]} new, {changes["changed_files"]} changed, {changes["unchanged_files"]} unchanged ({duration}s)',
        ))
        return record
