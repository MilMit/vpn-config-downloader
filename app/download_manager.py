"""Professional concurrent Download Manager with checkpointing, rate-limit backoff and atomic writes.

A task is counted as succeeded ONLY after its content is received, validated,
atomically written to disk, and verified readable on disk.
No secrets (cookies, tokens, passwords, private keys) are written to checkpoints or errors.
"""
from __future__ import annotations

import hashlib
import json
import random
import threading
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .core import Event, safe_store, valid_profile
from .security import redact_secrets


class RateLimitError(Exception):
    """Raised when a remote endpoint returns HTTP 429 or signals rate limiting."""
    def __init__(self, message: str = 'Rate limited', retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class TransientDownloadError(Exception):
    """Raised on transient network/5xx errors eligible for backoff retry."""


@dataclass
class DownloadTask:
    task_id: str
    label: str
    protocol: str
    destination: Path
    fetcher: Callable[[], bytes | str]
    metadata: dict = field(default_factory=dict)
    validate_kind: str = ''  # defaults to protocol; set to 'none' to skip valid_profile


@dataclass
class TaskOutcome:
    task_id: str
    label: str
    protocol: str
    status: str  # 'downloaded', 'reused', 'duplicate', 'failed', 'cancelled', 'skipped'
    file: str = ''
    sha256: str = ''
    attempts: int = 0
    error_type: str = ''
    error_detail: str = ''
    metadata: dict = field(default_factory=dict)


class GlobalRateLimiter:
    """Thread-safe pacing and shared HTTP 429 cooldown across concurrent download workers."""

    def __init__(self, min_interval: float = 0.0):
        self.min_interval = max(0.0, float(min_interval))
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def trigger_cooldown(self, seconds: float) -> None:
        cooldown = min(90.0, max(1.0, float(seconds)))
        with self._lock:
            target = time.monotonic() + cooldown
            if target > self._next_allowed:
                self._next_allowed = target

    def wait_slot(self, stop: threading.Event, pause: threading.Event) -> bool:
        """Reserve next allowed request slot, honoring pause and cancellation.

        Returns False if cancelled before acquiring slot.
        """
        while True:
            if stop.is_set():
                return False
            while not pause.wait(0.1):
                if stop.is_set():
                    return False
            with self._lock:
                now = time.monotonic()
                if now >= self._next_allowed:
                    self._next_allowed = now + self.min_interval
                    return True
                wait_for = self._next_allowed - now
            if not _interruptible_sleep(wait_for, stop, pause):
                return False


def _interruptible_sleep(seconds: float, stop: threading.Event, pause: threading.Event) -> bool:
    """Sleep up to `seconds`, waking immediately on `stop` and freezing during `pause`."""
    remaining = max(0.0, float(seconds))
    while remaining > 0:
        if stop.is_set():
            return False
        if not pause.is_set():
            pause.wait(0.15)
            continue
        step = min(0.15, remaining)
        if stop.wait(step):
            return False
        remaining -= step
    return not stop.is_set()


class DownloadCheckpoint:
    """Atomic JSON checkpoint file tracking completed, failed, and pending task IDs."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self) -> dict:
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text('utf-8'))
                if isinstance(raw, dict) and isinstance(raw.get('tasks'), dict):
                    return raw
            except (OSError, json.JSONDecodeError):
                pass
        return {
            'schema_version': 1,
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'tasks': {},
        }

    def record(self, outcome: TaskOutcome) -> None:
        with self._lock:
            self.data['updated_at'] = datetime.now(timezone.utc).isoformat()
            self.data['tasks'][outcome.task_id] = {
                'label': outcome.label,
                'protocol': outcome.protocol,
                'status': outcome.status,
                'file': outcome.file,
                'sha256': outcome.sha256[:16] if outcome.sha256 else '',
                'attempts': outcome.attempts,
                'error_type': outcome.error_type,
                'error_detail': redact_secrets(outcome.error_detail)[:180],
                'metadata': {k: v for k, v in outcome.metadata.items()
                             if k not in ('cookie', 'password', 'private_key', 'auth_hash')},
            }
            safe_store(self.path, json.dumps(self.data, ensure_ascii=False, indent=2))

    def failed_ids(self) -> set[str]:
        with self._lock:
            return {
                tid for tid, entry in self.data.get('tasks', {}).items()
                if entry.get('status') in ('failed', 'cancelled')
            }

    def completed_ids(self) -> set[str]:
        with self._lock:
            return {
                tid for tid, entry in self.data.get('tasks', {}).items()
                if entry.get('status') in ('downloaded', 'reused')
            }

    def summary(self) -> dict:
        with self._lock:
            tasks = self.data.get('tasks', {}).values()
            return {
                'total_tracked': len(self.data.get('tasks', {})),
                'downloaded': sum(1 for t in tasks if t.get('status') == 'downloaded'),
                'reused': sum(1 for t in tasks if t.get('status') == 'reused'),
                'duplicate': sum(1 for t in tasks if t.get('status') == 'duplicate'),
                'failed': sum(1 for t in tasks if t.get('status') == 'failed'),
                'cancelled': sum(1 for t in tasks if t.get('status') == 'cancelled'),
            }


class DownloadManager:
    """Concurrent, resumable, rate-limit-aware download engine with atomic verification."""

    def __init__(
        self,
        root: Path,
        *,
        concurrency: int = 2,
        retries: int = 2,
        delay: float = 1.0,
        base_backoff: float = 1.5,
        max_backoff: float = 45.0,
        overwrite: bool = False,
        checkpoint_name: str = 'checkpoint.json',
        jitter: bool = True,
    ):
        self.root = Path(root).resolve()
        self.concurrency = max(1, min(8, int(concurrency)))
        self.retries = max(0, min(10, int(retries)))
        self.base_backoff = max(0.05, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        self.overwrite = bool(overwrite)
        self.jitter = jitter
        self.limiter = GlobalRateLimiter(min_interval=max(0.0, float(delay)))
        self.checkpoint = DownloadCheckpoint(self.root / checkpoint_name)
        self._dedupe_lock = threading.Lock()
        self._seen_hashes: set[str] = set()
        self._progress_lock = threading.Lock()
        self._done_count = 0

    def _compute_backoff(self, attempt: int, retry_after: float | None = None) -> float:
        exp = min(self.max_backoff, self.base_backoff * (2 ** attempt))
        if retry_after is not None and retry_after > 0:
            exp = min(90.0, max(exp, float(retry_after)))
        if self.jitter:
            exp *= random.uniform(0.85, 1.15)
        return exp

    def _extract_retry_after(self, exc: Exception) -> float | None:
        if isinstance(exc, RateLimitError):
            return exc.retry_after
        if isinstance(exc, urllib.error.HTTPError) and exc.headers:
            hdr = exc.headers.get('Retry-After')
            if hdr and hdr.strip().isascii() and hdr.strip().isdecimal():
                return float(hdr.strip())
        return None

    def _is_retryable(self, exc: Exception) -> tuple[bool, bool]:
        """Returns (should_retry, is_rate_limit)."""
        if isinstance(exc, RateLimitError):
            return True, True
        if isinstance(exc, urllib.error.HTTPError):
            if exc.code == 429:
                return True, True
            if exc.code in (500, 502, 503, 504):
                return True, False
            return False, False
        if isinstance(exc, (TransientDownloadError, urllib.error.URLError, TimeoutError, ConnectionError)):
            return True, False
        return False, False

    def _execute_one(
        self,
        task: DownloadTask,
        total: int,
        emit: Callable[[Event], None],
        stop: threading.Event,
        pause: threading.Event,
    ) -> TaskOutcome:
        validate_kind = task.validate_kind or task.protocol
        rel = str(task.destination.relative_to(self.root)) if task.destination.resolve().is_relative_to(self.root) else task.destination.name

        # Wait while paused; stop immediately if cancelled.
        while not pause.wait(0.1):
            if stop.is_set():
                return TaskOutcome(task.task_id, task.label, task.protocol, 'cancelled', metadata=task.metadata)
        if stop.is_set():
            return TaskOutcome(task.task_id, task.label, task.protocol, 'cancelled', metadata=task.metadata)

        # Resume / Reuse existing valid profile on disk
        if not self.overwrite and task.destination.is_file():
            try:
                existing = task.destination.read_bytes()
                if validate_kind == 'none' or valid_profile(validate_kind, existing):
                    digest = hashlib.sha256(existing).hexdigest()
                    with self._dedupe_lock:
                        self._seen_hashes.add(digest)
                    outcome = TaskOutcome(
                        task.task_id, task.label, task.protocol, 'reused',
                        file=rel, sha256=digest, attempts=0, metadata=task.metadata,
                    )
                    self.checkpoint.record(outcome)
                    self._emit_progress(emit, 'success', f'reused: {task.label}', total)
                    return outcome
            except OSError:
                pass

        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            if stop.is_set():
                outcome = TaskOutcome(task.task_id, task.label, task.protocol, 'cancelled', attempts=attempt, metadata=task.metadata)
                self.checkpoint.record(outcome)
                return outcome
            if not self.limiter.wait_slot(stop, pause):
                outcome = TaskOutcome(task.task_id, task.label, task.protocol, 'cancelled', attempts=attempt, metadata=task.metadata)
                self.checkpoint.record(outcome)
                return outcome
            try:
                raw_data = task.fetcher()
                payload = raw_data.encode('utf-8') if isinstance(raw_data, str) else bytes(raw_data)
                if validate_kind != 'none' and not valid_profile(validate_kind, payload):
                    raise ValueError(f'{task.protocol} profile failed structural validation')
                digest = hashlib.sha256(payload).hexdigest()
                with self._dedupe_lock:
                    if digest in self._seen_hashes:
                        outcome = TaskOutcome(
                            task.task_id, task.label, task.protocol, 'duplicate',
                            sha256=digest, attempts=attempt + 1, metadata=task.metadata,
                        )
                        self.checkpoint.record(outcome)
                        self._emit_progress(emit, 'skip', f'duplicate skipped: {task.label}', total)
                        return outcome
                    self._seen_hashes.add(digest)
                # Atomic write + strict post-write verification
                safe_store(task.destination, payload)
                verified = task.destination.read_bytes()
                if hashlib.sha256(verified).hexdigest() != digest:
                    raise IOError('Post-write verification digest mismatch')
                if validate_kind != 'none' and not valid_profile(validate_kind, verified):
                    raise IOError('Post-write validation failed')
                outcome = TaskOutcome(
                    task.task_id, task.label, task.protocol, 'downloaded',
                    file=rel, sha256=digest, attempts=attempt + 1, metadata=task.metadata,
                )
                self.checkpoint.record(outcome)
                self._emit_progress(emit, 'success', f'downloaded: {task.label}', total)
                return outcome
            except Exception as exc:
                last_exc = exc
                retryable, is_rate_limit = self._is_retryable(exc)
                if not retryable or attempt >= self.retries:
                    break
                retry_after = self._extract_retry_after(exc)
                delay_s = self._compute_backoff(attempt, retry_after=retry_after)
                if is_rate_limit:
                    self.limiter.trigger_cooldown(delay_s)
                    emit(Event('info', f'Rate limit on {task.label}; backing off {delay_s:.1f}s (retry {attempt + 1}/{self.retries})'))
                else:
                    emit(Event('info', f'Transient {type(exc).__name__} on {task.label}; retrying in {delay_s:.1f}s ({attempt + 1}/{self.retries})'))
                if not _interruptible_sleep(delay_s, stop, pause):
                    outcome = TaskOutcome(task.task_id, task.label, task.protocol, 'cancelled', attempts=attempt + 1, metadata=task.metadata)
                    self.checkpoint.record(outcome)
                    return outcome

        err_type = type(last_exc).__name__ if last_exc else 'UnknownError'
        err_msg = redact_secrets(str(last_exc))[:180] if last_exc else ''
        outcome = TaskOutcome(
            task.task_id, task.label, task.protocol, 'failed',
            attempts=self.retries + 1, error_type=err_type, error_detail=err_msg,
            metadata=task.metadata,
        )
        self.checkpoint.record(outcome)
        self._emit_progress(emit, 'fail', f'failed: {task.label} ({err_type})', total)
        return outcome

    def _emit_progress(self, emit: Callable[[Event], None], kind: str, message: str, total: int) -> None:
        with self._progress_lock:
            self._done_count += 1
            current = self._done_count
        emit(Event(kind, message, current, total))

    def run(
        self,
        tasks: list[DownloadTask],
        *,
        emit: Callable[[Event], None],
        stop: threading.Event,
        pause: threading.Event,
        only_failed_from_checkpoint: bool = False,
    ) -> list[TaskOutcome]:
        """Execute tasks concurrently and return outcomes in submission order."""
        self.root.mkdir(parents=True, exist_ok=True)
        queue = tasks
        if only_failed_from_checkpoint:
            failed = self.checkpoint.failed_ids()
            queue = [t for t in tasks if t.task_id in failed]
        total = len(queue)
        self._done_count = 0
        if not queue:
            return []

        outcomes_by_id: dict[str, TaskOutcome] = {}
        if self.concurrency <= 1:
            for task in queue:
                if stop.is_set():
                    outcomes_by_id[task.task_id] = TaskOutcome(
                        task.task_id, task.label, task.protocol, 'cancelled', metadata=task.metadata
                    )
                    continue
                outcomes_by_id[task.task_id] = self._execute_one(task, total, emit, stop, pause)
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                future_map = {}
                for task in queue:
                    if stop.is_set():
                        outcomes_by_id[task.task_id] = TaskOutcome(
                            task.task_id, task.label, task.protocol, 'cancelled', metadata=task.metadata
                        )
                        continue
                    fut = pool.submit(self._execute_one, task, total, emit, stop, pause)
                    future_map[fut] = task
                for fut in as_completed(future_map):
                    task = future_map[fut]
                    try:
                        outcomes_by_id[task.task_id] = fut.result()
                    except Exception as exc:
                        outcomes_by_id[task.task_id] = TaskOutcome(
                            task.task_id, task.label, task.protocol, 'failed',
                            error_type=type(exc).__name__, error_detail=redact_secrets(str(exc))[:180],
                            metadata=task.metadata,
                        )
        return [outcomes_by_id[t.task_id] for t in queue if t.task_id in outcomes_by_id]
