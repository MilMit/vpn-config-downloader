"""Conservative live session diagnostics using official account pages.

It is safer to return UNKNOWN rather than mislabel a persisted browser profile
as an authenticated account. Never access passwords, responses, cookies or 2FA.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .accounts import PROVIDER_URLS, profile_dir, has_session_profile, harden_profile_tree, launch_browser_context
from .account_registry import AccountRegistry, validate_account


@dataclass(frozen=True)
class SessionCheck:
    state: str  # absent, expired, browser_error, unknown, portal_accessible
    detail: str
    plan_hint: str = ''
    checked_at: str = ''


def _detect_plan_hint(page, provider: str) -> str:
    """Best-effort, strictly non-secret subscription/plan hint from visible page text."""
    try:
        snippet = page.evaluate('() => (document.body?.innerText || "").slice(0, 4000)')
        if not isinstance(snippet, str):
            return ''
        low = snippet.lower()
        if provider == 'windscribe':
            if 'pro' in re.findall(r'\bpro\b', low) and ('account' in low or 'unlimited' in low):
                return 'Pro (unverified page text)'
            if 'free' in re.findall(r'\bfree\b', low) and 'gb' in low:
                return 'Free (config generator usually requires Pro)'
        elif provider == 'proton':
            for tier in ('vpn plus', 'proton unlimited', 'proton visionary', 'proton free', 'vpn free'):
                if tier in low:
                    return f'{tier.title()} (unverified page text)'
        elif provider == 'surfshark':
            for tier in ('surfshark one+', 'surfshark one', 'surfshark starter', 'active subscription'):
                if tier in low:
                    return f'{tier.title()} (unverified page text)'
    except Exception:
        pass
    return ''


def check_account_session(
    provider: str,
    alias: str = 'default',
    *,
    factory=None,
    timeout: int = 25_000,
    base: Path | None = None,
    record_status: bool = True,
) -> SessionCheck:
    validate_account(provider, alias)
    now_iso = datetime.now(timezone.utc).isoformat()

    def _finish(state: str, detail: str, plan_hint: str = '') -> SessionCheck:
        res = SessionCheck(state=state, detail=detail, plan_hint=plan_hint, checked_at=now_iso)
        if record_status:
            try:
                AccountRegistry(base=base).set_status(provider, alias, state=state, detail=detail, plan_hint=plan_hint)
            except Exception:
                pass
        return res

    if not has_session_profile(provider, base=base, account=alias):
        return _finish('absent', 'No saved Chromium profile. Sign in first.')
    if factory is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return _finish('browser_error', 'Install Playwright and Chromium.')
        factory = sync_playwright
    path = profile_dir(provider, base=base, account=alias)
    try:
        with factory() as pw:
            ctx = launch_browser_context(pw, path, headless=True, accept_downloads=False)
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.goto(PROVIDER_URLS[provider], wait_until='domcontentloaded', timeout=timeout)
                page.wait_for_timeout(1200)
                url = urlsplit(page.url)
                if url.scheme != 'https':
                    return _finish('unknown', 'Unexpected navigation; login not verified.')
                # In all cases only negative evidence of login is strong enough.
                if any(x in url.path.lower() for x in ('/login', '/signin', '/sign-in', '/authentication')):
                    return _finish('expired', 'Official portal redirected to a sign-in page. Re-login required.')
                if page.locator('input[type="password"]:visible').count():
                    return _finish('expired', 'Official portal displayed a login password field. Re-login required.')
                if url.hostname and any(
                    url.hostname == h or url.hostname.endswith('.' + h)
                    for h in ('surfshark.com', 'protonvpn.com', 'proton.me', 'windscribe.com')
                ):
                    plan_hint = _detect_plan_hint(page, provider)
                    return _finish(
                        'portal_accessible',
                        'Protected portal opened; verify account entitlement before export.',
                        plan_hint=plan_hint,
                    )
                return _finish('unknown', 'No definitive evidence of valid session.')
            finally:
                ctx.close()
    except Exception:
        return _finish('browser_error', 'Browser check failed or profile is in use; close other Chromium windows.')
    finally:
        harden_profile_tree(path)
