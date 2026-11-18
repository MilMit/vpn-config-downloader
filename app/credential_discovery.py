"""Opt-in extraction of manual OpenVPN service credentials.

Security policy:
- NEVER inspects website login forms, account passwords, browser password managers,
  or 2FA tokens.
- For Windscribe, uses the official authenticated REST API (/ServerCredentials?type=openvpn)
  when a session token is available.
- For Surfshark and Proton VPN, inspects only visible, non-login manual OpenVPN
  service credential blocks on the official manual-setup / account portal page,
  polling cleanly while the SPA renders.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from .account_registry import validate_account
from .accounts import (
    ProtocolVault,
    VaultUnavailable,
    harden_profile_tree,
    launch_browser_context,
    profile_dir,
    windscribe_cookie,
)

MANUAL_PAGES = {
    'surfshark': 'https://my.surfshark.com/vpn/manual-setup/main/openvpn',
    'proton': 'https://account.protonvpn.com/account-password',
    'windscribe': 'https://windscribe.com/myaccount/config-generator#openvpn',
}

ALLOWED_HOSTS = {
    'surfshark': ('surfshark.com',),
    'proton': ('protonvpn.com', 'proton.me'),
    'windscribe': ('windscribe.com',),
}

# Strictly refuses login pages/forms. Reads visible manual OpenVPN service credentials
# from either readonly <input> fields or copyable <code>/<span>/<div> value blocks.
SCRIPT = r'''() => {
  const path = (window.location.pathname || '').toLowerCase();
  if (/\/(login|signin|sign-in|auth|authentication)\b/.test(path)) return null;
  // Refuse if an editable website login password box is visible
  const loginPw = Array.from(document.querySelectorAll('input[type="password"]'))
    .filter(el => el.offsetParent !== null && !el.readOnly && !el.disabled);
  if (loginPw.length > 0 && /sign in|log in/i.test(document.body?.innerText?.slice(0, 1200) || '')) {
    return null;
  }

  const cleanVal = (s) => {
    const v = String(s || '').trim();
    if (!v || v.length < 4 || v.length > 256 || /[\r\n\x00]/.test(v)) return '';
    if (/^[•*●▪]+$/.test(v)) return ''; // masked dots are not real passwords
    if (/\s{2,}/.test(v)) return '';
    if (/^(username|password|copy|copied|show|hide|reveal|reset|change|edit|save|generate|credentials|openvpn|ikev2|openvpn\s*\/?\s*ikev2\s+(username|password))$/i.test(v)) return '';
    return v;
  };

  // Strategy A0: Dedicated Proton VPN #section-openvpn (never touches #section-password)
  const protonOvpn = document.querySelector('#section-openvpn');
  if (protonOvpn) {
    const codes = Array.from(protonOvpn.querySelectorAll('code'))
      .map(el => cleanVal(el.innerText || el.textContent))
      .filter(Boolean);
    if (codes.length >= 2 && codes[0] !== codes[1] && !/@/.test(codes[0])) {
      return { username: codes[0], password: codes[1] };
    }
  }

  // Strategy A: Read from visible <input> elements inside a manual/OpenVPN credentials container
  const containers = Array.from(document.querySelectorAll('section, article, fieldset, main, div'));
  const matches = [];
  for (const node of containers) {
    const text = (node.innerText || '').slice(0, 4000);
    if (text.length < 16 || text.length > 3500) continue;
    const hasContext = /(openvpn|ikev2|manual|service credentials|router credentials|credentials)/i.test(text);
    if (!hasContext) continue;
    const values = {};

    // A1: Input fields (readonly/disabled or text fields inside manual credentials container)
    for (const input of Array.from(node.querySelectorAll('input'))) {
      if (input.offsetParent === null || !input.value) continue;
      if (/current-password|new-password|email/.test((input.autocomplete || '').toLowerCase())) continue;
      if (input.type === 'password' && !input.readOnly && !input.disabled) continue;
      const id = input.id || '';
      const label = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null;
      const desc = [
        input.name || '', input.placeholder || '', input.getAttribute('aria-label') || '',
        label?.innerText || '', input.parentElement?.innerText?.slice(0, 120) || ''
      ].join(' ').toLowerCase();
      const v = cleanVal(input.value);
      if (!v) continue;
      if (/username|user name|vpn user/.test(desc) && !values.username) values.username = v;
      if (/password|passphrase|vpn pass/.test(desc) && !values.password) values.password = v;
    }

    // A2: Labeled text / code / copyable blocks (Surfshark & Proton OpenVpnIKEv2 SPA style)
    if (!values.username || !values.password) {
      const lines = text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      const userLabelRe = /^(openvpn\s*\/?\s*ikev2\s+)?(manual\s+|service\s+)?username:?$/;
      const passLabelRe = /^(openvpn\s*\/?\s*ikev2\s+)?(manual\s+|service\s+)?password:?$/;
      for (let i = 0; i < lines.length; i++) {
        const cur = lines[i].toLowerCase();
        // Same-line "Username: value" or "OpenVPN / IKEv2 username: value"
        const inlineUser = lines[i].match(/^(?:openvpn\s*\/?\s*ikev2\s+)?(?:manual\s+|service\s+)?username\s*:\s*(\S+)$/i);
        if (inlineUser && !values.username) {
          const cand = cleanVal(inlineUser[1]);
          if (cand && !/@/.test(cand)) values.username = cand;
          continue;
        }
        const inlinePass = lines[i].match(/^(?:openvpn\s*\/?\s*ikev2\s+)?(?:manual\s+|service\s+)?password\s*:\s*(\S+)$/i);
        if (inlinePass && !values.password) {
          const cand = cleanVal(inlinePass[1]);
          if (cand && !/@/.test(cand)) values.password = cand;
          continue;
        }
        // Multi-line label -> optional Copy/Show button text -> value (look ahead up to 3 lines)
        if (userLabelRe.test(cur) && !values.username) {
          for (let off = 1; off <= 3 && i + off < lines.length; off++) {
            const nxt = cleanVal(lines[i + off]);
            if (nxt && !/@/.test(nxt) && !passLabelRe.test(lines[i + off].toLowerCase())) {
              values.username = nxt;
              break;
            }
          }
        } else if (passLabelRe.test(cur) && !values.password) {
          for (let off = 1; off <= 3 && i + off < lines.length; off++) {
            const nxt = cleanVal(lines[i + off]);
            if (nxt && !/@/.test(nxt) && !userLabelRe.test(lines[i + off].toLowerCase())) {
              values.password = nxt;
              break;
            }
          }
        }
      }
    }

    if (values.username && values.password && values.username !== values.password) {
      matches.push(values);
    }
  }
  if (matches.length === 0) return null;
  const unique = matches.filter((x, i, a) => a.findIndex(y => x.username === y.username && x.password === y.password) === i);
  return unique.length === 1 ? unique[0] : unique[0];
}'''


def recognize_credentials_on_page(page) -> tuple[str, str] | None:
    """Helper with a Playwright-like page; never logs the resulting secret."""
    result = page.evaluate(SCRIPT)
    if not isinstance(result, dict):
        return None
    u, p = result.get('username'), result.get('password')
    if not isinstance(u, str) or not isinstance(p, str) or not u or not p:
        return None
    if any(c in u + p for c in '\n\r\x00'):
        return None
    return u, p


def _host_allowed(hostname: str | None, provider: str) -> bool:
    if not hostname:
        return False
    return any(hostname == h or hostname.endswith('.' + h) for h in ALLOWED_HOSTS.get(provider, ()))


def discover_openvpn_credentials(
    provider: str,
    account: str = 'default',
    *,
    factory=None,
    timeout: int = 25000,
    session_token: str = '',
    max_poll_seconds: float = 120.0,
) -> tuple[str, str] | None:
    """Retrieve manual OpenVPN service credentials safely without authentication bypass."""
    validate_account(provider, account)

    # 1. Windscribe official 2026 REST API path (instant & exact)
    if provider == 'windscribe':
        token = session_token.strip()
        if not token:
            try:
                token = ProtocolVault().get_session_token('windscribe', account) or ''
            except VaultUnavailable:
                token = ''
        if not token and factory is None:
            try:
                token = windscribe_cookie(account=account) or ''
            except Exception:
                token = ''
        if token:
            from .providers.windscribe_backend_v3 import get_openvpn_credentials
            try:
                return get_openvpn_credentials(token, timeout=max(10, int(timeout / 1000)))
            except Exception:
                pass

    # 2. Visible browser SPA reader for Surfshark / Proton (and Windscribe fallback)
    if factory is None:
        from playwright.sync_api import sync_playwright
        factory = sync_playwright
    target = MANUAL_PAGES[provider]
    path = profile_dir(provider, account=account, create=True)
    with factory() as pw:
        ctx = launch_browser_context(pw, path, headless=False, accept_downloads=False)
        try:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            try:
                page.goto(target, wait_until='domcontentloaded', timeout=timeout)
            except Exception:
                return None
            deadline = time.monotonic() + max_poll_seconds
            reveal_clicked = False
            while time.monotonic() < deadline:
                pages = [p for p in getattr(ctx, 'pages', [page]) if not p.is_closed()]
                if not pages:
                    return None
                for active_page in pages:
                    try:
                        resolved = urlsplit(active_page.url)
                        if resolved.scheme == 'https' and _host_allowed(resolved.hostname, provider):
                            # For Proton, safely click Show ONLY inside #section-openvpn (never account #section-password)
                            if provider == 'proton' and not reveal_clicked and hasattr(active_page, 'locator'):
                                try:
                                    show_btn = active_page.locator(
                                        '#section-openvpn button[title="Show"]:visible, #section-openvpn button:visible:has-text("Show")'
                                    ).first
                                    if show_btn.count():
                                        show_btn.click(timeout=2500)
                                        reveal_clicked = True
                                        active_page.wait_for_timeout(400)
                                except Exception:
                                    pass
                            found = recognize_credentials_on_page(active_page)
                            if found:
                                return found
                    except Exception as exc:
                        low = str(exc).lower()
                        if 'target closed' in low or 'browser has been closed' in low or 'context closed' in low:
                            return None
                        # Ignore transient SPA redirect errors (e.g. Execution context was destroyed)
                        continue
                try:
                    pages[0].wait_for_timeout(800)
                except Exception as exc:
                    low = str(exc).lower()
                    if 'target closed' in low or 'browser has been closed' in low or 'context closed' in low:
                        return None
                    time.sleep(0.5)
            return None
        finally:
            try:
                ctx.close()
            except Exception:
                pass
            harden_profile_tree(path)
