# VPN Config Downloader v4.1 — Engineering Architecture

## Module Layout

```text
app/
├── providers/
│   ├── base.py                  # Plugin ABC + 6-protocol standardized capability matrix
│   ├── __init__.py              # Extensible ProviderRegistry (register/unregister/load)
│   ├── official_download.py     # Surfshark live cluster discovery, bulk OpenVPN ZIP & browser capture
│   ├── importers.py             # Surfshark & Proton VPN adapters (AUTO + local import)
│   ├── windscribe.py            # Windscribe adapter integrated with concurrent DownloadManager
│   └── windscribe_backend_v3.py # Windscribe public server list, manual generator, IKEv2 & transport kits
├── ui/
│   ├── theme.py                 # Dark & Light QSS themes + status badge colors
│   ├── workers.py               # Non-blocking QThread workers (download, login, check, validator, scheduler)
│   ├── pages.py                 # Modular builders for all 10 GUI pages
│   └── main.py                  # MainWindow orchestration, settings, theme switching & shutdown guards
├── download_manager.py          # Concurrent DownloadManager (retry, 429 backoff, checkpoint, atomic verify)
├── scheduler.py                 # Authorized unattended ConfigScheduler (SHA-256 change detection + history)
├── health.py                    # 3-stage Health Checker (Syntax, Reachability, optional isolated VPN check)
├── security.py                  # X25519 keypairs, AES-256 ZIP + real verify, ZIP-bomb/traversal guard, redaction
├── protocol_manifest.py         # Non-secret structural preflight (OpenVPN certs, WireGuard key format)
├── accounts.py                  # Isolated per-(provider, alias) Chromium profiles & OS Keyring ProtocolVault
├── account_registry.py          # Non-secret multi-account index & session check status history
├── session_check.py             # Conservative official portal session check + non-secret plan hint
├── credential_discovery.py      # Opt-in beta reader for visible manual OpenVPN service credentials
├── auth_export.py               # Explicit opt-in OpenVPN service auth-file linker
├── core.py                      # Core models, standardized capability statuses, atomic writes, dedupe importer
└── cli.py                       # Headless CLI (export, --list-providers, --validate, --verify-zip)
```

## Security & Verification Invariants

1. **No website passwords or 2FA in app/logs:** Users sign into official vendor portals inside isolated Chromium profiles. All logs and error reports pass through `redact_secrets()`.
2. **Profile presence ≠ authenticated session:** `has_session_profile()` only reports local state; `check_account_session()` inspects live portal redirects/password prompts conservatively.
3. **No silent plaintext fallback:** `aes_zip()` uses `pyzipper` WinZip AES-256 with a minimum 12-character transient password and runs full `verify_aes_zip()` decryption before atomic commit.
4. **ZIP-bomb & Path Traversal defenses:** `safe_zip_entries()` enforces max entry count, max entry size, cumulative expanded size, compression ratio limits, symlink rejection, and Unix/Windows path traversal (`..`, `/`, `C:\`).
5. **Three independent health states:** Syntax Validation, Endpoint Reachability (DNS/TCP), and VPN Connection Verification (`Not Tested` unless explicitly consented). The OpenVPN probe uses non-routing flags but is not an OS sandbox; configuration directives are not filtered. Only trusted profiles should be passed to the optional probe. See `KNOWN_ISSUES.md`.
6. **Authorized-only scheduling:** `validate_unattended_spec()` strictly blocks scheduling interactive/2FA/cookie/password tasks; only public Surfshark OpenVPN archive refreshes are permitted unattended.
7. **Zero fabricated protocols:** Unsupported or manual-only protocols display exact status (`Supported`, `Requires Manual Action`, `Experimental`, `Unsupported`).
