# Known issues — beta

These limitations were reproduced during the local pre-publication review. Passing the existing test suite does not cover these cases.

## Optional OpenVPN probe is not sandboxed

`app/health.py` passes the original profile to OpenVPN. Non-routing flags do not filter other configuration directives or isolate the process from the filesystem. A profile containing a `log` directive created a file during a local check. Only enable the optional connection probe for trusted configurations; never run the application as root. Config inspection/import and the optional live probe are separate operations.

A future update should restrict supported directives and isolate execution before accepting untrusted profiles for live checks.

## Deduplication after a write failure

`app/download_manager.py` reserves a content hash before the file has been written and verified. If that write fails, a later task with identical content can be marked duplicate even though no usable copy was saved. Check failed tasks and rerun the export after resolving the filesystem error.

## Existing archive verification does not enforce AES-256

`verify_aes_zip()` checks encryption and successful decryption, but does not require the AES-256 encryption variant. An AES-128 archive was accepted during review. The application's archive writer explicitly requests AES-256; the issue concerns verification of existing/imported archives.

## Single-file CLI validation performs a network probe

`python -m app.cli --validate file.ovpn` currently attempts DNS/TCP checks even without `--check-reachability`. Directory validation respects that flag. For offline structural checks, put the file in its own directory and validate the directory without the flag.

## Provider and platform verification

- Provider adapters depend on external portals/APIs, user accounts and subscription permissions.
- Account-authenticated downloads and actual VPN tunnel connectivity have not been verified end to end in this environment.
- Native Windows packaging must be tested on Windows or GitHub Actions.
- Source and executable releases are separate. The old local `dist/MultiVPNConfigManager/` binary predates the rename and is excluded from this repository.
