First public beta of **VPN Config Downloader**.

## Downloads

- **Windows x86_64:** download the `windows-x86_64.zip` asset, extract the entire folder and run `VPNConfigDownloader.exe`.
- **Linux x86_64:** download the `linux-x86_64.tar.gz` asset, extract it and run `./VPNConfigDownloader/VPNConfigDownloader`. The build is tested on Ubuntu 24.04.
- **SHA256SUMS.txt:** checksums for both application packages.

Both packages include Python, the application dependencies and Playwright Chromium. A separate Python installation is not needed. Keep the executable and its `_internal` folder together. Linux still needs system Qt/Chromium libraries; if Qt reports missing libraries on Ubuntu, install `libegl1 libgl1 libopengl0 libxkbcommon0 libdbus-1-3`.

## Validation

The release workflow runs the unit/integration suite, GUI checks and native application startup checks on Windows and Linux before publication. Package inspection verifies that Chromium is included and that the Linux executable retains its permissions.

## Beta limitations

Account-authenticated provider downloads and real VPN connectivity remain unverified end to end. The optional OpenVPN probe is not an OS sandbox and must only be used with trusted configurations. Other reproduced limitations are documented in [KNOWN_ISSUES.md](https://github.com/MilMit/vpn-config-downloader/blob/main/KNOWN_ISSUES.md).

Windows builds are unsigned and may display a Windows security prompt.
