"""GUI smoke test using actual PySide6, with no VPN login or network requests.

Run with QT_QPA_PLATFORM=offscreen on Linux.
"""
from __future__ import annotations

import os
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix='multivpn-ui-test-') as home:
        os.environ['MULTIVPN_STATE_DIR'] = home
        os.environ['QT_QPA_PLATFORM'] = os.environ.get('QT_QPA_PLATFORM', 'offscreen')
        from PySide6.QtWidgets import QApplication
        from app.ui.main import MainWindow

        app = QApplication.instance() or QApplication([])
        win = MainWindow()
        assert 'v4' in win.windowTitle().lower()
        # Verify all 10 required pages exist
        assert win.stack.count() == 10
        assert len(win.nav_buttons) == 10
        assert win.archive_checkbox.isChecked()
        assert win.secure_archive.isChecked()

        # Navigate across every single page without errors
        for idx in range(win.stack.count()):
            win.nav_to(idx)
            app.processEvents()

        # Verify Dark / Light mode toggle (independent of persisted QSettings theme)
        initial_theme = win.theme_choice.currentData()
        expected_flipped = 'light' if initial_theme == 'dark' else 'dark'
        win.toggle_theme()
        app.processEvents()
        assert win.theme_choice.currentData() == expected_flipped
        win.toggle_theme()
        app.processEvents()
        assert win.theme_choice.currentData() == initial_theme

        # Verify Provider capability matrix populates all 6 protocols
        win.provider_choice.setCurrentIndex(1)  # Surfshark
        app.processEvents()
        assert win.provider_matrix_table.rowCount() == 6

        # Verify multi-account isolation & selection
        win.account_provider.setCurrentIndex(1)
        win.account_registry.add('surfshark', 'ci_account')
        win.settings.setValue('current_account_surfshark', 'ci_account')
        win.refresh_aliases()
        assert win.account_alias.findData('ci_account') >= 0
        win.account_alias.setCurrentIndex(win.account_alias.findData('ci_account'))
        assert win.alias() == 'ci_account'

        # Verify concurrency sync between Downloads and Settings
        win.concurrency.setValue(4)
        assert win.quick_concurrency.value() == 4
        win.quick_concurrency.setValue(3)
        assert win.concurrency.value() == 3

        # Verify Validator page fields & consent default off
        assert not win.vpn_verify_consent.isChecked()
        win.health_path.setText('/invalid/config.conf')

        # Verify Logs redaction
        from app.core import Event as CoreEvent
        win.log(CoreEvent('info', 'PrivateKey = SuperSecretKeyValue12345678901234567890='))
        assert 'SuperSecretKeyValue' not in win.logs.toPlainText()
        assert '[REDACTED]' in win.logs.toPlainText()

        # Verify Windscribe visual cookie guide dialog & provider/cookie auto-sync
        from app.ui.guides import WindscribeCookieGuideDialog
        dlg_dark = WindscribeCookieGuideDialog(win, dark=True)
        dlg_light = WindscribeCookieGuideDialog(win, dark=False)
        dlg_dark.close()
        dlg_light.close()

        # Switching to Surfshark then pasting a Windscribe cookie must switch active provider to Windscribe
        win.select_provider_by_key('surfshark')
        app.processEvents()
        assert win.provider().key == 'surfshark'
        win.cookie.setText('sample_ws_cookie_token')
        app.processEvents()
        assert win.provider().key == 'windscribe'
        assert 'Windscribe' in win.context_pill.text()
        assert win.account_profile_badge.text() == 'RAM Cookie Active'
        win.cookie.clear()

        win.show()
        app.processEvents()
        win.close()
        app.processEvents()
        print('GUI smoke test passed across all 10 pages, Dark/Light theme, accounts, validator, and log redaction.')


if __name__ == '__main__':
    main()
