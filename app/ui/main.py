"""VPN Config Downloader v4.1 — Modern PySide6 Desktop Workspace."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QSettings, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..account_registry import AccountRegistry
from ..accounts import (
    PROVIDER_URLS,
    WIREGUARD_REGISTRATION_URLS,
    ProtocolVault,
    VaultUnavailable,
    forget_profile,
    has_session_profile,
)
from ..core import Credentials, Event as CoreEvent, Options, safe_store
from ..providers import load_providers
from ..scheduler import ScheduleJobSpec, SchedulerHistory
from ..security import make_keypair, public_from_private, redact_secrets, verify_aes_zip
from .guides import WindscribeCookieGuideDialog
from .icons import make_logo_pixmap, make_nav_icon
from .pages import (
    make_accounts,
    make_dashboard,
    make_downloads,
    make_exports,
    make_logs,
    make_protocols,
    make_providers,
    make_servers,
    make_settings,
    make_validator,
)
from .theme import get_stylesheet, status_badge_object_name
from .workers import (
    AccountCheckThread,
    AccountLoginThread,
    BatchHealthThread,
    CredentialReadThread,
    DiscoveryThread,
    HealthThread,
    ScheduledRefreshThread,
    WorkThread,
)

# (title, subtitle, icon_key, section_header_or_None)
NAV_SPEC = [
    ('Dashboard', 'Overview, workflow quick-start & live account health', 'dashboard', 'WORKSPACE'),
    ('Providers', 'Plugin-based adapters & 6-protocol capability matrix', 'providers', None),
    ('Accounts', 'Isolated browser sessions & OS keyring protocol secrets', 'accounts', None),
    ('Servers', 'Live server catalogs, country filter & selection', 'servers', 'EXTRACTION'),
    ('Protocols', 'Protocol toggles, ports & memory-only overrides', 'protocols', None),
    ('Downloads', 'Concurrent worker queue, checkpoints & error table', 'downloads', None),
    ('Validator', '3-stage health check: Syntax, Reachability & isolated VPN test', 'validator', 'SECURITY & TOOLS'),
    ('Exports', 'WinZip AES-256 encryption, strength meter & decryption verifier', 'exports', None),
    ('Logs', 'Secret-redacted operational audit trail', 'logs', None),
    ('Settings', 'Dark/Light theme, concurrency tuning & automatic scheduler', 'settings', None),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.providers = load_providers()
        # Retain the existing settings namespace for users upgrading after the rename.
        self.settings = QSettings('LocalTools', 'MultiVPNConfigManager')
        self.locations = []
        self._locations_provider = ''
        self.discovery = None
        self.worker = None
        self.login_worker = None
        self.account_registry = AccountRegistry()
        self.scheduler_history = SchedulerHistory()
        self.session_checker = None
        self.health_worker = None
        self.batch_health_worker = None
        self.credential_reader = None
        self.sched_worker = None
        self.last_export_result = None
        self.last_scheduled = 0.0
        self._log_entries: list[tuple[str, str, str]] = []

        self.schedule_timer = QTimer(self)
        self.schedule_timer.setInterval(60_000)
        self.schedule_timer.timeout.connect(self.maybe_schedule)
        self.schedule_timer.start()

        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self._hide_toast)

        self.success_count = 0
        self.fail_count = 0
        self.skip_count = 0
        self.last_zip = ''

        self.setWindowTitle('VPN Config Downloader v4.1 — Accounts, Extraction, Security & Diagnostics')
        self.resize(1320, 840)
        self.setMinimumSize(960, 660)

        self.build_shell()
        self.load_settings()
        self.apply_theme(notify=False)
        self.apply_provider_mode()
        self.refresh_account_state()
        self.refresh_dashboard_accounts()
        self.refresh_scheduler_history()
        self.nav_to(0)

    # ---------- UI helper factories ----------
    def text(self, content: str, *, style: str = 'Muted', size: int | None = None) -> QLabel:
        label = QLabel(content)
        if style:
            label.setObjectName(style)
        label.setWordWrap(True)
        if size:
            label.setFont(QFont('DejaVu Sans', size))
        return label

    def card(self, title: str, info: str, *, card_style: str = 'Card') -> tuple[QFrame, QLabel]:
        box = QFrame()
        box.setObjectName(card_style)
        v = QVBoxLayout(box)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(4)
        v.addWidget(self.text(title, style='KpiTitle'))
        big = self.text('0', style='Huge')
        v.addWidget(big)
        v.addWidget(self.text(info, style='Muted'))
        return box, big

    def page(self, title: str = '', subtitle: str = '') -> tuple[QWidget, QVBoxLayout]:
        wrapper = QWidget()
        wrapper.setObjectName('PageCanvas')
        layout = QVBoxLayout(wrapper)
        layout.setContentsMargins(24, 18, 24, 22)
        layout.setSpacing(14)
        if title:
            layout.addWidget(self.text(title, style='Heading'))
        if subtitle:
            layout.addWidget(self.text(subtitle, style='Muted'))
        return wrapper, layout

    def _make_table_badge(self, text: str, status_key: str | None = None) -> QWidget:
        holder = QWidget()
        hl = QHBoxLayout(holder)
        hl.setContentsMargins(6, 2, 6, 2)
        hl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        lbl = QLabel(text)
        lbl.setObjectName(status_badge_object_name(status_key if status_key is not None else text))
        hl.addWidget(lbl)
        return holder

    def _set_badge(self, label: QLabel, text: str, status_key: str):
        label.setText(text)
        label.setObjectName(status_badge_object_name(status_key))
        label.style().unpolish(label)
        label.style().polish(label)

    def show_toast(self, message: str, duration_ms: int = 3400):
        if not hasattr(self, 'toast_bar'):
            return
        self.toast_label.setText(redact_secrets(message))
        self.toast_bar.setVisible(True)
        self._toast_timer.start(duration_ms)

    def _hide_toast(self):
        if hasattr(self, 'toast_bar'):
            self.toast_bar.setVisible(False)

    # ---------- Shell & navigation ----------
    def build_shell(self):
        shell = QWidget()
        shell.setObjectName('Shell')
        self.setCentralWidget(shell)
        outer = QHBoxLayout(shell)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName('Sidebar')
        sidebar.setFixedWidth(236)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(14, 18, 14, 16)
        sl.setSpacing(3)

        # Brand Header
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(make_logo_pixmap(34))
        brand_row.addWidget(logo)
        b_col = QVBoxLayout()
        b_col.setSpacing(1)
        b_top = QHBoxLayout()
        b_top.setSpacing(6)
        b_top.addWidget(self.text('VPN CONFIG', style='Brand'))
        ver = QLabel('v4.1')
        ver.setObjectName('VersionPill')
        b_top.addWidget(ver)
        b_top.addStretch(1)
        b_col.addLayout(b_top)
        b_col.addWidget(self.text('DOWNLOADER', style='BrandSub'))
        brand_row.addLayout(b_col, 1)
        sl.addLayout(brand_row)
        sl.addSpacing(8)

        # Grouped Navigation Buttons with Vector Icons
        self.nav_buttons: list[QPushButton] = []
        for idx, (name, _sub, icon_key, section) in enumerate(NAV_SPEC):
            if section:
                sec = QLabel(section)
                sec.setObjectName('NavSection')
                sl.addWidget(sec)
            b = QPushButton(f'  {name}')
            b.setObjectName('Nav')
            b.setCheckable(True)
            b.setIconSize(QSize(17, 17))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _checked=False, i=idx: self.nav_to(i))
            sl.addWidget(b)
            self.nav_buttons.append(b)

        sl.addStretch(1)
        self.quick_theme_btn = QPushButton('  Light Mode')
        self.quick_theme_btn.setObjectName('Ghost')
        self.quick_theme_btn.setIconSize(QSize(16, 16))
        self.quick_theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quick_theme_btn.clicked.connect(self.toggle_theme)
        sl.addWidget(self.quick_theme_btn)
        sl.addSpacing(4)
        sl.addWidget(self.text('LOCAL-FIRST · OS KEYRING · AES-256', style='BrandSub'))
        outer.addWidget(sidebar)

        # Main Area
        main = QWidget()
        mv = QVBoxLayout(main)
        mv.setContentsMargins(0, 0, 0, 0)
        mv.setSpacing(0)

        # Top Header Bar
        top = QFrame()
        top.setObjectName('TopBar')
        top.setFixedHeight(74)
        tl = QHBoxLayout(top)
        tl.setContentsMargins(24, 10, 24, 10)
        tl.setSpacing(12)

        title_lay = QVBoxLayout()
        title_lay.setSpacing(2)
        self.header_title = self.text('Dashboard', style='PageTitle')
        self.top_note = self.text('Overview, workflow quick-start & live account health', style='PageSubtitle')
        title_lay.addWidget(self.header_title)
        title_lay.addWidget(self.top_note)
        tl.addLayout(title_lay, 1)

        self.context_pill = QLabel('Windscribe · default')
        self.context_pill.setObjectName('ContextPill')
        self.context_pill.setFixedHeight(32)
        tl.addWidget(self.context_pill, alignment=Qt.AlignmentFlag.AlignVCenter)

        self.status_pill = QLabel('●  Idle')
        self.status_pill.setObjectName('Pill')
        self.status_pill.setFixedHeight(32)
        tl.addWidget(self.status_pill, alignment=Qt.AlignmentFlag.AlignVCenter)

        self.top_run = QPushButton('▶  START EXPORT')
        self.top_run.setObjectName('Primary')
        self.top_run.setFixedHeight(36)
        self.top_run.setCursor(Qt.CursorShape.PointingHandCursor)
        self.top_run.clicked.connect(self.start_job)
        tl.addWidget(self.top_run, alignment=Qt.AlignmentFlag.AlignVCenter)
        mv.addWidget(top)

        # Toast bar (hidden until notification)
        toast_wrap = QWidget()
        toast_wrap.setObjectName('PageCanvas')
        twl = QHBoxLayout(toast_wrap)
        twl.setContentsMargins(24, 10, 24, 0)
        self.toast_bar = QFrame()
        self.toast_bar.setObjectName('ToastBar')
        self.toast_bar.setVisible(False)
        tbl = QHBoxLayout(self.toast_bar)
        tbl.setContentsMargins(14, 8, 12, 8)
        self.toast_label = QLabel('')
        self.toast_label.setObjectName('ToastText')
        tbl.addWidget(self.toast_label, 1)
        t_close = QPushButton('✕')
        t_close.setObjectName('ToastClose')
        t_close.setFixedSize(26, 24)
        t_close.clicked.connect(self._hide_toast)
        tbl.addWidget(t_close)
        twl.addWidget(self.toast_bar)
        mv.addWidget(toast_wrap)

        # 10-Page Stack
        self.stack = QStackedWidget()
        for builder in (
            make_dashboard,
            make_providers,
            make_accounts,
            make_servers,
            make_protocols,
            make_downloads,
            make_validator,
            make_exports,
            make_logs,
            make_settings,
        ):
            self.stack.addWidget(builder(self))

        self.concurrency.valueChanged.connect(self._sync_concurrency_from_settings)
        self.quick_concurrency.valueChanged.connect(self._sync_concurrency_from_downloads)
        self.delay.valueChanged.connect(self._sync_delay_from_settings)
        self.quick_delay.valueChanged.connect(self._sync_delay_from_downloads)
        self.cookie.textChanged.connect(self._on_windscribe_cookie_changed)

        mv.addWidget(self.stack, 1)
        outer.addWidget(main, 1)

    def _refresh_nav_icons(self):
        theme = self.theme_choice.currentData() if hasattr(self, 'theme_choice') else 'dark'
        is_light = theme == 'light'
        inactive_col = '#475569' if is_light else '#94a3b8'
        active_col = '#0d9488' if is_light else '#5eead4'
        cur = self.stack.currentIndex() if hasattr(self, 'stack') else 0
        for idx, b in enumerate(self.nav_buttons):
            icon_key = NAV_SPEC[idx][2]
            b.setIcon(make_nav_icon(icon_key, active_col if idx == cur else inactive_col, 17))
        if hasattr(self, 'quick_theme_btn'):
            if is_light:
                self.quick_theme_btn.setText('  Dark Mode')
                self.quick_theme_btn.setIcon(make_nav_icon('moon', '#334155', 16))
            else:
                self.quick_theme_btn.setText('  Light Mode')
                self.quick_theme_btn.setIcon(make_nav_icon('sun', '#fbbf24', 16))

    def _sync_concurrency_from_settings(self, val: int):
        if self.quick_concurrency.value() != val:
            self.quick_concurrency.blockSignals(True)
            self.quick_concurrency.setValue(val)
            self.quick_concurrency.blockSignals(False)

    def _sync_concurrency_from_downloads(self, val: int):
        if self.concurrency.value() != val:
            self.concurrency.blockSignals(True)
            self.concurrency.setValue(val)
            self.concurrency.blockSignals(False)

    def _sync_delay_from_settings(self, val: float):
        if hasattr(self, 'quick_delay') and abs(self.quick_delay.value() - val) > 1e-6:
            self.quick_delay.blockSignals(True)
            self.quick_delay.setValue(val)
            self.quick_delay.blockSignals(False)

    def _sync_delay_from_downloads(self, val: float):
        if abs(self.delay.value() - val) > 1e-6:
            self.delay.blockSignals(True)
            self.delay.setValue(val)
            self.delay.blockSignals(False)

    def nav_to(self, index: int):
        self.stack.setCurrentIndex(index)
        for i, b in enumerate(self.nav_buttons):
            b.setChecked(i == index)
        title, sub, _icon, _sec = NAV_SPEC[index]
        self.header_title.setText(title)
        self.top_note.setText(sub)
        self._refresh_nav_icons()
        if index == 0:
            self.refresh_dashboard_accounts()
        elif index == 2:
            self.refresh_account_state()
            self.refresh_dashboard_accounts()
        elif index == 9:
            self.refresh_scheduler_history()

    def _update_context_pill(self):
        if hasattr(self, 'context_pill') and hasattr(self, 'provider_choice'):
            p = self.provider()
            al = self.alias() if hasattr(self, 'account_alias') else 'default'
            self.context_pill.setText(f'{p.label}  ·  {al}')

    # ---------- Theme (Dark / Light Mode) ----------
    def apply_theme(self, notify: bool = True):
        theme = self.theme_choice.currentData() if hasattr(self, 'theme_choice') else 'dark'
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(get_stylesheet(theme))
        self.settings.setValue('theme', theme)
        self._refresh_nav_icons()
        if notify:
            self.show_toast(f'Switched to {"Light" if theme == "light" else "Dark"} Mode.')

    def toggle_theme(self):
        cur = self.theme_choice.currentData()
        nxt = 'light' if cur == 'dark' else 'dark'
        idx = self.theme_choice.findData(nxt)
        if idx >= 0:
            self.theme_choice.setCurrentIndex(idx)

    # ---------- Dashboard & Providers ----------
    def _populate_accounts_table(self, table):
        table.setRowCount(0)
        vault = ProtocolVault()
        all_accounts = self.account_registry.list_all()
        for prov_key, aliases in all_accounts.items():
            prov_label = self.providers[prov_key].label if prov_key in self.providers else prov_key
            for alias in aliases:
                row = table.rowCount()
                table.insertRow(row)
                has_prof = has_session_profile(prov_key, account=alias)
                st = self.account_registry.get_status(prov_key, alias)
                if st:
                    check_txt = f"{st.get('state', 'unknown')}"
                    if st.get('plan_hint'):
                        check_txt += f" · {st['plan_hint']}"
                else:
                    check_txt = 'Not checked online'
                has_keyring_session = False
                try:
                    has_ov = vault.get_openvpn(prov_key, alias) is not None
                    has_wg = vault.get_wireguard(prov_key, alias) is not None
                    has_keyring_session = vault.get_session_token(prov_key, alias) is not None
                    secrets_txt = ', '.join(
                        x for x, ok in (('Session', has_keyring_session), ('OpenVPN', has_ov), ('WireGuard', has_wg)) if ok
                    ) or 'None'
                except VaultUnavailable:
                    secrets_txt = 'Keyring unavailable'
                has_ram_cookie = (
                    prov_key == 'windscribe'
                    and alias == (self.alias() if hasattr(self, 'account_alias') else 'default')
                    and hasattr(self, 'cookie')
                    and bool(self.cookie.text().strip())
                )
                if has_keyring_session:
                    prof_text, prof_style = 'Keyring Session Saved', 'supported'
                elif has_ram_cookie:
                    prof_text, prof_style = 'RAM Cookie Active', 'supported'
                elif has_prof:
                    prof_text, prof_style = 'Browser Profile Saved', 'present'
                else:
                    prof_text, prof_style = 'Not Signed In', 'neutral'

                p_item = QTableWidgetItem(prov_label)
                p_item.setData(Qt.ItemDataRole.UserRole, (prov_key, alias))
                table.setItem(row, 0, p_item)
                table.setItem(row, 1, QTableWidgetItem(alias))
                table.setCellWidget(row, 2, self._make_table_badge(prof_text, prof_style))
                table.setItem(row, 3, QTableWidgetItem(check_txt))
                table.setItem(row, 4, QTableWidgetItem(secrets_txt))

    def select_account_from_table(self, row: int, _col: int):
        if not hasattr(self, 'accounts_overview_table'):
            return
        item = self.accounts_overview_table.item(row, 0)
        if not item:
            return
        meta = item.data(Qt.ItemDataRole.UserRole)
        if not meta:
            return
        prov_key, alias = meta
        self.settings.setValue(f'current_account_{prov_key}', alias)
        self.select_provider_by_key(prov_key)
        idx = self.account_alias.findData(alias)
        if idx >= 0:
            self.account_alias.setCurrentIndex(idx)
        self.refresh_account_state()
        self.show_toast(f'حساب فعال به {self.providers[prov_key].label} / {alias} تغییر کرد.')

    def refresh_dashboard_accounts(self):
        if hasattr(self, 'dashboard_accounts_table'):
            self._populate_accounts_table(self.dashboard_accounts_table)
        if hasattr(self, 'accounts_overview_table'):
            self._populate_accounts_table(self.accounts_overview_table)

    def provider(self):
        return self.providers[self.provider_choice.currentData()]

    def select_provider_by_key(self, key: str):
        idx = self.provider_choice.findData(key)
        if idx >= 0:
            self.provider_choice.setCurrentIndex(idx)

    def apply_provider_mode(self):
        if not hasattr(self, 'provider_choice') or not hasattr(self, 'proto_boxes'):
            return
        p = self.provider()
        self.provider_description.setText(p.description)

        # Highlight active Provider Card
        if hasattr(self, 'provider_cards'):
            for k, (card, btn) in self.provider_cards.items():
                active = k == p.key
                card.setObjectName('ProviderCardActive' if active else 'ProviderCard')
                card.style().unpolish(card)
                card.style().polish(card)
                btn.setText('✓ Selected' if active else f'Select {self.providers[k].label}')
                btn.setObjectName('Primary' if active else 'Ghost')
                btn.style().unpolish(btn)
                btn.style().polish(btn)

        if hasattr(self, 'account_provider'):
            idx = self.account_provider.findData(p.key)
            if idx >= 0 and self.account_provider.currentIndex() != idx:
                self.account_provider.blockSignals(True)
                self.account_provider.setCurrentIndex(idx)
                self.account_provider.blockSignals(False)
                self.refresh_aliases()

        # Clear stale server rows from a different provider so Surfshark/Windscribe lists never mix.
        if hasattr(self, 'server_table') and self._locations_provider and self._locations_provider != p.key:
            self.locations = []
            self._locations_provider = ''
            self.server_table.blockSignals(True)
            self.server_table.setRowCount(0)
            self.server_table.blockSignals(False)
            if hasattr(self, 'country_filter'):
                self.country_filter.blockSignals(True)
                self.country_filter.clear()
                self.country_filter.addItem('All countries', '')
                self.country_filter.blockSignals(False)
            if hasattr(self, 'metric_labels') and self.metric_labels:
                self.metric_labels[0].setText('0')
            self.update_server_selection_count()
        self.capability_text.setText('CAPABILITIES  ·  ' + p.capabilities_string())

        # Populate full 6-protocol support matrix table with colored badges
        if hasattr(self, 'provider_matrix_table'):
            matrix = p.protocol_matrix()
            self.provider_matrix_table.setRowCount(0)
            for item in matrix:
                row = self.provider_matrix_table.rowCount()
                self.provider_matrix_table.insertRow(row)
                self.provider_matrix_table.setItem(row, 0, QTableWidgetItem(item['protocol'].upper()))
                self.provider_matrix_table.setCellWidget(row, 1, self._make_table_badge(item['status']))
                self.provider_matrix_table.setItem(row, 2, QTableWidgetItem(item['explanation']))

        wind = p.key == 'windscribe'
        auto = not wind and self.acquire_mode.currentData() == 'auto'
        self.source_input.setEnabled(not wind and not auto)
        self.acquire_mode.setEnabled(not wind)
        self.acquire_help.setText(
            'AUTO: Surfshark OpenVPN = official public ZIP (+ optional server filter). Account downloads reuse your local Chromium profile.'
            if auto
            else 'Import a local folder, ZIP archive, or .ovpn/.conf file.'
        )
        supported_protos = {m['protocol'] for m in p.protocol_matrix() if m['status'] != 'Unsupported'}
        for key, b in self.proto_boxes.items():
            b.setEnabled((wind and key in supported_protos) or (auto and key in supported_protos))
        if p.supports_server_discovery:
            self.server_note.setText(f'{p.label} supports live server catalog discovery. Click Refresh Locations.')
        else:
            self.server_note.setText(f'{p.label} server selection is performed on the official portal in the browser.')
        self._update_context_pill()
        self.save_settings(silent=True)

    # ---------- Accounts & Keyring ----------
    def account_key(self) -> str:
        return self.account_provider.currentData()

    def alias(self) -> str:
        return self.account_alias.currentData() or 'default'

    def refresh_aliases(self):
        provider = self.account_key()
        if not provider or not hasattr(self, 'account_alias'):
            return
        # Keep active workspace provider synced when user picks a provider on Accounts page
        if hasattr(self, 'provider_choice') and self.provider_choice.currentData() != provider:
            p_idx = self.provider_choice.findData(provider)
            if p_idx >= 0:
                self.provider_choice.setCurrentIndex(p_idx)
                return
        selected = self.settings.value(f'current_account_{provider}', 'default')
        self.account_alias.blockSignals(True)
        self.account_alias.clear()
        for alias in self.account_registry.list(provider):
            self.account_alias.addItem(alias, alias)
        idx = self.account_alias.findData(selected)
        self.account_alias.setCurrentIndex(max(0, idx))
        self.account_alias.blockSignals(False)
        self.refresh_account_state()

    def save_account_selection(self):
        if self.account_key() and hasattr(self, 'account_alias') and self.account_alias.currentData():
            self.settings.setValue(f'current_account_{self.account_key()}', self.alias())
            self._update_context_pill()

    def add_account(self):
        name, ok = QInputDialog.getText(self, 'Add account', 'Local account name (letters, numbers, _ or -):')
        if not ok:
            return
        try:
            clean = name.strip()
            self.account_registry.add(self.account_key(), clean)
            self.settings.setValue(f'current_account_{self.account_key()}', clean)
            self.refresh_aliases()
            self.refresh_dashboard_accounts()
            self.show_toast(f'Added isolated account "{clean}" for {self.account_key()}.')
        except ValueError as e:
            QMessageBox.warning(self, 'Account', str(e))

    def remove_account(self):
        provider, alias = self.account_key(), self.alias()
        if alias == 'default':
            QMessageBox.information(self, 'Account', 'Default account cannot be removed; use Forget local session instead.')
            return
        if QMessageBox.question(
            self,
            'Delete account',
            f'Forget browser profile and OS keyring secrets for {provider}/{alias}?',
        ) != QMessageBox.StandardButton.Yes:
            return
        if self.login_worker and self.login_worker.isRunning():
            return
        try:
            forget_profile(provider, account=alias)
            try:
                vault = ProtocolVault()
                vault.delete_openvpn(provider, alias)
                vault.delete_wireguard(provider, alias)
                vault.delete_session_token(provider, alias)
            except VaultUnavailable:
                pass
            self.account_registry.remove(provider, alias)
            self.settings.setValue(f'current_account_{provider}', 'default')
            self.refresh_aliases()
            self.refresh_dashboard_accounts()
            self.show_toast(f'Removed account {provider}/{alias}.')
        except Exception:
            QMessageBox.warning(self, 'Account', 'Could not remove local account; close running browsers.')

    def start_session_check(self):
        if any(t and t.isRunning() for t in (self.session_checker, self.login_worker, self.worker, self.credential_reader)):
            return
        self._set_badge(self.session_badge, 'Checking…', 'unknown')
        self.session_result.setText('Inspecting official portal…')
        self.session_checker = AccountCheckThread(self.account_key(), self.alias())
        self.session_checker.result.connect(self._session_check_done)
        self.session_checker.start()

    def _session_check_done(self, r):
        txt = r.detail
        if getattr(r, 'plan_hint', ''):
            txt += f' · Plan hint: {r.plan_hint}'
        self._set_badge(self.session_badge, r.state, r.state)
        self.session_result.setText(txt)
        self.log(CoreEvent('info' if r.state == 'portal_accessible' else 'skip', f'Session check ({self.account_key()}/{self.alias()}): {r.state}: {txt}'))
        self.refresh_dashboard_accounts()

    def save_wg_secret(self):
        try:
            pub = ProtocolVault().put_wireguard(self.account_key(), self.wgsecret.text().strip(), self.alias())
            self.wgsecret.clear()
            self.wg_public_text.setText('Public key: ' + pub)
            self.refresh_dashboard_accounts()
            self.show_toast('WireGuard private key saved securely in OS Keyring.')
        except (ValueError, VaultUnavailable) as e:
            QMessageBox.warning(self, 'WireGuard', str(e))

    def import_wg_from_conf(self):
        import re
        start_dir = self.output_input.text() if hasattr(self, 'output_input') else ''
        path, _ = QFileDialog.getOpenFileName(
            self, 'Select WireGuard .conf file', start_dir, 'WireGuard Config (*.conf);;All files (*)'
        )
        if not path:
            return
        try:
            raw = Path(path).read_text('utf-8', errors='replace')
            m = re.search(r'(?mi)^\s*PrivateKey\s*=\s*(\S+)\s*$', raw)
            if not m:
                raise ValueError('No PrivateKey directive found in the selected .conf file.')
            priv = m.group(1).strip()
            pub = ProtocolVault().put_wireguard(self.account_key(), priv, self.alias())
            self.wg_public_text.setText('Public key: ' + pub)
            self.refresh_dashboard_accounts()
            self.show_toast(f'WireGuard PrivateKey imported from {Path(path).name} into OS Keyring.')
        except (OSError, ValueError, VaultUnavailable) as e:
            QMessageBox.warning(self, 'Import WireGuard Key', str(e))

    def generate_wg_secret(self):
        if QMessageBox.question(
            self,
            'WireGuard keypair generation',
            'Generate a new X25519 keypair in the OS keyring?\n'
            'You must register its PUBLIC key in your provider account before configs using it will work.',
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            secret, pub = make_keypair()
            ProtocolVault().put_wireguard(self.account_key(), secret, self.alias())
            self.wg_public_text.setText('Register this PUBLIC key with provider: ' + pub)
            self.refresh_dashboard_accounts()
            self.show_toast('Generated new X25519 keypair in OS Keyring.')
        except (ValueError, VaultUnavailable) as e:
            QMessageBox.warning(self, 'WireGuard', str(e))

    def copy_wg_public(self):
        try:
            private = ProtocolVault().get_wireguard(self.account_key(), self.alias())
            if private:
                QApplication.clipboard().setText(public_from_private(private))
                self.account_event.setText('WireGuard public key copied to clipboard (safe to register on provider portal).')
                self.show_toast('WireGuard public key copied to clipboard.')
            else:
                self.account_event.setText('No WireGuard private key stored for this account.')
        except VaultUnavailable as e:
            QMessageBox.warning(self, 'WireGuard', str(e))

    def open_wg_registration_portal(self):
        key = self.account_key()
        try:
            private = ProtocolVault().get_wireguard(key, self.alias())
            if private:
                QApplication.clipboard().setText(public_from_private(private))
        except VaultUnavailable:
            pass
        url = WIREGUARD_REGISTRATION_URLS.get(key) or PROVIDER_URLS[key]
        if QMessageBox.question(
            self,
            'Guided WireGuard key registration',
            f'Open {url} in your browser to register your WireGuard Public Key?\n'
            '(If a key is stored in keyring, its public key was copied to your clipboard.)',
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl(url))

    def delete_wg_secret(self):
        try:
            ProtocolVault().delete_wireguard(self.account_key(), self.alias())
            self.wg_public_text.setText('Public key: none stored')
            self.refresh_dashboard_accounts()
            self.show_toast('Deleted stored WireGuard private key.')
        except VaultUnavailable as e:
            QMessageBox.warning(self, 'WireGuard', str(e))

    def refresh_account_state(self):
        if not hasattr(self, 'account_provider'):
            return
        key = self.account_key()
        al = self.alias()
        has_prof = has_session_profile(key, account=al)
        has_keyring_session = False
        try:
            has_keyring_session = ProtocolVault().get_session_token(key, al) is not None
        except VaultUnavailable:
            has_keyring_session = False
        has_ram_cookie = key == 'windscribe' and hasattr(self, 'cookie') and bool(self.cookie.text().strip())
        if hasattr(self, 'account_profile_badge'):
            if has_keyring_session:
                self._set_badge(self.account_profile_badge, 'Keyring Session Saved', 'supported')
            elif has_ram_cookie:
                self._set_badge(self.account_profile_badge, 'RAM Cookie Active', 'supported')
            elif has_prof:
                self._set_badge(self.account_profile_badge, 'Browser Profile Saved', 'present')
            else:
                self._set_badge(self.account_profile_badge, 'No Local Profile', 'neutral')
        if has_keyring_session:
            status = 'Session token securely saved in OS Keyring (persists across restarts until you forget it).'
        elif has_ram_cookie:
            status = 'Website session cookie loaded in RAM (ready to export Windscribe).'
        elif has_prof:
            status = 'Local browser profile saved (persists across restarts until you forget it).'
        else:
            status = 'No saved local browser session.'
        self.account_state.setText(f'{key.upper()} / {al}  •  {status}')
        last_st = self.account_registry.get_status(key, al)
        if last_st:
            plan = f" · {last_st['plan_hint']}" if last_st.get('plan_hint') else ''
            if hasattr(self, 'session_badge'):
                self._set_badge(self.session_badge, last_st['state'], last_st['state'])
            self.session_result.setText(f"{last_st['detail']}{plan}")
        else:
            if hasattr(self, 'session_badge'):
                self._set_badge(self.session_badge, 'Not Checked', 'neutral')
            self.session_result.setText('Not checked online yet.')
        try:
            vault = ProtocolVault()
            has_login = vault.get_openvpn(key, al) is not None
            self.vault_state.setText('Saved in OS Keyring' if has_login else 'No service credentials saved')
            if hasattr(self, 'vault_pw_toggle') and self.vault_pw_toggle.isChecked():
                self.vault_pw_toggle.blockSignals(True)
                self.vault_pw_toggle.setChecked(False)
                self.vault_pw_toggle.setText('Show')
                self.vault_pw_toggle.blockSignals(False)
                self.vault_password.setEchoMode(QLineEdit.EchoMode.Password)
                if getattr(self, '_vault_loaded_from_keyring', False):
                    self.vault_username.clear()
                    self.vault_password.clear()
                    self._vault_loaded_from_keyring = False
            if has_login:
                self.vault_username.setPlaceholderText('Saved in OS Keyring — click Show to view or Copy Username')
                self.vault_password.setPlaceholderText('Saved in OS Keyring — click Show to view or Copy Password')
            else:
                self.vault_username.setPlaceholderText('Manual OpenVPN service username from provider dashboard')
                self.vault_password.setPlaceholderText('Manual OpenVPN service password (stored only in OS keyring)')
            wg_priv = vault.get_wireguard(key, al)
            if wg_priv:
                self.wg_public_text.setText('Public key: ' + public_from_private(wg_priv))
            else:
                self.wg_public_text.setText('Public key: none stored')
        except VaultUnavailable:
            self.vault_state.setText('OS keyring unavailable')
            self.wg_public_text.setText('Public key: OS keyring unavailable')
        except ValueError:
            self.wg_public_text.setText('Public key: stored key invalid')
        self._update_context_pill()

    def start_login(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, 'Export running', 'Stop the export before opening account login.')
            return
        if self.login_worker and self.login_worker.isRunning():
            return
        key = self.account_key()
        self.login_worker = AccountLoginThread(key, self.alias())
        self.login_worker.info.connect(self.account_event.setText)
        self.login_worker.finished_info.connect(self.login_done)
        self.login_worker.failed.connect(self.login_failed)
        self.login_worker.finished.connect(lambda: self.login_button.setEnabled(True))
        self.login_worker.finished.connect(lambda: self.cancel_login_btn.setEnabled(False))
        self.login_button.setEnabled(False)
        self.cancel_login_btn.setEnabled(True)
        self.account_event.setText('Opening official website in persistent Chromium profile…')
        self.login_worker.start()

    def cancel_login(self):
        if self.login_worker and self.login_worker.isRunning():
            self.login_worker.cancel.set()
            self.account_event.setText('Closing account browser; pending session will be saved if available…')

    def login_done(self, message: str):
        # Ensure logged-in account is persisted in registry so it never vanishes across restarts.
        try:
            self.account_registry.add(self.account_key(), self.alias())
        except Exception:
            pass
        self.account_event.setText(message)
        self.refresh_account_state()
        self.refresh_dashboard_accounts()
        self.log(CoreEvent('info', 'Account browser closed; profile persisted locally until you forget/remove it.'))
        self.show_toast('پروفایل حساب ذخیره شد. برای تأیید وضعیت روی Check Session کلیک کنید.')

    def login_failed(self, message: str):
        self.account_event.setText(message)
        QMessageBox.warning(self, 'Account browser', message)
        self.refresh_account_state()

    def delete_session(self):
        if self.login_worker and self.login_worker.isRunning():
            QMessageBox.warning(self, 'Browser open', 'Close the account browser first.')
            return
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, 'Export running', 'Stop the export before deleting a browser session.')
            return
        key = self.account_key()
        if QMessageBox.question(
            self,
            'Forget local browser session',
            f'Delete the saved local browser data for {key}/{self.alias()}?',
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            forget_profile(key, account=self.alias())
            try:
                ProtocolVault().delete_session_token(key, self.alias())
            except VaultUnavailable:
                pass
            if key == 'windscribe' and hasattr(self, 'cookie'):
                self.cookie.clear()
            self.account_registry.clear_status(key, self.alias())
            self.show_toast(f'Local browser & keyring session cleared for {key}/{self.alias()}.')
        except Exception:
            QMessageBox.warning(self, 'Session', 'Could not delete browser state; close Chromium and try again.')
        self.refresh_account_state()
        self.refresh_dashboard_accounts()

    def open_account_portal(self):
        QDesktopServices.openUrl(QUrl(PROVIDER_URLS[self.account_key()]))

    def _on_windscribe_cookie_changed(self, text: str):
        val = text.strip()
        if val and hasattr(self, 'provider_choice') and self.provider_choice.currentData() != 'windscribe':
            self.select_provider_by_key('windscribe')
            self.show_toast('ارائه‌دهندهٔ فعال به Windscribe تغییر کرد (کوکی نشست در RAM فعال است).')
        self.refresh_account_state()
        self.refresh_dashboard_accounts()

    def open_windscribe_cookie_guide(self):
        is_dark = (self.theme_choice.currentData() if hasattr(self, 'theme_choice') else 'dark') != 'light'

        def _apply_cookie(token: str, save_to_keyring: bool = True):
            self.select_provider_by_key('windscribe')
            al = self.alias()
            self.account_registry.add('windscribe', al)
            self.cookie.blockSignals(True)
            self.cookie.setText(token)
            self.cookie.blockSignals(False)
            saved_msg = 'در RAM اعمال شد'
            if save_to_keyring:
                try:
                    ProtocolVault().put_session_token('windscribe', token, al)
                    saved_msg = f'در OS Keyring سیستم‌عامل برای windscribe/{al} ذخیره شد (در اجراهای بعدی باقی می‌ماند)'
                except (ValueError, VaultUnavailable):
                    saved_msg = 'در RAM اعمال شد (OS Keyring در دسترس نبود)'
            self.refresh_account_state()
            self.refresh_dashboard_accounts()
            self.account_event.setText(f'Windscribe session ({al}): {saved_msg}.')
            self.log(CoreEvent('info', f'Windscribe session token applied for account "{al}" (persisted={save_to_keyring}).'))
            self.nav_to(3)
            self.refresh_locations()
            self.show_toast(f'حساب Windscribe/{al} ذخیره و فعال شد ({saved_msg}).')

        dlg = WindscribeCookieGuideDialog(self, dark=is_dark, on_apply=_apply_cookie)
        dlg.exec()

    def discover_service_credentials(self):
        if any(t and t.isRunning() for t in (self.worker, self.login_worker, self.session_checker, self.credential_reader)):
            return
        key = self.account_key()
        tok = self.cookie.text().strip() if (key == 'windscribe' and hasattr(self, 'cookie')) else ''
        if key == 'windscribe':
            self.account_event.setText('Fetching Windscribe manual OpenVPN service credentials via official API / portal…')
        else:
            self.account_event.setText(
                'Opening official OpenVPN credentials portal (up to 2 min). If prompted to sign in (check "Keep me signed in" on Proton) or if Password is hidden, click Show/Reveal — it auto-captures once visible.'
            )
        self.credential_reader = CredentialReadThread(key, self.alias(), session_token=tok)
        self.credential_reader.result.connect(self.service_credentials_read)
        self.credential_reader.failed.connect(self.account_event.setText)
        self.credential_reader.start()

    def service_credentials_read(self, data):
        if not data:
            self.account_event.setText(
                'OpenVPN service credentials not reliably recognized. Open the Credentials tab on the portal and copy them manually.'
            )
            return
        username, password = data
        self.vault_username.setText(username)
        self.vault_password.setText(password)
        try:
            ProtocolVault().put_openvpn(self.account_key(), username, password, self.alias())
            self.refresh_account_state()
            self.refresh_dashboard_accounts()
            self.account_event.setText('OpenVPN service credentials read & saved in OS Keyring! Use Copy Username / Copy Password.')
            self.show_toast('اطلاعات OpenVPN خوانده و در OS Keyring ذخیره شد — از Copy Username / Copy Password استفاده کنید.')
        except (ValueError, VaultUnavailable):
            self.account_event.setText('OpenVPN service credentials loaded! Click "Save in OS Keyring" to store them securely.')
            self.show_toast('اطلاعات OpenVPN خوانده شد — برای ذخیرهٔ دائمی روی Save in OS Keyring بزنید.')

    def save_openvpn_secret(self):
        try:
            ProtocolVault().put_openvpn(
                self.account_key(),
                self.vault_username.text().strip(),
                self.vault_password.text(),
                self.alias(),
            )
            self.vault_username.clear()
            self.vault_password.clear()
            self.refresh_account_state()
            self.refresh_dashboard_accounts()
            self.show_toast('OpenVPN service credentials saved in OS Keyring.')
        except (ValueError, VaultUnavailable) as ex:
            QMessageBox.warning(self, 'OpenVPN credentials', str(ex))

    def toggle_vault_password_visibility(self, checked: bool):
        if checked:
            if not self.vault_username.text().strip() or not self.vault_password.text():
                try:
                    stored = ProtocolVault().get_openvpn(self.account_key(), self.alias())
                except VaultUnavailable as ex:
                    QMessageBox.warning(self, 'OpenVPN credentials', str(ex))
                    stored = None
                if stored:
                    if not self.vault_username.text().strip():
                        self.vault_username.setText(stored[0])
                    if not self.vault_password.text():
                        self.vault_password.setText(stored[1])
                    self._vault_loaded_from_keyring = True
                elif not self.vault_password.text():
                    self.account_event.setText('No OpenVPN credentials saved for this account yet. Click "Read visible fields (Beta)" first.')
            self.vault_password.setEchoMode(QLineEdit.EchoMode.Normal)
            if hasattr(self, 'vault_pw_toggle'):
                self.vault_pw_toggle.setText('Hide')
        else:
            self.vault_password.setEchoMode(QLineEdit.EchoMode.Password)
            if hasattr(self, 'vault_pw_toggle'):
                self.vault_pw_toggle.setText('Show')
            if getattr(self, '_vault_loaded_from_keyring', False):
                self.vault_username.clear()
                self.vault_password.clear()
                self._vault_loaded_from_keyring = False

    def _resolve_openvpn_creds(self) -> tuple[str, str] | None:
        u = self.vault_username.text().strip()
        p = self.vault_password.text()
        if u or p:
            try:
                stored = ProtocolVault().get_openvpn(self.account_key(), self.alias())
            except VaultUnavailable:
                stored = None
            return (u or (stored[0] if stored else ''), p or (stored[1] if stored else ''))
        try:
            return ProtocolVault().get_openvpn(self.account_key(), self.alias())
        except VaultUnavailable as ex:
            QMessageBox.warning(self, 'OpenVPN credentials', str(ex))
            return None

    def copy_openvpn_username(self):
        creds = self._resolve_openvpn_creds()
        if not creds or not creds[0]:
            self.account_event.setText('No OpenVPN username saved yet. Click "Read visible fields (Beta)" or enter it first.')
            return
        QApplication.clipboard().setText(creds[0])
        self.account_event.setText('OpenVPN service username copied to clipboard (ready to paste in Ubuntu VPN settings).')
        self.show_toast('نام کاربری OpenVPN در کلیپ‌بورد کپی شد.')

    def copy_openvpn_password(self):
        creds = self._resolve_openvpn_creds()
        if not creds or not creds[1]:
            self.account_event.setText('No OpenVPN password saved yet. Click "Read visible fields (Beta)" or enter it first.')
            return
        QApplication.clipboard().setText(creds[1])
        self.account_event.setText('OpenVPN service password copied to clipboard (ready to paste in Ubuntu VPN settings).')
        self.show_toast('پسورد OpenVPN در کلیپ‌بورد کپی شد.')

    def delete_openvpn_secret(self):
        try:
            ProtocolVault().delete_openvpn(self.account_key(), self.alias())
            self.vault_username.clear()
            self.vault_password.clear()
            self.refresh_account_state()
            self.refresh_dashboard_accounts()
            self.show_toast('Deleted saved OpenVPN service credentials.')
        except (ValueError, VaultUnavailable) as ex:
            QMessageBox.warning(self, 'OpenVPN credentials', str(ex))

    # ---------- File & URL pickers ----------
    def choose_source_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose downloaded profiles folder')
        if path:
            self.source_input.setText(path)

    def choose_source_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 'Choose archive or profile', '', 'VPN profiles (*.zip *.ovpn *.conf);;All files (*)'
        )
        if path:
            self.source_input.setText(path)

    def choose_path(self, field: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, 'Choose input file', '', 'All files (*)')
        if path:
            field.setText(path)

    def choose_output(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose export root directory', self.output_input.text())
        if path:
            self.output_input.setText(path)

    def choose_batch_validator_folder(self):
        path = QFileDialog.getExistingDirectory(self, 'Choose folder to validate', self.output_input.text())
        if path:
            self.batch_val_path.setText(path)

    def open_output(self):
        folder = Path(self.output_input.text()).expanduser()
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder.resolve())))

    def open_last(self):
        if self.last_zip:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(self.last_zip).parent)))

    def open_provider_page(self):
        QDesktopServices.openUrl(QUrl(self.provider().official_url))

    # ---------- Servers ----------
    def refresh_locations(self):
        p = self.provider()
        if not p.supports_server_discovery:
            QMessageBox.information(
                self,
                'Provider server list',
                f'{p.label} restricts unauthenticated server catalog access. Choose servers inside the official portal in the browser.',
            )
            return
        if self.discovery is not None and self.discovery.isRunning():
            return
        self.server_note.setText(f'Refreshing public {p.label} server catalog...')
        source = self.location_source.currentData() if p.key == 'windscribe' else 'live'
        self.discovery = DiscoveryThread(p, source)
        self.discovery.result.connect(self.locations_received)
        self.discovery.failed.connect(self.locations_failed)
        self.discovery.start()

    def locations_received(self, records):
        self.locations = records
        self._locations_provider = self.provider().key
        self.server_table.blockSignals(True)
        self.server_table.setRowCount(0)
        countries = sorted({loc.country for loc in records if loc.country})
        self.country_filter.blockSignals(True)
        self.country_filter.clear()
        self.country_filter.addItem(f'All countries ({len(countries)})', '')
        for c in countries:
            self.country_filter.addItem(c, c)
        self.country_filter.blockSignals(False)

        for loc in records:
            row = self.server_table.rowCount()
            self.server_table.insertRow(row)
            item = QTableWidgetItem()
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            self.server_table.setItem(row, 0, item)
            for col, value in enumerate([loc.country or '—', loc.name, loc.tier], start=1):
                cell = QTableWidgetItem(value)
                cell.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self.server_table.setItem(row, col, cell)
        self.server_table.blockSignals(False)
        self.server_note.setText(f'{len(records)} public locations loaded ({self.provider().label})')
        self.metric_labels[0].setText(str(len(records)))
        self.filter_servers()
        self.update_server_selection_count()
        self.log(CoreEvent('info', f'Loaded {len(records)} {self.provider().label} locations'))
        self.show_toast(f'Discovered {len(records)} servers for {self.provider().label}.')

    def locations_failed(self, description: str):
        self.server_note.setText('Could not load server list')
        QMessageBox.warning(self, 'Catalog unavailable', description + '\n\nCheck your connection or try another source.')
        self.log(CoreEvent('fail', 'Server listing failed: ' + description))

    def filter_servers(self):
        q = self.search_servers.text().casefold().strip()
        country = (self.country_filter.currentData() or '').casefold()
        for row in range(self.server_table.rowCount()):
            c_val = self.server_table.item(row, 1).text().casefold()
            value = ' '.join((self.server_table.item(row, col).text() for col in (1, 2, 3))).casefold()
            hide = (bool(country) and c_val != country) or (bool(q) and q not in value)
            self.server_table.setRowHidden(row, hide)

    def set_visible_checked(self, yes: bool):
        self.server_table.blockSignals(True)
        for row in range(self.server_table.rowCount()):
            if not self.server_table.isRowHidden(row):
                self.server_table.item(row, 0).setCheckState(
                    Qt.CheckState.Checked if yes else Qt.CheckState.Unchecked
                )
        self.server_table.blockSignals(False)
        self.update_server_selection_count()

    def update_server_selection_count(self, *_args):
        if not hasattr(self, 'server_count_pill'):
            return
        total = self.server_table.rowCount()
        checked = sum(
            1 for r in range(total)
            if self.server_table.item(r, 0) and self.server_table.item(r, 0).checkState() == Qt.CheckState.Checked
        )
        self._set_badge(self.server_count_pill, f'{checked} / {total} selected', 'supported' if checked else 'neutral')

    def selected_locations(self):
        return [
            loc for row, loc in enumerate(self.locations)
            if row < self.server_table.rowCount()
            and self.server_table.item(row, 0).checkState() == Qt.CheckState.Checked
        ]

    # ---------- Password Strength Meter ----------
    def update_password_strength(self, text: str):
        if not hasattr(self, 'pw_strength_bar'):
            return
        n = len(text)
        if n == 0:
            self.pw_strength_bar.setValue(0)
            self._set_badge(self.pw_strength_badge, 'Enter >= 12 chars', 'neutral')
            return
        variety = sum([
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
            any(not c.isalnum() for c in text),
        ])
        if n < 12:
            pct = min(45, int(n * 3.8))
            self.pw_strength_bar.setObjectName('StrengthWeak')
            self.pw_strength_bar.setValue(pct)
            self._set_badge(self.pw_strength_badge, f'Too short ({n}/12)', 'invalid')
        elif n < 16 or variety < 3:
            self.pw_strength_bar.setObjectName('StrengthGood')
            self.pw_strength_bar.setValue(72)
            self._set_badge(self.pw_strength_badge, 'Good AES-256', 'warning')
        else:
            self.pw_strength_bar.setObjectName('StrengthStrong')
            self.pw_strength_bar.setValue(100)
            self._set_badge(self.pw_strength_badge, 'Strong AES-256', 'supported')
        self.pw_strength_bar.style().unpolish(self.pw_strength_bar)
        self.pw_strength_bar.style().polish(self.pw_strength_bar)

    # ---------- Downloads / Exports ----------
    def parse_ports(self):
        from ..providers.windscribe_backend_v3 import parse_ports
        return {key: parse_ports(inp.text()) for key, inp in self.port_inputs.items()}

    def start_job(self):
        if self.worker is not None and self.worker.isRunning():
            return
        if self.login_worker is not None and self.login_worker.isRunning():
            QMessageBox.warning(self, 'Browser open', 'Close the account browser before exporting.')
            return
        p = self.provider()
        locs = self.selected_locations() if p.supports_server_discovery else []
        if p.key == 'windscribe' and not locs:
            QMessageBox.warning(self, 'Select locations', 'Go to Servers → Refresh Locations → choose locations.')
            self.nav_to(3)
            return
        if p.key != 'windscribe' and self.acquire_mode.currentData() == 'import' and not self.source_input.text().strip():
            QMessageBox.warning(self, 'Select local profiles', 'In Import mode, choose a local folder, ZIP or profile file.')
            self.nav_to(1)
            return
        try:
            supported_protos = {m['protocol'] for m in p.protocol_matrix() if m['status'] != 'Unsupported'}
            protocols = [key for key, box in self.proto_boxes.items() if box.isChecked() and key in supported_protos]
            if p.key != 'windscribe' and self.acquire_mode.currentData() == 'import':
                protocols = ['wireguard', 'udp', 'tcp']
            if not protocols:
                raise ValueError('Select at least one supported protocol.')
            ports = self.parse_ports()
            output = Path(self.output_input.text()).expanduser().resolve()
            if output.exists() and not output.is_dir():
                raise ValueError('Output path must be a directory.')
            pass_locs = locs if (p.key == 'windscribe' or (p.key == 'surfshark' and locs and len(locs) < len(self.locations))) else []
            opts = Options(
                output=str(output),
                protocols=protocols,
                ports=ports,
                delay=self.delay.value(),
                timeout=self.timeout.value(),
                retries=self.retries.value(),
                overwrite=self.overwrite.isChecked(),
                archive=self.archive_checkbox.isChecked(),
                browser_limit=self.browser_limit.value(),
                account=self.alias(),
                concurrency=self.concurrency.value(),
            )
            creds = Credentials(
                website_cookie=self.cookie.text().strip(),
                wireguard_public_key=self.wgpub.text().strip(),
                wireguard_private_key_file=self.wgpriv.text().strip(),
                ikev2_credentials_file=self.ikefile.text().strip(),
                ikev2_auth_hash=self.ikehash.text().strip(),
                ikev2_hostnames_file=self.ikehosts.text().strip(),
                transport_endpoints_file=self.transport.text().strip(),
            )
            has_ws_keyring_session = False
            if p.key == 'windscribe' and not creds.website_cookie:
                try:
                    has_ws_keyring_session = bool(ProtocolVault().get_session_token('windscribe', self.alias()))
                except VaultUnavailable:
                    has_ws_keyring_session = False
            if (
                p.key == 'windscribe'
                and not creds.website_cookie
                and not has_ws_keyring_session
                and set(protocols) & {'udp', 'tcp', 'wireguard', 'stealth', 'wstunnel'}
                and not has_session_profile('windscribe', account=self.alias())
            ):
                raise ValueError('Sign in to Windscribe via Accounts, or save your session cookie via Visual Guide.')

            password = self.zip_password.text() if self.archive_checkbox.isChecked() and self.secure_archive.isChecked() else ''
            if self.archive_checkbox.isChecked() and self.secure_archive.isChecked():
                if len(password) < 12:
                    raise ValueError('AES-256 ZIP requires a password of at least 12 characters.')
                try:
                    import pyzipper  # noqa: F401
                except ImportError:
                    raise ValueError('Install pyzipper: pip install pyzipper. Encryption will not fall back to plaintext.')
            elif self.archive_checkbox.isChecked() and not self.secure_archive.isChecked():
                if QMessageBox.question(
                    self,
                    'Unencrypted ZIP warning',
                    'AES-256 encryption is disabled. Exported configs may contain private keys.\n'
                    'Are you sure you want to create an UNENCRYPTED ZIP archive?',
                ) != QMessageBox.StandardButton.Yes:
                    return

            if self.embed_auth.isChecked() and not password:
                raise ValueError('Embedding OpenVPN credentials requires AES-256 encrypted ZIP.')
            if self.embed_auth.isChecked():
                if ProtocolVault().get_openvpn(p.key, self.alias()) is None:
                    raise ValueError('Save manual OpenVPN service credentials in Accounts before including them in the export.')
                if QMessageBox.question(
                    self,
                    'Sensitive OpenVPN credentials',
                    'Service credentials will be written into the export staging folder and encrypted ZIP. Continue?',
                ) != QMessageBox.StandardButton.Yes:
                    return
            self.save_settings(silent=True)
        except Exception as ex:
            QMessageBox.warning(self, 'Check export options', str(ex))
            self.nav_to(7 if 'ZIP' in str(ex) or 'password' in str(ex).lower() else (4 if p.key == 'windscribe' else 1))
            return

        self.success_count = 0
        self.fail_count = 0
        self.skip_count = 0
        self.metric_labels[1].setText('0')
        self.metric_labels[2].setText('0')
        self.metric_labels[3].setText('0')
        self.download_errors_table.setRowCount(0)
        self.progress.setValue(0)
        self.progress_text.setText('Starting concurrent worker queue...')
        self.worker = WorkThread(
            p,
            pass_locs,
            creds,
            opts,
            self.source_input.text().strip() if p.key != 'windscribe' and self.acquire_mode.currentData() == 'import' else '',
            embed_auth=self.embed_auth.isChecked(),
            zip_password=password,
            keep_plaintext=self.keep_plaintext.isChecked(),
        )
        self.worker.event.connect(self.log)
        self.worker.result.connect(self.job_done)
        self.worker.failed.connect(self.job_failed)
        self.worker.finished.connect(self.job_stopped)
        self.worker.start()
        self.zip_password.clear()
        self.set_busy(True)
        self.nav_to(5)
        self.log(CoreEvent('info', f'Starting {p.label}: {len(pass_locs) or "all"} locations • {", ".join(protocols)} • workers={opts.concurrency}'))

    def pause_job(self):
        if self.worker and self.worker.isRunning():
            paused = self.worker.toggle_pause()
            self.pause_btn.setText('▶ Resume' if paused else 'Ⅱ Pause')
            self.status_pill.setText('●  Paused' if paused else '●  Exporting')

    def stop_job(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.status_pill.setText('●  Stopping...')
            self.log(CoreEvent('info', 'Stop requested: active requests will abort safely and checkpoint is preserved.'))

    def job_done(self, payload: dict):
        self.last_export_result = payload
        self.profile_result_table.setRowCount(0)
        for record in (payload.get('records') or payload.get('results') or [])[:1500]:
            row = self.profile_result_table.rowCount()
            self.profile_result_table.insertRow(row)
            status_val = str(record.get('status') or '')
            self.profile_result_table.setItem(row, 0, QTableWidgetItem(str(record.get('file') or record.get('location') or record.get('name') or '')))
            self.profile_result_table.setItem(row, 1, QTableWidgetItem(str(record.get('protocol') or '').upper()))
            self.profile_result_table.setItem(row, 2, QTableWidgetItem(str(record.get('country') or '—')))
            self.profile_result_table.setCellWidget(row, 3, self._make_table_badge(status_val))

        self.download_errors_table.setRowCount(0)
        for err in (payload.get('errors') or [])[:500]:
            row = self.download_errors_table.rowCount()
            self.download_errors_table.insertRow(row)
            vals = (
                str(err.get('location') or err.get('name') or 'export'),
                str(err.get('protocol') or '').upper(),
                str(err.get('error_type') or 'Error'),
                redact_secrets(str(err.get('error_detail') or err.get('message') or '')),
            )
            for col, val in enumerate(vals):
                self.download_errors_table.setItem(row, col, QTableWidgetItem(val))

        last = payload.get('archive')
        if last:
            self.last_zip = last
            self.last_archive.setText(last)
        self.log(CoreEvent('info', f'Finished · {payload.get("provider")} · ZIP: {last or "not created"}'))
        self.progress_text.setText(
            'Finished. Encrypted archive verified and plaintext folder removed.'
            if payload.get('plaintext_removed')
            else 'Finished. See report.json and manifest.json in output folder.'
        )
        if payload.get('status') != 'cancelled':
            self.progress.setValue(100)
            self.show_toast(f'Export completed for {payload.get("provider")}.')

    def job_failed(self, description: str):
        safe_desc = redact_secrets(description)
        self.log(CoreEvent('fail', 'Export error: ' + safe_desc))
        self.progress_text.setText('Export failed. See Errors table & Logs.')
        row = self.download_errors_table.rowCount()
        self.download_errors_table.insertRow(row)
        for col, val in enumerate(('Export', '—', 'Fatal', safe_desc)):
            self.download_errors_table.setItem(row, col, QTableWidgetItem(val))
        QMessageBox.warning(self, 'Export failed', safe_desc)

    def job_stopped(self):
        self.set_busy(False)

    def set_busy(self, busy: bool):
        self.top_run.setEnabled(not busy)
        self.run_btn.setEnabled(not busy)
        self.pause_btn.setEnabled(busy)
        self.stop_btn.setEnabled(busy)
        self.provider_choice.setEnabled(not busy)
        self.status_pill.setText('●  Exporting' if busy else '●  Idle')
        self.status_pill.setObjectName('PillBusy' if busy else 'Pill')
        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)
        if not busy:
            self.pause_btn.setText('Ⅱ Pause')

    def retry_failed(self):
        if self.worker and self.worker.isRunning():
            return
        if self.provider().key != 'windscribe':
            QMessageBox.information(
                self,
                'Retry failed',
                'For Surfshark/Proton, re-running Start Export automatically reuses already downloaded valid files via SHA-256 deduplication.',
            )
            return
        if not self.last_export_result:
            QMessageBox.information(self, 'Retry failed', 'Run an export first before retrying failed locations.')
            return
        rows = self.last_export_result.get('results', [])
        failed_keys = {str(r.get('location_key', '')) for r in rows if r.get('status') == 'failed'}
        if not failed_keys:
            QMessageBox.information(self, 'Retry failed', 'No failed locations in the previous run.')
            return
        self.server_table.blockSignals(True)
        for row in range(self.server_table.rowCount()):
            self.server_table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        for i, loc in enumerate(self.locations):
            if loc.key in failed_keys and i < self.server_table.rowCount():
                self.server_table.item(i, 0).setCheckState(Qt.CheckState.Checked)
        self.server_table.blockSignals(False)
        self.update_server_selection_count()
        self.overwrite.setChecked(False)
        self.start_job()

    # ---------- Validator (3-stage single & batch) ----------
    def start_health_check(self):
        path = self.health_path.text().strip()
        if not path:
            return
        if self.health_worker and self.health_worker.isRunning():
            return
        consent = self.vpn_verify_consent.isChecked()
        self.health_result.setText('Running 3-stage diagnostic…')
        self.health_worker = HealthThread(path, verify_vpn=consent, user_consent=consent)
        self.health_worker.result.connect(self._health_check_done)
        self.health_worker.start()

    def _health_check_done(self, x: dict):
        syn = x.get('syntax_validation') or {}
        reach = x.get('endpoint_reachability') or {}
        vpn = x.get('vpn_connection_verification') or {}

        self._set_badge(self.val_syntax_badge, syn.get('label', 'Invalid'), syn.get('status', 'invalid'))
        syn_notes = '; '.join((syn.get('required_actions') or []) + (syn.get('warnings') or [])) or 'Structure and directives look valid.'
        self.val_syntax_detail.setText(f"Protocol: {syn.get('protocol') or 'n/a'} · {syn_notes}")

        self._set_badge(self.val_reach_badge, reach.get('label', 'Not Tested'), reach.get('status', 'not_tested'))
        ips = ', '.join(reach.get('resolved_ips') or [])
        self.val_reach_detail.setText(
            f"DNS={reach.get('dns', 'n/a')} · TCP={reach.get('tcp', 'n/a')}" + (f" · IPs: {ips}" if ips else '')
        )

        self._set_badge(self.val_vpn_badge, vpn.get('label', 'Not Tested'), vpn.get('status', 'not_tested'))
        self.val_vpn_detail.setText(vpn.get('reason', 'Not Tested'))

        self.health_result.setText(
            f"Summary: {x.get('state', 'unknown')} · VPN verified: {'YES' if x.get('vpn_verified') else 'NO'} · {x.get('reason', '')}"
        )

    def start_batch_validation(self):
        folder = self.batch_val_path.text().strip() or self.output_input.text().strip()
        if not folder or not Path(folder).expanduser().is_dir():
            QMessageBox.warning(self, 'Validator', 'Select an existing folder containing .ovpn / .conf files.')
            return
        if self.batch_health_worker and self.batch_health_worker.isRunning():
            return
        self.validator_table.setRowCount(0)
        self.batch_summary.setText('Scanning configurations…')
        self.batch_run_btn.setEnabled(False)
        self.batch_stop_btn.setEnabled(True)
        self.batch_health_worker = BatchHealthThread(
            str(Path(folder).expanduser()),
            check_reachability=self.batch_reach_cb.isChecked(),
        )
        self.batch_health_worker.progress.connect(self._batch_val_row)
        self.batch_health_worker.finished_results.connect(self._batch_val_done)
        self.batch_health_worker.failed.connect(lambda m: QMessageBox.warning(self, 'Validator', m))
        self.batch_health_worker.finished.connect(self._batch_val_cleanup)
        self.batch_health_worker.start()

    def stop_batch_validation(self):
        if self.batch_health_worker and self.batch_health_worker.isRunning():
            self.batch_health_worker.stop()

    def _batch_val_row(self, cur: int, tot: int, rec: dict):
        row = self.validator_table.rowCount()
        self.validator_table.insertRow(row)
        syn = rec.get('syntax_validation') or {}
        reach = rec.get('endpoint_reachability') or {}
        vpn = rec.get('vpn_connection_verification') or {}
        self.validator_table.setItem(row, 0, QTableWidgetItem(str(rec.get('file', ''))))
        self.validator_table.setItem(row, 1, QTableWidgetItem(str(rec.get('protocol') or 'invalid').upper()))
        self.validator_table.setCellWidget(row, 2, self._make_table_badge(syn.get('label', 'Invalid'), syn.get('status', 'invalid')))
        self.validator_table.setCellWidget(row, 3, self._make_table_badge(reach.get('label', 'Not Tested'), reach.get('status', 'not_tested')))
        self.validator_table.setCellWidget(row, 4, self._make_table_badge(vpn.get('label', 'Not Tested'), vpn.get('status', 'not_tested')))
        self.batch_summary.setText(f'Scanned {cur}/{tot} files…')

    def _batch_val_done(self, results: list):
        valid_n = sum(1 for r in results if (r.get('syntax_validation') or {}).get('status') != 'invalid')
        invalid_n = len(results) - valid_n
        self.batch_summary.setText(
            f'Completed: {len(results)} files · Syntax valid: {valid_n} · Invalid: {invalid_n} · VPN verified: 0 (Not Tested)'
        )
        self.show_toast(f'Batch validation finished: {valid_n}/{len(results)} syntactically valid.')

    def _batch_val_cleanup(self):
        self.batch_run_btn.setEnabled(True)
        self.batch_stop_btn.setEnabled(False)

    # ---------- Verify existing AES-256 ZIP ----------
    def verify_existing_zip(self):
        zip_path = self.verify_zip_path.text().strip() or self.last_zip
        if not zip_path or not Path(zip_path).is_file():
            QMessageBox.warning(self, 'Verify ZIP', 'Select an existing AES-256 ZIP file first.')
            return
        pw, ok = QInputDialog.getText(
            self,
            'Verify AES-256 ZIP',
            'Enter archive password to test real decryption (not saved):',
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pw:
            return
        try:
            info = verify_aes_zip(Path(zip_path), pw)
            msg = f"VERIFIED: decrypted {info['entries']} encrypted files ({info['total_bytes']} bytes)."
            self.verify_zip_status.setText(msg)
            self.log(CoreEvent('success', f'AES-256 ZIP verification passed: {Path(zip_path).name} ({info["entries"]} files)'))
            self.show_toast('AES-256 archive decryption verified successfully.')
        except Exception as exc:
            err = f'Verification FAILED ({type(exc).__name__}): {redact_secrets(str(exc), secrets=(pw,))}'
            self.verify_zip_status.setText(err)
            self.log(CoreEvent('fail', err))
            QMessageBox.warning(self, 'Verify ZIP Failed', err)

    # ---------- Logs ----------
    def log(self, event: CoreEvent):
        safe_msg = redact_secrets(event.message)
        ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
        self._log_entries.append((ts, event.kind, safe_msg))
        if len(self._log_entries) > 5000:
            self._log_entries = self._log_entries[-5000:]
        if self._log_matches_filter(event.kind, safe_msg):
            sign = {'success': '✓', 'fail': '✕', 'skip': '·', 'info': 'ℹ'}.get(event.kind, '•')
            self.logs.appendPlainText(f'[{ts}] {sign}  {safe_msg}')
        if event.current and event.total:
            self.progress.setValue(min(100, round(100 * event.current / event.total)))
            self.progress_text.setText(f'{event.current}/{event.total} items processed')
        if event.kind == 'success':
            self.success_count += 1
            self.metric_labels[1].setText(str(self.success_count))
        elif event.kind == 'fail':
            self.fail_count += 1
            self.metric_labels[2].setText(str(self.fail_count))
        elif event.kind == 'skip':
            self.skip_count += 1
            self.metric_labels[3].setText(str(self.skip_count))

    def _log_matches_filter(self, kind: str, msg: str) -> bool:
        if not hasattr(self, 'log_level_filter'):
            return True
        lvl = self.log_level_filter.currentData()
        if lvl and lvl != 'all' and kind != lvl:
            return False
        q = self.log_search.text().casefold().strip()
        return not q or q in msg.casefold()

    def refresh_log_view(self):
        self.logs.clear()
        for ts, kind, msg in self._log_entries:
            if self._log_matches_filter(kind, msg):
                sign = {'success': '✓', 'fail': '✕', 'skip': '·', 'info': 'ℹ'}.get(kind, '•')
                self.logs.appendPlainText(f'[{ts}] {sign}  {msg}')

    def clear_logs(self):
        self._log_entries.clear()
        self.logs.clear()

    def export_logs_to_file(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export redacted log', 'vpn-config-downloader-log.txt', 'Text files (*.txt)')
        if not path:
            return
        lines = [f'[{ts}] [{kind.upper()}] {redact_secrets(msg)}' for ts, kind, msg in self._log_entries]
        safe_store(Path(path), '\n'.join(lines) + '\n')
        self.show_toast(f'Exported {len(lines)} redacted log entries.')

    # ---------- Scheduler ----------
    def refresh_scheduler_history(self):
        if not hasattr(self, 'scheduler_history_table'):
            return
        rows = self.scheduler_history.list()
        self.scheduler_history_table.setRowCount(0)
        for rec in rows:
            row = self.scheduler_history_table.rowCount()
            self.scheduler_history_table.insertRow(row)
            st = str(rec.get('status', ''))
            self.scheduler_history_table.setItem(row, 0, QTableWidgetItem(str(rec.get('timestamp', ''))[:19].replace('T', ' ')))
            self.scheduler_history_table.setItem(row, 1, QTableWidgetItem(str(rec.get('provider', ''))))
            self.scheduler_history_table.setCellWidget(row, 2, self._make_table_badge(st))
            self.scheduler_history_table.setItem(row, 3, QTableWidgetItem(str(rec.get('new_files', 0))))
            self.scheduler_history_table.setItem(row, 4, QTableWidgetItem(str(rec.get('changed_files', 0))))
            self.scheduler_history_table.setItem(row, 5, QTableWidgetItem(str(rec.get('unchanged_files', 0))))
            self.scheduler_history_table.setItem(row, 6, QTableWidgetItem(str(rec.get('error', ''))))

    def clear_scheduler_history(self):
        self.scheduler_history.clear()
        self.refresh_scheduler_history()
        self.show_toast('Cleared scheduler run history.')

    def run_scheduled_now(self):
        if any(t and t.isRunning() for t in (self.worker, self.login_worker, self.sched_worker)):
            QMessageBox.information(self, 'Busy', 'Wait for the current task to finish first.')
            return
        spec = ScheduleJobSpec(
            provider='surfshark',
            protocols=('udp', 'tcp'),
            output=str(Path(self.output_input.text()).expanduser()),
            interval_minutes=self.schedule_minutes.value(),
            timeout=self.timeout.value(),
            delay=self.delay.value(),
        )
        self.run_sched_now_btn.setEnabled(False)
        self.status_pill.setText('●  Scheduled Refresh')
        self.status_pill.setObjectName('PillBusy')
        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)
        self.sched_worker = ScheduledRefreshThread(spec)
        self.sched_worker.event.connect(self.log)
        self.sched_worker.finished_record.connect(self._scheduled_done)
        self.sched_worker.finished.connect(self._scheduled_cleanup)
        self.sched_worker.start()

    def _scheduled_done(self, rec: dict):
        self.refresh_scheduler_history()
        self.show_toast(f"Scheduled refresh {rec.get('status')}: +{rec.get('new_files', 0)} new, {rec.get('unchanged_files', 0)} unchanged.")

    def _scheduled_cleanup(self):
        self.run_sched_now_btn.setEnabled(True)
        self.status_pill.setText('●  Idle')
        self.status_pill.setObjectName('Pill')
        self.status_pill.style().unpolish(self.status_pill)
        self.status_pill.style().polish(self.status_pill)

    def maybe_schedule(self):
        if not hasattr(self, 'schedule_enabled') or not self.schedule_enabled.isChecked():
            return
        if any(t and t.isRunning() for t in (self.worker, self.login_worker, self.sched_worker)):
            return
        now = time.monotonic()
        if not self.last_scheduled:
            self.last_scheduled = now
            return
        if now - self.last_scheduled < self.schedule_minutes.value() * 60:
            return
        self.last_scheduled = now
        self.run_scheduled_now()

    # ---------- Settings persistence ----------
    def load_settings(self):
        theme = str(self.settings.value('theme', 'dark')).lower()
        t_idx = self.theme_choice.findData(theme)
        self.theme_choice.blockSignals(True)
        if t_idx >= 0:
            self.theme_choice.setCurrentIndex(t_idx)
        self.theme_choice.blockSignals(False)

        key = self.settings.value('provider', 'windscribe')
        idx = self.provider_choice.findData(key)
        self.provider_choice.blockSignals(True)
        if idx >= 0:
            self.provider_choice.setCurrentIndex(idx)
        self.provider_choice.blockSignals(False)

        self.output_input.setText(self.settings.value('output', str(Path.home() / 'Documents' / 'MultiVPN-Configs')))
        self.concurrency.setValue(int(self.settings.value('concurrency', 6)))
        self.quick_concurrency.setValue(self.concurrency.value())
        self.delay.setValue(float(self.settings.value('delay', 0.25)))
        if hasattr(self, 'quick_delay'):
            self.quick_delay.setValue(self.delay.value())
        self.timeout.setValue(int(self.settings.value('timeout', 25)))
        self.retries.setValue(int(self.settings.value('retries', 2)))
        self.browser_limit.setValue(int(self.settings.value('browser_limit', 40)))
        self.schedule_minutes.setValue(int(self.settings.value('schedule_minutes', 1440)))
        self.schedule_enabled.setChecked(str(self.settings.value('schedule_enabled', 'false')).lower() == 'true')
        self.overwrite.setChecked(str(self.settings.value('overwrite', 'false')).lower() == 'true')
        for pkey, inp in self.port_inputs.items():
            inp.setText(str(self.settings.value(f'ports_{pkey}', inp.text())))
        self.archive_checkbox.setChecked(str(self.settings.value('archive', 'true')).lower() == 'true')

    def save_settings(self, silent: bool = False):
        if not hasattr(self, 'output_input'):
            return
        self.settings.setValue('theme', self.theme_choice.currentData())
        self.settings.setValue('provider', self.provider_choice.currentData())
        self.settings.setValue('output', self.output_input.text())
        self.settings.setValue('concurrency', self.concurrency.value())
        self.settings.setValue('delay', self.delay.value())
        self.settings.setValue('timeout', self.timeout.value())
        self.settings.setValue('retries', self.retries.value())
        self.settings.setValue('browser_limit', self.browser_limit.value())
        self.settings.setValue('schedule_minutes', self.schedule_minutes.value())
        self.settings.setValue('schedule_enabled', self.schedule_enabled.isChecked())
        self.settings.setValue('overwrite', self.overwrite.isChecked())
        self.settings.setValue('archive', self.archive_checkbox.isChecked())
        for key, field in self.port_inputs.items():
            self.settings.setValue(f'ports_{key}', field.text())
        if hasattr(self, 'logs') and not silent:
            self.log(CoreEvent('info', 'Non-secret preferences saved.'))
            self.show_toast('Preferences saved.')

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, 'Export running', 'Stop the current export before closing this window.')
            event.ignore()
            return
        if self.login_worker and self.login_worker.isRunning():
            QMessageBox.information(self, 'Login browser open', 'Close the account browser window before closing this app.')
            event.ignore()
            return
        for extra in (self.session_checker, self.health_worker, self.batch_health_worker, self.credential_reader, self.sched_worker):
            if extra is not None and extra.isRunning():
                QMessageBox.information(self, 'Task running', 'Wait for the background check/refresh to finish.')
                event.ignore()
                return
        if self.discovery and self.discovery.isRunning():
            QMessageBox.information(self, 'Refreshing', 'Wait for server refresh to finish before closing.')
            event.ignore()
            return
        self.save_settings(silent=True)
        event.accept()


def start(argv):
    app = QApplication(argv)
    app.setApplicationName('VPN Config Downloader')
    app.setOrganizationName('LocalTools')
    app.setStyle('Fusion')
    app.setStyleSheet(get_stylesheet('dark'))
    window = MainWindow()
    window.show()
    return app.exec()
