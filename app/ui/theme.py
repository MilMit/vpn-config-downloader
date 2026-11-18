"""Modern Dark & Light QSS design system and semantic badge helpers for VPN Config Downloader."""
from __future__ import annotations

DARK_STYLE = '''
QMainWindow, QDialog, QWidget#Shell, QWidget#PageCanvas, QStackedWidget { background:#090d16; color:#e6edf7; }
QWidget { color:#e6edf7; font-family: 'Inter', 'Segoe UI', 'DejaVu Sans', sans-serif; font-size:12px; }

/* Sidebar */
QFrame#Sidebar { background:#0e1422; border-right:1px solid #1b263b; }
QLabel#Brand { color:#f8fafc; font-size:15px; font-weight:800; letter-spacing:0.6px; }
QLabel#BrandSub { color:#64748b; font-size:10px; font-weight:700; letter-spacing:1.2px; }
QLabel#NavSection { color:#64748b; font-size:10px; font-weight:700; letter-spacing:1.3px; padding:10px 10px 3px 10px; }
QLabel#VersionPill { color:#34d399; background:#0d2d2a; border:1px solid #164e45; padding:2px 8px; border-radius:9px; font-size:10px; font-weight:700; }

QPushButton#Nav {
    background:transparent; border:1px solid transparent; padding:9px 12px; text-align:left;
    border-radius:10px; color:#94a3b8; font-weight:600; font-size:12.5px;
}
QPushButton#Nav:hover { background:#162033; color:#f1f5f9; }
QPushButton#Nav:checked {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #113537, stop:1 #112334);
    color:#5eead4; border:1px solid #1f5659; border-left:3px solid #14e3b2; font-weight:700;
}

/* Top Header Bar */
QFrame#TopBar { background:#0c1220; border-bottom:1px solid #1a2538; }
QLabel#PageTitle { color:#f8fafc; font-size:18px; font-weight:800; }
QLabel#PageSubtitle { color:#8899b3; font-size:11.5px; }
QLabel#ContextPill {
    color:#bae6fd; background:#112338; border:1px solid #1e3a5f;
    padding:5px 12px; border-radius:14px; font-size:11px; font-weight:700;
}
QLabel#Pill {
    color:#6ee7b7; background:#0d2e2a; border:1px solid #165549;
    padding:5px 13px; border-radius:14px; font-size:11px; font-weight:700;
}
QLabel#PillBusy {
    color:#fde68a; background:#36290e; border:1px solid #6b4e16;
    padding:5px 13px; border-radius:14px; font-size:11px; font-weight:700;
}

/* Cards & GroupBoxes */
QFrame#Card, QGroupBox {
    background:#121a2a; border:1px solid #1e2d44; border-radius:14px;
}
QFrame#HeroCard {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #112737, stop:0.55 #121c30, stop:1 #102b2d);
    border:1px solid #224159; border-radius:16px;
}
QFrame#StepCard {
    background:rgba(15, 23, 42, 0.72); border:1px solid #22344d; border-radius:11px;
}
QFrame#KpiBlue   { background:#121a2a; border:1px solid #1e2d44; border-top:3px solid #38bdf8; border-radius:14px; }
QFrame#KpiGreen  { background:#121a2a; border:1px solid #1e2d44; border-top:3px solid #10d9a3; border-radius:14px; }
QFrame#KpiRed    { background:#121a2a; border:1px solid #1e2d44; border-top:3px solid #fb7185; border-radius:14px; }
QFrame#KpiAmber  { background:#121a2a; border:1px solid #1e2d44; border-top:3px solid #fbbf24; border-radius:14px; }

QFrame#ProviderCard {
    background:#121a2a; border:1px solid #22324a; border-radius:14px;
}
QFrame#ProviderCard:hover {
    background:#172236; border:1px solid #345075;
}
QFrame#ProviderCardActive {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #113038, stop:1 #132238);
    border:2px solid #14d8a8; border-radius:14px;
}

QGroupBox {
    margin-top:14px; padding:20px 15px 14px; font-weight:700; font-size:12.5px; color:#e2e8f0;
}
QGroupBox::title {
    subcontrol-origin:margin; top:2px; left:16px; padding:2px 8px;
    background:#090d16; border-radius:6px; color:#94a3b8; font-size:11px; letter-spacing:0.4px;
}

/* Typography */
QLabel#Muted { color:#8899b3; }
QLabel#KpiTitle { color:#7c90ad; font-size:10.5px; font-weight:700; letter-spacing:0.9px; }
QLabel#Huge { color:#f8fafc; font-size:28px; font-weight:800; }
QLabel#Heading { color:#f8fafc; font-size:21px; font-weight:800; }
QLabel#CardTitle { color:#f1f5f9; font-size:14px; font-weight:700; }

/* Semantic Badges */
QLabel#BadgeOk {
    color:#6ee7b7; background:#0d332c; border:1px solid #165e4d;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeWarn {
    color:#fde68a; background:#3b2d0d; border:1px solid #6b5015;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeErr {
    color:#fda4af; background:#3f1924; border:1px solid #752c40;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeInfo {
    color:#7dd3fc; background:#0f2a42; border:1px solid #1d4e78;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeNeutral {
    color:#cbd5e1; background:#1e293b; border:1px solid #334155;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}

/* Toast Notification */
QFrame#ToastBar {
    background:#0f2e2b; border:1px solid #186454; border-radius:10px;
}
QLabel#ToastText { color:#a7f3d0; font-weight:600; font-size:12px; }
QPushButton#ToastClose {
    background:transparent; border:1px solid #1b5c50; border-radius:6px;
    color:#a7f3d0; padding:2px 6px; font-weight:700;
}
QPushButton#ToastClose:hover { background:#16453f; }

/* Buttons */
QPushButton {
    background:#1a2538; border:1px solid #2b3c57; padding:8px 14px;
    border-radius:9px; font-weight:600; color:#e2e8f0;
}
QPushButton:hover { background:#23324b; border-color:#3f587d; }
QPushButton:pressed { background:#152031; }
QPushButton:disabled { background:#131a27; color:#52637c; border-color:#1c2738; }

QPushButton#Primary {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10c998, stop:1 #0db4c9);
    color:#041c1a; border:1px solid #2de0b0; font-weight:800; padding:8px 16px;
}
QPushButton#Primary:hover {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2ee0b1, stop:1 #28cbe0);
}
QPushButton#Primary:disabled { background:#163332; color:#4e7773; border-color:#1e4442; }

QPushButton#Danger {
    background:#381a24; color:#fda4af; border:1px solid #6b2d3f; font-weight:700;
}
QPushButton#Danger:hover { background:#4c2230; border-color:#943d55; }

QPushButton#Ghost {
    background:transparent; border:1px solid #24344d; color:#cbd5e1; padding:7px 12px;
}
QPushButton#Ghost:hover { background:#172236; border-color:#385075; color:#f8fafc; }

/* Inputs */
QLineEdit, QComboBox, QDoubleSpinBox, QSpinBox {
    background:#0b111e; border:1px solid #25354d; color:#f1f5f9;
    border-radius:9px; padding:8px 11px; selection-background-color:#14b8a6;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover { border-color:#385175; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border:1px solid #14d8a8; background:#0d1526; }
QLineEdit:disabled, QComboBox:disabled { background:#0c111b; color:#52637c; border-color:#1a2436; }
QComboBox::drop-down { border:0; width:24px; }
QComboBox QAbstractItemView {
    background:#101929; color:#e6edf7; border:1px solid #2a3e5c;
    selection-background-color:#144e4a; outline:0; padding:4px;
}

QCheckBox { spacing:9px; padding:4px; color:#e2e8f0; }
QCheckBox::indicator {
    width:17px; height:17px; border-radius:5px;
    border:1.5px solid #385070; background:#0b111e;
}
QCheckBox::indicator:checked { background:#10c998; border-color:#10c998; }
QCheckBox::indicator:hover { border-color:#2de0b0; }

/* Tables & Logs */
QPlainTextEdit {
    background:#070b14; border:1px solid #1e2d44; border-radius:11px;
    color:#a8bfd9; padding:12px; font-family:'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', monospace; font-size:11.5px;
}
QTableWidget {
    background:#0e1523; alternate-background-color:#121b2d; border:1px solid #1e2d44;
    border-radius:11px; gridline-color:#1a273b; selection-background-color:#164647; color:#e2e8f0;
    outline:0;
}
QHeaderView::section {
    background:#152033; padding:9px 10px; color:#94a3b8; border:0;
    border-bottom:1px solid #23344d; font-weight:700; font-size:11px; letter-spacing:0.5px;
}
QTableWidget::item { padding:6px 8px; }

/* Progress & Strength Bars */
QProgressBar {
    background:#172235; border:1px solid #23334c; border-radius:8px; height:14px;
    text-align:center; color:#f8fafc; font-size:10.5px; font-weight:700;
}
QProgressBar::chunk {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10c998, stop:1 #0ea5e9);
    border-radius:7px;
}
QProgressBar#StrengthWeak::chunk { background:#f43f5e; border-radius:5px; }
QProgressBar#StrengthGood::chunk { background:#f59e0b; border-radius:5px; }
QProgressBar#StrengthStrong::chunk { background:#10d9a3; border-radius:5px; }

/* Scrollbars */
QScrollArea { border:0; background:#090d16; }
QScrollArea > QWidget > QWidget { background:#090d16; }
QScrollBar:vertical { width:9px; background:transparent; margin:2px; }
QScrollBar::handle:vertical { background:#273852; border-radius:4px; min-height:28px; }
QScrollBar::handle:vertical:hover { background:#3a5278; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar:horizontal { height:9px; background:transparent; margin:2px; }
QScrollBar::handle:horizontal { background:#273852; border-radius:4px; min-width:28px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
'''

LIGHT_STYLE = '''
QMainWindow, QDialog, QWidget#Shell, QWidget#PageCanvas, QStackedWidget { background:#f2f6fb; color:#0f172a; }
QWidget { color:#0f172a; font-family: 'Inter', 'Segoe UI', 'DejaVu Sans', sans-serif; font-size:12px; }

/* Sidebar */
QFrame#Sidebar { background:#ffffff; border-right:1px solid #dde6f1; }
QLabel#Brand { color:#0f172a; font-size:15px; font-weight:800; letter-spacing:0.6px; }
QLabel#BrandSub { color:#64748b; font-size:10px; font-weight:700; letter-spacing:1.2px; }
QLabel#NavSection { color:#94a3b8; font-size:10px; font-weight:700; letter-spacing:1.3px; padding:10px 10px 3px 10px; }
QLabel#VersionPill { color:#047857; background:#d1fae5; border:1px solid #a7f3d0; padding:2px 8px; border-radius:9px; font-size:10px; font-weight:700; }

QPushButton#Nav {
    background:transparent; border:1px solid transparent; padding:9px 12px; text-align:left;
    border-radius:10px; color:#475569; font-weight:600; font-size:12.5px;
}
QPushButton#Nav:hover { background:#f1f5f9; color:#0f172a; }
QPushButton#Nav:checked {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #dcfcf2, stop:1 #e8f5fe);
    color:#065f46; border:1px solid #99e6cf; border-left:3px solid #0d9488; font-weight:700;
}

/* Top Header Bar */
QFrame#TopBar { background:#ffffff; border-bottom:1px solid #dde6f1; }
QLabel#PageTitle { color:#0f172a; font-size:18px; font-weight:800; }
QLabel#PageSubtitle { color:#64748b; font-size:11.5px; }
QLabel#ContextPill {
    color:#0369a1; background:#e0f2fe; border:1px solid #bae6fd;
    padding:5px 12px; border-radius:14px; font-size:11px; font-weight:700;
}
QLabel#Pill {
    color:#047857; background:#d1fae5; border:1px solid #a7f3d0;
    padding:5px 13px; border-radius:14px; font-size:11px; font-weight:700;
}
QLabel#PillBusy {
    color:#92400e; background:#fef3c7; border:1px solid #fde68a;
    padding:5px 13px; border-radius:14px; font-size:11px; font-weight:700;
}

/* Cards & GroupBoxes */
QFrame#Card, QGroupBox {
    background:#ffffff; border:1px solid #dce5f0; border-radius:14px;
}
QFrame#HeroCard {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ecfdf5, stop:0.55 #ffffff, stop:1 #f0f9ff);
    border:1px solid #bae6d8; border-radius:16px;
}
QFrame#StepCard {
    background:#ffffff; border:1px solid #dce5f0; border-radius:11px;
}
QFrame#KpiBlue   { background:#ffffff; border:1px solid #dce5f0; border-top:3px solid #0284c7; border-radius:14px; }
QFrame#KpiGreen  { background:#ffffff; border:1px solid #dce5f0; border-top:3px solid #059669; border-radius:14px; }
QFrame#KpiRed    { background:#ffffff; border:1px solid #dce5f0; border-top:3px solid #e11d48; border-radius:14px; }
QFrame#KpiAmber  { background:#ffffff; border:1px solid #dce5f0; border-top:3px solid #d97706; border-radius:14px; }

QFrame#ProviderCard {
    background:#ffffff; border:1px solid #d5e0ee; border-radius:14px;
}
QFrame#ProviderCard:hover {
    background:#f8fbff; border:1px solid #93b4d8;
}
QFrame#ProviderCardActive {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #ecfdf5, stop:1 #f0f9ff);
    border:2px solid #0d9488; border-radius:14px;
}

QGroupBox {
    margin-top:14px; padding:20px 15px 14px; font-weight:700; font-size:12.5px; color:#0f172a;
}
QGroupBox::title {
    subcontrol-origin:margin; top:2px; left:16px; padding:2px 8px;
    background:#f2f6fb; border-radius:6px; color:#475569; font-size:11px; letter-spacing:0.4px;
}

/* Typography */
QLabel#Muted { color:#64748b; }
QLabel#KpiTitle { color:#64748b; font-size:10.5px; font-weight:700; letter-spacing:0.9px; }
QLabel#Huge { color:#0f172a; font-size:28px; font-weight:800; }
QLabel#Heading { color:#0f172a; font-size:21px; font-weight:800; }
QLabel#CardTitle { color:#0f172a; font-size:14px; font-weight:700; }

/* Semantic Badges */
QLabel#BadgeOk {
    color:#065f46; background:#d1fae5; border:1px solid #a7f3d0;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeWarn {
    color:#92400e; background:#fef3c7; border:1px solid #fde68a;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeErr {
    color:#9f1239; background:#ffe4e6; border:1px solid #fecdd3;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeInfo {
    color:#0369a1; background:#e0f2fe; border:1px solid #bae6fd;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}
QLabel#BadgeNeutral {
    color:#475569; background:#e2e8f0; border:1px solid #cbd5e1;
    padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700;
}

/* Toast Notification */
QFrame#ToastBar {
    background:#ecfdf5; border:1px solid #6ee7b7; border-radius:10px;
}
QLabel#ToastText { color:#065f46; font-weight:600; font-size:12px; }
QPushButton#ToastClose {
    background:transparent; border:1px solid #6ee7b7; border-radius:6px;
    color:#065f46; padding:2px 6px; font-weight:700;
}
QPushButton#ToastClose:hover { background:#d1fae5; }

/* Buttons */
QPushButton {
    background:#eef3f9; border:1px solid #cbd7e6; padding:8px 14px;
    border-radius:9px; font-weight:600; color:#1e293b;
}
QPushButton:hover { background:#e2ebf5; border-color:#9fb6cf; }
QPushButton:pressed { background:#d6e2f0; }
QPushButton:disabled { background:#f1f5f9; color:#94a3b8; border-color:#e2e8f0; }

QPushButton#Primary {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d9488, stop:1 #0284c7);
    color:#ffffff; border:1px solid #0b7d73; font-weight:800; padding:8px 16px;
}
QPushButton#Primary:hover {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f766e, stop:1 #0369a1);
}
QPushButton#Primary:disabled { background:#cbd5e1; color:#64748b; border-color:#cbd5e1; }

QPushButton#Danger {
    background:#ffe4e6; color:#9f1239; border:1px solid #fda4af; font-weight:700;
}
QPushButton#Danger:hover { background:#fecdd3; border-color:#fb7185; }

QPushButton#Ghost {
    background:transparent; border:1px solid #cbd5e1; color:#334155; padding:7px 12px;
}
QPushButton#Ghost:hover { background:#f1f5f9; border-color:#94a3b8; color:#0f172a; }

/* Inputs */
QLineEdit, QComboBox, QDoubleSpinBox, QSpinBox {
    background:#f8fafc; border:1px solid #cbd5e1; color:#0f172a;
    border-radius:9px; padding:8px 11px; selection-background-color:#0d9488;
}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover { border-color:#94a3b8; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus { border:1px solid #0d9488; background:#ffffff; }
QLineEdit:disabled, QComboBox:disabled { background:#f1f5f9; color:#94a3b8; border-color:#e2e8f0; }
QComboBox::drop-down { border:0; width:24px; }
QComboBox QAbstractItemView {
    background:#ffffff; color:#0f172a; border:1px solid #cbd5e1;
    selection-background-color:#d1fae5; selection-color:#065f46; outline:0; padding:4px;
}

QCheckBox { spacing:9px; padding:4px; color:#0f172a; }
QCheckBox::indicator {
    width:17px; height:17px; border-radius:5px;
    border:1.5px solid #94a3b8; background:#ffffff;
}
QCheckBox::indicator:checked { background:#0d9488; border-color:#0d9488; }
QCheckBox::indicator:hover { border-color:#0d9488; }

/* Tables & Logs */
QPlainTextEdit {
    background:#f8fafc; border:1px solid #cbd5e1; border-radius:11px;
    color:#1e293b; padding:12px; font-family:'JetBrains Mono', 'Fira Code', 'DejaVu Sans Mono', monospace; font-size:11.5px;
}
QTableWidget {
    background:#ffffff; alternate-background-color:#f8fafc; border:1px solid #dce5f0;
    border-radius:11px; gridline-color:#e2e8f0; selection-background-color:#d1fae5; selection-color:#065f46; color:#0f172a;
    outline:0;
}
QHeaderView::section {
    background:#eef3f9; padding:9px 10px; color:#475569; border:0;
    border-bottom:1px solid #d5e0ee; font-weight:700; font-size:11px; letter-spacing:0.5px;
}
QTableWidget::item { padding:6px 8px; }

/* Progress & Strength Bars */
QProgressBar {
    background:#e2e8f0; border:1px solid #cbd5e1; border-radius:8px; height:14px;
    text-align:center; color:#0f172a; font-size:10.5px; font-weight:700;
}
QProgressBar::chunk {
    background:qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d9488, stop:1 #0284c7);
    border-radius:7px;
}
QProgressBar#StrengthWeak::chunk { background:#e11d48; border-radius:5px; }
QProgressBar#StrengthGood::chunk { background:#d97706; border-radius:5px; }
QProgressBar#StrengthStrong::chunk { background:#059669; border-radius:5px; }

/* Scrollbars */
QScrollArea { border:0; background:#f2f6fb; }
QScrollArea > QWidget > QWidget { background:#f2f6fb; }
QScrollBar:vertical { width:9px; background:transparent; margin:2px; }
QScrollBar::handle:vertical { background:#cbd5e1; border-radius:4px; min-height:28px; }
QScrollBar::handle:vertical:hover { background:#94a3b8; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar:horizontal { height:9px; background:transparent; margin:2px; }
QScrollBar::handle:horizontal { background:#cbd5e1; border-radius:4px; min-width:28px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
'''


def get_stylesheet(theme: str = 'dark') -> str:
    return LIGHT_STYLE if str(theme).lower() == 'light' else DARK_STYLE


def status_badge_object_name(status: str) -> str:
    low = str(status or '').strip().lower()
    if any(k in low for k in ('supported', 'tcp reachable', 'tcp_reachable', 'verified', 'portal_accessible', 'completed', 'downloaded', 'imported', 'reused')) and 'unsupported' not in low:
        return 'BadgeOk'
    if low == 'valid':
        return 'BadgeOk'
    if any(k in low for k in ('requires manual', 'experimental', 'warning', 'action required', 'dns resolved', 'dns_only', 'unknown', 'paused')):
        return 'BadgeWarn'
    if any(k in low for k in ('unsupported', 'invalid', 'failed', 'expired', 'unreachable', 'dns_failed', 'browser_error', 'error', 'cancelled')):
        return 'BadgeErr'
    if any(k in low for k in ('live', 'public', 'active', 'present')):
        return 'BadgeInfo'
    return 'BadgeNeutral'
