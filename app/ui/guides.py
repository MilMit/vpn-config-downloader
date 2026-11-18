"""Interactive visual step-by-step guide dialogs with crisp QPainter illustrations."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


def _make_canvas(w: int, h: int, bg: str) -> tuple[QPixmap, QPainter]:
    pm = QPixmap(w * 2, h * 2)
    pm.setDevicePixelRatio(2.0)
    pm.fill(QColor(bg))
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    return pm, p


def render_step1_login_illustration(dark: bool = True) -> QPixmap:
    """Illustration 1: Normal Chrome/Firefox browser logging in at windscribe.com/login."""
    w, h = 680, 175
    bg = '#0b1220' if dark else '#f8fafc'
    chrome_bar = '#162235' if dark else '#e2e8f0'
    url_bg = '#0c1526' if dark else '#ffffff'
    card_bg = '#131f33' if dark else '#ffffff'
    border = '#29405e' if dark else '#cbd5e1'
    fg = '#f1f5f9' if dark else '#0f172a'
    muted = '#94a3b8' if dark else '#475569'
    accent = '#10d9a3' if dark else '#0d9488'

    pm, p = _make_canvas(w, h, bg)

    # Outer browser window frame
    p.setPen(QPen(QColor(border), 1.5))
    p.setBrush(QColor(card_bg))
    p.drawRoundedRect(QRectF(4, 4, w - 8, h - 8), 12, 12)

    # Top browser toolbar
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(chrome_bar))
    p.drawRoundedRect(QRectF(5, 5, w - 10, 34), 10, 10)
    p.drawRect(QRectF(5, 22, w - 10, 17))

    # Window dots
    for idx, col in enumerate(('#fb7185', '#fbbf24', '#34d399')):
        p.setBrush(QColor(col))
        p.drawEllipse(QRectF(18 + idx * 14, 17, 9, 9))

    # URL address bar
    p.setPen(QPen(QColor(accent), 1.4))
    p.setBrush(QColor(url_bg))
    p.drawRoundedRect(QRectF(72, 10, 420, 24), 7, 7)
    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans Mono', 9, QFont.Weight.Bold))
    p.drawText(QRectF(84, 10, 400, 24), Qt.AlignmentFlag.AlignVCenter, '🔒  https://windscribe.com/login')

    # Badge on right of address bar
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor('#0d3b32' if dark else '#d1fae5'))
    p.drawRoundedRect(QRectF(504, 10, 162, 24), 7, 7)
    p.setPen(QColor('#6ee7b7' if dark else '#065f46'))
    p.setFont(QFont('DejaVu Sans', 8.5, QFont.Weight.Bold))
    p.drawText(QRectF(504, 10, 162, 24), Qt.AlignmentFlag.AlignCenter, 'Chrome / Firefox معمولی')

    # Left: Login form mockup
    p.setPen(QPen(QColor(border), 1.2))
    p.setBrush(QColor(url_bg))
    p.drawRoundedRect(QRectF(26, 52, 290, 106), 9, 9)
    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans', 9.5, QFont.Weight.Bold))
    p.drawText(QRectF(40, 58, 250, 20), Qt.AlignmentFlag.AlignVCenter, 'Windscribe Sign In')

    p.setPen(QPen(QColor(border), 1.0))
    p.setBrush(QColor(card_bg))
    p.drawRoundedRect(QRectF(40, 82, 170, 22), 5, 5)
    p.drawRoundedRect(QRectF(40, 109, 170, 22), 5, 5)
    p.setPen(QColor(muted))
    p.setFont(QFont('DejaVu Sans', 8))
    p.drawText(QRectF(48, 82, 155, 22), Qt.AlignmentFlag.AlignVCenter, 'Username & Password')
    p.drawText(QRectF(48, 109, 155, 22), Qt.AlignmentFlag.AlignVCenter, '✓ CAPTCHA + 2FA')

    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(accent))
    p.drawRoundedRect(QRectF(220, 82, 82, 49), 7, 7)
    p.setPen(QColor('#041c1a' if dark else '#ffffff'))
    p.setFont(QFont('DejaVu Sans', 9, QFont.Weight.Bold))
    p.drawText(QRectF(220, 82, 82, 49), Qt.AlignmentFlag.AlignCenter, 'Login ✓')

    # Arrow ->
    p.setPen(QPen(QColor(accent), 2.2))
    p.drawLine(QPointF(330, 105), QPointF(374, 105))
    p.drawLine(QPointF(365, 98), QPointF(374, 105))
    p.drawLine(QPointF(365, 112), QPointF(374, 105))

    # Right: Press F12 keycap
    p.setPen(QPen(QColor(accent), 1.6))
    p.setBrush(QColor('#112a36' if dark else '#e0f2fe'))
    p.drawRoundedRect(QRectF(390, 56, 266, 98), 10, 10)

    # F12 Keycap
    p.setPen(QPen(QColor(accent), 1.8))
    p.setBrush(QColor(card_bg))
    p.drawRoundedRect(QRectF(410, 74, 68, 46), 8, 8)
    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans Mono', 13, QFont.Weight.Bold))
    p.drawText(QRectF(410, 74, 68, 46), Qt.AlignmentFlag.AlignCenter, 'F12')

    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans', 9.5, QFont.Weight.Bold))
    p.drawText(QRectF(490, 70, 156, 24), Qt.AlignmentFlag.AlignVCenter, 'سپس کلید F12 بزنید')
    p.setPen(QColor(muted))
    p.setFont(QFont('DejaVu Sans', 8.3))
    p.drawText(QRectF(490, 94, 158, 46), Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
               'یا راست‌کلیک روی صفحه ← Inspect\n(باز شدن پنجره DevTools)')

    p.end()
    return pm


def render_step2_devtools_illustration(dark: bool = True) -> QPixmap:
    """Illustration 2: Exact Chrome/Firefox DevTools -> Application -> Cookies -> ws_session_auth_hash."""
    w, h = 680, 235
    bg = '#0b1220' if dark else '#f8fafc'
    panel = '#111a2b' if dark else '#ffffff'
    bar = '#182438' if dark else '#e2e8f0'
    sidebar = '#0e1625' if dark else '#f1f5f9'
    border = '#29405e' if dark else '#cbd5e1'
    fg = '#f1f5f9' if dark else '#0f172a'
    muted = '#8fa3bf' if dark else '#475569'
    accent = '#10d9a3' if dark else '#0d9488'
    warn = '#fbbf24' if dark else '#d97706'

    pm, p = _make_canvas(w, h, bg)

    # DevTools outer window
    p.setPen(QPen(QColor(border), 1.5))
    p.setBrush(QColor(panel))
    p.drawRoundedRect(QRectF(4, 4, w - 8, h - 8), 11, 11)

    # Top DevTools tab bar
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(bar))
    p.drawRoundedRect(QRectF(5, 5, w - 10, 34), 10, 10)
    p.drawRect(QRectF(5, 22, w - 10, 17))

    tabs = [('Elements', False), ('Console', False), ('Network', False), ('Application (Chrome) / Storage (Firefox)', True)]
    x = 16
    for label, active in tabs:
        tw = 74 if not active else 280
        if active:
            p.setPen(QPen(QColor(accent), 1.6))
            p.setBrush(QColor('#0e3832' if dark else '#d1fae5'))
            p.drawRoundedRect(QRectF(x, 8, tw, 27), 6, 6)
            p.setPen(QColor('#6ee7b7' if dark else '#065f46'))
            p.setFont(QFont('DejaVu Sans', 8.5, QFont.Weight.Bold))
        else:
            p.setPen(QColor(muted))
            p.setFont(QFont('DejaVu Sans', 8.5))
        p.drawText(QRectF(x, 8, tw, 27), Qt.AlignmentFlag.AlignCenter, label)
        x += tw + 8

    # Callout badge (1)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(accent))
    p.drawEllipse(QRectF(552, 10, 22, 22))
    p.setPen(QColor('#041c1a' if dark else '#ffffff'))
    p.setFont(QFont('DejaVu Sans', 9, QFont.Weight.Bold))
    p.drawText(QRectF(552, 10, 22, 22), Qt.AlignmentFlag.AlignCenter, '1')

    # Left tree panel (Storage -> Cookies -> https://windscribe.com)
    p.setPen(QPen(QColor(border), 1.0))
    p.setBrush(QColor(sidebar))
    p.drawRect(QRectF(5, 39, 206, h - 44))

    p.setFont(QFont('DejaVu Sans', 8.5))
    p.setPen(QColor(muted))
    p.drawText(QRectF(16, 48, 185, 20), Qt.AlignmentFlag.AlignVCenter, '▾  Storage')
    p.drawText(QRectF(28, 70, 170, 20), Qt.AlignmentFlag.AlignVCenter, '▸  Local Storage')
    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans', 8.5, QFont.Weight.Bold))
    p.drawText(QRectF(28, 92, 170, 20), Qt.AlignmentFlag.AlignVCenter, '▾  🍪 Cookies')

    # Highlighted https://windscribe.com row
    p.setPen(QPen(QColor(accent), 1.5))
    p.setBrush(QColor('#113842' if dark else '#dbeafe'))
    p.drawRoundedRect(QRectF(18, 116, 184, 28), 6, 6)
    p.setPen(QColor('#7dd3fc' if dark else '#0369a1'))
    p.setFont(QFont('DejaVu Sans Mono', 8.3, QFont.Weight.Bold))
    p.drawText(QRectF(26, 116, 172, 28), Qt.AlignmentFlag.AlignVCenter, 'https://windscribe.com')

    # Callout badge (2)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(accent))
    p.drawEllipse(QRectF(176, 148, 22, 22))
    p.setPen(QColor('#041c1a' if dark else '#ffffff'))
    p.setFont(QFont('DejaVu Sans', 9, QFont.Weight.Bold))
    p.drawText(QRectF(176, 148, 22, 22), Qt.AlignmentFlag.AlignCenter, '2')

    # Right Cookies table
    tx = 220
    tw = w - tx - 14
    p.setPen(QPen(QColor(border), 1.0))
    p.setBrush(QColor(bar))
    p.drawRect(QRectF(tx, 48, tw, 24))
    p.setPen(QColor(muted))
    p.setFont(QFont('DejaVu Sans', 8.3, QFont.Weight.Bold))
    p.drawText(QRectF(tx + 10, 48, 170, 24), Qt.AlignmentFlag.AlignVCenter, 'Name')
    p.drawText(QRectF(tx + 190, 48, 230, 24), Qt.AlignmentFlag.AlignVCenter, 'Value')

    # Dummy row 1
    p.setPen(QColor(muted))
    p.setFont(QFont('DejaVu Sans Mono', 8.2))
    p.drawText(QRectF(tx + 10, 76, 170, 24), Qt.AlignmentFlag.AlignVCenter, 'i_can_has_cookie')
    p.drawText(QRectF(tx + 190, 76, 220, 24), Qt.AlignmentFlag.AlignVCenter, '1')

    # Highlighted ws_session_auth_hash row!
    p.setPen(QPen(QColor(warn), 1.8))
    p.setBrush(QColor('#2c2511' if dark else '#fef3c7'))
    p.drawRoundedRect(QRectF(tx + 2, 104, tw - 4, 34), 6, 6)
    p.setPen(QColor('#fde68a' if dark else '#92400e'))
    p.setFont(QFont('DejaVu Sans Mono', 8.8, QFont.Weight.Bold))
    p.drawText(QRectF(tx + 10, 104, 175, 34), Qt.AlignmentFlag.AlignVCenter, 'ws_session_auth_hash')

    # Highlighted Value box
    p.setPen(QPen(QColor(accent), 1.6))
    p.setBrush(QColor('#0c2f2a' if dark else '#d1fae5'))
    p.drawRoundedRect(QRectF(tx + 188, 109, 244, 24), 5, 5)
    p.setPen(QColor('#6ee7b7' if dark else '#065f46'))
    p.setFont(QFont('DejaVu Sans Mono', 8.3, QFont.Weight.Bold))
    p.drawText(QRectF(tx + 196, 109, 230, 24), Qt.AlignmentFlag.AlignVCenter, '123456:1:17634...:a9f3e...  📋')

    # Dummy row 3
    p.setPen(QColor(muted))
    p.setFont(QFont('DejaVu Sans Mono', 8.2))
    p.drawText(QRectF(tx + 10, 144, 170, 24), Qt.AlignmentFlag.AlignVCenter, 'ws_lang')
    p.drawText(QRectF(tx + 190, 144, 220, 24), Qt.AlignmentFlag.AlignVCenter, 'en')

    # Bottom callout instruction box (3)
    p.setPen(QPen(QColor(accent), 1.4))
    p.setBrush(QColor('#0e2a2c' if dark else '#ecfdf5'))
    p.drawRoundedRect(QRectF(tx + 4, 176, tw - 8, 44), 8, 8)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(accent))
    p.drawEllipse(QRectF(tx + 14, 187, 22, 22))
    p.setPen(QColor('#041c1a' if dark else '#ffffff'))
    p.setFont(QFont('DejaVu Sans', 9, QFont.Weight.Bold))
    p.drawText(QRectF(tx + 14, 187, 22, 22), Qt.AlignmentFlag.AlignCenter, '3')
    p.setPen(QColor(fg))
    p.setFont(QFont('DejaVu Sans', 8.7, QFont.Weight.Bold))
    p.drawText(
        QRectF(tx + 44, 180, tw - 58, 36),
        Qt.AlignmentFlag.AlignVCenter | Qt.TextFlag.TextWordWrap,
        'روی ستون Value ردیف ws_session_auth_hash دبل‌کلیک کنید و Ctrl+C بزنید (مقدار را کپی کنید).',
    )

    p.end()
    return pm


def render_step3_app_illustration(dark: bool = True) -> QPixmap:
    """Illustration 3: Paste into app (RAM-only) -> Servers -> Start Export."""
    w, h = 680, 118
    bg = '#0b1220' if dark else '#f8fafc'
    card = '#131f33' if dark else '#ffffff'
    border = '#29405e' if dark else '#cbd5e1'
    fg = '#f1f5f9' if dark else '#0f172a'
    muted = '#94a3b8' if dark else '#475569'
    accent = '#10d9a3' if dark else '#0d9488'

    pm, p = _make_canvas(w, h, bg)
    boxes = [
        ('۱. پیست در کادر پایین', 'یا Protocols → Website cookie', 'RAM Only · بدون ذخیره'),
        ('۲. انتخاب سرورها', 'Servers → Refresh Locations', '۲۰۲ موقعیت Windscribe'),
        ('۳. شروع استخراج', '▶ START EXPORT', 'OpenVPN + WireGuard + AES-256'),
    ]
    bw = 204
    gap = 24
    for i, (t1, t2, t3) in enumerate(boxes):
        x = 10 + i * (bw + gap)
        p.setPen(QPen(QColor(accent if i == 2 else border), 1.6 if i == 2 else 1.2))
        p.setBrush(QColor('#102e2f' if (i == 2 and dark) else ('#ecfdf5' if i == 2 else card)))
        p.drawRoundedRect(QRectF(x, 10, bw, 98), 11, 11)
        p.setPen(QColor(fg))
        p.setFont(QFont('DejaVu Sans', 9.2, QFont.Weight.Bold))
        p.drawText(QRectF(x + 12, 18, bw - 24, 22), Qt.AlignmentFlag.AlignVCenter, t1)
        p.setPen(QColor(accent))
        p.setFont(QFont('DejaVu Sans Mono', 8.2, QFont.Weight.Bold))
        p.drawText(QRectF(x + 12, 46, bw - 24, 22), Qt.AlignmentFlag.AlignVCenter, t2)
        p.setPen(QColor(muted))
        p.setFont(QFont('DejaVu Sans', 8))
        p.drawText(QRectF(x + 12, 72, bw - 24, 22), Qt.AlignmentFlag.AlignVCenter, t3)
        if i < 2:
            ax = x + bw + 4
            p.setPen(QPen(QColor(accent), 2.0))
            p.drawLine(QPointF(ax, 59), QPointF(ax + 15, 59))
            p.drawLine(QPointF(ax + 10, 53), QPointF(ax + 15, 59))
            p.drawLine(QPointF(ax + 10, 65), QPointF(ax + 15, 59))
    p.end()
    return pm


class WindscribeCookieGuideDialog(QDialog):
    """Visual step-by-step guide + instant RAM-only paste box for Windscribe session cookie."""

    def __init__(self, parent=None, *, dark: bool = True, on_apply=None):
        super().__init__(parent)
        self._on_apply = on_apply
        self.setWindowTitle('راهنمای تصویری ورود Windscribe (از طریق مرورگر معمولی)')
        self.setObjectName('Shell')
        self.resize(800, 790)
        self.setMinimumSize(785, 650)

        root_lay = QVBoxLayout(self)
        root_lay.setContentsMargins(18, 16, 18, 16)
        root_lay.setSpacing(12)

        # Header
        head = QFrame()
        head.setObjectName('HeroCard')
        hl = QVBoxLayout(head)
        hl.setContentsMargins(16, 12, 16, 12)
        hl.setSpacing(4)
        title = QLabel('راهنمای تصویری دریافت نشست Windscribe بدون مشکل CAPTCHA')
        title.setObjectName('CardTitle')
        hl.addWidget(title)
        sub = QLabel(
            'چون Windscribe روی مرورگر اتوماسیون Playwright کپچا را قفل می‌کند، کافیست یک بار در مرورگر معمولی خودتان '
            '(Chrome / Firefox) وارد شوید و مقدار کوکی ws_session_auth_hash را مطابق تصاویر زیر کپی کنید.'
        )
        sub.setObjectName('Muted')
        sub.setWordWrap(True)
        hl.addWidget(sub)
        root_lay.addWidget(head)

        # Scrollable steps with rendered diagrams
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        body.setObjectName('PageCanvas')
        bl = QVBoxLayout(body)
        bl.setContentsMargins(4, 4, 8, 4)
        bl.setSpacing(12)

        # Step 1
        s1_box = QFrame()
        s1_box.setObjectName('Card')
        s1l = QVBoxLayout(s1_box)
        s1l.setContentsMargins(14, 12, 14, 12)
        s1_top = QHBoxLayout()
        lbl1 = QLabel('مرحله ۱: ورود عادی در مرورگر معمولی و زدن کلید F12')
        lbl1.setObjectName('CardTitle')
        s1_top.addWidget(lbl1, 1)
        open_ws = QPushButton('↗ باز کردن windscribe.com/login در مرورگر')
        open_ws.setObjectName('Primary')
        open_ws.clicked.connect(lambda: QDesktopServices.openUrl(QUrl('https://windscribe.com/login')))
        s1_top.addWidget(open_ws)
        s1l.addLayout(s1_top)
        img1 = QLabel()
        img1.setPixmap(render_step1_login_illustration(dark))
        img1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s1l.addWidget(img1)
        bl.addWidget(s1_box)

        # Step 2
        s2_box = QFrame()
        s2_box.setObjectName('Card')
        s2l = QVBoxLayout(s2_box)
        s2l.setContentsMargins(14, 12, 14, 12)
        lbl2 = QLabel('مرحله ۲: کپی کردن مقدار ws_session_auth_hash از DevTools')
        lbl2.setObjectName('CardTitle')
        s2l.addWidget(lbl2)
        img2 = QLabel()
        img2.setPixmap(render_step2_devtools_illustration(dark))
        img2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s2l.addWidget(img2)
        bl.addWidget(s2_box)

        # Step 3
        s3_box = QFrame()
        s3_box.setObjectName('Card')
        s3l = QVBoxLayout(s3_box)
        s3l.setContentsMargins(14, 12, 14, 12)
        lbl3 = QLabel('مرحله ۳: وارد کردن در حافظهٔ موقت برنامه (RAM) و شروع استخراج')
        lbl3.setObjectName('CardTitle')
        s3l.addWidget(lbl3)
        img3 = QLabel()
        img3.setPixmap(render_step3_app_illustration(dark))
        img3.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s3l.addWidget(img3)
        bl.addWidget(s3_box)

        scroll.setWidget(body)
        root_lay.addWidget(scroll, 1)

        # Quick Apply Footer (with secure OS Keyring persistence option)
        foot = QFrame()
        foot.setObjectName('Card')
        fl = QVBoxLayout(foot)
        fl.setContentsMargins(14, 10, 14, 10)
        fl.setSpacing(8)
        fl.addWidget(QLabel('ورود کوکی نشست Windscribe (هرگز در فایل متنی یا لاگ ذخیره نمی‌شود):'))
        self.save_keyring_cb = QCheckBox('ذخیره امن در OS Keyring سیستم‌عامل (برای حفظ حساب در اجراهای بعدی تا زمانی که خودتان پاک کنید)')
        self.save_keyring_cb.setChecked(True)
        fl.addWidget(self.save_keyring_cb)
        prow = QHBoxLayout()
        self.cookie_edit = QLineEdit()
        self.cookie_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.cookie_edit.setPlaceholderText('مقدار ws_session_auth_hash کپی‌شده را اینجا Paste کنید...')
        prow.addWidget(self.cookie_edit, 1)
        apply_btn = QPushButton('✓ ذخیره و اعمال در برنامه')
        apply_btn.setObjectName('Primary')
        apply_btn.clicked.connect(self._apply)
        prow.addWidget(apply_btn)
        close_btn = QPushButton('بستن')
        close_btn.clicked.connect(self.reject)
        prow.addWidget(close_btn)
        fl.addLayout(prow)
        root_lay.addWidget(foot)

    def _apply(self):
        raw = self.cookie_edit.text().strip()
        # Allow users who accidentally pasted "ws_session_auth_hash=..." to work seamlessly
        if raw.lower().startswith('ws_session_auth_hash='):
            raw = raw.split('=', 1)[1].strip()
        if not raw or any(c in raw for c in '\r\n; '):
            QMessageBox.warning(
                self,
                'فرمت نامعتبر',
                'مقدار ws_session_auth_hash نباید خالی باشد یا شامل فاصله/خط جدید/سمیکالن باشد.\n'
                'فقط ستون Value را کپی کنید.',
            )
            return
        if self._on_apply:
            self._on_apply(raw, self.save_keyring_cb.isChecked())
        self.cookie_edit.clear()
        self.accept()
