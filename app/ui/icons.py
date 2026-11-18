"""Crisp resolution-independent vector icons rendered with QPainter (zero external assets)."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap


def _canvas(size: int = 24) -> tuple[QPixmap, QPainter]:
    pm = QPixmap(size * 2, size * 2)
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    return pm, p


def make_logo_pixmap(size: int = 34) -> QPixmap:
    """Modern emerald-cyan geometric shield emblem."""
    pm, p = _canvas(size)
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor('#10d9a3'))
    grad.setColorAt(1.0, QColor('#0ea5e9'))

    # Rounded square backdrop
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(QRectF(1, 1, size - 2, size - 2), size * 0.28, size * 0.28)

    # Inner shield path
    s = size
    path = QPainterPath()
    path.moveTo(s * 0.50, s * 0.20)
    path.lineTo(s * 0.76, s * 0.30)
    path.lineTo(s * 0.76, s * 0.52)
    path.quadTo(s * 0.76, s * 0.72, s * 0.50, s * 0.82)
    path.quadTo(s * 0.24, s * 0.72, s * 0.24, s * 0.52)
    path.lineTo(s * 0.24, s * 0.30)
    path.closeSubpath()

    pen = QPen(QColor('#071a19'), max(1.8, size * 0.065), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(QColor(255, 255, 255, 235))
    p.drawPath(path)

    # Inner lock/check accent
    check = QPainterPath()
    check.moveTo(s * 0.39, s * 0.52)
    check.lineTo(s * 0.47, s * 0.60)
    check.lineTo(s * 0.62, s * 0.42)
    p.setPen(QPen(QColor('#0d9488'), max(2.0, size * 0.075), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(check)
    p.end()
    return pm


def make_nav_icon(name: str, color: str = '#94a3b8', size: int = 18) -> QIcon:
    """Draw clean minimalist stroke icons for the 10 navigation pages & controls."""
    pm, p = _canvas(size)
    pen = QPen(QColor(color), 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    s = float(size)

    if name == 'dashboard':
        # 4 rounded grid tiles
        g = s * 0.14
        w = s * 0.31
        p.drawRoundedRect(QRectF(g, g, w, w), 2.5, 2.5)
        p.drawRoundedRect(QRectF(s - g - w, g, w, w), 2.5, 2.5)
        p.drawRoundedRect(QRectF(g, s - g - w, w, w), 2.5, 2.5)
        p.drawRoundedRect(QRectF(s - g - w, s - g - w, w, w), 2.5, 2.5)
    elif name == 'providers':
        # Globe / network rings
        p.drawEllipse(QRectF(s * 0.15, s * 0.15, s * 0.70, s * 0.70))
        p.drawEllipse(QRectF(s * 0.33, s * 0.15, s * 0.34, s * 0.70))
        p.drawLine(QPointF(s * 0.16, s * 0.50), QPointF(s * 0.84, s * 0.50))
    elif name == 'accounts':
        # User head + shoulders
        p.drawEllipse(QRectF(s * 0.33, s * 0.16, s * 0.34, s * 0.34))
        path = QPainterPath()
        path.moveTo(s * 0.18, s * 0.84)
        path.quadTo(s * 0.18, s * 0.60, s * 0.50, s * 0.60)
        path.quadTo(s * 0.82, s * 0.60, s * 0.82, s * 0.84)
        p.drawPath(path)
    elif name == 'servers':
        # Stacked server racks
        p.drawRoundedRect(QRectF(s * 0.15, s * 0.18, s * 0.70, s * 0.25), 2.5, 2.5)
        p.drawRoundedRect(QRectF(s * 0.15, s * 0.56, s * 0.70, s * 0.25), 2.5, 2.5)
        p.drawPoint(QPointF(s * 0.28, s * 0.305))
        p.drawPoint(QPointF(s * 0.28, s * 0.685))
    elif name == 'protocols':
        # Sliders / toggles
        for y, x in ((0.26, 0.36), (0.50, 0.66), (0.74, 0.44)):
            p.drawLine(QPointF(s * 0.16, s * y), QPointF(s * 0.84, s * y))
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(s * x, s * y), s * 0.08, s * 0.08)
            p.setBrush(Qt.BrushStyle.NoBrush)
    elif name == 'downloads':
        # Downward arrow into tray
        p.drawLine(QPointF(s * 0.50, s * 0.16), QPointF(s * 0.50, s * 0.62))
        p.drawLine(QPointF(s * 0.32, s * 0.46), QPointF(s * 0.50, s * 0.64))
        p.drawLine(QPointF(s * 0.68, s * 0.46), QPointF(s * 0.50, s * 0.64))
        path = QPainterPath()
        path.moveTo(s * 0.18, s * 0.64)
        path.lineTo(s * 0.18, s * 0.82)
        path.lineTo(s * 0.82, s * 0.82)
        path.lineTo(s * 0.82, s * 0.64)
        p.drawPath(path)
    elif name == 'validator':
        # Shield with checkmark
        path = QPainterPath()
        path.moveTo(s * 0.50, s * 0.14)
        path.lineTo(s * 0.80, s * 0.26)
        path.lineTo(s * 0.80, s * 0.52)
        path.quadTo(s * 0.80, s * 0.76, s * 0.50, s * 0.86)
        path.quadTo(s * 0.20, s * 0.76, s * 0.20, s * 0.52)
        path.lineTo(s * 0.20, s * 0.26)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(s * 0.36, s * 0.50), QPointF(s * 0.46, s * 0.60))
        p.drawLine(QPointF(s * 0.46, s * 0.60), QPointF(s * 0.65, s * 0.40))
    elif name == 'exports':
        # Lock / encrypted package
        p.drawRoundedRect(QRectF(s * 0.22, s * 0.45, s * 0.56, s * 0.40), 3.0, 3.0)
        arch = QPainterPath()
        arch.moveTo(s * 0.34, s * 0.45)
        arch.lineTo(s * 0.34, s * 0.32)
        arch.arcTo(QRectF(s * 0.34, s * 0.16, s * 0.32, s * 0.32), 180, -180)
        arch.lineTo(s * 0.66, s * 0.45)
        p.drawPath(arch)
    elif name == 'logs':
        # Terminal / lines
        p.drawRoundedRect(QRectF(s * 0.14, s * 0.18, s * 0.72, s * 0.64), 3.0, 3.0)
        p.drawLine(QPointF(s * 0.28, s * 0.38), QPointF(s * 0.40, s * 0.48))
        p.drawLine(QPointF(s * 0.40, s * 0.48), QPointF(s * 0.28, s * 0.58))
        p.drawLine(QPointF(s * 0.48, s * 0.58), QPointF(s * 0.72, s * 0.58))
    elif name == 'settings':
        # Minimalist gear circle + spokes
        p.drawEllipse(QRectF(s * 0.32, s * 0.32, s * 0.36, s * 0.36))
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
    elif name == 'sun':
        p.drawEllipse(QRectF(s * 0.31, s * 0.31, s * 0.38, s * 0.38))
        for dx, dy in ((0, -0.34), (0, 0.34), (-0.34, 0), (0.34, 0), (-0.24, -0.24), (0.24, 0.24), (-0.24, 0.24), (0.24, -0.24)):
            p.drawLine(QPointF(s * (0.5 + dx * 0.78), s * (0.5 + dy * 0.78)), QPointF(s * (0.5 + dx), s * (0.5 + dy)))
    elif name == 'moon':
        path = QPainterPath()
        path.addEllipse(QRectF(s * 0.20, s * 0.18, s * 0.62, s * 0.62))
        cut = QPainterPath()
        cut.addEllipse(QRectF(s * 0.38, s * 0.12, s * 0.54, s * 0.54))
        p.drawPath(path.subtracted(cut))
    else:
        p.drawEllipse(QRectF(s * 0.25, s * 0.25, s * 0.50, s * 0.50))

    p.end()
    return QIcon(pm)
