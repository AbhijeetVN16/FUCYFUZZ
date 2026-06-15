"""
DBC Analyzer Pro — FucyFuzz
Clean, smooth, professional. Inspired by Vector CANdb++ / CANoe.

Tabs: Overview · Messages · Signals · Bit Layout · Bus Load · Consistency · Builder · Diff
"""

import os, math
from collections import Counter

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QSplitter,
    QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QHeaderView,
    QTabWidget, QWidget, QGroupBox, QFrame, QComboBox, QFileDialog,
    QAbstractItemView, QSizePolicy, QMessageBox, QScrollArea,
    QTextEdit, QApplication
)
from PyQt5.QtCore  import Qt, QRect, QRectF, QPointF, QSize, QPoint, QTimer
from PyQt5.QtGui   import (
    QColor, QFont, QBrush, QPainter, QPen, QFontMetrics,
    QLinearGradient, QRadialGradient, QPainterPath
)

from ui.theme   import COLORS
from ui.widgets import GlowButton, SolidButton

C = COLORS

# ── Palette ───────────────────────────────────────────────────────────────────
def qc(h): return QColor(h)

CHART_PAL = [
    "#00d4ff","#10b981","#a78bfa","#fbbf24","#f43f5e",
    "#f97316","#14b8a6","#3b82f6","#ec4899","#84cc16",
    "#06b6d4","#8b5cf6","#fb923c","#34d399","#f472b6",
]
SIG_PAL = [
    "#1565c0","#2e7d32","#6a1e8a","#b5451b","#00695c",
    "#4527a0","#c62828","#0277bd","#558b2f","#4e342e",
    "#00838f","#6d4c41","#37474f","#ad1457","#1b5e20",
]
def cp(i): return CHART_PAL[i % len(CHART_PAL)]
def sp(i): return SIG_PAL[i % len(SIG_PAL)]


# ═══════════════════════════════════════════════════════════════════════
#  KPI CARD  — animated fade-in with glow accent
# ═══════════════════════════════════════════════════════════════════════
class KpiCard(QWidget):
    def __init__(self, title, value, color, icon="", parent=None):
        super().__init__(parent)
        self._color = color
        self._title = title
        self._icon  = icon
        self._value = str(value)
        self._alpha = 0.0
        self.setMinimumSize(140, 88)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._t.start(14)

    def _tick(self):
        self._alpha = min(1.0, self._alpha + 0.07)
        self.update()
        if self._alpha >= 1.0: self._t.stop()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        a = int(self._alpha * 255)

        # Card
        bg = QColor(C['bg_elevated']); bg.setAlpha(a)
        path = QPainterPath(); path.addRoundedRect(QRectF(0, 0, w, h), 10, 10)
        p.fillPath(path, bg)

        # Top gradient bar
        bar = QLinearGradient(0, 0, w, 0)
        bar.setColorAt(0, QColor(self._color))
        c2 = QColor(self._color); c2.setAlpha(0)
        bar.setColorAt(1, c2)
        p.fillRect(QRect(0, 0, w, 3), bar)

        # Glow blob bottom-right
        gr = QRadialGradient(w * 0.82, h * 0.78, h * 0.65)
        gc = QColor(self._color); gc.setAlpha(int(22 * self._alpha))
        gr.setColorAt(0, gc); gr.setColorAt(1, QColor(0,0,0,0))
        p.fillRect(QRect(0, 0, w, h), gr)

        # Icon
        p.setFont(QFont("Segoe UI", 15))
        ic = QColor(self._color); ic.setAlpha(int(160 * self._alpha))
        p.setPen(ic)
        p.drawText(QRect(w-40, 8, 32, 32), Qt.AlignCenter, self._icon)

        # Value
        p.setFont(QFont("Segoe UI", 22, QFont.Bold))
        vc = QColor(self._color); vc.setAlpha(a)
        p.setPen(vc)
        p.drawText(QRect(12, 12, w-52, 38), Qt.AlignLeft | Qt.AlignVCenter, self._value)

        # Title
        p.setFont(QFont("Segoe UI", 9))
        tc = QColor(C['text_muted']); tc.setAlpha(a)
        p.setPen(tc)
        p.drawText(QRect(12, h-24, w-16, 20), Qt.AlignLeft | Qt.AlignVCenter, self._title)
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  DONUT CHART
# ═══════════════════════════════════════════════════════════════════════
class DonutChart(QWidget):
    def __init__(self, title, segments, parent=None):
        super().__init__(parent)
        self._title = title
        self._segs  = segments   # [(label, value, color), ...]
        self._phase = 0.0
        self.setMinimumSize(200, 210)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(14)

    def _tick(self):
        self._phase = min(1.0, self._phase + 0.045)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, qc(C['bg_card']))

        total = sum(v for _, v, _ in self._segs) or 1
        leg_h = len(self._segs) * 20 + 6
        dia   = min(w - 24, h - leg_h - 30)
        cx, cy = w // 2, 18 + dia // 2
        R, r  = dia // 2, int(dia // 2 * 0.54)

        rect = QRectF(cx-R, cy-R, R*2, R*2)
        angle = 90 * 16
        for label, val, color in self._segs:
            span = int(360 * 16 * (val / total) * self._phase)
            if span == 0: continue
            p.setBrush(qc(color))
            p.setPen(QPen(qc(C['bg_primary']), 2))
            p.drawPie(rect, angle, -span)
            angle -= span

        # Hole
        p.setBrush(qc(C['bg_card'])); p.setPen(Qt.NoPen)
        p.drawEllipse(QRectF(cx-r, cy-r, r*2, r*2))

        # Centre label
        p.setFont(QFont("Segoe UI", 13, QFont.Bold))
        p.setPen(qc(C['text_primary']))
        p.drawText(QRect(cx-r, cy-16, r*2, 20), Qt.AlignCenter, str(total))
        p.setFont(QFont("Segoe UI", 8))
        p.setPen(qc(C['text_muted']))
        p.drawText(QRect(cx-r, cy+2, r*2, 16), Qt.AlignCenter, "total")

        # Title
        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.setPen(qc(C['text_secondary']))
        p.drawText(QRect(0, 2, w, 16), Qt.AlignCenter, self._title)

        # Legend
        ly = cy + R + 10
        for i, (label, val, color) in enumerate(self._segs):
            p.fillRect(8, ly + i*20 + 5, 10, 10, qc(color))
            p.setFont(QFont("Segoe UI", 8))
            p.setPen(qc(C['text_primary']))
            pct = f"{val/total*100:.0f}%"
            p.drawText(22, ly + i*20, w-24, 20, Qt.AlignVCenter,
                       f"{label}  ({val})  {pct}")
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  BAR CHART  (vertical, animated)
# ═══════════════════════════════════════════════════════════════════════
class BarChart(QWidget):
    def __init__(self, title, data, parent=None):
        """data = [(label, value, color|None), ...]"""
        super().__init__(parent)
        self._title = title
        self._data  = data
        self._phase = 0.0
        self.setMinimumSize(240, 180)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(14)

    def _tick(self):
        self._phase = min(1.0, self._phase + 0.05)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, qc(C['bg_card']))
        if not self._data: p.end(); return

        PL, PR, PT, PB = 42, 12, 32, 38
        cw = w - PL - PR
        ch = h - PT - PB
        mx = max(v for _, v, _ in self._data) or 1
        n  = len(self._data)
        bw = max(6, cw // n - 6)
        gap = max(2, (cw - bw * n) // max(n, 1))

        # Title
        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.setPen(qc(C['text_secondary']))
        p.drawText(QRect(0, 4, w, 20), Qt.AlignCenter, self._title)

        # Grid + y-labels
        for i in range(5):
            gy = PT + ch - int(ch * i / 4)
            p.setPen(QPen(qc(C['border']), 1, Qt.DotLine))
            p.drawLine(PL, gy, w-PR, gy)
            p.setPen(qc(C['text_muted']))
            p.setFont(QFont("Segoe UI", 7))
            p.drawText(QRect(0, gy-8, PL-4, 16), Qt.AlignRight|Qt.AlignVCenter,
                       str(int(mx * i / 4)))

        # Bars
        for i, (lbl, val, col) in enumerate(self._data):
            bh = int(ch * (val / mx) * self._phase)
            bx = PL + i * (bw + gap) + gap // 2
            by = PT + ch - bh
            c_ = col if col else cp(i)

            gr = QLinearGradient(bx, by, bx, by + bh)
            gr.setColorAt(0, QColor(c_).lighter(120))
            c2 = QColor(c_); c2.setAlpha(170)
            gr.setColorAt(1, c2)
            pp = QPainterPath()
            pp.addRoundedRect(QRectF(bx, by, bw, bh), 3, 3)
            p.fillPath(pp, gr)

            # Value label
            if val > 0:
                p.setFont(QFont("Segoe UI", 7, QFont.Bold))
                p.setPen(qc(c_))
                p.drawText(QRect(bx-4, by-15, bw+8, 13), Qt.AlignCenter, str(val))

            # X label
            p.setFont(QFont("Segoe UI", 7))
            p.setPen(qc(C['text_muted']))
            fm = QFontMetrics(p.font())
            xl = fm.elidedText(str(lbl), Qt.ElideRight, bw + gap - 2)
            p.drawText(QRect(bx - gap//2, PT+ch+4, bw+gap, 18), Qt.AlignCenter, xl)

        # Axes
        p.setPen(QPen(qc(C['border']), 1))
        p.drawLine(PL, PT, PL, PT+ch)
        p.drawLine(PL, PT+ch, w-PR, PT+ch)
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  HORIZONTAL BAR CHART
# ═══════════════════════════════════════════════════════════════════════
class HBarChart(QWidget):
    def __init__(self, title, data, parent=None):
        super().__init__(parent)
        self._title = title
        self._data  = data
        self._phase = 0.0
        self.setMinimumSize(220, max(160, len(data)*28 + 50))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(14)

    def _tick(self):
        self._phase = min(1.0, self._phase + 0.05)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, qc(C['bg_card']))
        if not self._data: p.end(); return

        PL, PR, PT, PB = 96, 46, 30, 8
        cw = w - PL - PR
        ch = h - PT - PB
        n   = len(self._data)
        rh  = max(16, ch // n)
        mx  = max(v for _, v, _ in self._data) or 1

        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.setPen(qc(C['text_secondary']))
        p.drawText(QRect(0, 4, w, 22), Qt.AlignCenter, self._title)

        for i, (lbl, val, col) in enumerate(self._data):
            by  = PT + i * rh
            bw_ = int(cw * (val / mx) * self._phase)
            c_  = col if col else cp(i)

            gr = QLinearGradient(PL, by, PL + bw_, by)
            gr.setColorAt(0, QColor(c_))
            c2 = QColor(c_); c2.setAlpha(120)
            gr.setColorAt(1, c2)
            pp = QPainterPath()
            pp.addRoundedRect(QRectF(PL, by+3, max(bw_, 2), rh-8), 3, 3)
            p.fillPath(pp, gr)

            # Label
            p.setFont(QFont("Segoe UI", 8))
            p.setPen(qc(C['text_primary']))
            fm = QFontMetrics(p.font())
            ll = fm.elidedText(lbl, Qt.ElideRight, PL-8)
            p.drawText(QRect(4, by, PL-8, rh), Qt.AlignRight|Qt.AlignVCenter, ll)

            # Value
            p.setFont(QFont("Segoe UI", 8, QFont.Bold))
            p.setPen(qc(c_))
            p.drawText(QRect(PL + bw_ + 4, by, PR-4, rh),
                       Qt.AlignLeft|Qt.AlignVCenter, str(val))
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  SCATTER / BUBBLE CHART  (signal length distribution)
# ═══════════════════════════════════════════════════════════════════════
class BubbleChart(QWidget):
    def __init__(self, title, counts, parent=None):
        """counts = Counter(length -> frequency)"""
        super().__init__(parent)
        self._title  = title
        self._counts = counts
        self._phase  = 0.0
        self.setMinimumSize(220, 160)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(14)

    def _tick(self):
        self._phase = min(1.0, self._phase + 0.04)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, qc(C['bg_card']))
        if not self._counts: p.end(); return

        PL, PR, PT, PB = 36, 12, 30, 28
        cw = w - PL - PR
        ch = h - PT - PB
        xs = sorted(self._counts)
        mn, mx_ = xs[0], xs[-1]
        my = max(self._counts.values()) or 1

        p.setFont(QFont("Segoe UI", 9, QFont.Bold))
        p.setPen(qc(C['text_secondary']))
        p.drawText(QRect(0, 4, w, 20), Qt.AlignCenter, self._title)

        # Grid
        for i in range(5):
            gy = PT + ch - int(ch * i / 4)
            p.setPen(QPen(qc(C['border']), 1, Qt.DotLine))
            p.drawLine(PL, gy, w-PR, gy)

        rx = max(mx_ - mn, 1)
        for bits, cnt in self._counts.items():
            x  = PL + int((bits - mn) / rx * cw)
            y  = PT + ch - int(ch * (cnt / my) * self._phase)
            r  = max(5, int(9 * (cnt / my) * self._phase))
            cc = QColor(C['accent_cyan']); cc.setAlpha(int(210 * self._phase))
            p.setBrush(cc)
            p.setPen(QPen(qc(C['bg_primary']), 1))
            p.drawEllipse(QPointF(x, y), r, r)
            p.setFont(QFont("Segoe UI", 7))
            p.setPen(qc(C['text_muted']))
            p.drawText(QRect(x-14, PT+ch+4, 28, 14), Qt.AlignCenter, str(bits))

        p.setPen(QPen(qc(C['border']), 1))
        p.drawLine(PL, PT, PL, PT+ch)
        p.drawLine(PL, PT+ch, w-PR, PT+ch)
        p.setFont(QFont("Segoe UI", 7))
        p.setPen(qc(C['text_muted']))
        p.drawText(QRect(0, PT+ch+16, w, 12), Qt.AlignCenter, "bits")
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  BUS LOAD GAUGE  (animated arc)
# ═══════════════════════════════════════════════════════════════════════
class BusGauge(QWidget):
    def __init__(self, pct, kbps, parent=None):
        super().__init__(parent)
        self._pct   = min(float(pct), 100.0)
        self._kbps  = kbps
        self._phase = 0.0
        self.setFixedHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        t = QTimer(self); t.timeout.connect(self._tick); t.start(14)

    def _tick(self):
        self._phase = min(1.0, self._phase + 0.035)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, qc(C['bg_card']))

        cx, cy = w // 2, h - 16
        R = min(cx - 18, cy - 8)

        # Track
        p.setPen(QPen(qc(C['border']), 11, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(QRect(cx-R, cy-R, R*2, R*2), 0, 180*16)

        # Value arc
        val_deg = int(180 * (self._pct / 100) * self._phase)
        color = (C['accent_green']  if self._pct < 40 else
                 C['accent_yellow'] if self._pct < 70 else
                 C['accent_orange'] if self._pct < 90 else C['accent_pink'])
        p.setPen(QPen(qc(color), 11, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(QRect(cx-R, cy-R, R*2, R*2), 180*16, -val_deg*16)

        # Percentage
        p.setFont(QFont("Segoe UI", 19, QFont.Bold))
        p.setPen(qc(color))
        p.drawText(QRect(cx-50, cy-52, 100, 36), Qt.AlignCenter,
                   f"{self._pct:.1f}%")
        p.setFont(QFont("Segoe UI", 8))
        p.setPen(qc(C['text_muted']))
        p.drawText(QRect(cx-55, cy-20, 110, 16), Qt.AlignCenter,
                   f"@ {self._kbps} kbps")
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  BIT LAYOUT GRID  (with hover highlight)
# ═══════════════════════════════════════════════════════════════════════
class BitLayoutWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._signals   = []
        self._dlc       = 8
        self._occ       = {}
        self._hover_sig = None
        self._tooltip   = SignalTooltip()
        self.setMinimumHeight(240)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMouseTracking(True)

    def set_message(self, msg):
        if msg is None:
            self._signals, self._dlc, self._occ = [], 8, {}
        else:
            self._dlc    = max(msg.length, 1)
            self._signals = list(msg.signals)
            self._occ    = self._build_occ(self._signals)
        self.setMinimumHeight(max(240, self._dlc * 34 + 60))
        self._hover_sig = None
        self.update()

    def _build_occ(self, signals):
        occ = {}
        for si, sig in enumerate(signals):
            try:
                if sig.byte_order == 'little_endian':
                    for k in range(sig.length):
                        occ[sig.start + k] = (sig, si)
                else:
                    bit = sig.start
                    for _ in range(sig.length):
                        occ[bit] = (sig, si)
                        bit = (bit + 15) if (bit % 8 == 0) else (bit - 1)
            except Exception:
                pass
        return occ

    def _cell_geometry(self):
        HEADER_H, LABEL_W = 30, 52
        cell_w = max(20, (self.width() - LABEL_W) // 8)
        cell_h = max(24, (self.height() - HEADER_H - 10) // max(self._dlc, 1))
        return HEADER_H, LABEL_W, cell_w, cell_h

    def mouseMoveEvent(self, ev):
        HH, LW, cw, ch = self._cell_geometry()
        mx, my = ev.x(), ev.y()
        if mx >= LW and my >= HH:
            col = (mx - LW) // cw
            row = (my - HH) // ch
            if 0 <= col < 8 and 0 <= row < self._dlc:
                bit   = row * 8 + (7 - col)
                entry = self._occ.get(bit)
                new_h = entry[0].name if entry else None
                if new_h != self._hover_sig:
                    self._hover_sig = new_h
                    self.update()
                if entry:
                    gp = ev.globalPos()
                    self._tooltip.show_for(entry[0], entry[1],
                                           QPoint(gp.x(), gp.y()))
                    return
        self._tooltip.hide()

    def leaveEvent(self, ev):
        self._tooltip.hide()
        self._hover_sig = None
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        HH, LW, cw, ch = self._cell_geometry()

        p.fillRect(0, 0, w, h, qc(C['bg_card']))

        # Column headers
        for col in range(8):
            x = LW + col * cw
            p.fillRect(x, 0, cw-1, HH-2, qc(C['bg_elevated']))
            p.setFont(QFont("JetBrains Mono", 9, QFont.Bold))
            p.setPen(qc(C['accent_cyan']))
            p.drawText(QRect(x, 0, cw-1, HH-2), Qt.AlignCenter, str(7-col))

        for row in range(self._dlc):
            y = HH + row * ch
            # Row label
            p.fillRect(0, y, LW-2, ch-1, qc(C['bg_elevated']))
            p.setFont(QFont("Segoe UI", 8))
            p.setPen(qc(C['text_secondary']))
            p.drawText(QRect(0, y, LW-2, ch-1), Qt.AlignCenter, f"B{row}")

            for col in range(8):
                x   = LW + col * cw
                bit = row * 8 + (7 - col)

                if bit in self._occ:
                    sig, si = self._occ[bit]
                    hover   = (sig.name == self._hover_sig)
                    base    = QColor(sp(si))
                    top_c   = base.lighter(115 if not hover else 155)
                    bot_c   = QColor(base); bot_c.setAlpha(200)
                    gr = QLinearGradient(x, y, x, y+ch)
                    gr.setColorAt(0, top_c); gr.setColorAt(1, bot_c)
                    pp2 = QPainterPath()
                    pp2.addRoundedRect(QRectF(x+1, y+1, cw-3, ch-3), 3, 3)
                    p.fillPath(pp2, gr)
                    p.setFont(QFont("JetBrains Mono", 7, QFont.Bold))
                    p.setPen(qc("#ffffff"))
                    p.drawText(QRect(x, y, cw-1, ch-1), Qt.AlignCenter, sig.name[0])
                    if hover:
                        p.setPen(QPen(qc("#ffffff"), 2))
                        p.drawRoundedRect(QRectF(x+1, y+1, cw-3, ch-3), 3, 3)
                else:
                    p.fillRect(QRect(x+1, y+1, cw-3, ch-3), qc(C['bg_input']))

                p.setPen(QPen(qc(C['border']), 1))
                p.drawRect(QRect(x, y, cw-1, ch-1))
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  SIGNAL LEGEND
# ═══════════════════════════════════════════════════════════════════════
class SignalLegend(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._signals = []

    def set_signals(self, signals):
        self._signals = signals
        rows = max(1, math.ceil(len(signals) / 3))
        self.setFixedHeight(rows * 22 + 10)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), qc(C['bg_card']))
        if not self._signals: p.end(); return
        per_col = max(1, math.ceil(len(self._signals) / 3))
        col_w   = (self.width() - 16) // 3
        p.setFont(QFont("Segoe UI", 8))
        for i, sig in enumerate(self._signals):
            row = i % per_col
            col = i // per_col
            cx  = 8 + col * col_w
            cy  = 6 + row * 22
            rr  = QPainterPath()
            rr.addRoundedRect(QRectF(cx, cy+4, 12, 12), 3, 3)
            p.fillPath(rr, qc(sp(i)))
            p.setPen(qc(C['text_primary']))
            fm  = QFontMetrics(p.font())
            lbl = fm.elidedText(sig.name, Qt.ElideRight, col_w - 22)
            p.drawText(QRect(cx+16, cy, col_w-18, 22), Qt.AlignVCenter, lbl)
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  SIGNAL TOOLTIP  (floating card, shown on bit-cell hover)
# ═══════════════════════════════════════════════════════════════════════
class SignalTooltip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent, Qt.ToolTip | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._sig = None
        self._si  = 0
        self.resize(258, 178)
        self.hide()

    def show_for(self, sig, si, pos: QPoint):
        self._sig = sig
        self._si  = si
        screen = QApplication.primaryScreen().availableGeometry()
        x = min(pos.x() + 14, screen.right()  - self.width()  - 4)
        y = min(pos.y() + 14, screen.bottom() - self.height() - 4)
        self.move(x, y)
        self.update()
        self.show()

    def paintEvent(self, e):
        if not self._sig: return
        sig = self._sig
        p   = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        col  = sp(self._si)

        bg = QColor(C['bg_elevated']); bg.setAlpha(248)
        pp = QPainterPath(); pp.addRoundedRect(QRectF(0,0,w,h), 10, 10)
        p.fillPath(pp, bg)
        p.fillRect(QRect(0, 0, 4, h), qc(col))
        p.setPen(QPen(QColor(col+"66"), 1))
        p.drawRoundedRect(QRectF(0.5, 0.5, w-1, h-1), 10, 10)

        p.setFont(QFont("Segoe UI", 11, QFont.Bold))
        p.setPen(qc(col))
        p.drawText(QRect(12, 8, w-20, 22), Qt.AlignVCenter, sig.name)

        rows = [
            ("Bits",       f"{sig.length}  (start {sig.start})"),
            ("Byte Order", "Intel LE" if sig.byte_order=="little_endian" else "Motorola BE"),
            ("Scale",      str(sig.scale)),
            ("Offset",     str(sig.offset)),
            ("Range",      f"{sig.minimum} … {sig.maximum}" if sig.minimum is not None else "—"),
            ("Unit",       sig.unit or "—"),
            ("Signed",     "Yes" if sig.is_signed else "No"),
        ]
        y0 = 34
        for lbl, val in rows:
            p.setFont(QFont("Segoe UI", 8)); p.setPen(qc(C['text_muted']))
            p.drawText(QRect(12, y0, 80, 17), Qt.AlignVCenter, lbl)
            p.setPen(qc(C['text_primary']))
            p.drawText(QRect(94, y0, w-102, 17), Qt.AlignVCenter, val)
            y0 += 18

        if sig.choices:
            pairs = list(sig.choices.items())[:3]
            txt   = "  ".join(f"{k}={v}" for k, v in pairs)
            if len(sig.choices) > 3: txt += "…"
            p.setFont(QFont("Segoe UI", 7))
            p.setPen(qc(C['text_muted']))
            p.drawText(QRect(12, y0, w-20, 16), Qt.AlignVCenter, txt)
        p.end()


# ═══════════════════════════════════════════════════════════════════════
#  CONSISTENCY CHECKER
# ═══════════════════════════════════════════════════════════════════════
def run_consistency(db, all_msgs):
    results = []
    names = Counter(m.name      for m in all_msgs)
    ids   = Counter(m.frame_id  for m in all_msgs)

    for msg in all_msgs:
        if names[msg.name] > 1:
            results.append(('error', 'Message', msg.name,
                'Duplicate name', f"{names[msg.name]}× occurrences"))
        if ids[msg.frame_id] > 1:
            results.append(('error', 'Message', msg.name,
                'Duplicate frame ID', f"0x{msg.frame_id:04X}"))
        if not msg.senders:
            results.append(('warning', 'Message', msg.name,
                'No transmitter defined', ''))
        if not msg.signals:
            results.append(('info', 'Message', msg.name,
                'No signals', ''))
        if msg.cycle_time == 0:
            results.append(('warning', 'Message', msg.name,
                'Cycle time = 0 ms', ''))

        occ = {}
        for sig in msg.signals:
            needed = math.ceil((sig.start + sig.length) / 8)
            if needed > msg.length:
                results.append(('error', 'Signal', sig.name,
                    'Exceeds DLC', f"needs {needed}B, DLC={msg.length}"))
            if sig.length == 0:
                results.append(('error', 'Signal', sig.name, 'Zero length', ''))
            if sig.length > 64:
                results.append(('warning', 'Signal', sig.name,
                    'Length > 64 bits', f"{sig.length}"))
            if (sig.minimum is not None and sig.maximum is not None
                    and sig.minimum > sig.maximum):
                results.append(('error', 'Signal', sig.name,
                    'Min > Max', f"{sig.minimum} > {sig.maximum}"))
            try:
                bits = (list(range(sig.start, sig.start + sig.length))
                        if sig.byte_order == 'little_endian'
                        else _motorola_bits(sig))
                for b in bits:
                    if b in occ:
                        results.append(('error', 'Signal', sig.name,
                            f'Bit overlap with {occ[b]}', f"bit {b}"))
                        break
                    occ[b] = sig.name
            except Exception:
                pass

    if not results:
        results.append(('info', '—', '—', 'Database is consistent ✓', ''))
    return results

def _motorola_bits(sig):
    bits, bit = [], sig.start
    for _ in range(sig.length):
        bits.append(bit)
        bit = (bit + 15) if (bit % 8 == 0) else (bit - 1)
    return bits


# ═══════════════════════════════════════════════════════════════════════
#  SMALL FORM WIDGETS
# ═══════════════════════════════════════════════════════════════════════
_field_ss = (f"background:{C['bg_input']}; border:1px solid {C['border']}; "
             f"border-radius:4px; padding:4px 8px; color:{C['text_primary']}; font-size:11px;")

class FLineEdit(QLineEdit):
    def __init__(self, ph="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(ph)
        self.setStyleSheet(_field_ss)

class FCombo(QComboBox):
    def __init__(self, items, idx=0, parent=None):
        super().__init__(parent)
        for it in items: self.addItem(it)
        self.setCurrentIndex(idx)
        self.setStyleSheet(_field_ss)


# ═══════════════════════════════════════════════════════════════════════
#  DBC BUILDER
# ═══════════════════════════════════════════════════════════════════════
class DBCBuilderWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._messages = []
        self._cur      = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10); root.setSpacing(8)

        banner = QLabel("  🛠  DBC Builder — design a new database from scratch")
        banner.setStyleSheet(
            f"color:{C['accent_cyan']}; font-size:11px; font-weight:700; "
            f"background:{C['bg_elevated']}; padding:7px 14px; "
            f"border-left:3px solid {C['accent_cyan']}; border-radius:3px;")
        root.addWidget(banner)

        sp = QSplitter(Qt.Horizontal); sp.setHandleWidth(5)
        sp.addWidget(self._msg_panel())
        sp.addWidget(self._sig_panel())
        sp.setSizes([360, 700])
        root.addWidget(sp, 1)

        # Preview
        pg = QGroupBox("DBC Preview")
        pl = QVBoxLayout(pg)
        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFont(QFont("JetBrains Mono", 9))
        self._preview.setFixedHeight(120)
        self._preview.setStyleSheet(
            f"background:{C['bg_input']}; color:{C['accent_green']}; "
            f"border:1px solid {C['border']}; border-radius:4px; padding:6px;")
        pl.addWidget(self._preview)
        sr = QHBoxLayout(); sr.addStretch()
        sb = SolidButton("💾  Save .dbc", C['accent_cyan'])
        sb.setFixedWidth(140); sb.clicked.connect(self._save)
        sr.addWidget(sb); pl.addLayout(sr)
        root.addWidget(pg)

    # ── Message panel ─────────────────────────────────────────────────
    def _msg_panel(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.setContentsMargins(0,0,4,0); v.setSpacing(6)

        hdr = QLabel("  Messages")
        hdr.setStyleSheet(f"color:{C['accent_yellow']}; font-weight:700; font-size:11px; "
                          f"background:{C['bg_elevated']}; padding:6px 10px;")
        v.addWidget(hdr)

        fg = QGroupBox("New Message"); fl = QVBoxLayout(fg); fl.setSpacing(4)

        def R(lbl, w_):
            row = QHBoxLayout()
            l = QLabel(lbl); l.setFixedWidth(72)
            l.setStyleSheet(f"color:{C['text_muted']}; font-size:10px;")
            row.addWidget(l); row.addWidget(w_); fl.addLayout(row)

        self._m_name  = FLineEdit("e.g. ENGINE_STATUS")
        self._m_id    = FLineEdit("e.g. 0x100 or 256")
        self._m_dlc   = FCombo([str(i) for i in range(1,9)], 7)
        self._m_tx    = FLineEdit("e.g. ECM")
        self._m_cycle = FLineEdit("0  (0 = event)")
        self._m_cmt   = FLineEdit("optional comment")
        R("Name",     self._m_name)
        R("ID",       self._m_id)
        R("DLC",      self._m_dlc)
        R("TX Node",  self._m_tx)
        R("Cycle ms", self._m_cycle)
        R("Comment",  self._m_cmt)
        ab = SolidButton("＋  Add Message", C['accent_green'])
        ab.clicked.connect(self._add_msg); fl.addWidget(ab)
        v.addWidget(fg)

        self._ml = QTableWidget(0, 4)
        self._ml.setHorizontalHeaderLabels(["Name","ID","DLC","TX"])
        self._ml.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._ml.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._ml.setAlternatingRowColors(True)
        self._ml.verticalHeader().setVisible(False)
        self._ml.horizontalHeader().setStretchLastSection(True)
        self._ml.itemSelectionChanged.connect(self._on_msg_sel)
        v.addWidget(self._ml, 1)

        db = GlowButton("🗑  Delete Message", C['accent_pink'])
        db.clicked.connect(self._del_msg); v.addWidget(db)
        return w

    # ── Signal panel ──────────────────────────────────────────────────
    def _sig_panel(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.setContentsMargins(4,0,0,0); v.setSpacing(6)

        self._sh = QLabel("  Signals  —  select a message first")
        self._sh.setStyleSheet(
            f"color:{C['accent_purple']}; font-weight:700; font-size:11px; "
            f"background:{C['bg_elevated']}; padding:6px 10px;")
        v.addWidget(self._sh)

        fg = QGroupBox("New Signal"); fl = QVBoxLayout(fg); fl.setSpacing(4)
        top = QHBoxLayout(); top.setSpacing(12)
        lc  = QVBoxLayout(); rc = QVBoxLayout()

        def R(layout, lbl, w_):
            row = QHBoxLayout()
            l = QLabel(lbl); l.setFixedWidth(72)
            l.setStyleSheet(f"color:{C['text_muted']}; font-size:10px;")
            row.addWidget(l); row.addWidget(w_); layout.addLayout(row)

        self._sn_name   = FLineEdit("e.g. EngineRPM")
        self._sn_start  = FLineEdit("0")
        self._sn_len    = FLineEdit("16")
        self._sn_order  = FCombo(["Intel (LE)", "Motorola (BE)"])
        self._sn_signed = FCombo(["Unsigned", "Signed"])
        self._sn_rx     = FLineEdit("e.g. BCM,TCM")
        self._sn_scale  = FLineEdit("1.0")
        self._sn_offset = FLineEdit("0")
        self._sn_min    = FLineEdit("0")
        self._sn_max    = FLineEdit("65535")
        self._sn_unit   = FLineEdit("e.g. rpm")
        self._sn_cmt    = FLineEdit("optional")

        R(lc, "Name",       self._sn_name)
        R(lc, "Start Bit",  self._sn_start)
        R(lc, "Length",     self._sn_len)
        R(lc, "Byte Order", self._sn_order)
        R(lc, "Signed",     self._sn_signed)
        R(lc, "Receivers",  self._sn_rx)
        R(rc, "Scale",      self._sn_scale)
        R(rc, "Offset",     self._sn_offset)
        R(rc, "Min",        self._sn_min)
        R(rc, "Max",        self._sn_max)
        R(rc, "Unit",       self._sn_unit)
        R(rc, "Comment",    self._sn_cmt)
        top.addLayout(lc); top.addLayout(rc); fl.addLayout(top)
        asb = SolidButton("＋  Add Signal", C['accent_purple'])
        asb.clicked.connect(self._add_sig); fl.addWidget(asb)
        v.addWidget(fg)

        cols = ["Name","Start","Len","Order","Scale","Offset","Min","Max","Unit","Signed"]
        self._sl = QTableWidget(0, len(cols))
        self._sl.setHorizontalHeaderLabels(cols)
        self._sl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._sl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._sl.setAlternatingRowColors(True)
        self._sl.verticalHeader().setVisible(False)
        self._sl.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self._sl, 1)

        dsb = GlowButton("🗑  Delete Signal", C['accent_pink'])
        dsb.clicked.connect(self._del_sig); v.addWidget(dsb)
        return w

    # ── CRUD ──────────────────────────────────────────────────────────
    def _add_msg(self):
        name = self._m_name.text().strip()
        id_s = self._m_id.text().strip()
        if not name or not id_s:
            QMessageBox.warning(self, "Builder", "Name and ID are required."); return
        try:
            fid = int(id_s, 0)
        except ValueError:
            QMessageBox.warning(self, "Builder", f"Invalid ID: {id_s}"); return
        cyc = 0
        try: cyc = int(self._m_cycle.text().strip())
        except: pass
        self._messages.append(dict(name=name, frame_id=fid,
            dlc=int(self._m_dlc.currentText()),
            tx=self._m_tx.text().strip(),
            cycle=cyc, comment=self._m_cmt.text().strip(), signals=[]))
        self._refresh_ml()
        self._refresh_preview()
        self._ml.selectRow(len(self._messages)-1)

    def _del_msg(self):
        rows = self._ml.selectionModel().selectedRows()
        if not rows: return
        self._messages.pop(rows[0].row())
        self._cur = None
        self._refresh_ml()
        self._sl.setRowCount(0)
        self._sh.setText("  Signals  —  select a message first")
        self._refresh_preview()

    def _on_msg_sel(self):
        rows = self._ml.selectionModel().selectedRows()
        if not rows: self._cur = None; return
        self._cur = rows[0].row()
        m = self._messages[self._cur]
        self._sh.setText(f"  Signals  —  {m['name']}  (0x{m['frame_id']:04X}  DLC:{m['dlc']})")
        self._refresh_sl()

    def _add_sig(self):
        if self._cur is None:
            QMessageBox.warning(self, "Builder", "Select a message first."); return
        name = self._sn_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Builder", "Signal name required."); return
        try:
            start  = int(self._sn_start.text())
            length = int(self._sn_len.text())
            scale  = float(self._sn_scale.text() or "1")
            offset = float(self._sn_offset.text() or "0")
            mn     = float(self._sn_min.text() or "0")
            mx     = float(self._sn_max.text() or "0")
        except ValueError as ex:
            QMessageBox.warning(self, "Builder", f"Invalid value: {ex}"); return
        self._messages[self._cur]['signals'].append(dict(
            name=name, start=start, length=length,
            byte_order="little_endian" if "Intel" in self._sn_order.currentText() else "big_endian",
            scale=scale, offset=offset, min=mn, max=mx,
            unit=self._sn_unit.text().strip(),
            signed=self._sn_signed.currentText()=="Signed",
            receivers=[r.strip() for r in self._sn_rx.text().split(",") if r.strip()],
            comment=self._sn_cmt.text().strip()))
        self._refresh_sl(); self._refresh_preview()

    def _del_sig(self):
        if self._cur is None: return
        rows = self._sl.selectionModel().selectedRows()
        if not rows: return
        self._messages[self._cur]['signals'].pop(rows[0].row())
        self._refresh_sl(); self._refresh_preview()

    def _refresh_ml(self):
        t = self._ml; t.setRowCount(0)
        for m in self._messages:
            r = t.rowCount(); t.insertRow(r)
            for c, txt in enumerate([m['name'], f"0x{m['frame_id']:04X}",
                                      str(m['dlc']), m['tx'] or '—']):
                it = QTableWidgetItem(txt)
                if c == 1:
                    it.setForeground(QBrush(qc(C['accent_cyan'])))
                    it.setFont(QFont("JetBrains Mono", 9))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()

    def _refresh_sl(self):
        if self._cur is None: return
        t = self._sl; t.setRowCount(0)
        for i, s in enumerate(self._messages[self._cur]['signals']):
            r = t.rowCount(); t.insertRow(r)
            oc = "Intel LE" if s['byte_order']=='little_endian' else "Motorola BE"
            for c, txt in enumerate([s['name'], str(s['start']), str(s['length']),
                                      oc, str(s['scale']), str(s['offset']),
                                      str(s['min']), str(s['max']),
                                      s['unit'] or '—', "✓" if s['signed'] else "—"]):
                it = QTableWidgetItem(txt)
                if c == 0:
                    it.setForeground(QBrush(qc(sp(i))))
                    it.setFont(QFont("Segoe UI", 10, QFont.Bold))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()

    def _refresh_preview(self):
        self._preview.setPlainText(self._gen_dbc())

    def _gen_dbc(self):
        nodes = sorted({m['tx'] for m in self._messages if m['tx']})
        L = ["VERSION \"\"", "", "NS_ :", "", "BS_:", "",
             f"BU_: {' '.join(nodes)}", ""]
        for m in self._messages:
            tx = m['tx'] or "Vector__XXX"
            L.append(f"BO_ {m['frame_id']} {m['name']}: {m['dlc']} {tx}")
            for s in m['signals']:
                oc = "@1" if s['byte_order']=='little_endian' else "@0"
                sc = "+" if not s['signed'] else "-"
                rx = ",".join(s['receivers']) if s['receivers'] else "Vector__XXX"
                L.append(f" SG_ {s['name']} : {s['start']}|{s['length']}{oc}{sc}"
                         f" ({s['scale']},{s['offset']}) [{s['min']}|{s['max']}]"
                         f" \"{s['unit']}\" {rx}")
            L.append("")
        for m in self._messages:
            if m['comment']:
                L.append(f"CM_ BO_ {m['frame_id']} \"{m['comment']}\";")
            for s in m['signals']:
                if s['comment']:
                    L.append(f"CM_ SG_ {m['frame_id']} {s['name']} \"{s['comment']}\";")
        return "\n".join(L)

    def _save(self):
        if not self._messages:
            QMessageBox.warning(self, "Builder", "Add at least one message."); return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save DBC", "new_database.dbc", "DBC Files (*.dbc)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._gen_dbc())
            QMessageBox.information(self, "Saved",
                f"Saved to:\n{path}\n\n"
                f"{len(self._messages)} messages, "
                f"{sum(len(m['signals']) for m in self._messages)} signals.")
        except Exception as ex:
            QMessageBox.critical(self, "Error", str(ex))


# ═══════════════════════════════════════════════════════════════════════
#  DBC DIFF
# ═══════════════════════════════════════════════════════════════════════
class DBCDiffWidget(QWidget):
    def __init__(self, ref_db, ref_path, parent=None):
        super().__init__(parent)
        self._ref_db   = ref_db
        self._ref_path = ref_path
        self._cmp_db   = None
        self._build_ui()

    def _build_ui(self):
        v = QVBoxLayout(self); v.setContentsMargins(10,10,10,10); v.setSpacing(8)

        top = QHBoxLayout()
        rl = QLabel(f"Reference:  {os.path.basename(self._ref_path)}")
        rl.setStyleSheet(f"color:{C['accent_cyan']}; font-size:11px; font-weight:700;")
        top.addWidget(rl); top.addStretch()
        self._cl = QLabel("Compare: (none loaded)")
        self._cl.setStyleSheet(f"color:{C['text_muted']}; font-size:11px;")
        top.addWidget(self._cl)
        lb = SolidButton("📂  Load Compare DBC", C['accent_purple'])
        lb.clicked.connect(self._load); top.addWidget(lb)
        v.addLayout(top)

        # Legend chips
        leg = QHBoxLayout()
        for txt, col in [("  ● Added  ", C['accent_green']),
                         ("  ● Removed  ", C['accent_pink']),
                         ("  ● Modified  ", C['accent_yellow']),
                         ("  ● Identical  ", C['text_muted'])]:
            ll = QLabel(txt)
            ll.setStyleSheet(f"color:{col}; font-size:10px; "
                             f"background:{C['bg_elevated']}; padding:3px 8px; border-radius:3px;")
            leg.addWidget(ll)
        leg.addStretch(); v.addLayout(leg)

        cols = ["Status","Message","Ref ID","Ref DLC","Ref Sigs",
                "Cmp ID","Cmp DLC","Cmp Sigs","Detail"]
        self._tbl = QTableWidget(0, len(cols))
        self._tbl.setHorizontalHeaderLabels(cols)
        self._tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._tbl.setAlternatingRowColors(True)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self._tbl, 1)

        self._sum = QLabel("Load a compare file to see differences.")
        self._sum.setStyleSheet(
            f"color:{C['text_secondary']}; font-size:10px; "
            f"background:{C['bg_elevated']}; padding:5px 12px; border-radius:3px;")
        v.addWidget(self._sum)

    def _load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Compare DBC", "", "DBC Files (*.dbc)")
        if not path: return
        try:
            import cantools
            self._cmp_db = cantools.database.load_file(path)
            self._cl.setText(f"Compare:  {os.path.basename(path)}")
            self._run_diff()
        except Exception as ex:
            QMessageBox.critical(self, "Error", str(ex))

    def _run_diff(self):
        ref = {m.name: m for m in self._ref_db.messages}
        cmp = {m.name: m for m in self._cmp_db.messages}
        all_names = sorted(ref.keys() | cmp.keys())
        t = self._tbl; t.setRowCount(0)
        cnt = Counter()
        for name in all_names:
            ir, ic = name in ref, name in cmp
            if ir and ic:
                rm, cm = ref[name], cmp[name]
                diffs = []
                if rm.frame_id != cm.frame_id:
                    diffs.append(f"ID:{hex(rm.frame_id)}→{hex(cm.frame_id)}")
                if rm.length != cm.length:
                    diffs.append(f"DLC:{rm.length}→{cm.length}")
                rs = {s.name for s in rm.signals}
                cs = {s.name for s in cm.signals}
                if cs-rs: diffs.append(f"+{','.join(sorted(cs-rs))}")
                if rs-cs: diffs.append(f"-{','.join(sorted(rs-cs))}")
                if diffs:
                    status, col = "MODIFIED", C['accent_yellow']; cnt['modified'] += 1
                else:
                    status, col = "identical", C['text_muted']; cnt['identical'] += 1
                self._row(t, status, col, name,
                          f"0x{rm.frame_id:04X}", str(rm.length), str(len(rm.signals)),
                          f"0x{cm.frame_id:04X}", str(cm.length), str(len(cm.signals)),
                          "  |  ".join(diffs) or "—")
            elif ir:
                rm = ref[name]
                self._row(t, "REMOVED", C['accent_pink'], name,
                          f"0x{rm.frame_id:04X}", str(rm.length), str(len(rm.signals)),
                          "—","—","—","not in compare"); cnt['removed'] += 1
            else:
                cm = cmp[name]
                self._row(t, "ADDED", C['accent_green'], name,
                          "—","—","—",
                          f"0x{cm.frame_id:04X}", str(cm.length), str(len(cm.signals)),
                          "not in reference"); cnt['added'] += 1
        t.resizeColumnsToContents()
        self._sum.setText(
            f"  {cnt['added']} added   │   {cnt['removed']} removed   │   "
            f"{cnt['modified']} modified   │   {cnt['identical']} identical   │   "
            f"{len(all_names)} total")

    def _row(self, t, status, col, *vals):
        r = t.rowCount(); t.insertRow(r)
        all_vals = [status] + list(vals)
        for c, txt in enumerate(all_vals):
            it = QTableWidgetItem(txt)
            it.setForeground(QBrush(qc(col if c==0 else
                                       C['text_primary'] if c!=9 else C['text_secondary'])))
            if c==0: it.setFont(QFont("Segoe UI", 10, QFont.Bold))
            t.setItem(r, c, it)


# ═══════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════
class DBCAnalyzerWindow(QDialog):
    def __init__(self, db, dbc_path, parent=None):
        super().__init__(parent)
        self._db       = db
        self._dbc_path = dbc_path
        self._all      = sorted(db.messages, key=lambda m: m.frame_id)
        self._filt     = list(self._all)
        self._cur      = None
        self._stats    = self._compute_stats()

        self.setWindowTitle(f"DBC Analyzer Pro  —  {os.path.basename(dbc_path)}")
        self.setMinimumSize(1300, 800)
        self.resize(1480, 900)
        self._apply_style()
        self._build_ui()
        self._fill_tree()
        self._fill_msg_table()

    # ── Style ─────────────────────────────────────────────────────────
    def _apply_style(self):
        self.setStyleSheet(f"""
        QDialog  {{ background:{C['bg_primary']}; }}
        QGroupBox {{
            color:{C['text_secondary']}; font-size:11px; font-weight:600;
            border:1px solid {C['border']}; border-radius:6px;
            margin-top:14px; padding-top:8px;
        }}
        QGroupBox::title {{ subcontrol-origin:margin; left:10px; top:2px; }}
        QTreeWidget, QTableWidget {{
            background:{C['bg_secondary']}; border:1px solid {C['border']};
            border-radius:4px; color:{C['text_primary']}; font-size:11px;
            gridline-color:{C['border']};
            selection-background-color:{C['accent_blue']}33;
            alternate-background-color:{C['bg_card']};
        }}
        QTreeWidget::item:selected, QTableWidget::item:selected {{
            background:{C['accent_blue']}44; color:{C['text_primary']};
        }}
        QTreeWidget::item:hover, QTableWidget::item:hover {{ background:{C['bg_elevated']}; }}
        QHeaderView::section {{
            background:{C['bg_elevated']}; color:{C['accent_cyan']};
            border:none; border-right:1px solid {C['border']};
            border-bottom:1px solid {C['border']}; padding:5px 8px;
            font-size:11px; font-weight:600;
        }}
        QLineEdit {{
            background:{C['bg_input']}; border:1px solid {C['border']};
            border-radius:5px; padding:6px 10px; color:{C['text_primary']}; font-size:12px;
        }}
        QLineEdit:focus {{ border:1px solid {C['accent_cyan']}; }}
        QTabWidget::pane {{ border:1px solid {C['border']}; background:{C['bg_card']}; }}
        QTabBar::tab {{
            background:{C['bg_secondary']}; color:{C['text_muted']};
            border:1px solid {C['border']}; padding:7px 16px; margin-right:2px;
            border-top-left-radius:5px; border-top-right-radius:5px; font-size:10px;
        }}
        QTabBar::tab:selected {{
            background:{C['bg_card']}; color:{C['accent_cyan']};
            border-bottom:2px solid {C['accent_cyan']}; font-weight:700;
        }}
        QTabBar::tab:hover {{ background:{C['bg_elevated']}; color:{C['text_primary']}; }}
        QLabel {{ background:transparent; color:{C['text_primary']}; }}
        QComboBox {{
            background:{C['bg_input']}; border:1px solid {C['border']};
            border-radius:5px; padding:5px 10px; color:{C['text_primary']}; font-size:11px;
        }}
        QScrollBar:vertical {{ background:{C['bg_secondary']}; width:5px; border-radius:3px; }}
        QScrollBar::handle:vertical {{ background:{C['border_bright']}; border-radius:3px; }}
        QScrollBar:horizontal {{ background:{C['bg_secondary']}; height:5px; border-radius:3px; }}
        QScrollBar::handle:horizontal {{ background:{C['border_bright']}; border-radius:3px; }}
        QSplitter::handle {{ background:{C['border']}; }}
        QTextEdit {{
            background:{C['bg_input']}; border:1px solid {C['border']};
            border-radius:4px; color:{C['text_primary']};
        }}
        """)

    # ── Layout ────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 6); root.setSpacing(6)
        root.addLayout(self._toolbar())

        split = QSplitter(Qt.Horizontal); split.setHandleWidth(4)
        split.addWidget(self._left_panel())
        split.addWidget(self._right_panel())
        split.setSizes([230, 1250])
        root.addWidget(split, 1)

        self._status = QLabel()
        self._status.setStyleSheet(
            f"color:{C['text_muted']}; font-size:10px; padding:3px 8px; "
            f"background:{C['bg_secondary']}; border-top:1px solid {C['border']};")
        root.addWidget(self._status)

    # ── Toolbar ───────────────────────────────────────────────────────
    def _toolbar(self):
        hb = QHBoxLayout(); hb.setSpacing(8)
        pl = QLabel(f"📂  {self._dbc_path}")
        pl.setStyleSheet(
            f"color:{C['text_secondary']}; font-size:10px; background:{C['bg_secondary']}; "
            f"padding:5px 10px; border:1px solid {C['border']}; border-radius:4px;")
        pl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        hb.addWidget(pl)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search messages / signals…")
        self._search.setFixedWidth(280)
        self._search.textChanged.connect(self._apply_filter)
        hb.addWidget(self._search)

        self._tx_combo = QComboBox(); self._tx_combo.setFixedWidth(155)
        self._tx_combo.addItem("All transmitters")
        nodes = sorted({n.name for n in self._db.nodes} |
                       {s for m in self._all for s in (m.senders or [])})
        for n in nodes: self._tx_combo.addItem(n)
        self._tx_combo.currentTextChanged.connect(self._apply_filter)
        hb.addWidget(self._tx_combo)

        exp = SolidButton("⬇  Export CSV", C['accent_green'])
        exp.setFixedWidth(120); exp.clicked.connect(self._export_csv)
        hb.addWidget(exp)

        cl = GlowButton("✕  Close", C['text_muted'])
        cl.setFixedWidth(88); cl.clicked.connect(self.close)
        hb.addWidget(cl)
        return hb

    # ── Left panel ────────────────────────────────────────────────────
    def _left_panel(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.setContentsMargins(0,0,4,0); v.setSpacing(4)

        hdr = QLabel("  Network Nodes")
        hdr.setStyleSheet(
            f"color:{C['accent_cyan']}; font-size:11px; font-weight:700; "
            f"background:{C['bg_elevated']}; padding:6px 10px; "
            f"border-bottom:1px solid {C['border']};")
        v.addWidget(hdr)

        self._tree = QTreeWidget()
        self._tree.setHeaderHidden(True); self._tree.setIndentation(12)
        self._tree.itemClicked.connect(self._on_node_click)
        v.addWidget(self._tree, 1)

        sf = QFrame()
        sf.setStyleSheet(f"background:{C['bg_elevated']}; border:1px solid {C['border']}; "
                         f"border-radius:4px;")
        sl = QVBoxLayout(sf); sl.setContentsMargins(10,8,10,8); sl.setSpacing(5)
        self._kv = {}
        for key, col in [("Messages",C['accent_cyan']),("Signals",C['accent_green']),
                          ("Nodes",C['accent_purple']),("Max DLC",C['accent_yellow'])]:
            row = QHBoxLayout()
            lk = QLabel(key); lk.setStyleSheet(f"color:{C['text_muted']}; font-size:10px;")
            lv = QLabel("—"); lv.setStyleSheet(
                f"color:{col}; font-size:12px; font-weight:700;")
            lv.setAlignment(Qt.AlignRight)
            row.addWidget(lk); row.addWidget(lv); sl.addLayout(row)
            self._kv[key] = lv
        v.addWidget(sf)
        return w

    # ── Right panel ───────────────────────────────────────────────────
    def _right_panel(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.setContentsMargins(4,0,0,0); v.setSpacing(0)
        self._tabs = QTabWidget()
        self._tabs.addTab(self._tab_overview(),   "📊  Overview")
        self._tabs.addTab(self._tab_messages(),   "📋  Messages")
        self._tabs.addTab(self._tab_signals(),    "🔬  Signals")
        self._tabs.addTab(self._tab_bit_layout(), "🗺  Bit Layout")
        self._tabs.addTab(self._tab_bus_load(),   "📡  Bus Load")
        self._tabs.addTab(self._tab_consistency(),"✅  Consistency")
        self._tabs.addTab(self._tab_builder(),    "🛠  Builder")
        self._tabs.addTab(self._tab_diff(),       "⚡  Compare")
        v.addWidget(self._tabs)
        return w

    # ── TAB 1: Overview ───────────────────────────────────────────────
    def _tab_overview(self):
        sc = QScrollArea(); sc.setWidgetResizable(True)
        sc.setStyleSheet("background:transparent; border:none;")
        inner = QWidget(); v = QVBoxLayout(inner)
        v.setContentsMargins(12,12,12,12); v.setSpacing(12)
        s = self._stats

        # KPI cards
        kr = QHBoxLayout(); kr.setSpacing(10)
        for title, val, col, icon in [
            ("Total Messages",  s['msg_count'],          C['accent_cyan'],   "📋"),
            ("Total Signals",   s['sig_count'],          C['accent_green'],  "📡"),
            ("Network Nodes",   s['node_count'],         C['accent_purple'], "🔌"),
            ("Cyclic Messages", s['cyclic'],             C['accent_yellow'], "🔄"),
            ("Event Messages",  s['event'],              C['accent_pink'],   "⚡"),
            ("Avg Sigs/Msg",    f"{s['avg_sigs']:.1f}", C['accent_teal'],   "∑"),
        ]:
            kr.addWidget(KpiCard(title, val, col, icon))
        v.addLayout(kr)

        # Row 1: donut + bar + donut
        r1 = QHBoxLayout(); r1.setSpacing(10)
        r1.addWidget(DonutChart("Message Type", [
            ("Cyclic", s['cyclic'], C['accent_cyan']),
            ("Event",  s['event'],  C['accent_pink']),
        ]), 2)
        r1.addWidget(BarChart("DLC Distribution",
            [(str(k), v, cp(k)) for k, v in sorted(s['dlc_dist'].items())]), 3)
        le = sum(1 for m in self._all for sg in m.signals
                 if sg.byte_order=='little_endian')
        be = s['sig_count'] - le
        r1.addWidget(DonutChart("Byte Order", [
            ("Intel LE",   le, C['accent_blue']),
            ("Motorola BE",be, C['accent_orange']),
        ]), 2)
        v.addLayout(r1)

        # Row 2: hbar + bubble + bar
        r2 = QHBoxLayout(); r2.setSpacing(10)
        tx_data = sorted([(tx, d[0], cp(i))
                          for i,(tx,d) in enumerate(s['tx_dist'].items())],
                         key=lambda x:-x[1])
        r2.addWidget(HBarChart("Messages per Transmitter", tx_data[:12]), 3)
        lens = [sg.length for m in self._all for sg in m.signals]
        r2.addWidget(BubbleChart("Signal Length Distribution", Counter(lens)), 3)
        top_m = sorted(self._all, key=lambda m: len(m.signals), reverse=True)[:12]
        r2.addWidget(BarChart("Top Messages by Signal Count",
            [(m.name[:10], len(m.signals), None) for m in top_m]), 4)
        v.addLayout(r2)

        v.addStretch()
        sc.setWidget(inner)
        return sc

    # ── TAB 2: Messages ───────────────────────────────────────────────
    def _tab_messages(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(6,6,6,6)
        cols = ["Name","ID (hex)","ID (dec)","DLC","Cycle (ms)","Transmitter","Signals","Comment"]
        self._mt = QTableWidget(0, len(cols))
        self._mt.setHorizontalHeaderLabels(cols)
        self._mt.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._mt.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._mt.setAlternatingRowColors(True)
        self._mt.horizontalHeader().setStretchLastSection(True)
        self._mt.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._mt.verticalHeader().setVisible(False)
        self._mt.itemSelectionChanged.connect(self._on_msg_select)
        self._mt.setSortingEnabled(True)
        v.addWidget(self._mt)

        # ── Fuzz button bar ───────────────────────────────────────────
        from PyQt5.QtWidgets import QHBoxLayout
        btn_bar = QHBoxLayout(); btn_bar.setContentsMargins(0, 4, 0, 0)
        self._fuzz_msg_btn = GlowButton("⚡  Fuzz This Message", color=C['accent_cyan'])
        self._fuzz_msg_btn.setEnabled(False)
        self._fuzz_msg_btn.setFixedHeight(32)
        self._fuzz_msg_btn.clicked.connect(self._launch_msg_fuzzer)
        btn_bar.addStretch()
        btn_bar.addWidget(self._fuzz_msg_btn)
        v.addLayout(btn_bar)
        return w

    # ── TAB 3: Signals ────────────────────────────────────────────────
    def _tab_signals(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(6,6,6,6)
        self._sig_banner = QLabel("Select a message to view its signals")
        self._sig_banner.setStyleSheet(
            f"color:{C['accent_yellow']}; font-size:11px; font-weight:600; "
            f"background:{C['bg_elevated']}; padding:6px 12px; "
            f"border-left:3px solid {C['accent_yellow']}; border-radius:3px;")
        v.addWidget(self._sig_banner)
        cols = ["Signal","Start","Len","Byte Order","Scale","Offset",
                "Min","Max","Unit","Signed","Receivers","Choices","Comment"]
        self._st = QTableWidget(0, len(cols))
        self._st.setHorizontalHeaderLabels(cols)
        self._st.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._st.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._st.setAlternatingRowColors(True)
        self._st.horizontalHeader().setStretchLastSection(True)
        self._st.verticalHeader().setVisible(False)
        self._st.setSortingEnabled(True)
        v.addWidget(self._st, 1)
        return w

    # ── TAB 4: Bit Layout ─────────────────────────────────────────────
    def _tab_bit_layout(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.setContentsMargins(6,6,6,6); v.setSpacing(6)
        self._bl_banner = QLabel("Select a message from the Messages tab")
        self._bl_banner.setStyleSheet(
            f"color:{C['text_secondary']}; font-size:10px; "
            f"background:{C['bg_elevated']}; padding:5px 14px; border-radius:3px;")
        v.addWidget(self._bl_banner)
        self._bit_w = BitLayoutWidget()
        sc = QScrollArea(); sc.setWidgetResizable(True); sc.setWidget(self._bit_w)
        sc.setStyleSheet(f"background:{C['bg_card']};")
        v.addWidget(sc, 3)
        lg = QGroupBox("Signal Legend")
        ll = QVBoxLayout(lg)
        self._legend = SignalLegend()
        ll.addWidget(self._legend)
        v.addWidget(lg)
        return w

    # ── TAB 5: Bus Load ───────────────────────────────────────────────
    def _tab_bus_load(self):
        sc = QScrollArea(); sc.setWidgetResizable(True)
        sc.setStyleSheet("background:transparent; border:none;")
        inner = QWidget(); v = QVBoxLayout(inner)
        v.setContentsMargins(14,14,14,14); v.setSpacing(14)
        s = self._stats

        # Bitrate selector
        br = QHBoxLayout()
        bl = QLabel("CAN Bitrate:")
        bl.setStyleSheet(f"color:{C['text_secondary']}; font-size:12px;")
        self._br = FCombo(["125 kbps","250 kbps","500 kbps","1000 kbps",
                           "2000 kbps (FD)","5000 kbps (FD)"], 2)
        self._br.setFixedWidth(160)
        self._br.currentIndexChanged.connect(self._refresh_gauge)
        br.addWidget(bl); br.addWidget(self._br); br.addStretch()
        v.addLayout(br)

        mid = QHBoxLayout(); mid.setSpacing(14)

        # Gauge container — fixed height, no nested layout swap needed
        self._gauge_frame = QFrame()
        self._gauge_frame.setStyleSheet(
            f"background:{C['bg_card']}; border:1px solid {C['border']}; border-radius:8px;")
        self._gauge_frame.setFixedHeight(200)
        self._gauge_vlay = QVBoxLayout(self._gauge_frame)
        self._gauge_vlay.setContentsMargins(8,8,8,8)
        self._gauge_widget = BusGauge(s['bus_load_500'], 500)
        self._gauge_vlay.addWidget(self._gauge_widget)
        self._gauge_info = QLabel()
        self._gauge_info.setAlignment(Qt.AlignCenter)
        self._gauge_info.setStyleSheet(
            f"color:{C['text_secondary']}; font-size:10px; padding:4px;")
        self._gauge_vlay.addWidget(self._gauge_info)
        mid.addWidget(self._gauge_frame, 2)

        cy_grp = QGroupBox("Cyclic Messages — Timing")
        cy_lay = QVBoxLayout(cy_grp)
        self._cyc_tbl = QTableWidget(0, 4)
        self._cyc_tbl.setHorizontalHeaderLabels(["Message","ID","Cycle (ms)","Bits/s Est."])
        self._cyc_tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._cyc_tbl.setAlternatingRowColors(True)
        self._cyc_tbl.horizontalHeader().setStretchLastSection(True)
        self._cyc_tbl.verticalHeader().setVisible(False)
        cy_lay.addWidget(self._cyc_tbl)
        mid.addWidget(cy_grp, 3)
        v.addLayout(mid)

        # Cycle time bar chart
        cyc = sorted([(m.name[:10], m.cycle_time, None)
                      for m in self._all if m.cycle_time], key=lambda x: x[1])[:20]
        if cyc:
            v.addWidget(BarChart("Cycle Times (ms) — Top 20 Cyclic Messages", cyc))
        v.addStretch()

        self._fill_cyc_table()
        self._refresh_gauge()
        sc.setWidget(inner)
        return sc

    # ── TAB 6: Consistency ────────────────────────────────────────────
    def _tab_consistency(self):
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(10,10,10,10); v.setSpacing(8)
        top = QHBoxLayout()
        lbl = QLabel("  Consistency Check — database integrity report")
        lbl.setStyleSheet(
            f"color:{C['accent_cyan']}; font-size:11px; font-weight:700; "
            f"background:{C['bg_elevated']}; padding:7px 14px; "
            f"border-left:3px solid {C['accent_cyan']}; border-radius:3px;")
        top.addWidget(lbl); top.addStretch()
        rb = SolidButton("↺  Re-run", C['accent_teal'])
        rb.setFixedWidth(90)
        top.addWidget(rb); v.addLayout(top)

        self._con_cards = QHBoxLayout(); v.addLayout(self._con_cards)

        cols = ["Level","Type","Object","Issue","Detail"]
        self._con_tbl = QTableWidget(0, len(cols))
        self._con_tbl.setHorizontalHeaderLabels(cols)
        self._con_tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._con_tbl.setAlternatingRowColors(True)
        self._con_tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._con_tbl.verticalHeader().setVisible(False)
        self._con_tbl.horizontalHeader().setStretchLastSection(True)
        self._con_tbl.setSortingEnabled(True)
        v.addWidget(self._con_tbl, 1)

        rb.clicked.connect(self._run_consistency)
        self._run_consistency()
        return w

    # ── TAB 7: Builder ────────────────────────────────────────────────
    def _tab_builder(self):
        return DBCBuilderWidget(self)

    # ── TAB 8: Compare ────────────────────────────────────────────────
    def _tab_diff(self):
        return DBCDiffWidget(self._db, self._dbc_path, self)

    # ── Data ──────────────────────────────────────────────────────────
    def _compute_stats(self):
        msgs = self._all
        sigs = sum(len(m.signals) for m in msgs)
        nodes = len(self._db.nodes) or len({s for m in msgs for s in (m.senders or [])})
        cyc  = sum(1 for m in msgs if m.cycle_time)
        dlc  = Counter(m.length for m in msgs)
        txd  = {}
        for m in msgs:
            for s in (m.senders or ["<none>"]):
                txd.setdefault(s, [0,0])
                txd[s][0] += 1; txd[s][1] += len(m.signals)
        txd = {k: tuple(v) for k, v in txd.items()}
        bps = sum(((m.length*8+47)*1000/m.cycle_time) for m in msgs if m.cycle_time)
        return dict(msg_count=len(msgs), sig_count=sigs, node_count=nodes,
                    cyclic=cyc, event=len(msgs)-cyc,
                    avg_sigs=sigs/max(len(msgs),1),
                    dlc_dist=dlc, tx_dist=txd,
                    bus_load_500=min(bps/500_000*100, 100.0), bps_total=bps)

    def _fill_tree(self):
        self._tree.clear()
        db = QTreeWidgetItem([f"📦  {os.path.basename(self._dbc_path)}"])
        db.setForeground(0, QBrush(qc(C['accent_cyan'])))
        db.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
        db.setData(0, Qt.UserRole, "all")
        self._tree.addTopLevelItem(db)

        mi = QTreeWidgetItem([f"📋  All Messages  ({len(self._all)})"])
        mi.setData(0, Qt.UserRole, "all")
        mi.setForeground(0, QBrush(qc(C['text_secondary']))); db.addChild(mi)

        nr = QTreeWidgetItem(["🔌  Network Nodes"])
        nr.setForeground(0, QBrush(qc(C['accent_purple']))); db.addChild(nr)

        nodes = sorted({n.name for n in self._db.nodes} |
                       {s for m in self._all for s in (m.senders or [])})
        for node in nodes:
            n_msgs = [m for m in self._all if node in (m.senders or [])]
            ni = QTreeWidgetItem([f"  {node}  ({len(n_msgs)})"])
            ni.setData(0, Qt.UserRole, ("node", node))
            ni.setForeground(0, QBrush(qc(C['text_primary']))); nr.addChild(ni)

        cr = QTreeWidgetItem(["🔄  Cyclic"]); cr.setData(0, Qt.UserRole, "cyclic")
        cr.setForeground(0, QBrush(qc(C['accent_yellow']))); db.addChild(cr)
        er = QTreeWidgetItem(["⚡  Event"]); er.setData(0, Qt.UserRole, "event")
        er.setForeground(0, QBrush(qc(C['accent_pink']))); db.addChild(er)

        db.setExpanded(True); nr.setExpanded(True)

    def _fill_msg_table(self, msgs=None):
        if msgs is None: msgs = self._filt
        t = self._mt; t.setSortingEnabled(False); t.setRowCount(0)
        for msg in msgs:
            r = t.rowCount(); t.insertRow(r)
            for c, txt in enumerate([
                msg.name,
                f"0x{msg.frame_id:04X}",
                str(msg.frame_id),
                str(msg.length),
                str(msg.cycle_time) if msg.cycle_time else "—",
                ", ".join(msg.senders) if msg.senders else "—",
                str(len(msg.signals)),
                msg.comment or "",
            ]):
                it = QTableWidgetItem(txt)
                it.setData(Qt.UserRole, msg)
                if c == 1:
                    it.setForeground(QBrush(qc(C['accent_cyan'])))
                    it.setFont(QFont("JetBrains Mono", 10))
                elif c == 5: it.setForeground(QBrush(qc(C['accent_yellow'])))
                elif c == 4 and msg.cycle_time:
                    it.setForeground(QBrush(qc(C['accent_green'])))
                t.setItem(r, c, it)
        t.setSortingEnabled(True)
        t.resizeColumnsToContents()
        self._update_stats()

    def _fill_sig_table(self, msg):
        t = self._st; t.setSortingEnabled(False); t.setRowCount(0)
        self._sig_banner.setText(
            f"  {msg.name}   │   ID: 0x{msg.frame_id:04X}   │   "
            f"DLC: {msg.length}B   │   {len(msg.signals)} signals   │   "
            f"TX: {', '.join(msg.senders) if msg.senders else '—'}")
        for i, sig in enumerate(sorted(msg.signals, key=lambda s: s.start)):
            r = t.rowCount(); t.insertRow(r)
            col = sp(i)
            choices = ""
            if sig.choices:
                choices = "  ".join(f"{k}={v}" for k,v in list(sig.choices.items())[:5])
                if len(sig.choices) > 5: choices += "…"
            for c, txt in enumerate([
                sig.name,
                str(sig.start), str(sig.length),
                "Intel LE" if sig.byte_order=='little_endian' else "Motorola BE",
                str(sig.scale), str(sig.offset),
                str(sig.minimum) if sig.minimum is not None else "—",
                str(sig.maximum) if sig.maximum is not None else "—",
                sig.unit or "—",
                "✓" if sig.is_signed else "—",
                ", ".join(sig.receivers) if sig.receivers else "—",
                choices, sig.comment or "",
            ]):
                it = QTableWidgetItem(txt)
                if c == 0:
                    it.setForeground(QBrush(qc(col)))
                    it.setFont(QFont("Segoe UI", 10, QFont.Bold))
                elif c == 3:
                    it.setForeground(QBrush(qc(
                        C['accent_cyan'] if 'Intel' in txt else C['accent_orange'])))
                t.setItem(r, c, it)
        t.setSortingEnabled(True); t.resizeColumnsToContents()

    def _fill_cyc_table(self):
        t = self._cyc_tbl; t.setRowCount(0)
        for msg in sorted((m for m in self._all if m.cycle_time), key=lambda m: m.cycle_time):
            bps_est = int((msg.length*8+47)*1000/msg.cycle_time)
            r = t.rowCount(); t.insertRow(r)
            for c, txt in enumerate([msg.name, f"0x{msg.frame_id:04X}",
                                      str(msg.cycle_time), f"{bps_est:,}"]):
                it = QTableWidgetItem(txt)
                if c==1: it.setForeground(QBrush(qc(C['accent_cyan'])))
                elif c==2: it.setForeground(QBrush(qc(C['accent_green'])))
                elif c==3: it.setForeground(QBrush(qc(C['accent_yellow'])))
                t.setItem(r, c, it)
        t.resizeColumnsToContents()

    def _refresh_gauge(self):
        kbps = int(self._br.currentText().split()[0])
        pct  = min(self._stats['bps_total'] / (kbps * 1000) * 100, 100.0)
        # Remove old gauge, insert new one at index 0
        old = self._gauge_widget
        self._gauge_widget = BusGauge(pct, kbps)
        lay = self._gauge_vlay
        lay.removeWidget(old); old.deleteLater()
        lay.insertWidget(0, self._gauge_widget)
        status = ("✅ Low load" if pct < 40 else "⚠️  Moderate" if pct < 70 else
                  "🔶 High" if pct < 90 else "🔴 Critical")
        self._gauge_info.setText(
            f"{status}   │   {self._stats['bps_total']/1000:.1f} kbps effective   │   "
            f"{self._stats['cyclic']} cyclic msgs")

    def _run_consistency(self):
        results = run_consistency(self._db, self._all)
        # Rebuild cards
        while self._con_cards.count():
            it = self._con_cards.takeAt(0)
            if it.widget(): it.widget().deleteLater()
        counts = Counter(r[0] for r in results)
        for level, count, col, icon in [
            ('error',   counts['error'],   C['accent_pink'],   '✖'),
            ('warning', counts['warning'], C['accent_yellow'], '⚠'),
            ('info',    counts['info'],    C['accent_cyan'],   'ℹ'),
        ]:
            f = QFrame()
            f.setStyleSheet(
                f"background:{C['bg_elevated']}; border:1px solid {col}44; "
                f"border-top:2px solid {col}; border-radius:6px;")
            fl = QVBoxLayout(f); fl.setSpacing(2)
            vl = QLabel(f"{icon}  {count}")
            vl.setStyleSheet(f"color:{col}; font-size:20px; font-weight:800; background:transparent;")
            vl.setAlignment(Qt.AlignCenter)
            tl = QLabel(level.title())
            tl.setStyleSheet(f"color:{C['text_muted']}; font-size:9px; background:transparent;")
            tl.setAlignment(Qt.AlignCenter)
            fl.addWidget(vl); fl.addWidget(tl)
            f.setFixedWidth(120); f.setFixedHeight(68)
            self._con_cards.addWidget(f)
        self._con_cards.addStretch()

        lc = {'error': C['accent_pink'], 'warning': C['accent_yellow'], 'info': C['accent_cyan']}
        icons = {'error':'✖ ','warning':'⚠ ','info':'ℹ '}
        t = self._con_tbl; t.setSortingEnabled(False); t.setRowCount(0)
        for level, obj_type, obj_name, issue, detail in results:
            r = t.rowCount(); t.insertRow(r)
            col = lc.get(level, C['text_primary'])
            for c, txt in enumerate([f"{icons.get(level,'')+level.upper()}",
                                     obj_type, obj_name, issue, detail]):
                it = QTableWidgetItem(txt)
                it.setForeground(QBrush(qc(col if c==0 else C['text_primary'])))
                if c==0: it.setFont(QFont("Segoe UI", 10, QFont.Bold))
                t.setItem(r, c, it)
        t.setSortingEnabled(True); t.resizeColumnsToContents()

    # ── Filter ────────────────────────────────────────────────────────
    def _apply_filter(self):
        text = self._search.text().strip().lower()
        tx   = self._tx_combo.currentText()
        res  = self._all
        if tx and tx != "All transmitters":
            res = [m for m in res if tx in (m.senders or [])]
        if text:
            res = [m for m in res
                   if text in m.name.lower()
                   or text in f"0x{m.frame_id:x}"
                   or any(text in s.name.lower() for s in m.signals)]
        self._filt = res
        self._fill_msg_table(res)

    # ── Events ────────────────────────────────────────────────────────
    def _on_msg_select(self):
        rows = self._mt.selectionModel().selectedRows()
        if not rows:
            self._fuzz_msg_btn.setEnabled(False)
            return
        it = self._mt.item(rows[0].row(), 0)
        if not it:
            self._fuzz_msg_btn.setEnabled(False)
            return
        msg = it.data(Qt.UserRole)
        if not msg:
            self._fuzz_msg_btn.setEnabled(False)
            return
        self._cur = msg
        self._fuzz_msg_btn.setEnabled(True)
        self._fill_sig_table(msg)
        self._bit_w.set_message(msg)
        self._legend.set_signals(msg.signals)
        self._bl_banner.setText(
            f"  {msg.name}   ID: 0x{msg.frame_id:04X}   "
            f"DLC: {msg.length}B   {len(msg.signals)} signals")

    # ── DBC-inline fuzzer dialog ──────────────────────────────────────

    # ── DBC-aware pattern generation helpers ──────────────────────────

    @staticmethod
    def _dbc_signal_bytes(msg, sig):
        """Return set of byte indices occupied by a signal via test encoding."""
        try:
            base = {s.name: (s.offset or 0) for s in msg.signals}
            data_z = msg.encode(base)
            test = dict(base)
            max_raw = (1 << sig.length) - 1
            test[sig.name] = max_raw * (sig.scale or 1) + (sig.offset or 0)
            data_m = msg.encode(test)
            return {i for i in range(len(data_z)) if data_z[i] != data_m[i]}
        except Exception:
            # Fallback: derive from start bit (little-endian assumption)
            positions = set()
            for bit in range(sig.start, sig.start + sig.length):
                positions.add(bit // 8)
            return {p for p in positions if p < msg.length}

    @staticmethod
    def _dbc_bruteforce_pattern(msg, selected_sigs=None):
        """Build hex pattern with '..' on signal bytes, '00' on non-signal bytes."""
        dlc = msg.length
        if not msg.signals:
            return '..' * dlc

        occupied = set()
        sigs = selected_sigs if selected_sigs else list(msg.signals)
        for sig in sigs:
            try:
                base = {s.name: (s.offset or 0) for s in msg.signals}
                data_z = msg.encode(base)
                test = dict(base)
                max_raw = (1 << sig.length) - 1
                test[sig.name] = max_raw * (sig.scale or 1) + (sig.offset or 0)
                data_m = msg.encode(test)
                for i in range(len(data_z)):
                    if data_z[i] != data_m[i]:
                        occupied.add(i)
            except Exception:
                for bit in range(sig.start, sig.start + sig.length):
                    b = bit // 8
                    if b < dlc:
                        occupied.add(b)

        if not occupied:
            occupied = set(range(dlc))

        return ''.join('..' if b in occupied else '00' for b in range(dlc))

    @staticmethod
    def _dbc_boundary_corpus(msg, selected_sigs=None):
        """Generate hex base-pattern strings from signal boundary values."""
        patterns = []
        dlc = msg.length
        sigs = selected_sigs if selected_sigs else list(msg.signals)

        # ── Baselines ────────────────────────────────────────────────
        patterns.append('00' * dlc)
        patterns.append('ff' * dlc)

        # ── Encoded baselines ────────────────────────────────────────
        try:
            base = {s.name: (s.offset or 0) for s in msg.signals}
            patterns.append(msg.encode(base).hex())
            # All signals at raw-max
            max_vals = {}
            for s in msg.signals:
                max_raw = (1 << s.length) - 1
                max_vals[s.name] = max_raw * (s.scale or 1) + (s.offset or 0)
            patterns.append(msg.encode(max_vals).hex())
        except Exception:
            pass

        # ── Per-signal boundary testing ──────────────────────────────
        try:
            base = {s.name: (s.offset or 0) for s in msg.signals}
        except Exception:
            base = {}

        for sig in sigs:
            max_raw = (1 << sig.length) - 1
            scale = sig.scale if sig.scale else 1
            offset = sig.offset if sig.offset else 0

            test_raws = {0, 1, 2, max_raw, max_raw - 1, max_raw // 2}

            # Physical min/max → raw boundaries
            if sig.minimum is not None and scale != 0:
                try:
                    r = int((sig.minimum - offset) / scale)
                    test_raws.update([r, max(0, r - 1), r + 1])
                except Exception:
                    pass
            if sig.maximum is not None and scale != 0:
                try:
                    r = int((sig.maximum - offset) / scale)
                    test_raws.update([r, max(0, r - 1), r + 1])
                except Exception:
                    pass

            # Interesting bit patterns
            if sig.length >= 8:
                test_raws.add(0x55 & max_raw)   # 01010101…
                test_raws.add(0xAA & max_raw)   # 10101010…
            if sig.length >= 16:
                test_raws.add(0xDEAD & max_raw)
                test_raws.add(0x7FFF & max_raw)

            for raw_val in test_raws:
                try:
                    vals = dict(base)
                    vals[sig.name] = raw_val * scale + offset
                    data = msg.encode(vals)
                    h = data.hex()
                    if h not in patterns:
                        patterns.append(h)
                except Exception:
                    pass

        # Deduplicate while preserving order
        seen, unique = set(), []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique if unique else ['00' * dlc]

    # ── Main fuzzer dialog ────────────────────────────────────────────

    def _launch_msg_fuzzer(self):
        if not self._cur:
            return
        msg    = self._cur
        sender = msg.senders[0] if msg.senders else "Unknown"
        can_id = msg.frame_id
        dlc    = msg.length

        import threading, time as _time, random as _random
        from PyQt5.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
            QTextEdit, QPushButton, QLabel, QGroupBox, QCheckBox,
            QScrollArea, QWidget
        )
        from PyQt5.QtCore  import QObject, pyqtSignal
        from ui.widgets    import GlowButton, SolidButton

        # ── Signal bridge (thread → Qt) ───────────────────────────────
        class _Bridge(QObject):
            line  = pyqtSignal(str)
            err   = pyqtSignal(str)
            done  = pyqtSignal()

        bridge      = _Bridge()
        stop_event  = threading.Event()
        fuzz_thread = [None]

        # ── Dialog ────────────────────────────────────────────────────
        dlg = QDialog(self)
        dlg.setWindowTitle(
            f"Fuzz  —  {msg.name}   (ECU: {sender})   ID: 0x{can_id:X}")
        dlg.setMinimumWidth(620)
        dlg.setMinimumHeight(680)
        dlg.setStyleSheet(f"""
            QDialog        {{ background:{C['bg_primary']}; color:{C['text_primary']}; }}
            QGroupBox      {{ color:{C['text_secondary']}; font-size:11px; font-weight:600;
                              border:1px solid {C['border']}; border-radius:6px;
                              margin-top:14px; padding-top:8px; }}
            QGroupBox::title {{ subcontrol-origin:margin; left:10px; top:2px; }}
            QLabel         {{ background:transparent; color:{C['text_primary']}; font-size:11px; }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                background:{C['bg_input']}; border:1px solid {C['border']};
                border-radius:5px; padding:5px 8px; color:{C['text_primary']}; font-size:11px; }}
            QTextEdit      {{ background:#0d1117; border:1px solid {C['border']};
                              border-radius:4px; color:#c9d1d9; font-family:Consolas,monospace;
                              font-size:11px; }}
            QPushButton    {{ background:{C['bg_elevated']}; border:1px solid {C['border']};
                              border-radius:5px; padding:6px 14px; color:{C['text_primary']};
                              font-size:11px; }}
            QPushButton:hover {{ background:{C['bg_card']}; }}
            QCheckBox      {{ color:{C['text_primary']}; font-size:11px; spacing:6px; }}
            QCheckBox::indicator {{ width:14px; height:14px; border:1px solid {C['border']};
                                   border-radius:3px; background:{C['bg_input']}; }}
            QCheckBox::indicator:checked {{ background:{C['accent_cyan']};
                                           border-color:{C['accent_cyan']}; }}
        """)

        root = QVBoxLayout(dlg); root.setSpacing(8); root.setContentsMargins(12,12,12,12)

        # ── Info banner ───────────────────────────────────────────────
        info = QLabel(
            f"  Message: <b>{msg.name}</b>   │   "
            f"ID: <b>0x{can_id:X}</b>   │   "
            f"DLC: <b>{dlc}</b> B   │   "
            f"ECU / Sender: <b>{sender}</b>")
        info.setStyleSheet(
            f"color:{C['accent_cyan']}; font-size:11px; font-weight:600;"
            f"background:{C['bg_elevated']}; padding:7px 12px;"
            f"border-left:3px solid {C['accent_cyan']}; border-radius:3px;")
        root.addWidget(info)

        # ── Config group ──────────────────────────────────────────────
        cfg_grp = QGroupBox("Fuzzer Config")
        form    = QFormLayout(cfg_grp); form.setSpacing(6)

        iface_edit  = QLineEdit("vcan0")
        mode_combo  = QComboBox()
        mode_combo.addItems(["random", "bruteforce", "mutate", "boundary", "bitflip"])
        count_spin  = QSpinBox();  count_spin.setRange(1, 100000); count_spin.setValue(100)
        delay_spin  = QDoubleSpinBox()
        delay_spin.setRange(0.1, 5000.0); delay_spin.setValue(10.0); delay_spin.setSuffix(" ms")

        form.addRow("Interface:",   iface_edit)
        form.addRow("Fuzz Mode:",   mode_combo)
        form.addRow("Frame Count:", count_spin)
        form.addRow("Delay:",       delay_spin)
        root.addWidget(cfg_grp)

        # ── Signal targeting group ────────────────────────────────────
        sig_grp  = QGroupBox(f"Signal Targeting  ({len(msg.signals)} signals)")
        sig_lay  = QVBoxLayout(sig_grp); sig_lay.setSpacing(4)
        sig_checks = []

        if msg.signals:
            select_all_cb = QCheckBox("Select / Deselect All")
            select_all_cb.setChecked(True)
            sig_lay.addWidget(select_all_cb)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setMaximumHeight(110)
            scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
            scroll_w = QWidget()
            scroll_l = QVBoxLayout(scroll_w)
            scroll_l.setSpacing(2)
            scroll_l.setContentsMargins(16, 4, 4, 4)

            for sig in sorted(msg.signals, key=lambda s: s.start):
                order = "LE" if sig.byte_order == 'little_endian' else "BE"
                rng = ""
                if sig.minimum is not None and sig.maximum is not None:
                    rng = f"  [{sig.minimum}..{sig.maximum}]"
                elif sig.length:
                    rng = f"  [0..{(1 << sig.length) - 1}]"

                cb = QCheckBox(
                    f"{sig.name}   (bit {sig.start}, {sig.length}b, {order}){rng}")
                cb.setChecked(True)
                cb._sig_ref = sig          # store reference for later retrieval
                sig_checks.append(cb)
                scroll_l.addWidget(cb)

            scroll_l.addStretch()
            scroll.setWidget(scroll_w)
            sig_lay.addWidget(scroll)

            def _toggle_all(state):
                for _cb in sig_checks:
                    _cb.setChecked(state == Qt.Checked)
            select_all_cb.stateChanged.connect(_toggle_all)
        else:
            sig_lay.addWidget(QLabel("  No signals defined in this message"))

        root.addWidget(sig_grp)

        # ── Pattern / preset group ────────────────────────────────────
        pat_grp = QGroupBox("Pattern / Seed Corpus")
        pat_lay = QVBoxLayout(pat_grp); pat_lay.setSpacing(4)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Preset:"))
        preset_combo = QComboBox()
        preset_combo.addItems([
            "Auto (DBC-aware)", "All wildcards (..) ",
            "All zeros", "All 0xFF", "Counter sweep", "Custom"])
        preset_row.addWidget(preset_combo)
        pat_lay.addLayout(preset_row)

        initial_pattern = self._dbc_bruteforce_pattern(msg)
        pattern_edit = QLineEdit(initial_pattern)
        pattern_edit.setPlaceholderText(
            "Hex pattern: 12ab..78  ('..'=wildcard per byte)")
        pattern_edit.setFont(QFont("Consolas", 10))
        pat_lay.addWidget(pattern_edit)

        initial_corpus = self._dbc_boundary_corpus(msg)
        corpus_lbl = QLabel(
            f"  ✓ Seed corpus: {len(initial_corpus)} boundary patterns "
            f"auto-generated from DBC")
        corpus_lbl.setStyleSheet(
            f"color:{C['accent_green']}; font-size:10px;")
        pat_lay.addWidget(corpus_lbl)

        root.addWidget(pat_grp)

        # ── Refresh pattern / corpus on signal or preset change ───────
        def _get_selected_sigs():
            sel = [cb._sig_ref for cb in sig_checks if cb.isChecked()]
            return sel if sel else None

        def _refresh_pattern(*_args):
            preset = preset_combo.currentText()
            sel    = _get_selected_sigs()
            if "Auto" in preset:
                pattern_edit.setText(
                    self._dbc_bruteforce_pattern(msg, sel))
            elif "wildcards" in preset:
                pattern_edit.setText('..' * dlc)
            elif "zeros" in preset:
                pattern_edit.setText('00' * dlc)
            elif "0xFF" in preset:
                pattern_edit.setText('ff' * dlc)
            elif "Counter" in preset:
                pattern_edit.setText('00' * max(dlc - 1, 0) + '..')
            # 'Custom' → don't touch

            corpus = self._dbc_boundary_corpus(msg, sel)
            corpus_lbl.setText(
                f"  ✓ Seed corpus: {len(corpus)} boundary patterns "
                f"auto-generated from DBC")

        preset_combo.currentTextChanged.connect(_refresh_pattern)
        for _cb in sig_checks:
            _cb.stateChanged.connect(_refresh_pattern)

        # ── Terminal output ───────────────────────────────────────────
        terminal = QTextEdit()
        terminal.setReadOnly(True)
        terminal.setMinimumHeight(160)
        root.addWidget(terminal)

        # ── Buttons ───────────────────────────────────────────────────
        btn_row   = QHBoxLayout()
        start_btn = GlowButton("▶  Start Fuzzing", color=C['accent_cyan'])
        stop_btn  = GlowButton(
            "■  Stop",
            color=C['accent_red'] if 'accent_red' in C else '#f43f5e')
        close_btn = QPushButton("Close")
        stop_btn.setEnabled(False)
        btn_row.addWidget(start_btn); btn_row.addWidget(stop_btn)
        btn_row.addStretch(); btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

        # ── Wire bridge signals ───────────────────────────────────────
        bridge.line.connect(
            lambda t: terminal.append(
                f'<span style="color:#c9d1d9">{t}</span>'),
            type=Qt.QueuedConnection)
        bridge.err.connect(
            lambda t: terminal.append(
                f'<span style="color:#f85149">{t}</span>'),
            type=Qt.QueuedConnection)
        bridge.done.connect(
            lambda: (start_btn.setEnabled(True),
                     stop_btn.setEnabled(False),
                     terminal.append(
                         '<span style="color:#3fb950">[DONE]</span>')),
            type=Qt.QueuedConnection)

        # ── Boundary-value inline fuzzer ──────────────────────────────
        def _run_boundary_fuzz(iface, delay, count, sel_sigs, stop_ev, status_cb):
            """Send exact boundary-value frames derived from DBC signals."""
            from utils.can_interface import check_interface, NonBlockingCANSender

            def _worker():
                status = check_interface(iface)
                if not status.ok:
                    bridge.err.emit(f"[ERROR] {status.user_message()}")
                    bridge.done.emit()
                    return

                corpus = self._dbc_boundary_corpus(msg, sel_sigs)
                status_cb(f"[START] BoundaryFuzzer  iface={iface}  "
                          f"id=0x{can_id:X}  corpus={len(corpus)} frames")

                sent = errors = frame_n = 0
                with NonBlockingCANSender(iface) as snd:
                    ok, err = snd.open()
                    if not ok:
                        bridge.err.emit(f"[ERROR] {err}")
                        bridge.done.emit()
                        return
                    while frame_n < count and not stop_ev.is_set():
                        pat  = corpus[frame_n % len(corpus)]
                        data = bytes.fromhex(pat)
                        tx_ok, tx_err = snd.send_frame(can_id, data)
                        if tx_ok:
                            sent += 1
                            status_cb(
                                f"[TX] 0x{can_id:03X}#"
                                f"{data.hex().upper()}  sent  "
                                f"(boundary {frame_n+1}/"
                                f"{min(count, len(corpus))})")
                        else:
                            errors += 1
                            bridge.err.emit(
                                f"[TX] 0x{can_id:03X}#"
                                f"{data.hex().upper()}  error:{tx_err}")
                        frame_n += 1
                        if delay > 0:
                            end = _time.time() + delay
                            while (_time.time() < end
                                   and not stop_ev.is_set()):
                                _time.sleep(
                                    min(0.005, end - _time.time()))
                status_cb(f"[DONE] sent={sent} errors={errors}")
                bridge.done.emit()

            t = threading.Thread(target=_worker, daemon=True)
            t.start()
            fuzz_thread[0] = t

        # ── Bit-flip inline fuzzer ────────────────────────────────────
        def _run_bitflip_fuzz(iface, delay, sel_sigs, stop_ev, status_cb):
            """Flip each bit one at a time to find single-bit-sensitive ECU logic."""
            from utils.can_interface import check_interface, NonBlockingCANSender

            def _worker():
                status = check_interface(iface)
                if not status.ok:
                    bridge.err.emit(f"[ERROR] {status.user_message()}")
                    bridge.done.emit()
                    return

                # Build baseline frame
                try:
                    base_v = {s.name: (s.offset or 0)
                              for s in msg.signals}
                    baseline = bytearray(msg.encode(base_v))
                except Exception:
                    baseline = bytearray(dlc)

                # Determine which bits to flip
                bits = []
                if sel_sigs:
                    for sig in sel_sigs:
                        byte_set = self._dbc_signal_bytes(msg, sig)
                        for by in sorted(byte_set):
                            bits.extend(by * 8 + b for b in range(8))
                else:
                    bits = list(range(dlc * 8))

                bits = sorted(set(b for b in bits if b // 8 < dlc))
                total = len(bits)
                status_cb(f"[START] BitflipFuzzer  iface={iface}  "
                          f"id=0x{can_id:X}  bits={total}")

                sent = errors = 0
                with NonBlockingCANSender(iface) as snd:
                    ok, err = snd.open()
                    if not ok:
                        bridge.err.emit(f"[ERROR] {err}")
                        bridge.done.emit()
                        return
                    for bit_idx in bits:
                        if stop_ev.is_set():
                            break
                        byte_pos = bit_idx // 8
                        bit_in   = bit_idx % 8
                        frame = bytearray(baseline)
                        frame[byte_pos] ^= (1 << bit_in)
                        data = bytes(frame)
                        tx_ok, tx_err = snd.send_frame(can_id, data)
                        if tx_ok:
                            sent += 1
                            status_cb(
                                f"[TX] 0x{can_id:03X}#"
                                f"{data.hex().upper()}  "
                                f"bit {bit_idx} "
                                f"(byte{byte_pos}.{bit_in})  "
                                f"[{sent}/{total}]")
                        else:
                            errors += 1
                            bridge.err.emit(
                                f"[TX ERR] bit {bit_idx}: {tx_err}")
                        if delay > 0:
                            end = _time.time() + delay
                            while (_time.time() < end
                                   and not stop_ev.is_set()):
                                _time.sleep(
                                    min(0.005, end - _time.time()))
                status_cb(f"[DONE] sent={sent} errors={errors}  "
                          f"({total} bits tested)")
                bridge.done.emit()

            t = threading.Thread(target=_worker, daemon=True)
            t.start()
            fuzz_thread[0] = t

        # ── Start handler ─────────────────────────────────────────────
        def _start():
            if fuzz_thread[0] and fuzz_thread[0].is_alive():
                terminal.append(
                    '<span style="color:#f85149">'
                    '[WARN] Already running.</span>')
                return
            stop_event.clear()
            iface = iface_edit.text().strip() or "vcan0"
            mode  = mode_combo.currentText()
            count = count_spin.value()
            delay = delay_spin.value() / 1000.0   # ms → seconds
            sel   = _get_selected_sigs()

            def cb(line: str):
                if "[ERROR]" in line:
                    bridge.err.emit(line)
                else:
                    bridge.line.emit(line)

            # ── Boundary / bitflip — custom inline fuzzers ────────────
            if mode == "boundary":
                start_btn.setEnabled(False); stop_btn.setEnabled(True)
                terminal.append(
                    f'<span style="color:#58a6ff">'
                    f'[START] boundary → 0x{can_id:X}  '
                    f'iface={iface}  delay={delay*1000:.1f}ms</span>')
                _run_boundary_fuzz(
                    iface, delay, count, sel, stop_event, cb)
                return

            if mode == "bitflip":
                start_btn.setEnabled(False); stop_btn.setEnabled(True)
                terminal.append(
                    f'<span style="color:#58a6ff">'
                    f'[START] bitflip → 0x{can_id:X}  '
                    f'iface={iface}  bits={dlc*8}  '
                    f'delay={delay*1000:.1f}ms</span>')
                _run_bitflip_fuzz(
                    iface, delay, sel, stop_event, cb)
                return

            # ── Standard engine-backed modes ──────────────────────────
            try:
                from utils.fuzzer_engine import (
                    RandomFuzzer, BruteforceFuzzer, MutateFuzzer)

                if mode == "random":
                    fuzzer = RandomFuzzer(
                        iface=iface, can_id=can_id,
                        min_dlc=dlc, max_dlc=dlc,
                        delay=delay, max_frames=count,
                        timeout=600.0, seed=None,
                        stop_event=stop_event,
                        status_cb=cb, log_path=None)

                elif mode == "bruteforce":
                    pattern = pattern_edit.text().strip()
                    if not pattern:
                        pattern = self._dbc_bruteforce_pattern(msg, sel)
                        pattern_edit.setText(pattern)
                    terminal.append(
                        f'<span style="color:#58a6ff">'
                        f'[INFO] Bruteforce pattern: '
                        f'{pattern}</span>')
                    fuzzer = BruteforceFuzzer(
                        iface=iface, can_id=can_id,
                        pattern=pattern, delay=delay,
                        timeout=600.0,
                        stop_event=stop_event, status_cb=cb)

                elif mode == "mutate":
                    corpus = self._dbc_boundary_corpus(msg, sel)
                    terminal.append(
                        f'<span style="color:#58a6ff">'
                        f'[INFO] Auto-generated {len(corpus)} seed '
                        f'patterns from DBC signal definitions'
                        f'</span>')
                    for i, p in enumerate(corpus[:5]):
                        terminal.append(
                            f'<span style="color:#8b949e">'
                            f'  seed[{i}]: {p}</span>')
                    if len(corpus) > 5:
                        terminal.append(
                            f'<span style="color:#8b949e">'
                            f'  … +{len(corpus)-5} more</span>')
                    fuzzer = MutateFuzzer(
                        iface=iface, can_id=can_id,
                        base_patterns=corpus,
                        mutation_rate=0.15,
                        delay=delay, max_frames=count,
                        timeout=600.0,
                        stop_event=stop_event, status_cb=cb)
                else:
                    return

            except Exception as exc:
                terminal.append(
                    f'<span style="color:#f85149">'
                    f'[ERROR] {exc}</span>')
                return

            start_btn.setEnabled(False); stop_btn.setEnabled(True)
            terminal.append(
                f'<span style="color:#58a6ff">[START] {mode} → '
                f'0x{can_id:X}  iface={iface}  count={count}  '
                f'delay={delay*1000:.1f}ms</span>')

            t = fuzzer.start_in_thread()
            fuzz_thread[0] = t

            def _watch():
                t.join()
                bridge.done.emit()
            threading.Thread(target=_watch, daemon=True).start()

        def _stop():
            stop_event.set()
            terminal.append(
                '<span style="color:#d29922">'
                '[STOP] Signal sent…</span>')
            stop_btn.setEnabled(False)

        start_btn.clicked.connect(_start)
        stop_btn.clicked.connect(_stop)
        close_btn.clicked.connect(dlg.accept)

        dlg.exec_()

    def _on_node_click(self, item, col):
        d = item.data(0, Qt.UserRole)
        if d == "all" or d is None:
            self._filt = list(self._all)
        elif d == "cyclic":
            self._filt = [m for m in self._all if m.cycle_time]
        elif d == "event":
            self._filt = [m for m in self._all if not m.cycle_time]
        elif isinstance(d, tuple) and d[0] == "node":
            nd = d[1]
            self._filt = [m for m in self._all if nd in (m.senders or [])]
        else:
            self._filt = list(self._all)
        self._fill_msg_table(self._filt)
        self._tabs.setCurrentIndex(1)

    def _update_stats(self):
        msgs = self._filt
        sigs = sum(len(m.signals) for m in msgs)
        nds  = {s for m in msgs for s in (m.senders or [])}
        mdlc = max((m.length for m in msgs), default=0)
        self._kv["Messages"].setText(str(len(msgs)))
        self._kv["Signals"].setText(str(sigs))
        self._kv["Nodes"].setText(str(len(nds)))
        self._kv["Max DLC"].setText(str(mdlc))
        s = self._stats
        self._status.setText(
            f"  {os.path.basename(self._dbc_path)}   │   "
            f"Showing {len(msgs)}/{s['msg_count']} messages   │   "
            f"{s['sig_count']} signals   │   {s['node_count']} nodes   │   "
            f"Bus load @ 500kbps: {s['bus_load_500']:.1f}%")

    # ── Export CSV ────────────────────────────────────────────────────
    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if not path: return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Message","ID_hex","ID_dec","DLC","CycleTime_ms","Transmitter",
                             "Signal","StartBit","Length","ByteOrder","Scale","Offset",
                             "Min","Max","Unit","Signed","Receivers","Comment"])
                for msg in self._filt:
                    snd = ", ".join(msg.senders or [])
                    if msg.signals:
                        for sig in msg.signals:
                            w.writerow([msg.name, f"0x{msg.frame_id:04X}", msg.frame_id,
                                        msg.length, msg.cycle_time or "", snd,
                                        sig.name, sig.start, sig.length, sig.byte_order,
                                        sig.scale, sig.offset, sig.minimum, sig.maximum,
                                        sig.unit or "", sig.is_signed,
                                        ",".join(sig.receivers or []), sig.comment or ""])
                    else:
                        w.writerow([msg.name, f"0x{msg.frame_id:04X}", msg.frame_id,
                                    msg.length, msg.cycle_time or "", snd,
                                    *[""] * 12])
            QMessageBox.information(self, "Export Complete", f"Saved to:\n{path}")
        except Exception as ex:
            QMessageBox.critical(self, "Export Error", str(ex))
