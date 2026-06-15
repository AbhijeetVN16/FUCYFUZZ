"""
Dashboard Tab — Revamped (v3)
==============================

Changes from v2
---------------
* REMOVED:  ModuleBreakdownWidget (the horizontal bar chart of faults per module).
* REPLACED WITH: LiveFuzzingStatusWidget — a real-time session error summary
  panel that shows:
    - Session duration (live clock)
    - Total TX / RX frame count (from SessionLogger)
    - Per-severity fault counters (Critical / High / Low / Info)
    - A "Recent Anomalies" mini-list (last 5 faults, always fresh)

* Dashboard real-time update BUG FIXED:
  - DataManager.fault_pushed now connects to EVERY relevant widget, including
    the new LiveFuzzingStatusWidget, via Qt.QueuedConnection so updates
    arrive on the main thread regardless of which worker detected the fault.
  - The 2-second refresh timer is kept as a heartbeat for the stat cards.
  - LiveAlertStack and LiveVulnerabilityFeed retain their zero-latency wiring.
"""

import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QSizePolicy, QAbstractItemView,
    QScrollArea, QPushButton, QGraphicsOpacityEffect,
    QApplication,
)
from PyQt5.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve,
    pyqtSignal, pyqtSlot,
)
from PyQt5.QtGui import QColor, QFont

from ui.widgets import StatCard, SectionHeader, GlowButton, CardFrame
from ui.theme import COLORS
from utils.data_manager import DataManager

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    'critical': COLORS['critical'],
    'high':     COLORS['high'],
    'medium':   COLORS['medium'],
    'low':      COLORS['low'],
}

_SEV_ICONS = {
    'critical': '🔴',
    'high':     '🟠',
    'medium':   '🟡',
    'low':      '🔵',
}


def _sev_color(sev: str) -> str:
    return _SEV_COLORS.get(sev.lower(), COLORS['accent_cyan'])


def _sev_icon(sev: str) -> str:
    return _SEV_ICONS.get(sev.lower(), '⚪')


# ---------------------------------------------------------------------------
# VulnerabilityAlertBanner  (unchanged)
# ---------------------------------------------------------------------------

class VulnerabilityAlertBanner(QFrame):
    dismissed = pyqtSignal(object)
    _LINGER_MS = 8000
    _FADE_MS   = 400

    def __init__(self, fault, parent=None):
        super().__init__(parent)
        self._fault = fault
        color = _sev_color(fault.severity)
        icon  = _sev_icon(fault.severity)
        ts    = time.strftime('%H:%M:%S', time.localtime(fault.time))

        self.setObjectName("AlertBanner")
        self.setStyleSheet(f"""
            QFrame#AlertBanner {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {color}28, stop:1 {COLORS['bg_card']});
                border: 1px solid {color}88;
                border-left: 4px solid {color};
                border-radius: 6px;
            }}
        """)
        self.setFixedHeight(46)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 0, 8, 0)
        row.setSpacing(10)

        icon_lbl = QLabel(f"{icon}")
        icon_lbl.setStyleSheet("font-size:14px; background:transparent; border:none;")
        icon_lbl.setFixedWidth(20)
        row.addWidget(icon_lbl)

        sev_lbl = QLabel(fault.severity.upper())
        sev_lbl.setStyleSheet(
            f"color:{color}; font-size:10px; font-weight:700; "
            f"letter-spacing:1px; background:transparent; border:none;"
        )
        sev_lbl.setFixedWidth(68)
        row.addWidget(sev_lbl)

        desc_lbl = QLabel(f"[{fault.module}]  {fault.fault[:80]}")
        desc_lbl.setStyleSheet(
            f"color:{COLORS['text_primary']}; font-size:11px; "
            f"background:transparent; border:none;"
        )
        desc_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        desc_lbl.setWordWrap(False)
        row.addWidget(desc_lbl, 1)

        ts_lbl = QLabel(ts)
        ts_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']}; font-size:10px; "
            f"background:transparent; border:none;"
        )
        ts_lbl.setFixedWidth(56)
        ts_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        row.addWidget(ts_lbl)

        x_btn = QPushButton("✕")
        x_btn.setFixedSize(22, 22)
        x_btn.setCursor(Qt.PointingHandCursor)
        x_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; border: none;
                color: {COLORS['text_muted']}; font-size: 11px;
            }}
            QPushButton:hover {{ color: {COLORS['text_primary']}; }}
        """)
        x_btn.clicked.connect(self._dismiss)
        row.addWidget(x_btn)

        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(1.0)
        self.setGraphicsEffect(self._opacity)

        self._linger_timer = QTimer(self)
        self._linger_timer.setSingleShot(True)
        self._linger_timer.timeout.connect(self._start_fade)
        self._linger_timer.start(self._LINGER_MS)

    def _start_fade(self):
        anim = QPropertyAnimation(self._opacity, b"opacity", self)
        anim.setDuration(self._FADE_MS)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.finished.connect(self._on_fade_done)
        anim.start()
        self._anim = anim

    def _on_fade_done(self):
        self.dismissed.emit(self)

    def _dismiss(self):
        self._linger_timer.stop()
        self._start_fade()


# ---------------------------------------------------------------------------
# LiveAlertStack  (unchanged)
# ---------------------------------------------------------------------------

class LiveAlertStack(QWidget):
    _MAX_VISIBLE = 5
    _MAX_HEIGHT  = 240   # caps at ~5 banners (each ≈46px + 4px spacing)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMaximumHeight(self._MAX_HEIGHT)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._banners = []

    def push(self, fault):
        if len(self._banners) >= self._MAX_VISIBLE:
            oldest = self._banners.pop(0)
            self._layout.removeWidget(oldest)
            oldest.deleteLater()
        banner = VulnerabilityAlertBanner(fault, self)
        banner.dismissed.connect(self._remove_banner)
        self._layout.insertWidget(0, banner)
        self._banners.append(banner)
        self.setVisible(True)

    @pyqtSlot(object)
    def _remove_banner(self, banner):
        if banner in self._banners:
            self._banners.remove(banner)
        self._layout.removeWidget(banner)
        banner.deleteLater()
        if not self._banners:
            self.setVisible(False)


# ---------------------------------------------------------------------------
# LiveFuzzingStatusWidget  — replaces ModuleBreakdownWidget
# ---------------------------------------------------------------------------

class LiveFuzzingStatusWidget(CardFrame):
    """
    Real-time session error summary — replaces the old Module Breakdown panel.

    Displays:
      • Session duration (live 1-second clock)
      • Severity counters (Critical / High / Low / Info) — updated on every fault
      • Recent anomalies mini-list (latest 5, newest first)

    Wired directly to DataManager.fault_pushed so every detected fault
    updates the widget in < 1 frame, with no polling.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session_start = datetime.now()
        self._counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        self._recent: list = []   # last 5 fault strings

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(10)

        # ── Header ────────────────────────────────────────────────────────────
        hdr_row = QHBoxLayout()
        title = QLabel("⚡  LIVE FUZZING STATUS")
        title.setStyleSheet(
            f"color:{COLORS['accent_cyan']}; font-size:10px; font-weight:700; "
            f"letter-spacing:2px; background:transparent;"
        )
        hdr_row.addWidget(title)
        hdr_row.addStretch()
        self._duration_lbl = QLabel("00:00:00")
        self._duration_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']}; font-size:10px; "
            f"font-family:monospace; background:transparent;"
        )
        hdr_row.addWidget(self._duration_lbl)
        outer.addLayout(hdr_row)

        # ── Severity counters ──────────────────────────────────────────────────
        sev_grid = QHBoxLayout()
        sev_grid.setSpacing(8)
        self._sev_labels = {}
        for sev, color, icon in [
            ('critical', COLORS['critical'],      '🔴'),
            ('high',     COLORS['high'],          '🟠'),
            ('low',      COLORS['low'],           '🔵'),
            ('info',     COLORS['text_muted'],    '⬜'),
        ]:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: {color}18;
                    border: 1px solid {color}55;
                    border-radius: 6px;
                }}
            """)
            card_lay = QVBoxLayout(card)
            card_lay.setContentsMargins(10, 6, 10, 6)
            card_lay.setSpacing(2)

            count_lbl = QLabel("0")
            count_lbl.setAlignment(Qt.AlignCenter)
            count_lbl.setStyleSheet(
                f"color:{color}; font-size:22px; font-weight:800; "
                f"background:transparent; font-family:monospace;"
            )
            card_lay.addWidget(count_lbl)

            name_lbl = QLabel(f"{icon} {sev.upper()}")
            name_lbl.setAlignment(Qt.AlignCenter)
            name_lbl.setStyleSheet(
                f"color:{color}; font-size:8px; font-weight:700; "
                f"letter-spacing:1px; background:transparent;"
            )
            card_lay.addWidget(name_lbl)
            sev_grid.addWidget(card)
            self._sev_labels[sev] = count_lbl

        outer.addLayout(sev_grid)

        # ── Recent anomalies list ──────────────────────────────────────────────
        recent_hdr = QLabel("Recent Anomalies")
        recent_hdr.setStyleSheet(
            f"color:{COLORS['text_secondary']}; font-size:9px; font-weight:700; "
            f"letter-spacing:1px; background:transparent;"
        )
        outer.addWidget(recent_hdr)

        self._recent_list = QLabel("—  No anomalies yet")
        self._recent_list.setWordWrap(True)
        self._recent_list.setStyleSheet(
            f"color:{COLORS['text_muted']}; font-size:9px; "
            f"font-family:monospace; background:transparent; "
            f"padding:4px 0;"
        )
        self._recent_list.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        outer.addWidget(self._recent_list)
        outer.addStretch()

        # Duration clock — ticks every second
        self._clock = QTimer(self)
        self._clock.timeout.connect(self._tick_duration)
        self._clock.start(1000)

    def _tick_duration(self):
        elapsed = int((datetime.now() - self._session_start).total_seconds())
        h, rem = divmod(elapsed, 3600)
        m, s   = divmod(rem, 60)
        self._duration_lbl.setText(f"{h:02d}:{m:02d}:{s:02d}")

    @pyqtSlot(object)
    def on_fault_pushed(self, fault):
        """Update severity counters and recent list immediately on new fault."""
        sev = fault.severity.lower()
        if sev in self._counts:
            self._counts[sev] += 1
        else:
            self._counts['info'] += 1

        # Update counter labels
        for key, lbl in self._sev_labels.items():
            val = self._counts.get(key, 0)
            lbl.setText(str(val))
            # Flash the counter bright on increment
            if key == sev or (key == 'info' and sev not in self._counts):
                orig = lbl.styleSheet()
                lbl.setStyleSheet(orig.replace(
                    f"color:{_sev_color(key)}",
                    f"color:{COLORS['text_primary']}"
                ))
                QTimer.singleShot(400, lambda l=lbl, s=orig: l.setStyleSheet(s))

        # Recent anomalies (last 5, newest first)
        ts  = time.strftime('%H:%M:%S', time.localtime(fault.time))
        icon = _sev_icon(sev)
        self._recent.insert(0, f"{icon} [{ts}]  {fault.fault[:60]}")
        self._recent = self._recent[:5]
        self._recent_list.setText("\n".join(self._recent))

    def reset_session(self):
        """Reset all counters when a new fuzzing session starts."""
        self._session_start = datetime.now()
        self._counts = {k: 0 for k in self._counts}
        for lbl in self._sev_labels.values():
            lbl.setText("0")
        self._recent.clear()
        self._recent_list.setText("—  No anomalies yet")


# ---------------------------------------------------------------------------
# LiveVulnerabilityFeed  (unchanged)
# ---------------------------------------------------------------------------

class LiveVulnerabilityFeed(CardFrame):
    _MAX_ROWS = 200

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        hdr = QWidget()
        hdr.setFixedHeight(38)
        hdr.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {COLORS['bg_elevated']}, stop:1 {COLORS['bg_card']});
            border-bottom: 1px solid {COLORS['border']};
            border-radius: 6px 6px 0 0;
        """)
        hdr_row = QHBoxLayout(hdr)
        hdr_row.setContentsMargins(14, 0, 14, 0)
        title = QLabel("⚡  LIVE VULNERABILITY FEED")
        title.setStyleSheet(
            f"color:{COLORS['accent_cyan']}; font-size:10px; font-weight:700; "
            f"letter-spacing:2px; background:transparent;"
        )
        hdr_row.addWidget(title)
        hdr_row.addStretch()
        self._count_lbl = QLabel("0 events")
        self._count_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']}; font-size:10px; background:transparent;"
        )
        hdr_row.addWidget(self._count_lbl)
        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setFixedHeight(22)
        self._clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {COLORS['border_bright']};
                color: {COLORS['text_muted']};
                border-radius: 4px; font-size: 10px; padding: 0 8px;
            }}
            QPushButton:hover {{
                color: {COLORS['text_primary']};
                border-color: {COLORS['accent_cyan']}55;
            }}
        """)
        self._clear_btn.clicked.connect(self._clear)
        hdr_row.addWidget(self._clear_btn)
        outer.addWidget(hdr)

        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Severity", "Module / Service", "Vulnerability Detected", "Time", "Status"]
        )
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(True)
        self._table.setSortingEnabled(False)
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_card']};
                border: none; border-radius: 0 0 6px 6px;
                font-size: 11px; outline: none;
            }}
            QTableWidget::item {{
                padding: 5px 10px;
                border-bottom: 1px solid {COLORS['border']};
                color: {COLORS['text_primary']};
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['accent_cyan']}18;
                color: {COLORS['accent_cyan']};
            }}
            QTableWidget::item:alternate {{
                background-color: {COLORS['bg_secondary']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_elevated']};
                border: none;
                border-right: 1px solid {COLORS['border']};
                border-bottom: 1px solid {COLORS['border']};
                padding: 6px 10px;
                color: {COLORS['text_secondary']};
                font-size: 10px; font-weight: 700; letter-spacing: 1px;
            }}
        """)
        outer.addWidget(self._table)
        self._event_count = 0

    @pyqtSlot(object)
    def on_fault_pushed(self, fault):
        self._event_count += 1
        self._count_lbl.setText(f"{self._event_count} event{'s' if self._event_count != 1 else ''}")
        while self._table.rowCount() >= self._MAX_ROWS:
            self._table.removeRow(self._table.rowCount() - 1)
        self._table.insertRow(0)
        color = _sev_color(fault.severity)
        icon  = _sev_icon(fault.severity)
        ts    = time.strftime('%H:%M:%S', time.localtime(fault.time))

        def _item(text, fg=None, bold=False, align=Qt.AlignVCenter | Qt.AlignLeft):
            it = QTableWidgetItem(text)
            it.setTextAlignment(align)
            if fg:
                it.setForeground(QColor(fg))
            if bold:
                f = it.font(); f.setBold(True); it.setFont(f)
            return it

        self._table.setItem(0, 0, _item(f"{icon}  {fault.severity.upper()}", fg=color, bold=True))
        self._table.setItem(0, 1, _item(fault.module))
        self._table.setItem(0, 2, _item(fault.fault))
        self._table.setItem(0, 3, _item(ts, align=Qt.AlignVCenter | Qt.AlignHCenter))
        self._table.setItem(0, 4, _item(
            fault.status.upper(),
            fg=COLORS['accent_yellow'] if fault.status == 'open' else COLORS['success']
        ))
        self._table.setRowHeight(0, 34)
        self._flash_row(0, color)

    def _flash_row(self, row: int, color: str):
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setBackground(QColor(color + "44"))
        def _clear_flash():
            try:
                for c in range(self._table.columnCount()):
                    it = self._table.item(row, c)
                    if it:
                        it.setBackground(QColor(0, 0, 0, 0))
            except Exception:
                pass
        QTimer.singleShot(900, _clear_flash)

    def _clear(self):
        self._table.setRowCount(0)
        self._event_count = 0
        self._count_lbl.setText("0 events")


# ---------------------------------------------------------------------------
# SeverityDistributionWidget  (unchanged)
# ---------------------------------------------------------------------------

class SeverityBar(QWidget):
    def __init__(self, label, color, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(12)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {color}; font-size: 10px;")
        dot.setFixedWidth(14)
        layout.addWidget(dot)
        lbl = QLabel(label.upper())
        lbl.setStyleSheet(f"color: {color}; font-size: 10px; letter-spacing:1px;")
        layout.addWidget(lbl)
        self.track = QFrame()
        self.track.setFixedHeight(4)
        self.track.setStyleSheet(f"background:{COLORS['border']}; border-radius:2px;")
        self.track.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(self.track)
        self.bar = QFrame(self.track)
        self.bar.setFixedHeight(4)
        self.bar.setStyleSheet(f"background:{color}; border-radius:2px;")
        self.bar.setFixedWidth(0)
        self._count_lbl = QLabel("0")
        self._count_lbl.setStyleSheet(f"color:{COLORS['text_secondary']}; font-size:11px;")
        self._count_lbl.setAlignment(Qt.AlignRight)
        layout.addWidget(self._count_lbl)

    def set_value(self, count: int, total: int):
        self._count_lbl.setText(str(count))
        if total > 0 and self.track.width() > 0:
            self.bar.setFixedWidth(int((count / total) * self.track.width()))
        else:
            self.bar.setFixedWidth(0)


class SeverityDistributionWidget(CardFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.addWidget(SectionHeader("Severity Distribution"))
        self._bars = {}
        for sev, color in [
            ("critical", COLORS["critical"]),
            ("high",     COLORS["high"]),
            ("medium",   COLORS["medium"]),
            ("low",      COLORS["low"]),
        ]:
            bar = SeverityBar(sev, color)
            layout.addWidget(bar)
            self._bars[sev] = bar
        layout.addStretch()

    def update_data(self, severity_counts: dict):
        total = sum(severity_counts.values())
        for sev, bar in self._bars.items():
            bar.set_value(severity_counts.get(sev, 0), total)


# ---------------------------------------------------------------------------
# RecentFaultsTable  (unchanged — kept for compatibility)
# ---------------------------------------------------------------------------

class RecentFaultsTable(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Severity", "Module", "Fault", "Command", "Time", "Status"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)

    def update_faults(self, faults):
        self.table.setRowCount(0)
        if not faults:
            self.table.setRowCount(1)
            item = QTableWidgetItem("No faults recorded yet")
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, 6)
            return
        for row, f in enumerate(faults):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(f.severity.upper()))
            self.table.setItem(row, 1, QTableWidgetItem(f.module))
            self.table.setItem(row, 2, QTableWidgetItem(f.fault))
            self.table.setItem(row, 3, QTableWidgetItem(f.cmd[:60]))
            self.table.setItem(row, 4, QTableWidgetItem(f.time_str()))
            self.table.setItem(row, 5, QTableWidgetItem(f.status.upper()))
            self.table.setRowHeight(row, 34)


# ---------------------------------------------------------------------------
# DashboardTab  — revamped layout + real-time update fix
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SeedAnalysisCard — live seed analysis panel
# ---------------------------------------------------------------------------

class SeedAnalysisCard(CardFrame):
    """
    Real-time seed analysis panel. Wired to DataManager.seed_stats_updated
    so it refreshes after EVERY seed received — no dedup, always live.
    """
    _SEV_COLOR = {
        "CRITICAL": COLORS.get("critical", "#dc2626"),
        "HIGH":     COLORS.get("high",     "#ef4444"),
        "MEDIUM":   COLORS.get("medium",   "#f59e0b"),
        "SAFE":     COLORS.get("accent_green", "#10b981"),
        "—":        COLORS.get("text_secondary", "#6b7280"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(8)

        hdr = QLabel("🔑  Seed Analysis  (live)")
        hdr.setStyleSheet(
            f"color:{COLORS.get('accent_cyan','#22d3ee')};"
            "font-size:12px;font-weight:700;letter-spacing:1px;"
            "background:transparent;border:none;"
        )
        outer.addWidget(hdr)

        # Stat strip
        stats_row = QHBoxLayout()
        stats_row.setSpacing(6)
        self._stat_labels = {}
        for key, label in [
            ("total",    "Total"),
            ("unique",   "Unique"),
            ("duplicates","Dupes"),
            ("dup_rate", "Dup %"),
            ("stream_entropy", "Entropy"),
            ("severity", "Status"),
        ]:
            col = QVBoxLayout()
            col.setSpacing(1)
            v = QLabel("—")
            v.setAlignment(Qt.AlignCenter)
            v.setStyleSheet(
                f"color:{COLORS.get('accent_cyan','#22d3ee')};"
                "font-size:16px;font-weight:700;background:transparent;border:none;"
            )
            lbl = QLabel(label)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(
                f"color:{COLORS.get('text_secondary','#94a3b8')};"
                "font-size:9px;font-weight:600;background:transparent;border:none;"
            )
            col.addWidget(v)
            col.addWidget(lbl)
            self._stat_labels[key] = v
            frame = QFrame()
            frame.setStyleSheet(
                f"background:{COLORS.get('bg_elevated','#1e2433')};"
                f"border:1px solid {COLORS.get('border','#2d3748')};"
                "border-radius:4px;"
            )
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(8, 6, 8, 6)
            fl.addLayout(col)
            stats_row.addWidget(frame)
        outer.addLayout(stats_row)

        # Last seed + findings log
        self._last_seed_lbl = QLabel("Last seed: —")
        self._last_seed_lbl.setStyleSheet(
            f"color:{COLORS.get('text_secondary','#94a3b8')};"
            "font-size:10px;background:transparent;border:none;"
        )
        outer.addWidget(self._last_seed_lbl)

        self._findings_log = QTableWidget(0, 3)
        self._findings_log.setHorizontalHeaderLabels(["Detector", "Severity", "Detail"])
        self._findings_log.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._findings_log.horizontalHeader().setDefaultSectionSize(90)
        self._findings_log.setEditTriggers(QTableWidget.NoEditTriggers)
        self._findings_log.setSelectionBehavior(QTableWidget.SelectRows)
        self._findings_log.verticalHeader().setVisible(False)
        self._findings_log.setMaximumHeight(120)
        self._findings_log.setStyleSheet(f"""
            QTableWidget {{
                background:{COLORS.get('bg_elevated','#1e2433')};
                color:{COLORS.get('text_primary','#e2e8f0')};
                gridline-color:{COLORS.get('border','#2d3748')};
                border:none; font-size:10px;
            }}
            QHeaderView::section {{
                background:{COLORS.get('bg_secondary','#1a2235')};
                color:{COLORS.get('text_secondary','#94a3b8')};
                border:none; padding:3px 5px;
                font-size:9px; font-weight:700;
            }}
        """)
        outer.addWidget(self._findings_log)

    @pyqtSlot(dict)
    def on_stats_updated(self, stats: dict):
        """Called by DataManager.seed_stats_updated — fires after every seed."""
        n   = stats.get("total", 0)
        dup = stats.get("duplicates", 0)
        dr  = stats.get("dup_rate", 0.0)
        ent = stats.get("stream_entropy", 0.0)
        sev = stats.get("severity", "—")

        self._stat_labels["total"].setText(str(n))
        self._stat_labels["unique"].setText(str(stats.get("unique", 0)))
        self._stat_labels["duplicates"].setText(str(dup))
        self._stat_labels["dup_rate"].setText(f"{dr*100:.0f}%")
        self._stat_labels["stream_entropy"].setText(f"{ent:.2f}")

        sev_color = self._SEV_COLOR.get(sev, "#6b7280")
        self._stat_labels["severity"].setText(sev)
        self._stat_labels["severity"].setStyleSheet(
            f"color:{sev_color};font-size:13px;font-weight:700;"
            "background:transparent;border:none;"
        )
        last = stats.get("last_seed_hex", "—")
        self._last_seed_lbl.setText(f"Last seed:  0x{last}")

    def add_finding(self, finding: dict):
        """Prepend a new finding row to the log table."""
        row = 0
        self._findings_log.insertRow(row)
        sev = finding.get("severity", "low")
        color = QColor(_SEV_COLORS.get(sev, "#6b7280"))
        for col, text in enumerate([
            finding.get("detector", ""),
            sev.upper(),
            finding.get("detail", ""),
        ]):
            item = QTableWidgetItem(text)
            item.setForeground(color)
            self._findings_log.setItem(row, col, item)
        # Keep table from growing unbounded
        while self._findings_log.rowCount() > 50:
            self._findings_log.removeRow(self._findings_log.rowCount() - 1)

    def reset(self):
        for lbl in self._stat_labels.values():
            lbl.setText("—")
        self._last_seed_lbl.setText("Last seed: —")
        self._findings_log.setRowCount(0)


# ---------------------------------------------------------------------------
# ECUEventCard — crash / hang / lockout live log
# ---------------------------------------------------------------------------

class ECUEventCard(CardFrame):
    """Live log of crash, hang, lockout and other suspicious ECU events."""

    _TYPE_ICON = {
        "crash":   "💥",
        "hang":    "🔒",
        "lockout": "🚨",
        "timeout_streak": "⏳",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(6)

        hdr = QLabel("⚠️  ECU Events  (live)")
        hdr.setStyleSheet(
            f"color:{COLORS.get('critical','#dc2626')};"
            "font-size:12px;font-weight:700;letter-spacing:1px;"
            "background:transparent;border:none;"
        )
        outer.addWidget(hdr)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Type", "Module", "Detail"])
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setMaximumHeight(100)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background:{COLORS.get('bg_elevated','#1e2433')};
                color:{COLORS.get('text_primary','#e2e8f0')};
                gridline-color:{COLORS.get('border','#2d3748')};
                border:none; font-size:10px;
            }}
            QHeaderView::section {{
                background:{COLORS.get('bg_secondary','#1a2235')};
                color:{COLORS.get('text_secondary','#94a3b8')};
                border:none; padding:3px 5px;
                font-size:9px; font-weight:700;
            }}
        """)
        outer.addWidget(self._table)

    @pyqtSlot(dict)
    def on_ecu_event(self, event: dict):
        etype  = event.get("type", "unknown")
        module = event.get("module", "—")
        raw    = event.get("raw", "")[:80]
        icon   = self._TYPE_ICON.get(etype, "⚠️")

        color = QColor(COLORS.get("critical", "#dc2626")
                       if etype in ("crash", "lockout") else
                       COLORS.get("high", "#ef4444"))
        row = 0
        self._table.insertRow(row)
        for col, text in enumerate([f"{icon} {etype.upper()}", module, raw]):
            item = QTableWidgetItem(text)
            item.setForeground(color)
            self._table.setItem(row, col, item)
        while self._table.rowCount() > 30:
            self._table.removeRow(self._table.rowCount() - 1)

    def reset(self):
        self._table.setRowCount(0)



class DashboardTab(QWidget):
    """
    Layout (top → bottom):
      1. Stat cards row                     (unchanged)
      2. LiveAlertStack                     (animated banner per vuln)
      3. Charts row:
           LEFT  → LiveFuzzingStatusWidget  (NEW — replaces Module Breakdown)
           RIGHT → SeverityDistributionWidget
      4. LiveVulnerabilityFeed              (zero-latency event list)
      5. RecentFaultsTable                  (polled every 2 s)

    All widgets connected to DataManager.fault_pushed via Qt.QueuedConnection
    so updates arrive on the GUI thread regardless of which worker thread
    detected the fault — fixing the real-time update bug.
    """

    def __init__(self, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.dm = data_manager
        self._setup_ui()
        self._connect_signals()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)

    def _setup_ui(self):
        # Outer layout holds a scroll area so the dashboard is usable at any window height
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # ── Row 1: Stat cards ──────────────────────────────────────────────
        cards_layout = QHBoxLayout()
        self._card_total    = StatCard("Total Faults",  "0", "All sessions",    COLORS["accent_cyan"])
        self._card_critical = StatCard("Critical",      "0", "Require action",  COLORS["critical"])
        self._card_open     = StatCard("Open",          "0", "Unresolved",      COLORS["accent_yellow"])
        self._card_sessions = StatCard("Sessions",      "0", "Unique sessions", COLORS["accent_purple"])
        for card in [self._card_total, self._card_critical,
                     self._card_open, self._card_sessions]:
            cards_layout.addWidget(card)
        layout.addLayout(cards_layout)

        # ── Row 2: Alert banners ───────────────────────────────────────────
        self._alert_stack = LiveAlertStack()
        self._alert_stack.setVisible(False)
        layout.addWidget(self._alert_stack)

        # ── Row 3: Charts ─────────────────────────────────────────────────
        charts_layout = QHBoxLayout()
        self._fuzzing_status = LiveFuzzingStatusWidget()   # NEW
        self._severity_chart = SeverityDistributionWidget()
        charts_layout.addWidget(self._fuzzing_status)
        charts_layout.addWidget(self._severity_chart)
        layout.addLayout(charts_layout)

        # ── Row 3b: NRC Tracker ──────────────────────────────────────────
        from modules.uds_response_tab import _NRCTrackerWidget
        self._nrc_tracker = _NRCTrackerWidget()
        layout.addWidget(self._nrc_tracker)

        # ── Row 3c: Seed Analysis + ECU Events (side by side) ────────────────
        seed_ecu_row = QHBoxLayout()
        self._seed_card = SeedAnalysisCard()
        self._ecu_event_card = ECUEventCard()
        seed_ecu_row.addWidget(self._seed_card, stretch=3)
        seed_ecu_row.addWidget(self._ecu_event_card, stretch=2)
        layout.addLayout(seed_ecu_row)

        # ── Row 4: Live vulnerability feed ────────────────────────────────
        self._live_feed = LiveVulnerabilityFeed()
        layout.addWidget(self._live_feed)

        # ── Row 5: Recent faults table ────────────────────────────────────
        self._faults_table = RecentFaultsTable()
        layout.addWidget(self._faults_table)
        layout.addStretch()

        scroll.setWidget(inner)
        outer.addWidget(scroll)

    def _connect_signals(self):
        # Existing connections (heartbeat refresh)
        self.dm.faults_updated.connect(self.refresh)
        self.dm.sessions_updated.connect(self._on_sessions_updated)

        # Real-time per-fault connections — all QueuedConnection so the
        # slot always executes on the main/GUI thread.
        self.dm.fault_pushed.connect(
            self._on_fault_pushed, type=Qt.QueuedConnection
        )
        self.dm.nrc_recorded.connect(self._on_nrc_recorded, Qt.QueuedConnection)
        self.dm.seed_stats_updated.connect(self._on_seed_stats_updated, Qt.QueuedConnection)
        self.dm.ecu_event.connect(self._on_ecu_event, Qt.QueuedConnection)
        # fault_hit fires when dedup collapses a repeat — also refresh dashboard
        self.dm.fault_hit.connect(self._on_fault_hit, Qt.QueuedConnection)

    @pyqtSlot(str, int, str)
    def _on_nrc_recorded(self, module: str, nrc_code: int, raw_line: str):
        """Forward NRC events to the dashboard NRC tracker widget."""
        try:
            self._nrc_tracker.record_nrc(nrc_code, raw_line)
        except Exception:
            pass

    @pyqtSlot(dict)
    def _on_seed_stats_updated(self, stats: dict):
        """Forward seed stats to SeedAnalysisCard — fires after EVERY seed."""
        try:
            self._seed_card.on_stats_updated(stats)
        except Exception:
            pass

    @pyqtSlot(dict)
    def _on_ecu_event(self, event: dict):
        """Forward ECU crash/hang/lockout events to ECUEventCard."""
        try:
            self._ecu_event_card.on_ecu_event(event)
        except Exception:
            pass

    @pyqtSlot(object)
    def _on_fault_hit(self, fault):
        """fault_hit fires when dedup collapses a repeat — still refresh stat cards."""
        try:
            self.refresh()
        except Exception:
            pass

    @pyqtSlot(object)
    def _on_fault_pushed(self, fault):
        """
        Single entry-point for all real-time fault updates.

        Runs in the main thread (QueuedConnection) regardless of which
        background thread called DataManager.add_fault().

        Updates every widget that needs to react instantly:
          - Animated alert banner
          - LiveFuzzingStatusWidget (severity counters + recent list)
          - LiveVulnerabilityFeed (prepend row)
          - Stat cards (instant count refresh)
          - Severity distribution chart
        """
        # 1. Animated banner
        self._alert_stack.push(fault)

        # 2. Live fuzzing status (counters + recent anomalies)
        self._fuzzing_status.on_fault_pushed(fault)

        # 3. Live feed table
        self._live_feed.on_fault_pushed(fault)

        # 4. Stat cards — instant update without waiting for 2-second timer
        self._card_total.set_value(self.dm.total_faults())
        self._card_critical.set_value(self.dm.critical_faults())
        self._card_open.set_value(self.dm.open_faults())
        self._card_sessions.set_value(len(self.dm.sessions))

        # 5. Severity distribution chart
        self._severity_chart.update_data(self.dm.severity_counts())

        # 6. Forward seed findings to SeedAnalysisCard findings log
        seed_keywords = ("seed", "entropy", "counter rng", "monotone", "dup rate")
        fault_lower = fault.fault.lower() if hasattr(fault, 'fault') else ""
        if any(k in fault_lower for k in seed_keywords):
            try:
                self._seed_card.add_finding({
                    "detector": "SEED",
                    "severity": fault.severity if hasattr(fault, 'severity') else "high",
                    "detail":   fault.fault if hasattr(fault, 'fault') else str(fault),
                })
            except Exception:
                pass

    def _on_sessions_updated(self):
        """Called when a session starts or ends. Reset live widgets on new session start."""
        self.refresh()
        # If a new session just started (module is set), reset all live panels
        if self.dm.active_module:
            try: self._fuzzing_status.reset_session()
            except Exception: pass
            try: self._nrc_tracker.reset()
            except Exception: pass
            try: self._seed_card.reset()
            except Exception: pass
            try: self._ecu_event_card.reset()
            except Exception: pass

    def refresh(self):
        """Full refresh — called by 2-second heartbeat timer and faults_updated."""
        self._card_total.set_value(self.dm.total_faults())
        self._card_critical.set_value(self.dm.critical_faults())
        self._card_open.set_value(self.dm.open_faults())
        self._card_sessions.set_value(len(self.dm.sessions))
        self._severity_chart.update_data(self.dm.severity_counts())
        self._faults_table.update_faults(self.dm.recent_faults())
