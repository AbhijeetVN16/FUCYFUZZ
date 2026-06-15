"""
UDS Response Analyser Tab
=========================
Replaces ECUMonitorTab.  Provides three panels:

  A — Live NRC (Negative Response Code) Tracker table
  B — Session Statistics Strip (counts + NRC diversity)
  C — Response Timeline sparkline (60-second rolling window)

All data is derived from output-line parsing via _extra_parse —
no ECU simulator keywords required.
"""

import re
import time
from collections import deque

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy,
    QSplitter, QScrollArea,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot
from PyQt5.QtGui import QColor, QPainter, QBrush, QPen, QFont

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, CardFrame
from ui.theme import COLORS

# ── NRC code table ────────────────────────────────────────────────────────────

NRC_TABLE = {
    0x10: ("generalReject",                   "low"),
    0x11: ("serviceNotSupported",             "low"),
    0x12: ("subFunctionNotSupported",         "low"),
    0x13: ("incorrectMessageLength",          "low"),
    0x22: ("conditionsNotCorrect",            "medium"),
    0x24: ("requestSequenceError",            "medium"),
    0x25: ("noResponseFromSubnetComponent",   "high"),
    0x31: ("requestOutOfRange",               "low"),
    0x33: ("securityAccessDenied",            "high"),
    0x35: ("invalidKey",                      "high"),
    0x36: ("exceededNumberOfAttempts",        "critical"),
    0x37: ("requiredTimeDelayNotExpired",     "medium"),
    0x70: ("uploadDownloadNotAccepted",       "medium"),
    0x72: ("generalProgrammingFailure",       "high"),
    0x7E: ("subFunctionNotSupportedInSession","low"),
    0x7F: ("serviceNotSupportedInSession",    "low"),
}

_SEV_COLORS = {
    "low":      COLORS.get("text_secondary", "#6b7280"),
    "medium":   COLORS.get("medium",         "#f59e0b"),
    "high":     COLORS.get("high",           "#ef4444"),
    "critical": COLORS.get("critical",       "#dc2626"),
}

_NRC_RE  = re.compile(r'7[Ff]\s+[0-9a-fA-F]{2}\s+([0-9a-fA-F]{2})')
_NRC_RE2 = re.compile(r'[Nn][Rr][Cc][=:\s]+0[xX]([0-9a-fA-F]{2})')
_TOUT_RE = re.compile(r'timeout|no response|timed out', re.I)
_POS_RE  = re.compile(r'\[RX\][^:]*:[0-9a-fA-F\s]+', re.I)


# ── Panel C — Timeline Sparkline ──────────────────────────────────────────────

class _TimelineWidget(QFrame):
    """
    Rolling 60-second response-rate sparkline.
    Buckets: one per second.  Green = positive, orange = negative, red = timeout.
    """
    BUCKETS = 60

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(80)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyleSheet(
            f"background: {COLORS.get('bg_elevated', '#1e2433')};"
            f"border: 1px solid {COLORS.get('border', '#2d3748')};"
            "border-radius: 6px;"
        )
        # Each bucket is (positive_count, negative_count, timeout_count)
        self._data: deque = deque(
            [(0, 0, 0)] * self.BUCKETS, maxlen=self.BUCKETS
        )
        self._cur = [0, 0, 0]  # accumulator for current second
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def add_positive(self):  self._cur[0] += 1
    def add_negative(self):  self._cur[1] += 1
    def add_timeout(self):   self._cur[2] += 1

    def _tick(self):
        self._data.append(tuple(self._cur))
        self._cur = [0, 0, 0]
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        pad = 8
        inner_w = w - 2 * pad
        inner_h = h - 2 * pad

        data = list(self._data)
        n = len(data)
        if n == 0:
            return

        max_val = max(sum(bucket) for bucket in data) or 1
        bar_w = max(2, inner_w // n - 1)
        gap   = max(1, (inner_w - bar_w * n) // max(n - 1, 1))

        colors = [
            QColor(COLORS.get("accent_green", "#10b981")),
            QColor(COLORS.get("medium",       "#f59e0b")),
            QColor(COLORS.get("critical",     "#ef4444")),
        ]

        for i, (pos, neg, tout) in enumerate(data):
            x = pad + i * (bar_w + gap)
            total = pos + neg + tout
            if total == 0:
                continue
            bar_total_h = int((total / max_val) * inner_h)
            y_base = pad + inner_h

            for count, col in zip([pos, neg, tout], colors):
                if count == 0:
                    continue
                seg_h = max(1, int((count / total) * bar_total_h))
                p.setBrush(QBrush(col))
                p.setPen(Qt.NoPen)
                p.drawRect(x, y_base - seg_h, bar_w, seg_h)
                y_base -= seg_h

        p.end()


# ── Panel A — NRC Tracker table ───────────────────────────────────────────────

class _NRCTrackerWidget(CardFrame):
    COLS = ["NRC Code", "Description", "Count", "Last Seen", "Severity"]

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        hdr = QLabel("Live NRC Tracker")
        hdr.setStyleSheet(
            f"color: {COLORS.get('accent_cyan','#22d3ee')};"
            "font-size: 12px; font-weight: 700; letter-spacing: 1px;"
        )
        layout.addWidget(hdr)

        self._table = QTableWidget(0, len(self.COLS))
        self._table.setHorizontalHeaderLabels(self.COLS)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setDefaultSectionSize(90)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS.get('bg_elevated','#1e2433')};
                color: {COLORS.get('text_primary','#e2e8f0')};
                gridline-color: {COLORS.get('border','#2d3748')};
                border: none;
                font-size: 11px;
            }}
            QTableWidget::item:alternate {{
                background: {COLORS.get('bg_card','#232b3e')};
            }}
            QHeaderView::section {{
                background: {COLORS.get('bg_secondary','#1a2235')};
                color: {COLORS.get('text_secondary','#94a3b8')};
                border: none;
                padding: 4px 6px;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
        """)
        layout.addWidget(self._table)

        self._rows: dict = {}   # nrc_code -> row_index

    def record_nrc(self, nrc_code: int, raw_line: str = ""):
        from datetime import datetime
        desc, sev = NRC_TABLE.get(nrc_code, (f"0x{nrc_code:02X}", "low"))
        ts = datetime.now().strftime("%H:%M:%S")
        color = QColor(_SEV_COLORS.get(sev, "#6b7280"))

        if nrc_code in self._rows:
            row = self._rows[nrc_code]
            cnt = int(self._table.item(row, 2).text()) + 1
            self._table.item(row, 2).setText(str(cnt))
            self._table.item(row, 3).setText(ts)
            self._flash_row(row, color)
        else:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._rows[nrc_code] = row

            items = [
                f"0x{nrc_code:02X}",
                desc,
                "1",
                ts,
                sev.upper(),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                item.setForeground(color)
                self._table.setItem(row, col, item)

            self._flash_row(row, color)

        # 0x36 lockout: row stays red permanently
        if nrc_code == 0x36:
            lockout_color = QColor(_SEV_COLORS["critical"])
            for col in range(self._table.columnCount()):
                if self._table.item(row, col):
                    self._table.item(row, col).setForeground(lockout_color)
                    self._table.item(row, col).setBackground(
                        QColor(COLORS.get("critical", "#dc2626") + "22")
                    )

    def _flash_row(self, row: int, color: QColor):
        flash_color = QColor(color.red(), color.green(), color.blue(), 60)
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setBackground(flash_color)
        QTimer.singleShot(400, lambda: self._clear_flash(row))

    def _clear_flash(self, row: int):
        if row >= self._table.rowCount():
            return
        # Don't clear 0x36 lockout colour
        try:
            code_item = self._table.item(row, 0)
            if code_item and code_item.text() == "0x36":
                return
        except Exception:
            return
        transparent = QColor(0, 0, 0, 0)
        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setBackground(transparent)

    def reset(self):
        self._table.setRowCount(0)
        self._rows.clear()


# ── Panel B — Session Statistics Strip ───────────────────────────────────────

class _StatCard(QFrame):
    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background: {COLORS.get('bg_elevated','#1e2433')};
                border: 1px solid {COLORS.get('border','#2d3748')};
                border-radius: 6px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        self._value = QLabel("0")
        self._value.setAlignment(Qt.AlignCenter)
        self._value.setStyleSheet(
            f"color: {COLORS.get('accent_cyan','#22d3ee')};"
            "font-size: 22px; font-weight: 700; border: none; background: transparent;"
        )
        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(
            f"color: {COLORS.get('text_secondary','#94a3b8')};"
            "font-size: 10px; font-weight: 600; letter-spacing: 0.5px;"
            "border: none; background: transparent;"
        )
        layout.addWidget(self._value)
        layout.addWidget(lbl)

    def set_value(self, v):
        self._value.setText(str(v))


class _StatsStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._cards = {}
        for key, label in [
            ("total",       "Total RX"),
            ("positive",    "Positive"),
            ("negative",    "Negative"),
            ("timeouts",    "Timeouts"),
            ("nrc_div",     "NRC Diversity"),
        ]:
            card = _StatCard(label)
            self._cards[key] = card
            layout.addWidget(card)

    def update_stats(self, total=0, positive=0, negative=0,
                     timeouts=0, nrc_diversity=0):
        self._cards["total"].set_value(total)
        self._cards["positive"].set_value(positive)
        self._cards["negative"].set_value(negative)
        self._cards["timeouts"].set_value(timeouts)
        self._cards["nrc_div"].set_value(nrc_diversity)


# ── Main Tab ──────────────────────────────────────────────────────────────────

class UDSResponseAnalyserTab(QWidget):
    """
    Standalone widget (not a BaseModuleTab — it observes the shared runner
    via DataManager signals and output-line hooks added to base_tab).

    Receives NRC events via DataManager.nrc_recorded signal.
    Receives raw lines via the session_logger GUI callback.
    """

    def __init__(self, data_manager, parent=None):
        super().__init__(parent)
        self.dm = data_manager
        self._total_rx   = 0
        self._positive   = 0
        self._negative   = 0
        self._timeouts   = 0
        self._nrc_set    = set()
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(14)

        # Title bar
        title = SectionHeader("UDS Response Analyser")
        outer.addWidget(title)

        # Panel B — stats strip
        self._stats = _StatsStrip()
        outer.addWidget(self._stats)

        # Panel C — timeline
        timeline_lbl = QLabel("Response Timeline (60 s)")
        timeline_lbl.setStyleSheet(
            f"color: {COLORS.get('text_secondary','#94a3b8')};"
            "font-size: 10px; font-weight: 600; letter-spacing: 0.5px;"
        )
        outer.addWidget(timeline_lbl)
        self._timeline = _TimelineWidget()
        outer.addWidget(self._timeline)

        # Panel A — NRC table
        self._nrc_tracker = _NRCTrackerWidget()
        outer.addWidget(self._nrc_tracker)

        outer.addStretch()

    def _connect_signals(self):
        # NRC events from DataManager
        self.dm.nrc_recorded.connect(self._on_nrc, Qt.QueuedConnection)

        # Raw output lines via session_logger GUI callback
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.add_gui_callback(self._on_log_entry)
        except Exception:
            pass

    @pyqtSlot(str, int, str)
    def _on_nrc(self, module: str, nrc_code: int, raw_line: str):
        self._nrc_tracker.record_nrc(nrc_code, raw_line)
        self._negative += 1
        self._total_rx += 1
        self._nrc_set.add(nrc_code)
        self._timeline.add_negative()
        self._refresh_stats()

    def _on_log_entry(self, entry: dict):
        """Called by session_logger on every logged line."""
        try:
            line = entry.get("raw_line", "") or ""
            self._extra_parse(line)
        except Exception:
            pass

    def _extra_parse(self, line: str):
        """Parse raw output lines to update stats (does not fire NRC signal — that's
        done by base_tab via ECUResponseMonitor to avoid double-counting)."""
        if _TOUT_RE.search(line):
            self._timeouts += 1
            self._timeline.add_timeout()
            self._refresh_stats()
            return

        # Positive response (heuristic: [RX] line without 7F)
        if _POS_RE.search(line) and "7f" not in line.lower():
            self._positive += 1
            self._total_rx += 1
            self._timeline.add_positive()
            self._refresh_stats()

    def _refresh_stats(self):
        self._stats.update_stats(
            total      = self._total_rx,
            positive   = self._positive,
            negative   = self._negative,
            timeouts   = self._timeouts,
            nrc_diversity = len(self._nrc_set),
        )

    def reset_session(self):
        self._total_rx = 0
        self._positive = 0
        self._negative = 0
        self._timeouts = 0
        self._nrc_set.clear()
        self._nrc_tracker.reset()
        self._refresh_stats()
