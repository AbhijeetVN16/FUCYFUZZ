"""
ECU Monitor Tab — v8 (Dynamic Detection, No JSON Upload)
=========================================================

Changes from v7
---------------
* REMOVED: "Vulnerability Profile (vulnerabilities.json)" panel.
  - No JSON file upload, no Browse/Load/Clear buttons, no vuln table mini-view.
  - VulnDB is now ALWAYS built automatically from the built-in Layer-1 patterns
    inside log_fault_parser.  Zero user configuration needed.

* Dynamic severity classification is now handled entirely by
  utils.session_logger.classify_severity().  Three tiers:
    CRITICAL  — ECU crash, timeout, bus-off, security bypass, hang
    HIGH      — Unexpected behaviour, logic errors, modify-response
    LOW/INFO  — Standard NRC, normal rejections

* All other functionality (live feed, counter updates, log replay,
  disk persistence) is preserved exactly.
"""

import hashlib
import json
import os
import time as _time
from datetime import datetime
from typing import Dict, Optional

from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QProgressBar,
    QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ui.theme import COLORS
from ui.widgets import (
    CardFrame, GlowButton, SectionHeader,
    SolidButton, StatusBadge, TerminalWidget,
)
from utils.config import APP_DIRS, ensure_app_dirs, get_config
from utils.data_manager import DataManager
from utils.log_fault_parser import (
    VulnDB, action_to_severity, parse_file, scan_line,
)
from utils.session_logger import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_INFO,
    classify_severity,
)

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

BATCH_SIZE = 25

_C = COLORS

_SEV_COLORS = {
    "critical": _C.get("critical",      "#FF4444"),
    "high":     _C.get("high",          "#FF8C00"),
    "medium":   _C.get("accent_yellow", "#FFD700"),
    "low":      _C.get("accent_cyan",   "#00BFFF"),
    "info":     _C.get("text_muted",    "#8fa8c8"),
}

_SRC_COLORS = {
    "Live Feed":  _C.get("success",       "#00FF88"),
    "Log Replay": _C.get("accent_orange", "#FF8C00"),
}

_ACT_COLORS = {
    "CRASH":           _C.get("critical",      "#FF4444"),
    "BYPASS_SECURITY": _C.get("critical",      "#FF4444"),
    "HANG":            _C.get("critical",      "#FF4444"),
    "LOGIC_ERR":       _C.get("high",          "#FF8C00"),
    "MODIFY_RESPONSE": _C.get("high",          "#FF8C00"),
}

# Column indices
COL_SEV   = 0
COL_ACT   = 1
COL_MOD   = 2
COL_SRC   = 3
COL_DESC  = 4
COL_HITS  = 5
COL_TIME  = 6


# ---------------------------------------------------------------------------
#  Dynamic severity classification (no JSON needed)
# ---------------------------------------------------------------------------

def _classify(text: str) -> str:
    """Map free-form log/UDS text to a severity string used in the table."""
    sev = classify_severity(text)
    _map = {
        SEVERITY_CRITICAL: "critical",
        SEVERITY_HIGH:     "high",
        SEVERITY_LOW:      "low",
        SEVERITY_INFO:     "info",
    }
    return _map.get(sev, "info")


# ---------------------------------------------------------------------------
#  Dedup key
# ---------------------------------------------------------------------------

def _dedup_key(module: str, description: str) -> bytes:
    h = hashlib.blake2b(
        f"{module}\x00{description}".encode("utf-8", errors="replace"),
        digest_size=8,
    )
    return h.digest()


# ---------------------------------------------------------------------------
#  CAN interface helpers
# ---------------------------------------------------------------------------

def _detect_can_interfaces():
    try:
        from utils.can_interface import list_can_interfaces
        detected = list_can_interfaces()
    except Exception:
        detected = []
    vcan   = sorted(i for i in detected if i.startswith("vcan"))
    can    = sorted(i for i in detected if i.startswith("can") and not i.startswith("vcan"))
    others = sorted(i for i in detected if i not in vcan and i not in can)
    return vcan + can + others


def _check_iface_up(iface: str) -> bool:
    try:
        from utils.can_interface import _iface_exists, _iface_is_up
        return _iface_exists(iface) and _iface_is_up(iface)
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  SessionLogger bridge
# ---------------------------------------------------------------------------

class _LogEntryBridge(QObject):
    entry_received = pyqtSignal(dict)

    def on_entry(self, entry: dict) -> None:
        try:
            self.entry_received.emit(entry)
        except Exception:
            pass


# ---------------------------------------------------------------------------
#  Replay worker
# ---------------------------------------------------------------------------

class _LogReplayWorker(QObject):
    batch_found = pyqtSignal(list)
    progress    = pyqtSignal(int, int)
    finished    = pyqtSignal(int, int)
    error       = pyqtSignal(str)

    def __init__(self, path: str, parent=None):
        super().__init__(parent)
        self._path      = path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    @pyqtSlot()
    def run(self):
        try:
            self._do_run()
        except Exception as exc:
            self.error.emit(str(exc))

    def _do_run(self):
        try:
            total_bytes = os.path.getsize(self._path)
        except OSError as exc:
            self.error.emit(f"Cannot stat file: {exc}")
            return
        if total_bytes == 0:
            self.finished.emit(0, 0)
            return

        n_faults = n_lines = 0
        batch: list = []
        seen: dict  = {}

        try:
            for event in parse_file(self._path):
                if self._cancelled:
                    return

                dk = _dedup_key(event.module, event.description)
                hit_count = seen.get(dk, 0) + 1
                seen[dk] = hit_count
                if len(seen) > 8000:
                    seen.clear()

                batch.append((
                    event.severity,
                    event.module,
                    event.description,
                    event.cmd,
                    event.timestamp,
                    "",    # vuln_id not needed (no JSON DB)
                    "",    # vuln_name
                    "",    # action
                    hit_count,
                    dk,
                ))
                n_faults += 1
                n_lines  += 1

                if len(batch) >= BATCH_SIZE:
                    self.batch_found.emit(list(batch))
                    batch.clear()

        except Exception as exc:
            self.error.emit(f"Parse error: {exc}")
            return

        if batch and not self._cancelled:
            self.batch_found.emit(batch)

        self.finished.emit(n_faults, n_lines)


# ---------------------------------------------------------------------------
#  Main tab
# ---------------------------------------------------------------------------

class ECUMonitorTab(QWidget):

    def __init__(self, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.dm  = data_manager
        self.cfg = get_config()

        ensure_app_dirs()
        self._sessions_root = APP_DIRS["ecu_sessions"]

        # PATH A: SessionLogger → Qt bridge (VULN + RX/TX entries)
        self._log_bridge = _LogEntryBridge(self)
        self._log_bridge.entry_received.connect(
            self._on_log_entry, type=Qt.QueuedConnection
        )
        self._register_log_bridge()

        # PATH B: DataManager.fault_pushed fallback (first hit)
        self.dm.fault_pushed.connect(
            self._on_dm_fault_pushed, type=Qt.QueuedConnection
        )

        # PATH C: DataManager.fault_hit (repeated hits)
        self.dm.fault_hit.connect(
            self._on_fault_hit, type=Qt.QueuedConnection
        )

        self._handled:   set          = set()
        self._row_index: Dict[bytes, int] = {}
        self._vuln_count: int         = 0

        self._session_id:         str      = None
        self._session_dir:        str      = None
        self._session_events:     list     = []
        self._session_start_time: datetime = None
        self._session_log_path:   str      = ""

        self._replay_worker:  Optional[_LogReplayWorker] = None
        self._replay_qthread: Optional[QThread]          = None

        self._past_sessions: list = []
        self._load_past_sessions_from_disk()

        self._setup_ui()

    # -----------------------------------------------------------------------
    #  Registration
    # -----------------------------------------------------------------------

    def _register_log_bridge(self) -> None:
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.add_gui_callback(self._log_bridge.on_entry)
        except Exception:
            pass

    def refresh_logger_connection(self) -> None:
        self._register_log_bridge()

    # -----------------------------------------------------------------------
    #  UI
    # -----------------------------------------------------------------------

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 10, 16, 10)
        root.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        ttl = QLabel("ECU MONITOR  —  DYNAMIC ANOMALY DETECTION")
        ttl.setStyleSheet(
            f"color:{_C['accent_cyan']};font-size:13px;"
            "letter-spacing:3px;background:transparent;"
        )
        hdr.addWidget(ttl)
        hdr.addStretch()
        self._status_badge = StatusBadge("LIVE", "active")
        hdr.addWidget(self._status_badge)
        root.addLayout(hdr)

        # Status strip
        sr = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(
            f"color:{_C['success']};font-size:12px;background:transparent;"
        )
        sr.addWidget(dot)
        slbl = QLabel(
            "Dynamic detection active — crashes, timeouts, security anomalies and NRCs "
            "are classified automatically into CRITICAL / HIGH / LOW.  "
            "No JSON profile required.  Repeated hits update [×N] counter in-place."
        )
        slbl.setStyleSheet(
            f"color:{_C['success']};font-size:10px;font-weight:600;background:transparent;"
        )
        sr.addWidget(slbl)
        sr.addStretch()
        root.addLayout(sr)

        # Control strip — only CAN interface panel + log replay panel
        ctrl = QHBoxLayout()
        ctrl.setSpacing(8)
        ctrl.addWidget(self._build_can_panel(),    1)
        ctrl.addWidget(self._build_replay_panel(), 2)
        root.addLayout(ctrl)

        # Splitter
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{_C['border']};height:2px;}}"
        )

        # Table card
        tbl_card = CardFrame()
        tbl_v = QVBoxLayout(tbl_card)
        tbl_v.setContentsMargins(0, 0, 0, 0)
        tbl_v.setSpacing(0)

        tbl_hdr = QWidget()
        tbl_hdr.setFixedHeight(34)
        tbl_hdr.setStyleSheet(
            f"background:{_C['bg_secondary']};"
            f"border-bottom:1px solid {_C['border']};"
            "border-radius:6px 6px 0 0;"
        )
        th = QHBoxLayout(tbl_hdr)
        th.setContentsMargins(12, 0, 12, 0)
        th.addWidget(SectionHeader("Detected Anomaly Events"))
        th.addStretch()
        for txt, col in [
            ("⬛ CRITICAL",  _SEV_COLORS["critical"]),
            ("■ HIGH",       _SEV_COLORS["high"]),
            ("■ Live Feed",  _SRC_COLORS["Live Feed"]),
            ("■ Log Replay", _SRC_COLORS["Log Replay"]),
        ]:
            lbl = QLabel(txt)
            lbl.setStyleSheet(
                f"color:{col};font-size:9px;font-weight:600;"
                "background:transparent;margin:0 5px;"
            )
            th.addWidget(lbl)
        self._count_label = QLabel("0 events")
        self._count_label.setStyleSheet(
            f"color:{_C['accent_cyan']};font-size:10px;background:transparent;"
        )
        th.addWidget(self._count_label)

        # Debug log toggle
        self._debug_toggle = QCheckBox("Debug Logs")
        self._debug_toggle.setChecked(False)
        self._debug_toggle.setStyleSheet(
            f"color:{_C['text_muted']};font-size:9px;background:transparent;"
        )
        self._debug_toggle.setToolTip(
            "When ON: show raw parser events and internal debug lines.\n"
            "When OFF (default): show only meaningful anomaly events.")
        th.addWidget(self._debug_toggle)

        tbl_v.addWidget(tbl_hdr)

        # 7-column table: SEV | ACTION | MODULE | SOURCE | DESCRIPTION | HITS | TIME
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels([
            "SEV", "ACTION", "MODULE", "SOURCE",
            "DESCRIPTION / DECODED REASON", "HITS", "TIME"
        ])
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(True)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(f"""
            QTableWidget{{
                background:{_C['bg_card']};border:none;
                border-radius:0 0 6px 6px;font-size:11px;
                alternate-background-color:{_C['bg_secondary']};
            }}
            QTableWidget::item{{
                padding:4px 8px;border-bottom:1px solid {_C['border']};
                color:{_C['text_primary']};
            }}
            QTableWidget::item:selected{{background:{_C['bg_elevated']};}}
            QHeaderView::section{{
                background:{_C['bg_secondary']};border:none;
                border-right:1px solid {_C['border']};
                border-bottom:1px solid {_C['border']};
                padding:4px 8px;color:{_C['text_secondary']};
                font-size:9px;font-weight:700;letter-spacing:1px;
            }}
        """)
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(COL_SEV,  QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COL_ACT,  QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COL_MOD,  QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COL_SRC,  QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COL_DESC, QHeaderView.Stretch)
        hh.setSectionResizeMode(COL_HITS, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COL_TIME, QHeaderView.ResizeToContents)
        tbl_v.addWidget(self._table)
        splitter.addWidget(tbl_card)

        # Terminal
        term_outer = QWidget()
        term_outer.setStyleSheet("background:transparent;")
        to_lay = QVBoxLayout(term_outer)
        to_lay.setContentsMargins(0, 0, 0, 0)
        to_lay.setSpacing(0)

        term_hdr = QWidget()
        term_hdr.setFixedHeight(30)
        term_hdr.setStyleSheet(
            f"background:{_C['bg_elevated']};"
            f"border:1px solid {_C['border']};"
            f"border-bottom:1px solid {_C['accent_cyan']}44;"
            "border-radius:6px 6px 0 0;"
        )
        th2 = QHBoxLayout(term_hdr)
        th2.setContentsMargins(12, 0, 12, 0)
        dots = QLabel("● ● ●")
        dots.setStyleSheet(
            f"color:{_C['border_bright']};font-size:9px;"
            "background:transparent;letter-spacing:3px;"
        )
        th2.addWidget(dots)
        th2.addSpacing(8)
        ttl2 = QLabel(">_  ECU ANOMALY INSIGHTS  ●  DYNAMIC SEVERITY FEED")
        ttl2.setStyleSheet(
            f"color:{_C['accent_cyan']};font-size:10px;"
            "font-weight:700;letter-spacing:2px;background:transparent;"
        )
        th2.addWidget(ttl2)
        th2.addStretch()
        to_lay.addWidget(term_hdr)

        self.terminal = TerminalWidget()
        self.terminal.output.setStyleSheet(
            self.terminal.output.styleSheet()
            + "\nQPlainTextEdit{font-size:12px;padding:12px 16px;"
              "border-radius:0 0 6px 6px;border-top:none;}"
        )
        self.terminal.setMinimumHeight(260)
        to_lay.addWidget(self.terminal)

        splitter.addWidget(term_outer)
        splitter.setSizes([280, 420])
        root.addWidget(splitter, 1)

    # -----------------------------------------------------------------------
    #  Control panels
    # -----------------------------------------------------------------------

    def _build_can_panel(self) -> QGroupBox:
        g = QGroupBox("CAN Interface")
        lay = QVBoxLayout(g)
        lay.setContentsMargins(8, 6, 8, 6)
        lay.setSpacing(4)

        row = QHBoxLayout()
        self._iface_combo = QComboBox()
        self._iface_combo.setEditable(True)
        self._iface_combo.setToolTip("vcan0 = virtual  |  can0 = hardware SocketCAN")
        self._iface_combo.setStyleSheet(f"""
            QComboBox{{background:{_C['bg_secondary']};border:1px solid {_C['border']};
                border-radius:4px;padding:3px 8px;color:{_C['text_primary']};font-size:10px;}}
            QComboBox::drop-down{{border:none;}}
            QComboBox QAbstractItemView{{background:{_C['bg_elevated']};
                color:{_C['text_primary']};selection-background-color:{_C['accent_cyan']}33;}}
        """)
        row.addWidget(self._iface_combo, 1)
        rb = GlowButton("↻", _C["accent_cyan"])
        rb.setFixedSize(28, 28)
        rb.setToolTip("Refresh interface list")
        rb.clicked.connect(self._refresh_can_interfaces)
        row.addWidget(rb)
        lay.addLayout(row)

        self._can_status = QLabel("")
        self._can_status.setWordWrap(True)
        self._can_status.setStyleSheet(
            f"color:{_C['text_muted']};font-size:9px;background:transparent;"
        )
        lay.addWidget(self._can_status)
        self._refresh_can_interfaces()
        return g

    def _refresh_can_interfaces(self):
        detected = _detect_can_interfaces()
        current  = self._iface_combo.currentText().strip()
        self._iface_combo.blockSignals(True)
        self._iface_combo.clear()
        if detected:
            self._iface_combo.addItems(detected)
            saved = self.cfg.get("interface", "vcan0")
            if current in detected:
                self._iface_combo.setCurrentText(current)
            elif saved in detected:
                self._iface_combo.setCurrentText(saved)
            iface = self._iface_combo.currentText()
            up    = _check_iface_up(iface)
            color = _C["success"] if up else _C["accent_yellow"]
            self._can_status.setText(f"{'UP ✓' if up else '⚠ DOWN'}  —  {iface}")
            self._can_status.setStyleSheet(
                f"color:{color};font-size:9px;background:transparent;"
            )
        else:
            for fb in ("vcan0", "can0"):
                self._iface_combo.addItem(fb)
            self._can_status.setText(
                "⚠ No interfaces detected\n"
                "sudo modprobe vcan && "
                "sudo ip link add vcan0 type vcan && "
                "sudo ip link set up vcan0"
            )
            self._can_status.setStyleSheet(
                f"color:{_C['accent_yellow']};font-size:9px;background:transparent;"
            )
        self._iface_combo.blockSignals(False)

    def current_interface(self) -> str:
        return self._iface_combo.currentText().strip() or self.cfg.get("interface", "vcan0")

    def _build_replay_panel(self) -> QGroupBox:
        g = QGroupBox("Load Session Log for Analysis  (.log / .csv / .jsonl)")
        lay = QVBoxLayout(g)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(6)

        hint = QLabel(
            "Browse to any past session log to replay it through the dynamic detector. "
            "Live detection works automatically — no log file needed."
        )
        hint.setStyleSheet(
            f"color:{_C['text_secondary']};font-size:9px;background:transparent;"
        )
        hint.setWordWrap(True)
        lay.addWidget(hint)

        # ── File path row ──────────────────────────────────────────────────
        path_row = QHBoxLayout()
        path_row.setSpacing(6)

        self._replay_path = QLineEdit()
        self._replay_path.setPlaceholderText("Select a session log file …")
        self._replay_path.setReadOnly(True)
        self._replay_path.setStyleSheet(f"""
            QLineEdit {{
                background: {_C['bg_input']};
                border: 1px solid {_C['border']};
                border-radius: 4px;
                padding: 5px 10px;
                color: {_C['text_primary']};
                font-size: 10px;
                font-family: 'Consolas', 'Courier New', monospace;
            }}
            QLineEdit:focus {{
                border-color: {_C['accent_cyan']};
            }}
        """)
        path_row.addWidget(self._replay_path, 1)

        # Browse button — icon style, compact
        brow = QPushButton("📂  Browse")
        brow.setFixedHeight(32)
        brow.setFixedWidth(96)
        brow.setCursor(Qt.PointingHandCursor)
        brow.setStyleSheet(f"""
            QPushButton {{
                background: {_C['bg_elevated']};
                border: 1px solid {_C['border']};
                border-radius: 4px;
                color: {_C['accent_cyan']};
                font-size: 11px;
                font-weight: 600;
                padding: 0 8px;
            }}
            QPushButton:hover {{
                background: {_C['accent_cyan']}18;
                border-color: {_C['accent_cyan']};
            }}
            QPushButton:pressed {{
                background: {_C['accent_cyan']}30;
            }}
        """)
        brow.clicked.connect(self._browse_replay_file)
        path_row.addWidget(brow)

        # Load / Cancel as one toggle button area
        self._load_btn = QPushButton("▶  Analyse")
        self._load_btn.setFixedHeight(32)
        self._load_btn.setFixedWidth(96)
        self._load_btn.setCursor(Qt.PointingHandCursor)
        self._load_btn.setStyleSheet(f"""
            QPushButton {{
                background: {_C['accent_purple']};
                border: none;
                border-radius: 4px;
                color: #ffffff;
                font-size: 11px;
                font-weight: 700;
                padding: 0 8px;
            }}
            QPushButton:hover {{
                background: {_C['accent_purple']}cc;
            }}
            QPushButton:disabled {{
                background: #333333;
                color: #666666;
            }}
        """)
        self._load_btn.clicked.connect(self._start_replay)
        path_row.addWidget(self._load_btn)

        self._cancel_btn = QPushButton("✕")
        self._cancel_btn.setFixedSize(32, 32)
        self._cancel_btn.setCursor(Qt.PointingHandCursor)
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setToolTip("Cancel replay")
        self._cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background: {_C['bg_elevated']};
                border: 1px solid {_C['border']};
                border-radius: 4px;
                color: {_C['critical']};
                font-size: 13px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background: {_C['critical']}22;
                border-color: {_C['critical']};
            }}
            QPushButton:disabled {{
                color: #444444;
                border-color: #333333;
                background: transparent;
            }}
        """)
        self._cancel_btn.clicked.connect(self._cancel_replay)
        path_row.addWidget(self._cancel_btn)

        lay.addLayout(path_row)

        # ── Thin progress bar ──────────────────────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(f"""
            QProgressBar {{
                background: {_C['border']};
                border: none;
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {_C['accent_purple']}, stop:1 {_C['accent_cyan']});
                border-radius: 2px;
            }}
        """)
        lay.addWidget(self._progress)

        # ── Status label ───────────────────────────────────────────────────
        self._replay_status = QLabel("")
        self._replay_status.setStyleSheet(
            f"color:{_C['text_muted']};font-size:9px;background:transparent;"
        )
        lay.addWidget(self._replay_status)
        return g

    # -----------------------------------------------------------------------
    #  PATH A: SessionLogger bridge
    # -----------------------------------------------------------------------

    @pyqtSlot(dict)
    def _on_log_entry(self, entry: dict) -> None:
        direction = entry.get("direction", "")
        module    = entry.get("module",    "")
        decoded   = entry.get("decoded",   "")
        raw_line  = entry.get("raw_line",  "")
        timestamp = entry.get("timestamp", _time.strftime("%H:%M:%S"))
        log_sev   = entry.get("severity",  "")

        # ── Module-aware routing: ignore events from inactive modules ──────
        # If an active session is running, only accept events from that module.
        # This prevents DoIP entropy events leaking into UDS sessions etc.
        active = self.dm.active_module  # "" when idle
        if active and module and module != active:
            return

        if direction == "VULN":
            # Parse severity tag that data_manager embeds in the decoded string
            severity    = "medium"
            description = decoded
            cmd         = ""

            if decoded.startswith("["):
                end = decoded.find("]")
                if end > 1:
                    sev_raw = decoded[1:end].lower()
                    if sev_raw in ("critical", "high", "medium", "low", "info"):
                        severity = sev_raw
                    description = decoded[end + 1:].strip()

            if "  |  cmd: " in description:
                parts       = description.split("  |  cmd: ", 1)
                description = parts[0].strip()
                cmd         = parts[1].strip() if len(parts) > 1 else ""

            # Override with log-level severity if available
            if log_sev and log_sev.upper() in ("CRITICAL", "HIGH", "LOW", "INFO"):
                severity = log_sev.lower()
                if severity == "info":
                    severity = "low"

            dk = _dedup_key(module, description)
            if dk in self._handled:
                return
            self._handled.add(dk)
            if len(self._handled) > 2000:
                self._handled.clear()
                self._row_index.clear()

            # Derive action tag from severity for the ACTION column
            action = self._severity_to_action(severity, description)
            self._create_row(
                dk, severity, module, "Live Feed",
                description, cmd, timestamp, action, decoded,
            )

        elif direction in ("RX", "TX", "ERROR"):
            # Dynamically classify the decoded UDS text or raw line
            check_text = decoded or raw_line
            if not check_text:
                return

            severity = _classify(check_text)
            # Only surface HIGH and CRITICAL anomalies in the monitor table
            # (LOW/INFO are visible in the Logs tab)
            if severity not in ("critical", "high"):
                # Show in terminal only if debug mode is on
                if hasattr(self, '_debug_toggle') and self._debug_toggle.isChecked():
                    ts = timestamp or _time.strftime("%H:%M:%S")
                    self.terminal.append(
                        f"[{ts}] [DEBUG][{module}] {check_text[:150]}",
                        _C.get("text_muted", "#4a6080")
                    )
                return

            desc = check_text[:200]
            dk   = _dedup_key(module, desc)
            if dk in self._handled:
                self._update_row_counter(dk, timestamp)
                return
            self._handled.add(dk)
            if len(self._handled) > 2000:
                self._handled.clear()
                self._row_index.clear()

            action = self._severity_to_action(severity, desc)
            self._create_row(
                dk, severity, module, "Live Feed",
                desc, "", timestamp, action, check_text,
            )
            self.dm.add_fault(
                severity=severity,
                module=module,
                fault=desc,
                cmd="",
            )

    @staticmethod
    def _severity_to_action(severity: str, text: str) -> str:
        """Derive a concise action tag from severity + text heuristics."""
        t = text.lower()
        if "crash" in t or "reset" in t:
            return "CRASH"
        if "bypass" in t or "unlocked" in t or "security access" in t:
            return "BYPASS_SECURITY"
        if "hang" in t or "timeout" in t or "no response" in t:
            return "HANG"
        if "logic" in t or "unexpected" in t:
            return "LOGIC_ERR"
        if severity == "critical":
            return "CRASH"
        if severity == "high":
            return "LOGIC_ERR"
        return "NRC"

    # -----------------------------------------------------------------------
    #  PATH B & C: DataManager signals
    # -----------------------------------------------------------------------

    @pyqtSlot(object)
    def _on_dm_fault_pushed(self, fault) -> None:
        dk = _dedup_key(fault.module, fault.fault)
        if dk in self._handled:
            return
        self._handled.add(dk)
        if len(self._handled) > 2000:
            self._handled.clear()
            self._row_index.clear()

        severity = getattr(fault, "severity", "medium")
        desc     = fault.fault
        action   = self._severity_to_action(severity, desc)
        ts = _time.strftime("%H:%M:%S")
        self._create_row(
            dk, severity, fault.module, "Live Feed",
            desc, fault.cmd, ts, action, "",
        )

    @pyqtSlot(object)
    def _on_fault_hit(self, fault) -> None:
        desc = fault.fault
        dk   = _dedup_key(fault.module, desc)
        ts   = fault.time_str()
        self._update_row_counter(dk, ts, hit_count=fault.hit_count)

    # -----------------------------------------------------------------------
    #  Row management helpers
    # -----------------------------------------------------------------------

    def _create_row(
        self,
        dk:          bytes,
        severity:    str,
        module:      str,
        source:      str,
        description: str,
        cmd:         str,
        timestamp:   str,
        action:      str = "",
        raw_trigger: str = "",
    ) -> None:
        event = {
            "severity": severity, "source": source, "module": module,
            "description": description, "cmd": cmd, "time": timestamp,
            "action": action,
        }
        self._session_events.append(event)
        self._write_event_to_disk(event)

        row = self._table.rowCount()
        self._table.insertRow(row)
        self._table.setRowHeight(row, 32)
        self._row_index[dk] = row

        sev_color = _SEV_COLORS.get(severity, _C["text_secondary"])
        act_color = _ACT_COLORS.get(action,   _C["text_secondary"])
        src_color = _SRC_COLORS.get(source,   _C["text_secondary"])

        def _item(text, fg=None, center=False):
            it = QTableWidgetItem(str(text))
            if fg:
                it.setForeground(QColor(fg))
            if center:
                it.setTextAlignment(Qt.AlignCenter)
            return it

        self._table.setItem(row, COL_SEV,  _item(severity.upper(), fg=sev_color, center=True))
        self._table.setItem(row, COL_ACT,  _item(action  or "—",   fg=act_color, center=True))
        self._table.setItem(row, COL_MOD,  _item(module))
        self._table.setItem(row, COL_SRC,  _item(source,           fg=src_color, center=True))
        self._table.setItem(row, COL_DESC, _item(description[:220]))
        self._table.setItem(row, COL_HITS, _item("×1",             fg=_C.get("accent_cyan"), center=True))
        self._table.setItem(row, COL_TIME, _item(timestamp or _time.strftime("%H:%M:%S")))
        self._table.scrollToBottom()

        # Terminal — clean professional format, no nested arrow spam
        ts = timestamp or _time.strftime("%H:%M:%S")
        prefix = f"[{ts}] [{severity.upper()}]"
        if source == "Log Replay":
            prefix = f"[{ts}] [REPLAY][{severity.upper()}]"
        mod_tag = f"[{module}]" if module else ""
        self.terminal.append(f"{prefix}{mod_tag} {description[:200]}", sev_color)

        self._vuln_count += 1
        self._count_label.setText(f"{self._vuln_count} unique events")

    def _update_row_counter(self, dk: bytes, timestamp: str, hit_count: int = 0) -> None:
        row = self._row_index.get(dk)
        if row is None or row >= self._table.rowCount():
            return

        hits_item = self._table.item(row, COL_HITS)
        if hits_item:
            try:
                current = int(hits_item.text().lstrip("×"))
            except (ValueError, AttributeError):
                current = 1
            new_count = hit_count if hit_count > current else current + 1
        else:
            new_count = hit_count or 2

        hits_text = f"×{new_count:,}"
        if self._table.item(row, COL_HITS):
            self._table.item(row, COL_HITS).setText(hits_text)
        else:
            ni = QTableWidgetItem(hits_text)
            ni.setForeground(QColor(_C.get("accent_cyan", "#00d4ff")))
            ni.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, COL_HITS, ni)

        if self._table.item(row, COL_TIME) and timestamp:
            self._table.item(row, COL_TIME).setText(timestamp)

    # -----------------------------------------------------------------------
    #  Replay
    # -----------------------------------------------------------------------

    def _browse_replay_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select FucyFuzz Session Log", os.path.expanduser("~"),
            "All Supported (*.log *.csv *.jsonl);;"
            "Log Files (*.log);;CSV (*.csv);;JSONL (*.jsonl);;All Files (*)"
        )
        if path:
            self._replay_path.setText(path)

    def _start_replay(self):
        path = self._replay_path.text().strip()
        if not path:
            self.terminal.append_error("No file selected.")
            return
        if not os.path.isfile(path):
            self.terminal.append_error(f"File not found: {path}")
            return

        self._cancel_replay()
        self._load_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress.setValue(0)
        self._replay_status.setText("Parsing…")
        self._set_status("REPLAYING", "active")
        self.terminal.append_command(f"Load: {os.path.basename(path)}  (dynamic detection)")

        self._replay_qthread = QThread(parent=self)
        self._replay_qthread.setObjectName("ECUMonitor-Replay")
        self._replay_worker = _LogReplayWorker(path)
        self._replay_worker.moveToThread(self._replay_qthread)

        self._replay_qthread.started.connect(self._replay_worker.run)
        self._replay_worker.batch_found.connect(self._on_replay_batch, type=Qt.QueuedConnection)
        self._replay_worker.progress.connect(self._on_replay_progress,  type=Qt.QueuedConnection)
        self._replay_worker.finished.connect(self._on_replay_finished,  type=Qt.QueuedConnection)
        self._replay_worker.error.connect(self._on_replay_error,        type=Qt.QueuedConnection)
        self._replay_worker.finished.connect(self._replay_qthread.quit)
        self._replay_worker.error.connect(self._replay_qthread.quit)
        self._replay_qthread.finished.connect(self._replay_qthread.deleteLater)
        self._replay_qthread.start()

    def _cancel_replay(self):
        if self._replay_worker:
            self._replay_worker.cancel()
        if self._replay_qthread and self._replay_qthread.isRunning():
            self._replay_qthread.quit()
            self._replay_qthread.wait(2000)
        self._replay_worker  = None
        self._replay_qthread = None
        self._cancel_btn.setEnabled(False)
        self._load_btn.setEnabled(True)
        self._progress.setValue(0)
        self._replay_status.setText("")

    @pyqtSlot(list)
    def _on_replay_batch(self, batch: list):
        self._table.setUpdatesEnabled(False)
        try:
            for item in batch:
                (severity, module, description, cmd,
                 timestamp, vuln_id, vuln_name, action,
                 hit_count, dk) = item

                ts = timestamp or _time.strftime("%H:%M:%S")

                if dk in self._handled:
                    self._update_row_counter(dk, ts, hit_count=hit_count)
                    continue

                self._handled.add(dk)
                if len(self._handled) > 2000:
                    self._handled.clear()
                    self._row_index.clear()

                # Re-derive action from dynamic classification
                if not action:
                    action = self._severity_to_action(severity, description)

                event = {
                    "severity": severity, "source": "Log Replay",
                    "module": module, "description": description,
                    "cmd": cmd, "time": ts, "action": action,
                }
                self._session_events.append(event)
                self._write_event_to_disk(event)

                row = self._table.rowCount()
                self._table.insertRow(row)
                self._table.setRowHeight(row, 32)
                self._row_index[dk] = row

                sev_color = _SEV_COLORS.get(severity, _C["text_secondary"])
                act_color = _ACT_COLORS.get(action,   _C["text_secondary"])
                src_color = _SRC_COLORS["Log Replay"]

                def _item(text, fg=None, center=False):
                    it = QTableWidgetItem(str(text))
                    if fg:
                        it.setForeground(QColor(fg))
                    if center:
                        it.setTextAlignment(Qt.AlignCenter)
                    return it

                self._table.setItem(row, COL_SEV,  _item(severity.upper(), fg=sev_color, center=True))
                self._table.setItem(row, COL_ACT,  _item(action  or "—",   fg=act_color, center=True))
                self._table.setItem(row, COL_MOD,  _item(module))
                self._table.setItem(row, COL_SRC,  _item("Log Replay",     fg=src_color, center=True))
                self._table.setItem(row, COL_DESC, _item(description[:220]))
                hits_it = _item(f"×{hit_count:,}" if hit_count > 1 else "×1",
                                fg=_C.get("accent_cyan"), center=True)
                self._table.setItem(row, COL_HITS, hits_it)
                self._table.setItem(row, COL_TIME, _item(ts))

                self.dm.add_fault(
                    severity=severity, module=module,
                    fault=description, cmd=cmd,
                )

                pfx = f"[{ts}] [REPLAY][{severity.upper()}]"
                mod_tag = f"[{module}]" if module else ""
                self.terminal.append(f"{pfx}{mod_tag} {description[:180]}", sev_color)
                self._vuln_count += 1
        finally:
            self._table.setUpdatesEnabled(True)

        self._count_label.setText(f"{self._vuln_count} unique events")
        if self._table.rowCount():
            self._table.scrollToBottom()

    @pyqtSlot(int, int)
    def _on_replay_progress(self, done: int, total: int):
        if total > 0:
            pct = min(int(done * 100 / total), 99)
            self._progress.setValue(pct)
            self._replay_status.setText(f"Scanning… {pct}%")

    @pyqtSlot(int, int)
    def _on_replay_finished(self, n_faults: int, n_lines: int):
        self._progress.setValue(100)
        self._load_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._replay_worker  = None
        self._replay_qthread = None
        msg = (
            f"Replay complete — {n_faults} detected events from {n_lines:,} lines."
            if n_faults else
            f"No anomalies detected in {n_lines:,} lines."
        )
        (self.terminal.append_success if n_faults else self.terminal.append_info)(msg)
        self._replay_status.setText(msg)
        self._set_status("LIVE", "active")

    @pyqtSlot(str)
    def _on_replay_error(self, msg: str):
        self.terminal.append_error(f"Replay error: {msg}")
        self._replay_status.setText(f"Error: {msg}")
        self._load_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._replay_worker  = None
        self._replay_qthread = None
        self._set_status("LIVE", "active")

    # -----------------------------------------------------------------------
    #  Disk persistence
    # -----------------------------------------------------------------------

    def _write_event_to_disk(self, event: dict):
        if not self._session_dir:
            return
        try:
            with open(
                os.path.join(self._session_dir, "events.jsonl"),
                "a", encoding="utf-8",
            ) as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass

    def _write_session_meta(self, session_end):
        if not self._session_dir:
            return
        try:
            with open(
                os.path.join(self._session_dir, "meta.json"),
                "w", encoding="utf-8",
            ) as f:
                json.dump({
                    "session_id":    self._session_id,
                    "session_start": (
                        self._session_start_time.strftime("%Y-%m-%d %H:%M:%S")
                        if self._session_start_time else "N/A"
                    ),
                    "session_end":   session_end or "",
                    "log_path":      self._session_log_path,
                    "event_count":   len(self._session_events),
                }, f, indent=2)
        except Exception:
            pass

    def _load_past_sessions_from_disk(self):
        if not os.path.isdir(self._sessions_root):
            return
        loaded = []
        for entry in sorted(os.listdir(self._sessions_root)):
            sd = os.path.join(self._sessions_root, entry)
            mp = os.path.join(sd, "meta.json")
            ep = os.path.join(sd, "events.jsonl")
            if not os.path.isdir(sd) or not os.path.exists(mp):
                continue
            try:
                with open(mp, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                continue
            events = []
            if os.path.exists(ep):
                try:
                    with open(ep, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    events.append(json.loads(line))
                                except Exception:
                                    pass
                except Exception:
                    pass
            se = meta.get("session_end", "")
            loaded.append({
                "session_id":    meta.get("session_id", entry),
                "session_start": meta.get("session_start", "N/A"),
                "session_end":   se if se else "(incomplete)",
                "log_path":      meta.get("log_path", "N/A"),
                "event_count":   len(events),
                "events":        events,
                "terminal_lines": [],
                "session_dir":   sd,
            })
        self._past_sessions = sorted(loaded, key=lambda s: s.get("session_start", ""))

    # -----------------------------------------------------------------------
    #  Export
    # -----------------------------------------------------------------------

    def get_export_data(self) -> dict:
        events = []
        for row in range(self._table.rowCount()):
            def _t(col, r=row):
                i = self._table.item(r, col)
                return i.text() if i else ""
            events.append({
                "severity":    _t(COL_SEV),
                "action":      _t(COL_ACT),
                "module":      _t(COL_MOD),
                "source":      _t(COL_SRC),
                "description": _t(COL_DESC),
                "hits":        _t(COL_HITS),
                "time":        _t(COL_TIME),
            })
        return {
            "events":         events,
            "log_path":       "SessionLogger (live feed)",
            "terminal_lines": self.terminal.output.toPlainText().splitlines(),
            "event_count":    self._vuln_count,
        }

    def get_session_export_data(self) -> dict:
        return {
            "events":         list(self._session_events),
            "log_path":       self._session_log_path,
            "terminal_lines": self.terminal.output.toPlainText().splitlines(),
            "event_count":    len(self._session_events),
            "session_start":  (
                self._session_start_time.strftime("%Y-%m-%d %H:%M:%S")
                if self._session_start_time else "N/A"
            ),
        }

    def get_past_sessions(self) -> list:
        return list(reversed(self._past_sessions))

    # -----------------------------------------------------------------------
    #  Status badge
    # -----------------------------------------------------------------------

    def _set_status(self, text: str, state: str):
        self._status_badge.setText(text)
        c = {
            "active": _C["success"],
            "idle":   _C["text_secondary"],
            "error":  _C["critical"],
        }.get(state, _C["text_secondary"])
        self._status_badge.setStyleSheet(f"""
            color:{c};background-color:{c}22;
            border:1px solid {c}66;border-radius:3px;
            padding:2px 8px;font-size:9px;letter-spacing:1px;
        """)

    def showEvent(self, event):
        super().showEvent(event)
        self._refresh_can_interfaces()
