"""
Log Viewer Tab  (modules/log_tab.py)
=====================================
Wireshark-style live CAN/UDS log viewer.

Features
--------
  • Live stats banner  — TX / RX / CMD / VULN / ERROR chips, live-updating
  • Wireshark-style table  — Time | Ch | Dir | Arb ID | DLC | Data | Decoded
  • Detail pane  — click any row: metadata + hex dump + full UDS decode
  • Auto-scroll toggle  — pin/unpin with one click
  • Direct Save Log dialog  — ASC / BLF / PCAP / JSONL with REAL timestamps
  • Filter bar  — direction, severity, module, free-text search
  • Post-Processing Analyzer  — load any supported CAN format offline
"""

import os
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QLineEdit, QComboBox,
    QFileDialog, QMessageBox, QPushButton,
    QTabWidget, QSplitter, QApplication, QPlainTextEdit,
    QProgressBar, QDialog,
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, pyqtSlot, QTimer
from PyQt5.QtGui import QColor

from ui.widgets import SectionHeader, GlowButton
from ui.theme import COLORS


# ── UDS decode tables ─────────────────────────────────────────────────────────
_SID_MAP = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDTCInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x50: "DiagSessCtrl_Resp",
    0x51: "ECUReset_Resp",
    0x62: "ReadDataByID_Resp",
    0x67: "SecurityAccess_Resp",
    0x7E: "TesterPresent_Resp",
    0x7F: "NegativeResponse",
}
_NRC_MAP = {
    0x10: "generalReject",          0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",0x13: "incorrectMessageLength",
    0x21: "busyRepeatRequest",      0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",   0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",   0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",0x37: "requiredTimeDelayNotExpired",
    0x78: "responsePending",        0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}
_SESSION_NAMES = {0x01:"DefaultSession",0x02:"ProgrammingSession",
                  0x03:"ExtendedDiagnosticSession",0x40:"SafetySystemDiagnosticSession"}


def _decode_uds_full(data_hex: str) -> str:
    if not data_hex or len(data_hex) < 2:
        return "  (empty payload)"
    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        return "  (invalid hex)"
    if not raw:
        return "  (empty)"

    sid  = raw[0]
    name = _SID_MAP.get(sid, f"Unknown (0x{sid:02X})")
    lines = [f"  Service   : 0x{sid:02X}  {name}"]

    if sid == 0x7F and len(raw) >= 3:
        req_name = _SID_MAP.get(raw[1], f"0x{raw[1]:02X}")
        nrc_name = _NRC_MAP.get(raw[2], f"0x{raw[2]:02X}")
        lines += [f"  Req SID   : 0x{raw[1]:02X}  {req_name}",
                  f"  NRC       : 0x{raw[2]:02X}  {nrc_name}"]
        return "\n".join(lines)

    if sid in (0x10, 0x50) and len(raw) >= 2:
        sname = _SESSION_NAMES.get(raw[1], f"0x{raw[1]:02X}")
        lines.append(f"  SubFunc   : 0x{raw[1]:02X}  {sname}")
        return "\n".join(lines)

    if sid in (0x27, 0x67) and len(raw) >= 2:
        kind = "RequestSeed" if (raw[1] % 2 == 1) else "SendKey"
        lines.append(f"  SubFunc   : 0x{raw[1]:02X}  ({kind})")
        if len(raw) > 2:
            lines.append(f"  Data      : {' '.join(f'{b:02X}' for b in raw[2:])}")
        return "\n".join(lines)

    if sid in (0x22, 0x62) and len(raw) >= 3:
        did = (raw[1] << 8) | raw[2]
        lines.append(f"  DID       : 0x{did:04X}")
        if sid == 0x62 and len(raw) > 3:
            lines.append(f"  Value     : {' '.join(f'{b:02X}' for b in raw[3:])}")
        return "\n".join(lines)

    if sid == 0x11 and len(raw) >= 2:
        rst = {0x01:"HardReset",0x02:"KeyOffOnReset",0x03:"SoftReset"}
        lines.append(f"  ResetType : 0x{raw[1]:02X}  {rst.get(raw[1],'Unknown')}")
        return "\n".join(lines)

    if len(raw) > 1:
        lines.append(f"  Payload   : {' '.join(f'{b:02X}' for b in raw[1:])}")
    return "\n".join(lines)


def _parse_ts_float(ts_str: str) -> float:
    if not ts_str:
        return time.time()
    try:
        s = ts_str.replace("T", " ").replace("Z", "")
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        try:
            return float(ts_str)
        except (ValueError, TypeError):
            return time.time()


# ── Thread-safe bridge ────────────────────────────────────────────────────────
class _LogBridge(QObject):
    entry_received = pyqtSignal(dict)
    def on_entry(self, entry: dict) -> None:
        try:
            self.entry_received.emit(entry)
        except Exception:
            pass


# ── Colour coding ─────────────────────────────────────────────────────────────
_DIR_COLORS = {
    "TX":"#00d4ff","RX":"#10b981","ERROR":"#f43f5e",
    "CMD":"#fbbf24","INFO":"#8fa8c8","VULN":"#f97316",
}
_SEV_COLORS = {
    "CRITICAL":"#f43f5e","HIGH":"#f97316","MEDIUM":"#fbbf24",
    "LOW":"#3b82f6","INFO":"#8fa8c8",
}


class LogTab(QWidget):
    """
    Wireshark-style log viewer with stats banner, detail pane, and
    direct save dialog that writes real timestamps to ASC/BLF/PCAP/JSONL.
    """
    export_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bridge = _LogBridge(self)
        self._bridge.entry_received.connect(self._on_entry, type=Qt.QueuedConnection)
        self._cnt = {"TX":0,"RX":0,"CMD":0,"VULN":0,"ERROR":0}
        self._entry_count  = 0
        self._max_rows     = 5000
        self._auto_scroll  = True
        self._pending: list = []

        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(80)
        self._flush_timer.timeout.connect(self._flush_pending)
        self._flush_timer.start()

        self._setup_ui()
        self._register_with_logger()

    # ─────────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0,0,0,0)
        outer.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border:none; background:{COLORS['bg_primary']}; }}
            QTabBar::tab {{
                background:{COLORS['bg_secondary']}; border:none;
                border-bottom:2px solid transparent;
                padding:9px 20px; color:{COLORS['text_secondary']};
                font-size:11px; font-weight:600; letter-spacing:0.5px;
            }}
            QTabBar::tab:selected {{
                background:{COLORS['bg_card']}; color:{COLORS['accent_cyan']};
                border-bottom:2px solid {COLORS['accent_cyan']};
            }}
            QTabBar::tab:hover:!selected {{
                color:{COLORS['text_primary']}; background:{COLORS['bg_elevated']};
            }}
        """)

        live_tab = QWidget()
        self._setup_live_tab(live_tab)
        self._tabs.addTab(live_tab, "📋  Live Session Log")

        analyzer_tab = QWidget()
        self._setup_analyzer_tab(analyzer_tab)
        self._tabs.addTab(analyzer_tab, "🔬  Post-Processing Analyzer")

        outer.addWidget(self._tabs)

    # ── Live tab ──────────────────────────────────────────────────────────────

    def _setup_live_tab(self, parent: QWidget):
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(14,10,14,10)
        outer.setSpacing(7)

        outer.addWidget(SectionHeader("📋  Live Session Log Viewer"))

        # Toolbar
        tb = QHBoxLayout(); tb.setSpacing(6)

        tb.addWidget(QLabel("Dir:"))
        self._dir_filter = QComboBox()
        self._dir_filter.addItems(["All","TX","RX","ERROR","CMD","INFO","VULN"])
        self._dir_filter.setFixedWidth(85)
        self._dir_filter.currentTextChanged.connect(self._apply_filter)
        tb.addWidget(self._dir_filter)

        tb.addWidget(QLabel("Sev:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All","CRITICAL","HIGH","MEDIUM","LOW","INFO"])
        self._sev_filter.setFixedWidth(90)
        self._sev_filter.currentTextChanged.connect(self._apply_filter)
        tb.addWidget(self._sev_filter)

        tb.addWidget(QLabel("Mod:"))
        self._mod_filter = QComboBox()
        self._mod_filter.addItems(["UDS", "DoIP"])
        self._mod_filter.setFixedWidth(100)
        self._mod_filter.currentTextChanged.connect(self._apply_filter)
        tb.addWidget(self._mod_filter)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search ID, data, decoded …")
        self._search.textChanged.connect(self._apply_filter)
        tb.addWidget(self._search)

        tb.addStretch()

        # Auto-scroll pin button
        self._pin_btn = QPushButton("📌 Pinned")
        self._pin_btn.setCheckable(True)
        self._pin_btn.setChecked(True)
        self._pin_btn.setFixedSize(80,28)
        self._pin_btn.setToolTip("Auto-scroll to latest (click to unpin)")
        self._pin_btn.toggled.connect(self._toggle_autoscroll)
        self._pin_btn.setStyleSheet(self._pin_style(True))
        tb.addWidget(self._pin_btn)

        save_btn = GlowButton("💾 Save Log…", COLORS['accent_green'])
        save_btn.setFixedHeight(28)
        save_btn.setToolTip("Save to ASC / BLF / PCAP / JSONL with real timestamps")
        save_btn.clicked.connect(self._save_log_dialog)
        tb.addWidget(save_btn)

        rpt_btn = GlowButton("📤 Report…", COLORS['accent_purple'])
        rpt_btn.setFixedHeight(28)
        rpt_btn.clicked.connect(self.export_requested.emit)
        tb.addWidget(rpt_btn)

        clr_btn = GlowButton("✕ Clear", COLORS['accent_pink'], danger=True)
        clr_btn.setFixedHeight(28)
        clr_btn.setToolTip("Clear display — disk files untouched")
        clr_btn.clicked.connect(self._clear_display)
        tb.addWidget(clr_btn)

        outer.addLayout(tb)

        # Stats banner
        sb = QHBoxLayout(); sb.setSpacing(6)
        self._chips = {}
        for key, color, label in [
            ("TX",    COLORS['accent_cyan'],   "↑ TX"),
            ("RX",    COLORS['accent_green'],  "↓ RX"),
            ("CMD",   COLORS['accent_yellow'], "⚡ CMD"),
            ("VULN",  COLORS['accent_orange'], "⚠ VULN"),
            ("ERROR", COLORS['critical'],      "✖ ERROR"),
        ]:
            chip = QLabel(f"{label}: 0")
            chip.setAlignment(Qt.AlignCenter)
            chip.setFixedHeight(22)
            chip.setMinimumWidth(76)
            chip.setStyleSheet(f"""
                QLabel {{
                    background:{color}18; border:1px solid {color}55;
                    border-radius:11px; color:{color};
                    font-size:10px; font-weight:700;
                    padding:0 8px;
                }}
            """)
            self._chips[key] = (chip, label)
            sb.addWidget(chip)
        sb.addStretch()
        self._count_lbl = QLabel("0 entries")
        self._count_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        sb.addWidget(self._count_lbl)
        outer.addLayout(sb)

        # Splitter: main table + detail pane
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{COLORS['border']};height:3px;}}"
            f"QSplitter::handle:hover{{background:{COLORS['accent_cyan']}55;}}"
        )

        self._table = self._make_table()
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self._table)

        detail_w = self._make_detail_pane("live")
        splitter.addWidget(detail_w)
        splitter.setSizes([560, 170])
        outer.addWidget(splitter, 1)

        # Status
        st = QHBoxLayout()
        self._session_lbl = QLabel("No active session")
        self._session_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        st.addStretch()
        st.addWidget(self._session_lbl)
        outer.addLayout(st)

        self._all_entries: list = []

    def _make_table(self) -> QTableWidget:
        t = QTableWidget(0, 7)
        t.setHorizontalHeaderLabels([
            "Timestamp","Ch","Dir","Arb ID","DLC","Data (hex)","Decoded / Note"
        ])
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        t.horizontalHeader().setStretchLastSection(True)
        t.verticalHeader().setVisible(False)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.setSortingEnabled(False)
        t.setWordWrap(False)
        for i, w in enumerate([130,50,50,80,40,185,1]):
            if i < 6:
                t.setColumnWidth(i, w)
        t.setStyleSheet(f"""
            QTableWidget {{
                background:{COLORS['bg_card']}; border:1px solid {COLORS['border']};
                gridline-color:{COLORS['border']}; border-radius:6px;
                font-size:11px; outline:none;
                font-family:'JetBrains Mono','Consolas','Courier New',monospace;
            }}
            QTableWidget::item {{ padding:3px 8px; border:none; color:{COLORS['text_primary']}; }}
            QTableWidget::item:selected {{
                background:{COLORS['accent_cyan']}22; color:{COLORS['accent_cyan']};
            }}
            QTableWidget::item:alternate {{ background:{COLORS['bg_secondary']}; }}
            QHeaderView::section {{
                background:{COLORS['bg_secondary']}; border:none;
                border-right:1px solid {COLORS['border']};
                border-bottom:2px solid {COLORS['accent_cyan']}44;
                padding:6px 8px; color:{COLORS['text_secondary']};
                font-size:10px; font-weight:700; letter-spacing:1px;
            }}
        """)
        return t

    def _make_detail_pane(self, prefix: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet(
            f"background:{COLORS['bg_secondary']};border-top:1px solid {COLORS['border']};"
        )
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10,6,10,6)
        lay.setSpacing(12)

        mono = f"""
            QPlainTextEdit {{
                background:{COLORS['bg_card']};
                border:1px solid {COLORS['border']};
                border-radius:4px;
                color:{COLORS['accent_green']};
                font-family:'JetBrains Mono','Consolas','Courier New',monospace;
                font-size:10px; padding:6px;
            }}
        """

        meta = QPlainTextEdit()
        meta.setReadOnly(True)
        meta.setPlaceholderText("Select a row to inspect …")
        meta.setFixedWidth(270)
        meta.setStyleSheet(mono)
        lay.addWidget(meta)

        hex_w = QPlainTextEdit()
        hex_w.setReadOnly(True)
        hex_w.setPlaceholderText("Hex dump …")
        hex_w.setFixedWidth(310)
        hex_w.setStyleSheet(mono)
        lay.addWidget(hex_w)

        uds_w = QPlainTextEdit()
        uds_w.setReadOnly(True)
        uds_w.setPlaceholderText("UDS decode …")
        uds_w.setStyleSheet(mono)
        lay.addWidget(uds_w)

        setattr(self, f"_{prefix}_meta", meta)
        setattr(self, f"_{prefix}_hex",  hex_w)
        setattr(self, f"_{prefix}_uds",  uds_w)
        return w

    # ── Analyzer tab ──────────────────────────────────────────────────────────

    def _setup_analyzer_tab(self, parent: QWidget):
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(14,10,14,10)
        outer.setSpacing(7)

        outer.addWidget(SectionHeader("🔬  Post-Processing Log Analyzer"))

        desc = QLabel(
            "Load any supported CAN log file (.jsonl .log .csv .asc .blf .pcap) "
            "to analyze offline.  All frames shown in the same Wireshark-style table."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(
            f"color:{COLORS['text_secondary']};font-size:10px;background:transparent;"
        )
        outer.addWidget(desc)

        file_row = QHBoxLayout()
        self._az_path = QLineEdit()
        self._az_path.setPlaceholderText(
            "Select .jsonl / .log / .csv / .asc / .blf / .pcap …"
        )
        self._az_path.setStyleSheet(f"""
            QLineEdit {{
                background:{COLORS['bg_secondary']}; border:1px solid {COLORS['border']};
                border-radius:4px; padding:5px 10px; color:{COLORS['text_primary']};
                font-size:11px;
            }}
        """)
        file_row.addWidget(self._az_path)

        browse_btn = GlowButton("📂 Browse", COLORS['accent_cyan'])
        browse_btn.setFixedHeight(30)
        browse_btn.clicked.connect(self._az_browse)
        file_row.addWidget(browse_btn)

        run_btn = GlowButton("▶ Load & Analyse", COLORS['accent_green'])
        run_btn.setFixedHeight(30)
        run_btn.clicked.connect(self._az_run)
        file_row.addWidget(run_btn)

        clr_btn = GlowButton("✕ Clear", COLORS['accent_pink'], danger=True)
        clr_btn.setFixedHeight(30)
        clr_btn.clicked.connect(self._az_clear)
        file_row.addWidget(clr_btn)
        outer.addLayout(file_row)

        self._az_progress = QProgressBar()
        self._az_progress.setRange(0, 0)
        self._az_progress.setFixedHeight(3)
        self._az_progress.setTextVisible(False)
        self._az_progress.setVisible(False)
        self._az_progress.setStyleSheet(f"""
            QProgressBar {{ background:{COLORS['border']}; border:none; border-radius:2px; }}
            QProgressBar::chunk {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {COLORS['accent_cyan']},stop:1 {COLORS['accent_purple']});
                border-radius:2px;
            }}
        """)
        outer.addWidget(self._az_progress)

        self._az_summary = QLabel("")
        self._az_summary.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        outer.addWidget(self._az_summary)

        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{COLORS['border']};height:3px;}}"
        )

        self._az_table = self._make_table()
        self._az_table.itemSelectionChanged.connect(self._az_show_detail)
        splitter.addWidget(self._az_table)

        detail_w = self._make_detail_pane("az")
        splitter.addWidget(detail_w)
        splitter.setSizes([480, 170])
        outer.addWidget(splitter, 1)

        self._az_frames: list = []

    # ── Stats / scroll ────────────────────────────────────────────────────────

    def _update_stats(self) -> None:
        self._count_lbl.setText(
            f"{self._entry_count} entries  |  shown: {self._table.rowCount()}"
        )
        for key, (chip, label) in self._chips.items():
            chip.setText(f"{label}: {self._cnt.get(key, 0)}")

    def _pin_style(self, pinned: bool) -> str:
        color = COLORS['accent_cyan'] if pinned else COLORS['text_muted']
        return (
            f"QPushButton {{ background:{color}18; border:1px solid {color}55; "
            f"border-radius:5px; color:{color}; font-size:10px; font-weight:700; }}"
            f"QPushButton:hover {{ background:{color}35; border-color:{color}; }}"
        )

    def _toggle_autoscroll(self, checked: bool) -> None:
        self._auto_scroll = checked
        self._pin_btn.setText("📌 Pinned" if checked else "📍 Free")
        self._pin_btn.setStyleSheet(self._pin_style(checked))
        if checked:
            self._table.scrollToBottom()

    # ── Detail pane ───────────────────────────────────────────────────────────

    def _on_row_selected(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if item:
            entry = item.data(Qt.UserRole)
            if isinstance(entry, dict):
                self._fill_detail(entry, "live")

    def _az_show_detail(self) -> None:
        row = self._az_table.currentRow()
        if 0 <= row < len(self._az_frames):
            self._fill_detail(self._az_frames[row], "az")

    def _fill_detail(self, entry: dict, prefix: str) -> None:
        meta_w = getattr(self, f"_{prefix}_meta")
        hex_w  = getattr(self, f"_{prefix}_hex")
        uds_w  = getattr(self, f"_{prefix}_uds")

        direction = entry.get("direction", "")
        ts        = entry.get("ts") or entry.get("timestamp", "")
        arb_id    = entry.get("arb_id", "")
        transport = entry.get("transport", "CAN")
        severity  = entry.get("severity", "")
        module    = entry.get("module", "")
        data_hex  = (entry.get("data_hex") or "").replace(" ", "").upper()
        decoded   = entry.get("decoded", "") or entry.get("note", "")
        dlc       = len(data_hex) // 2 if data_hex else 0

        # Metadata
        m_lines = [
            "── Frame Metadata ────────────────",
            f"  Timestamp : {ts}",
            f"  Direction : {direction}",
            f"  Channel   : {transport}",
            f"  Arb ID    : {arb_id}",
            f"  DLC       : {dlc}",
        ]
        if severity:  m_lines.append(f"  Severity  : {severity}")
        if module:    m_lines.append(f"  Module    : {module}")
        if entry.get("src_addr") or entry.get("dst_addr"):
            m_lines.append(f"  Route     : {entry.get('src_addr','')} → {entry.get('dst_addr','')}")
        if entry.get("vuln_id"):   m_lines.append(f"  Vuln ID   : {entry['vuln_id']}")
        if entry.get("vuln_name"): m_lines.append(f"  Vuln      : {entry['vuln_name']}")
        meta_w.setPlainText("\n".join(m_lines))

        # Hex dump
        if data_hex:
            try:
                raw = bytes.fromhex(data_hex)
                h_lines = ["── Hex Dump ─────────────────────────"]
                for i in range(0, len(raw), 8):
                    chunk = raw[i:i+8]
                    off   = f"{i:04X}"
                    hex_p = " ".join(f"{b:02X}" for b in chunk).ljust(23)
                    asc   = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
                    h_lines.append(f"  {off}  {hex_p}  {asc}")
                hex_w.setPlainText("\n".join(h_lines))
            except ValueError:
                hex_w.setPlainText(f"  (bad hex: {data_hex[:40]})")
        else:
            hex_w.setPlainText("── Hex Dump ─────────────────────────\n  (no data)")

        # UDS decode
        u_lines = ["── UDS / Protocol Decode ────────────"]
        if data_hex:
            u_lines.append(_decode_uds_full(data_hex))
        else:
            u_lines.append("  (no payload)")
        if decoded:
            u_lines += ["", "── Application Note ──────────────────", f"  {decoded}"]
        uds_w.setPlainText("\n".join(u_lines))

    # ── Logger connection ─────────────────────────────────────────────────────

    def _register_with_logger(self) -> None:
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.add_gui_callback(self._bridge.on_entry)
                self._update_session_label(sl)
        except Exception:
            pass

    def refresh_logger_connection(self) -> None:
        self._register_with_logger()

    # ── Entry ingestion (batched, non-blocking) ───────────────────────────────

    @pyqtSlot(dict)
    def _on_entry(self, entry: dict) -> None:
        self._pending.append(entry)

    def _flush_pending(self) -> None:
        if not self._pending:
            return
        batch = self._pending[:150]
        self._pending = self._pending[150:]
        for entry in batch:
            self._all_entries.append(entry)
            self._entry_count += 1
            direction = (entry.get("direction") or "INFO").upper()
            if direction in self._cnt:
                self._cnt[direction] += 1
            mod = entry.get("module", "")
            # Dynamic module addition removed as per user request to only keep UDS and DoIP
            if self._passes_filter(entry):
                self._add_row(entry, self._table)

        if self._table.rowCount() > self._max_rows:
            for _ in range(self._table.rowCount() - self._max_rows):
                self._table.removeRow(0)

        self._update_stats()
        if self._auto_scroll:
            self._table.scrollToBottom()

    def _passes_filter(self, entry: dict) -> bool:
        dir_f  = self._dir_filter.currentText()
        sev_f  = self._sev_filter.currentText()
        mod_f  = self._mod_filter.currentText().lower()
        search = self._search.text().strip().lower()
        
        # If 'uds' is selected, show UDS module logs and general CAN logs that aren't DoIP
        # If 'doip' is selected, show DoIP module logs
        if mod_f == "uds" and entry.get("module", "").lower() == "doip":
            return False
        if mod_f == "doip" and entry.get("module", "").lower() != "doip":
            return False
            
        if dir_f != "All" and entry.get("direction") != dir_f:
            return False
        if sev_f != "All" and (entry.get("severity","") or "").upper() != sev_f:
            return False
            
        if search:
            hay = (
                (entry.get("data_hex","") or "").lower()
                + (entry.get("decoded","")  or "").lower()
                + (entry.get("raw_line","") or "").lower()
                + (entry.get("arb_id","")   or "").lower()
                + (entry.get("note","")     or "").lower()
            )
            if search not in hay:
                return False
        return True

    def _apply_filter(self) -> None:
        self._table.setRowCount(0)
        for entry in self._all_entries[-self._max_rows:]:
            if self._passes_filter(entry):
                self._add_row(entry, self._table)
        if self._auto_scroll:
            self._table.scrollToBottom()

    def _add_row(self, entry: dict, table: QTableWidget) -> None:
        row = table.rowCount()
        table.insertRow(row)

        direction = entry.get("direction", "INFO")
        severity  = (entry.get("severity") or "").upper()
        col       = _DIR_COLORS.get(direction, _DIR_COLORS["INFO"])
        is_vuln   = direction == "VULN" or severity == "CRITICAL"
        sev_col   = _SEV_COLORS.get(severity, _SEV_COLORS["INFO"])

        data_hex = (entry.get("data_hex") or "").replace(" ", "")
        hex_disp = " ".join(data_hex[i:i+2] for i in range(0, len(data_hex), 2))

        transport = entry.get("transport", "CAN")
        id_str    = (entry.get("arb_id","") if (not transport or transport=="CAN")
                     else f"{entry.get('src_addr','')}→{entry.get('dst_addr','')}")
        dlc    = str(len(data_hex)//2) if data_hex else "0"
        note   = (entry.get("decoded") or entry.get("note") or
                  entry.get("raw_line",""))[:80]
        if severity in ("CRITICAL","HIGH") and note:
            note = f"[{severity}] {note}"

        values = [
            entry.get("ts") or entry.get("timestamp",""),
            transport, direction, id_str, dlc, hex_disp, note,
        ]
        for c, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            item.setData(Qt.UserRole, entry)
            if is_vuln:
                item.setForeground(QColor(sev_col))
                if c == 2:
                    f = item.font(); f.setBold(True); item.setFont(f)
            else:
                if c == 2:   item.setForeground(QColor(col))
                elif c == 0: item.setForeground(QColor(COLORS['text_muted']))
                elif c == 3: item.setForeground(QColor(COLORS['accent_yellow']))
                elif c == 5: item.setForeground(QColor(COLORS['text_secondary']))
                elif c == 6: item.setForeground(QColor(COLORS['accent_cyan']))
                else:        item.setForeground(QColor(COLORS['text_primary']))
            table.setItem(row, c, item)
        table.setRowHeight(row, 24)

    def _clear_display(self) -> None:
        self._table.setRowCount(0)
        self._all_entries.clear()
        self._entry_count = 0
        for k in self._cnt: self._cnt[k] = 0
        self._update_stats()
        for attr in ("_live_meta","_live_hex","_live_uds"):
            getattr(self, attr, None) and getattr(self, attr).clear()
        self._count_lbl.setText("0 entries  (display cleared — disk files intact)")

    # ── Direct Save Log dialog (no OverallReportDialog hack) ─────────────────

    def _save_log_dialog(self) -> None:
        visible = [e for e in self._all_entries if self._passes_filter(e)]
        if not visible:
            QMessageBox.warning(self, "Empty Log", "No visible entries to save.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Save Log — Choose Format")
        dlg.setFixedWidth(330)
        dlg.setModal(True)
        dlg.setStyleSheet(f"""
            QDialog {{
                background:{COLORS['bg_secondary']};
                border:1px solid {COLORS['border_bright']};
                border-radius:10px;
            }}
        """)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(20,20,20,18)
        lay.setSpacing(8)

        hdr = QLabel("💾  Save Log Entries")
        hdr.setStyleSheet(f"""
            color:{COLORS['text_primary']};font-size:14px;
            font-weight:700;padding-bottom:4px;background:transparent;
        """)
        lay.addWidget(hdr)

        info = QLabel(f"{len(visible)} entries  •  real timestamps preserved")
        info.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        lay.addWidget(info)

        chosen = [None]
        has_doip = any(e.get("transport") == "DoIP" for e in visible)
        
        options = []
        if not has_doip:
            options += [
                ("asc",  "📤  Vector ASC  (.asc)",       COLORS['accent_yellow'], "CANalyzer / CANdb++ — absolute timestamps"),
                ("blf",  "📥  Vector BLF  (.blf)",        COLORS['accent_green'], "Vector binary format — requires python-can")
            ]
        options += [
            ("pcap", "🕸  PCAP  (.pcap)",              COLORS['accent_purple'], "Wireshark PCAP (CAN / DoIP)"),
            ("jsonl","📋  FucyFuzz JSONL  (.jsonl)",   COLORS['accent_cyan'], "Native format — fully lossless replay-ready")
        ]

        for fmt, label, color, tip in options:
            btn = QPushButton(label)
            btn.setFixedHeight(40)
            btn.setToolTip(tip)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background:{color}18; border:1px solid {color}55;
                    border-radius:6px; color:{color};
                    font-size:12px; font-weight:600;
                    padding:0 14px; text-align:left;
                }}
                QPushButton:hover {{ background:{color}35; border-color:{color}; }}
            """)
            btn.clicked.connect(lambda _, f=fmt: (chosen.__setitem__(0, f), dlg.accept()))
            lay.addWidget(btn)

        cancel = QPushButton("Cancel")
        cancel.setFixedHeight(32)
        cancel.setStyleSheet(f"""
            QPushButton {{
                background:transparent; border:1px solid {COLORS['border']};
                border-radius:6px; color:{COLORS['text_muted']}; font-size:11px;
            }}
            QPushButton:hover {{ border-color:{COLORS['border_bright']}; color:{COLORS['text_primary']}; }}
        """)
        cancel.clicked.connect(dlg.reject)
        lay.addWidget(cancel)

        if dlg.exec_() != QDialog.Accepted or chosen[0] is None:
            return

        fmt = chosen[0]
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext_map = {
            "asc":  ("Vector ASC (*.asc)",      f"fucyfuzz_log_{stamp}.asc"),
            "blf":  ("Vector BLF (*.blf)",      f"fucyfuzz_log_{stamp}.blf"),
            "pcap": ("PCAP Capture (*.pcap)",   f"fucyfuzz_log_{stamp}.pcap"),
            "jsonl":("FucyFuzz JSONL (*.jsonl)",f"fucyfuzz_log_{stamp}.jsonl"),
        }
        file_filter, default_name = ext_map[fmt]
        dst, _ = QFileDialog.getSaveFileName(self, "Save Log", default_name, file_filter)
        if not dst:
            return

        from utils import export_manager
        if fmt == "asc":
            ok, msg = export_manager.export_logs_asc(None, dst, packets=visible)
        elif fmt == "blf":
            ok, msg = export_manager.export_logs_blf(None, dst, packets=visible)
        elif fmt == "pcap":
            ok, msg = export_manager.export_logs_pcap(None, dst, packets=visible)
        else:
            ok, msg = export_manager.export_json(None, dst, packets=visible)

        if ok:
            QMessageBox.information(self, "Saved", msg)
        else:
            QMessageBox.critical(self, "Export Failed", msg)

    # ── Post-Processing Analyzer ──────────────────────────────────────────────

    def _az_browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Log File", "",
            "CAN Logs (*.jsonl *.log *.csv *.asc *.blf *.pcap);;"
            "All Files (*)"
        )
        if path:
            self._az_path.setText(path)

    def _az_run(self):
        path = self._az_path.text().strip()
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Not Found", "Please select a valid log file.")
            return
        self._az_clear()
        self._az_progress.setVisible(True)
        self._az_summary.setText("Loading …")
        QApplication.processEvents()
        try:
            from utils.replay_loader import load_file
            frames, meta = load_file(path)
            for i, frame in enumerate(frames):
                ts_dt = datetime.fromtimestamp(frame["ts_float"])
                ts_str = ts_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:23]
                entry = {
                    "ts":        ts_str,
                    "timestamp": ts_str,
                    "direction": frame["direction"],
                    "transport": frame.get("channel","CAN"),
                    "arb_id":    frame["arb_id"],
                    "data_hex":  frame["data_hex"],
                    "decoded":   frame.get("decoded",""),
                    "severity":  frame.get("severity","INFO"),
                }
                self._az_frames.append(entry)
                self._add_row(entry, self._az_table)
                if i % 200 == 0:
                    QApplication.processEvents()

            self._az_summary.setText(
                f"✓  {meta['count']} frames  ·  "
                f"TX: {meta['tx_count']}  RX: {meta['rx_count']}  ·  "
                f"Duration: {meta['time_range_s']:.3f}s  ·  "
                f"Start: {meta['ts_start']}"
            )
            self._az_summary.setStyleSheet(
                f"color:{COLORS['success']};font-size:10px;font-weight:600;"
                f"background:transparent;"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Load Error", str(exc))
            self._az_summary.setText(f"Error: {exc}")
            self._az_summary.setStyleSheet(
                f"color:{COLORS['critical']};font-size:10px;background:transparent;"
            )
        finally:
            self._az_progress.setVisible(False)

    def _az_clear(self):
        self._az_table.setRowCount(0)
        self._az_frames.clear()
        for attr in ("_az_meta","_az_hex","_az_uds"):
            w = getattr(self, attr, None)
            if w:
                w.clear()
        self._az_summary.setText("")

    # ── Status label ──────────────────────────────────────────────────────────

    def _update_session_label(self, sl) -> None:
        if sl:
            self._session_lbl.setText(
                f"Session: {sl.session_id}  |  {sl.session_dir}"
            )
