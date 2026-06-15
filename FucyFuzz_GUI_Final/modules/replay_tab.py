"""
Replay Tab  (modules/replay_tab.py)  — COMPLETE REWRITE
=========================================================
Automotive-standard CAN frame replay with multi-format loading.

Layout  (3-column QSplitter)
─────────────────────────────────────────────────────────────────
Column 1 (~290px)  Load + Config panel
  • Multi-format file browser  (JSONL / LOG / CSV / ASC / BLF / PCAP)
  • CAN interface selector
  • Timing mode  (Original Timing / Custom Delay / Scaled Timing / Burst)
  • Loop count  (1× / 2× / 3× / 5× / 10× / ∞)
  • Progress bar + frame counter
  • Action buttons  (Dry Run / ▶ Replay / ⏹ Stop)

Column 2 (~520px)  Frame List table
  • Columns: # | ✓ | Time | Δt (ms) | ID | DLC | Data | Decoded | Sev
  • Per-row checkbox — replay only checked rows
  • Search / filter bar
  • Right-click context menu: replay single frame / edit payload / toggle include

Column 3 (~380px)  Terminal + Live Stats
  • Standard TerminalWidget (non-blocking)
  • Live stats panel: elapsed / frames sent / errors / frames-per-sec

Timing Modes
────────────
  Original Timing  — use real inter-frame delta_ms from loaded log
  Custom Delay     — fixed gap between all frames (ms spinbox)
  Scaled Timing    — original delta × scale factor (0.1×–5.0×)
  Burst Mode       — no inter-frame delay at all

Multi-format loading via utils/replay_loader.py
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import List, Dict, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QFileDialog, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView,
    QSplitter, QComboBox, QDoubleSpinBox, QSpinBox,
    QFrame, QPushButton, QScrollArea, QProgressBar,
    QCheckBox, QSizePolicy, QMenu, QAction,
    QMessageBox, QApplication,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QPoint
from PyQt5.QtGui import QColor

from ui.widgets import SectionHeader, GlowButton, TerminalWidget
from ui.theme import COLORS, FONT_MONO
from utils.config import get_config


# ── UDS SID map (for replay display) ─────────────────────────────────────────
_SID_MAP = {
    0x10:"DiagnosticSessionControl", 0x11:"ECUReset",
    0x14:"ClearDTCInformation",      0x19:"ReadDTCInformation",
    0x22:"ReadDataByIdentifier",     0x23:"ReadMemoryByAddress",
    0x27:"SecurityAccess",           0x28:"CommunicationControl",
    0x2E:"WriteDataByIdentifier",    0x3D:"WriteMemoryByAddress",
    0x3E:"TesterPresent",            0x50:"DiagSessCtrl_Resp",
    0x51:"ECUReset_Resp",            0x62:"ReadDataByID_Resp",
    0x67:"SecurityAccess_Resp",      0x7E:"TesterPresent_Resp",
    0x7F:"NegativeResponse",
}

_SEV_COLORS = {
    "CRITICAL": COLORS['critical'],
    "HIGH":     COLORS.get('high', "#f97316"),
    "MEDIUM":   COLORS.get('medium', "#fbbf24"),
    "LOW":      COLORS.get('low',  "#3b82f6"),
    "INFO":     COLORS['text_secondary'],
}


# ─────────────────────────────────────────────────────────────────────────────
# ISO-TP framing helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_isotp_frames(payload_hex: str) -> list:
    """Convert UDS payload hex into ISO-TP CAN data bytes (list of hex strings)."""
    try:
        data = bytes.fromhex(payload_hex.replace(" ", "").upper())
    except ValueError:
        return []
    length = len(data)
    frames = []
    if length <= 7:
        frame = bytes([length]) + data + bytes(7 - length)
        frames.append(frame.hex().upper())
    else:
        ff_b0 = 0x10 | ((length >> 8) & 0x0F)
        ff_b1 = length & 0xFF
        frames.append((bytes([ff_b0, ff_b1]) + data[:6]).hex().upper())
        remaining = data[6:]
        seq = 1
        while remaining:
            chunk     = remaining[:7]
            remaining = remaining[7:]
            frame     = bytes([0x20 | (seq & 0x0F)]) + chunk + bytes(7 - len(chunk))
            frames.append(frame.hex().upper())
            seq = (seq + 1) % 16
    return frames


# ─────────────────────────────────────────────────────────────────────────────
# Replay Worker
# ─────────────────────────────────────────────────────────────────────────────

class ReplayWorker(QObject):
    """
    Sends CAN frames in a background thread.

    Timing modes
    ────────────
      "original"  — use frame["delta_ms"] (real inter-frame gap from log)
      "custom"    — fixed delay_ms between every frame
      "scaled"    — frame["delta_ms"] * scale_factor
      "burst"     — no delay
    """
    progress   = pyqtSignal(int, int)      # (frame_index, total)
    log_line   = pyqtSignal(str, str)      # (text, color)
    stats_tick = pyqtSignal(dict)          # live stats dict
    finished   = pyqtSignal(bool, str)     # (success, message)

    def __init__(self, frames: list, interface: str,
                 timing_mode: str = "custom",
                 delay_ms: float = 10.0,
                 scale_factor: float = 1.0,
                 loop_count: int = 1,
                 dry_run: bool = False,
                 doip_host: str = "127.0.0.1",
                 doip_port: int = 13400):
        super().__init__()
        self._frames       = frames
        self._iface        = interface
        self._timing_mode  = timing_mode
        self._delay_ms     = delay_ms
        self._scale        = scale_factor
        self._loop_count   = loop_count   # -1 = infinite
        self._dry_run      = dry_run
        self._doip_host    = doip_host
        self._doip_port    = doip_port
        self._stop         = False
        self._sent         = 0
        self._errors       = 0
        self._t_start      = 0.0

    def run(self):
        self._t_start = time.monotonic()
        total = len(self._frames)
        if total == 0:
            self.finished.emit(False, "No frames to replay.")
            return

        doip_client = None
        cfg = None
        if self._iface == "doip":
            from protocol_layer.doip_layer import DoIPClient
            from utils.config import get_config
            cfg = get_config().get_doip_params()
            try:
                l_addr = int(cfg['logical_address'], 16) if isinstance(cfg['logical_address'], str) else cfg['logical_address']
                doip_client = DoIPClient(host=self._doip_host, port=self._doip_port, logical_address=l_addr)
                ok, err = doip_client.connect()
                if not ok:
                    self.finished.emit(False, f"DoIP connect failed: {err}")
                    return
                doip_client.activate_routing()
            except Exception as e:
                self.finished.emit(False, f"DoIP initialization failed: {e}")
                return

        try:
            loop_n = 0
            while True:
                loop_n += 1
                if self._stop:
                    break
                loop_label = f"[Loop {loop_n}] " if self._loop_count != 1 else ""

                for idx, frame in enumerate(self._frames):
                    if self._stop:
                        self.finished.emit(False, f"Replay aborted after {self._sent} frames.")
                        return

                    if not frame.get("include", True):
                        continue

                    arb_id   = frame.get("arb_id", "7E0").upper().lstrip("0X") or "7E0"
                    data_hex = (frame.get("data_hex") or "").replace(" ", "").upper()
                    severity = (frame.get("severity") or "INFO").upper()
                    decoded  = frame.get("decoded", "")
                    ts_rel   = frame.get("ts_rel", 0.0)
                    delta_ms = frame.get("delta_ms", 0.0)

                    sev_color = _SEV_COLORS.get(severity, _SEV_COLORS["INFO"])

                    if not data_hex:
                        self.log_line.emit(
                            f"  {loop_label}[{idx+1}/{total}] SKIP (empty payload)", COLORS['text_muted']
                        )
                        continue

                    self.progress.emit(idx, total)

                    # Build log line
                    sid_name = ""
                    if len(data_hex) >= 2:
                        try:
                            sid_name = _SID_MAP.get(int(data_hex[:2], 16), "")
                        except ValueError:
                            pass
                    note = f"  // {decoded[:45]}" if decoded else ""
                    sev_tag = f" <{severity}>" if severity not in ("INFO", "") else ""
                    ts_tag  = f" @{ts_rel:.4f}s" if ts_rel else ""

                    if self._iface == "doip":
                        try:
                            payload = bytes.fromhex(data_hex)
                            service = payload[0]
                            data_bytes = payload[1:]
                        except Exception:
                            self.log_line.emit(f"  {loop_label}[{idx+1}/{total}] SKIP (bad hex)", COLORS['text_muted'])
                            continue
                        cmd_str = f"doip_send {arb_id} {data_hex}"
                        line = f"  {loop_label}[{idx+1}/{total}]{sev_tag}{ts_tag}  {sid_name}  {cmd_str}{note}"
                        self.log_line.emit(line, sev_color)
                        if not self._dry_run:
                            try:
                                t_addr = int(arb_id, 16) if arb_id and len(arb_id) <= 4 else int(cfg['target_address'], 16) if isinstance(cfg['target_address'], str) else cfg['target_address']
                                ok, resp = doip_client.send_uds(service, data_bytes, target_address=t_addr)
                                if not ok:
                                    self.log_line.emit(f"    ERROR: {resp}", COLORS['critical'])
                                    self._errors += 1
                            except Exception as exc:
                                self.log_line.emit(f"    EXCEPTION: {exc}", COLORS['critical'])
                                self._errors += 1
                    else:
                        isotp_frames = build_isotp_frames(data_hex)
                        if not isotp_frames:
                            self.log_line.emit(
                                f"  {loop_label}[{idx+1}/{total}] SKIP (bad hex: {data_hex[:12]})",
                                COLORS['text_muted']
                            )
                            continue

                        for j, raw_frame in enumerate(isotp_frames):
                            cmd_str = f"cansend {self._iface} {arb_id}#{raw_frame}"
                            label = f"{loop_label}[{idx+1}/{total}]"
                            if j == 0:
                                line = f"  {label}{sev_tag}{ts_tag}  {sid_name}  {cmd_str}{note}"
                            else:
                                line = f"    [CF{j}]  {cmd_str}"

                            self.log_line.emit(line, sev_color)

                            if not self._dry_run:
                                try:
                                    res = subprocess.run(
                                        ["cansend", self._iface, f"{arb_id}#{raw_frame}"],
                                        capture_output=True, text=True, timeout=2
                                    )
                                    if res.returncode != 0:
                                        err_msg = res.stderr.strip()
                                        self.log_line.emit(
                                            f"    ERROR: {err_msg}", COLORS['critical']
                                        )
                                        self._errors += 1
                                except FileNotFoundError:
                                    self.finished.emit(
                                        False,
                                        "cansend not found.  Install: sudo apt install can-utils"
                                    )
                                    return
                                except subprocess.TimeoutExpired:
                                    self.log_line.emit("    TIMEOUT on cansend", COLORS['critical'])
                                    self._errors += 1
                                except Exception as exc:
                                    self.log_line.emit(f"    EXCEPTION: {exc}", COLORS['critical'])
                                    self._errors += 1
                            # Small gap between multi-frame segments
                            if j == 0 and len(isotp_frames) > 1:
                                time.sleep(0.020)
                            elif j > 0:
                                time.sleep(0.005)

                    self._sent += 1

                    # Emit live stats every 10 frames
                    if self._sent % 10 == 0:
                        elapsed = time.monotonic() - self._t_start
                        fps = self._sent / elapsed if elapsed > 0 else 0.0
                        self.stats_tick.emit({
                            "sent":   self._sent,
                            "total":  total,
                            "errors": self._errors,
                            "elapsed": elapsed,
                            "fps":    fps,
                        })

                    # Inter-frame timing
                    if not self._dry_run:
                        if self._timing_mode == "original":
                            sleep_s = max(0.0, delta_ms / 1000.0)
                        elif self._timing_mode == "scaled":
                            sleep_s = max(0.0, (delta_ms * self._scale) / 1000.0)
                        elif self._timing_mode == "burst":
                            sleep_s = 0.0
                        else:  # custom
                            sleep_s = self._delay_ms / 1000.0
                        if sleep_s > 0:
                            time.sleep(sleep_s)

                # End of one loop pass
                if self._loop_count == -1:     # infinite
                    continue
                if loop_n >= self._loop_count:
                    break
        finally:
            if doip_client:
                doip_client.close()

        elapsed = time.monotonic() - self._t_start
        fps = self._sent / elapsed if elapsed > 0 else 0.0
        mode_label = "DRY RUN" if self._dry_run else "Replay"
        self.finished.emit(
            True,
            f"{mode_label} complete — {self._sent} frames in {elapsed:.2f}s "
            f"({fps:.1f} fr/s)  errors: {self._errors}"
        )

    def stop(self):
        self._stop = True


# ─────────────────────────────────────────────────────────────────────────────
# Replay Tab
# ─────────────────────────────────────────────────────────────────────────────

class ReplayTab(QWidget):
    """
    3-column automotive replay tab.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cfg          = get_config()
        self._frames: List[Dict] = []
        self._worker     = None
        self._thread     = None
        self._t_replay_start = 0.0
        self._setup_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI Setup
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(SectionHeader("🔁  CAN Replay — Automotive Attack Simulation"))

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{COLORS['border']};width:2px;}}"
            f"QSplitter::handle:hover{{background:{COLORS['accent_cyan']}55;}}"
        )

        # Column 1: Config panel
        col1 = self._build_config_panel()
        splitter.addWidget(col1)

        # Column 2: Frame list
        col2 = self._build_frame_list()
        splitter.addWidget(col2)

        # Column 3: Terminal + stats
        col3 = self._build_terminal_panel()
        splitter.addWidget(col3)

        splitter.setSizes([290, 520, 380])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setCollapsible(2, False)
        root.addWidget(splitter, 1)

    # ── Column 1: Config panel ────────────────────────────────────────────────

    def _build_config_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            f"QScrollArea {{ border:none; background:{COLORS['bg_primary']}; }}"
        )
        inner = QWidget()
        inner.setStyleSheet(f"background:{COLORS['bg_primary']};")
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(14)

        # ── File Load ─────────────────────────────────────────────────────
        load_grp = self._grp("📂  LOAD LOG FILE")
        lg = QVBoxLayout(load_grp)
        lg.setSpacing(6)

        fmt_lbl = QLabel(
            "Supported: .jsonl  .log  .csv  .asc  .blf  .pcap"
        )
        fmt_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:9px;background:transparent;"
        )
        lg.addWidget(fmt_lbl)

        self._file_path = QLineEdit()
        self._file_path.setPlaceholderText("Select or paste file path …")
        self._file_path.returnPressed.connect(self._load_file)
        lg.addWidget(self._file_path)

        btn_row = QHBoxLayout()
        browse = GlowButton("📂 Browse", COLORS['accent_cyan'])
        browse.setFixedHeight(30)
        browse.clicked.connect(self._browse_file)
        btn_row.addWidget(browse)
        load_btn = GlowButton("⬆ Load", COLORS['accent_green'])
        load_btn.setFixedHeight(30)
        load_btn.clicked.connect(self._load_file)
        btn_row.addWidget(load_btn)
        lg.addLayout(btn_row)

        self._load_info = QLabel("No file loaded")
        self._load_info.setWordWrap(True)
        self._load_info.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        lg.addWidget(self._load_info)
        layout.addWidget(load_grp)

        # ── CAN Interface ─────────────────────────────────────────────────
        iface_grp = self._grp("🔌  CAN INTERFACE")
        ifg = QVBoxLayout(iface_grp)
        ifg.setSpacing(6)

        iface_row = QHBoxLayout()
        self._iface = QLineEdit(self.cfg.get("can_interface", "vcan0"))
        self._iface.setPlaceholderText("vcan0 / can0 / PCAN_USBBUS1")
        iface_row.addWidget(self._iface)
        ifg.addLayout(iface_row)

        iface_presets = QHBoxLayout()
        for preset in ("vcan0", "can0", "doip"):
            pb = QPushButton(preset)
            pb.setFixedHeight(24)
            pb.setStyleSheet(f"""
                QPushButton {{
                    background:{COLORS['bg_elevated']};
                    border:1px solid {COLORS['border']};
                    border-radius:4px; color:{COLORS['text_secondary']};
                    font-size:10px; padding:0 6px;
                }}
                QPushButton:hover {{ border-color:{COLORS['accent_cyan']}; color:{COLORS['accent_cyan']}; }}
            """)
            pb.clicked.connect(lambda _, v=preset: self._iface.setText(v))
            iface_presets.addWidget(pb)
        ifg.addLayout(iface_presets)
        layout.addWidget(iface_grp)

        # ── DoIP Settings ─────────────────────────────────────────────────
        self._doip_settings = QWidget()
        self._doip_layout = QVBoxLayout(self._doip_settings)
        self._doip_layout.setContentsMargins(0, 0, 0, 0)
        self._doip_layout.setSpacing(6)
        
        doip_host_row = QHBoxLayout()
        doip_host_row.addWidget(QLabel("DoIP Host:"))
        self._doip_host = QLineEdit(self.cfg.get("doip_host", "127.0.0.1"))
        self._doip_host.setPlaceholderText("IP Address")
        doip_host_row.addWidget(self._doip_host)
        self._doip_layout.addLayout(doip_host_row)
        
        doip_port_row = QHBoxLayout()
        doip_port_row.addWidget(QLabel("DoIP Port:"))
        self._doip_port = QSpinBox()
        self._doip_port.setRange(1, 65535)
        self._doip_port.setValue(int(self.cfg.get("doip_port", 13400)))
        doip_port_row.addWidget(self._doip_port)
        self._doip_layout.addLayout(doip_port_row)
        
        ifg.addWidget(self._doip_settings)
        
        self._iface.textChanged.connect(lambda t: self._doip_settings.setVisible(t.lower() == "doip"))
        self._doip_settings.setVisible(self._iface.text().lower() == "doip")

        # ── Timing Mode ───────────────────────────────────────────────────
        timing_grp = self._grp("⏱  TIMING MODE")
        tg = QVBoxLayout(timing_grp)
        tg.setSpacing(6)

        self._timing_mode = QComboBox()
        self._timing_mode.addItems([
            "Original Timing  (real inter-frame gaps)",
            "Custom Delay  (fixed ms between frames)",
            "Scaled Timing  (original × factor)",
            "Burst Mode  (no delay — max speed)",
        ])
        self._timing_mode.currentIndexChanged.connect(self._on_timing_changed)
        tg.addWidget(self._timing_mode)

        # Custom delay row
        self._custom_delay_row = QHBoxLayout()
        self._custom_delay_row.addWidget(QLabel("Delay (ms):"))
        self._delay_spin = QDoubleSpinBox()
        self._delay_spin.setRange(0.1, 10000.0)
        self._delay_spin.setValue(10.0)
        self._delay_spin.setSingleStep(1.0)
        self._delay_spin.setDecimals(1)
        self._delay_spin.setFixedWidth(90)
        self._custom_delay_row.addWidget(self._delay_spin)
        self._custom_delay_row.addStretch()
        tg.addLayout(self._custom_delay_row)

        # Scale factor row
        self._scale_row = QHBoxLayout()
        self._scale_row.addWidget(QLabel("Scale:"))
        self._scale_spin = QDoubleSpinBox()
        self._scale_spin.setRange(0.05, 10.0)
        self._scale_spin.setValue(1.0)
        self._scale_spin.setSingleStep(0.1)
        self._scale_spin.setDecimals(2)
        self._scale_spin.setFixedWidth(80)
        self._scale_row.addWidget(self._scale_spin)
        self._scale_row.addWidget(QLabel("×  (1.0 = real-time)"))
        self._scale_row.addStretch()
        tg.addLayout(self._scale_row)

        self._on_timing_changed(0)
        layout.addWidget(timing_grp)

        # ── Loop Count ────────────────────────────────────────────────────
        loop_grp = self._grp("🔄  LOOP COUNT")
        lg2 = QVBoxLayout(loop_grp)
        self._loop_combo = QComboBox()
        self._loop_combo.addItems(["1×  (single pass)", "2×", "3×", "5×", "10×", "∞  (until stopped)"])
        lg2.addWidget(self._loop_combo)
        layout.addWidget(loop_grp)

        # ── Frame Filter ──────────────────────────────────────────────────
        filter_grp = self._grp("🔽  FRAME SELECTION")
        fg = QVBoxLayout(filter_grp)
        sel_row = QHBoxLayout()
        sel_all = QPushButton("☑ All")
        sel_none = QPushButton("☐ None")
        sel_tx   = QPushButton("TX only")
        sel_rx   = QPushButton("RX only")
        for b in (sel_all, sel_none, sel_tx, sel_rx):
            b.setFixedHeight(26)
            b.setStyleSheet(self._mini_btn_style(COLORS['accent_cyan']))
            sel_row.addWidget(b)
        sel_all.clicked.connect(lambda: self._select_rows(True,  None))
        sel_none.clicked.connect(lambda: self._select_rows(False, None))
        sel_tx.clicked.connect(lambda:  self._select_rows(True,  "TX"))
        sel_rx.clicked.connect(lambda:  self._select_rows(True,  "RX"))
        fg.addLayout(sel_row)
        layout.addWidget(filter_grp)

        # ── Progress ──────────────────────────────────────────────────────
        prog_grp = self._grp("📊  PROGRESS")
        pg = QVBoxLayout(prog_grp)
        pg.setSpacing(4)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedHeight(8)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setStyleSheet(f"""
            QProgressBar {{ background:{COLORS['border']}; border:none; border-radius:4px; }}
            QProgressBar::chunk {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {COLORS['accent_cyan']},stop:1 {COLORS['accent_purple']});
                border-radius:4px;
            }}
        """)
        pg.addWidget(self._progress_bar)

        self._progress_lbl = QLabel("Ready")
        self._progress_lbl.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        pg.addWidget(self._progress_lbl)
        layout.addWidget(prog_grp)

        # ── Action Buttons ────────────────────────────────────────────────
        actions_grp = self._grp("▶  ACTIONS")
        ag = QVBoxLayout(actions_grp)
        ag.setSpacing(6)

        self._dry_btn = GlowButton("🔍 Dry Run  (preview timing)", COLORS['accent_yellow'])
        self._dry_btn.setFixedHeight(36)
        self._dry_btn.setEnabled(False)
        self._dry_btn.clicked.connect(self._start_dry_run)
        ag.addWidget(self._dry_btn)

        self._replay_btn = GlowButton("▶  REPLAY ATTACK", COLORS['accent_green'])
        self._replay_btn.setFixedHeight(40)
        self._replay_btn.setEnabled(False)
        self._replay_btn.clicked.connect(self._start_replay)
        ag.addWidget(self._replay_btn)

        self._stop_btn = GlowButton("⏹  STOP", COLORS['critical'], danger=True)
        self._stop_btn.setFixedHeight(36)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_replay)
        ag.addWidget(self._stop_btn)

        layout.addWidget(actions_grp)

        layout.addStretch()
        scroll.setWidget(inner)
        return scroll

    # ── Column 2: Frame List ──────────────────────────────────────────────────

    def _build_frame_list(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background:{COLORS['bg_primary']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 12, 8, 8)
        lay.setSpacing(6)

        hdr = QLabel("📋  FRAME LIST")
        hdr.setStyleSheet(f"""
            color:{COLORS['accent_cyan']};font-size:10px;font-weight:700;
            letter-spacing:2px;background:transparent;padding-left:4px;
        """)
        lay.addWidget(hdr)

        # Search row
        search_row = QHBoxLayout()
        self._frame_search = QLineEdit()
        self._frame_search.setPlaceholderText("Filter frames: ID, data, decoded …")
        self._frame_search.textChanged.connect(self._filter_frames)
        search_row.addWidget(self._frame_search)

        self._sev_combo = QComboBox()
        self._sev_combo.addItems(["All Severity","CRITICAL","HIGH","MEDIUM","LOW","INFO"])
        self._sev_combo.setFixedWidth(110)
        self._sev_combo.currentTextChanged.connect(self._filter_frames)
        search_row.addWidget(self._sev_combo)

        self._dir_combo = QComboBox()
        self._dir_combo.addItems(["All Dir","TX","RX"])
        self._dir_combo.setFixedWidth(80)
        self._dir_combo.currentTextChanged.connect(self._filter_frames)
        search_row.addWidget(self._dir_combo)

        lay.addLayout(search_row)

        # Table
        self._frame_table = QTableWidget(0, 9)
        self._frame_table.setHorizontalHeaderLabels([
            "#", "✓", "Rel Time (s)", "Δt (ms)", "Arb ID", "DLC", "Data (hex)", "Decoded", "Sev"
        ])
        self._frame_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._frame_table.horizontalHeader().setStretchLastSection(False)
        self._frame_table.verticalHeader().setVisible(False)
        self._frame_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._frame_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._frame_table.setAlternatingRowColors(True)
        self._frame_table.setSortingEnabled(False)
        self._frame_table.setWordWrap(False)
        self._frame_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._frame_table.customContextMenuRequested.connect(self._frame_context_menu)
        self._frame_table.cellClicked.connect(self._on_cell_clicked)

        for i, w_ in enumerate([38, 32, 105, 72, 65, 38, 165, 155, 65]):
            self._frame_table.setColumnWidth(i, w_)
        hh = self._frame_table.horizontalHeader()
        hh.setSectionResizeMode(7, QHeaderView.Stretch)

        self._frame_table.setStyleSheet(f"""
            QTableWidget {{
                background:{COLORS['bg_card']}; border:1px solid {COLORS['border']};
                gridline-color:{COLORS['border']}; border-radius:6px;
                font-size:11px; outline:none;
                font-family:'JetBrains Mono','Consolas','Courier New',monospace;
            }}
            QTableWidget::item {{ padding:3px 6px; border:none; color:{COLORS['text_primary']}; }}
            QTableWidget::item:selected {{
                background:{COLORS['accent_cyan']}22; color:{COLORS['accent_cyan']};
            }}
            QTableWidget::item:alternate {{ background:{COLORS['bg_secondary']}; }}
            QHeaderView::section {{
                background:{COLORS['bg_secondary']}; border:none;
                border-right:1px solid {COLORS['border']};
                border-bottom:2px solid {COLORS['accent_cyan']}44;
                padding:6px 6px; color:{COLORS['text_secondary']};
                font-size:10px; font-weight:700; letter-spacing:0.5px;
            }}
        """)
        lay.addWidget(self._frame_table, 1)

        # Bottom info
        self._frame_info = QLabel("No frames loaded")
        self._frame_info.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:10px;background:transparent;"
        )
        lay.addWidget(self._frame_info)
        return w

    # ── Column 3: Terminal + Live Stats ───────────────────────────────────────

    def _build_terminal_panel(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background:{COLORS['bg_primary']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 12, 14, 8)
        lay.setSpacing(8)

        self.terminal = TerminalWidget()
        lay.addWidget(self.terminal, 1)

        # Live stats panel
        stats_frame = QFrame()
        stats_frame.setStyleSheet(f"""
            QFrame {{
                background:{COLORS['bg_card']};
                border:1px solid {COLORS['border']};
                border-radius:6px;
            }}
        """)
        stats_frame.setFixedHeight(100)
        sl = QVBoxLayout(stats_frame)
        sl.setContentsMargins(12, 8, 12, 8)
        sl.setSpacing(4)

        stats_hdr = QLabel("LIVE STATS")
        stats_hdr.setStyleSheet(
            f"color:{COLORS['accent_cyan']};font-size:9px;font-weight:700;"
            f"letter-spacing:2px;background:transparent;"
        )
        sl.addWidget(stats_hdr)

        row1 = QHBoxLayout()
        self._stat_sent   = self._stat_chip("Sent: 0",    COLORS['accent_green'])
        self._stat_errors = self._stat_chip("Errors: 0",  COLORS['critical'])
        self._stat_fps    = self._stat_chip("0.0 fr/s",   COLORS['accent_cyan'])
        for c in (self._stat_sent, self._stat_errors, self._stat_fps):
            row1.addWidget(c)
        row1.addStretch()
        sl.addLayout(row1)

        row2 = QHBoxLayout()
        self._stat_elapsed = self._stat_chip("0.00s",     COLORS['accent_yellow'])
        self._stat_remain  = self._stat_chip("mode: —",   COLORS['accent_purple'])
        for c in (self._stat_elapsed, self._stat_remain):
            row2.addWidget(c)
        row2.addStretch()
        sl.addLayout(row2)

        lay.addWidget(stats_frame)
        return w

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _grp(self, title: str) -> QGroupBox:
        g = QGroupBox(title)
        g.setStyleSheet(f"""
            QGroupBox {{
                border:1px solid {COLORS['border']};
                border-radius:6px; margin-top:18px; padding-top:8px;
                color:{COLORS['accent_cyan']}; font-size:9px;
                font-weight:700; letter-spacing:1.5px;
            }}
            QGroupBox::title {{
                subcontrol-origin:margin; subcontrol-position:top left;
                padding:0 8px; left:12px; color:{COLORS['accent_cyan']};
            }}
        """)
        return g

    def _mini_btn_style(self, color: str) -> str:
        return (
            f"QPushButton {{ background:{color}18; border:1px solid {color}44; "
            f"border-radius:4px; color:{color}; font-size:9px; font-weight:700; }}"
            f"QPushButton:hover {{ background:{color}35; border-color:{color}; }}"
        )

    def _stat_chip(self, text: str, color: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setFixedHeight(20)
        lbl.setStyleSheet(f"""
            QLabel {{
                background:{color}18; border:1px solid {color}44;
                border-radius:10px; color:{color};
                font-size:10px; font-weight:700; padding:0 8px;
            }}
        """)
        return lbl

    # ── File Loading ──────────────────────────────────────────────────────────

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open CAN Log File", "",
            "CAN Log Files (*.jsonl *.log *.csv *.asc *.blf *.pcap);;"
            "FucyFuzz Logs (*.jsonl *.log *.csv);;"
            "Automotive Captures (*.asc *.blf *.pcap);;"
            "All Files (*)"
        )
        if path:
            self._file_path.setText(path)

    def _load_file(self):
        path = self._file_path.text().strip()
        if not path or not os.path.isfile(path):
            self.terminal.append_error("File not found. Check the path.")
            return

        self.terminal.append_info(f"Loading: {path}")
        self._load_info.setText("Loading …")
        QApplication.instance().processEvents()

        try:
            from utils.replay_loader import load_file, LoadError
            frames, meta = load_file(path)
            self._frames = frames

            self.terminal.append_success(
                f"Loaded {meta['count']} frames  •  "
                f"TX:{meta['tx_count']} RX:{meta['rx_count']}  •  "
                f"Duration:{meta['time_range_s']:.3f}s  •  "
                f"Format:{meta['format']}  •  "
                f"Start:{meta['ts_start']}"
            )
            self._load_info.setText(
                f"✓  {meta['count']} frames  •  {meta['format']}  •  "
                f"{meta['time_range_s']:.3f}s"
            )
            self._load_info.setStyleSheet(
                f"color:{COLORS['success']};font-size:10px;background:transparent;"
            )

            self._populate_frame_table(frames)
            self._dry_btn.setEnabled(True)
            self._replay_btn.setEnabled(True)
            self._progress_bar.setValue(0)
            self._progress_lbl.setText(f"0 / {len(frames)} frames")

        except Exception as exc:
            self.terminal.append_error(f"Load failed: {exc}")
            self._load_info.setText(f"Error: {exc}")
            self._load_info.setStyleSheet(
                f"color:{COLORS['critical']};font-size:10px;background:transparent;"
            )

    def _populate_frame_table(self, frames: list):
        self._frame_table.setRowCount(0)
        for idx, frame in enumerate(frames):
            self._insert_frame_row(idx, frame)
        included = sum(1 for f in frames if f.get("include", True))
        self._update_frame_info(len(frames), included)

    def _insert_frame_row(self, idx: int, frame: dict):
        row = self._frame_table.rowCount()
        self._frame_table.insertRow(row)

        direction = frame.get("direction", "TX")
        severity  = (frame.get("severity") or "INFO").upper()
        arb_id    = frame.get("arb_id", "")
        data_hex  = (frame.get("data_hex") or "").replace(" ", "")
        decoded   = frame.get("decoded", "")
        ts_rel    = frame.get("ts_rel", 0.0)
        delta_ms  = frame.get("delta_ms", 0.0)
        included  = frame.get("include", True)
        dlc       = str(len(data_hex) // 2) if data_hex else "0"
        hex_disp  = " ".join(data_hex[i:i+2] for i in range(0, len(data_hex), 2))

        dir_color = "#00d4ff" if direction == "TX" else "#10b981"
        sev_color = _SEV_COLORS.get(severity, _SEV_COLORS["INFO"])

        def cell(text, color=None):
            it = QTableWidgetItem(str(text))
            if color:
                it.setForeground(QColor(color))
            it.setData(Qt.UserRole, idx)
            return it

        self._frame_table.setItem(row, 0, cell(str(idx+1), COLORS['text_muted']))

        # Checkbox cell
        chk_item = QTableWidgetItem()
        chk_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        chk_item.setCheckState(Qt.Checked if included else Qt.Unchecked)
        chk_item.setData(Qt.UserRole, idx)
        self._frame_table.setItem(row, 1, chk_item)

        self._frame_table.setItem(row, 2, cell(f"{ts_rel:.4f}",  COLORS['text_muted']))
        self._frame_table.setItem(row, 3, cell(f"{delta_ms:.2f}", COLORS['text_secondary']))
        self._frame_table.setItem(row, 4, cell(arb_id,           COLORS['accent_yellow']))
        self._frame_table.setItem(row, 5, cell(dlc))
        self._frame_table.setItem(row, 6, cell(hex_disp,         COLORS['text_primary']))
        self._frame_table.setItem(row, 7, cell(decoded[:60],     COLORS['accent_cyan']))
        self._frame_table.setItem(row, 8, cell(severity,         sev_color))

        if severity == "CRITICAL":
            for c in range(self._frame_table.columnCount()):
                it = self._frame_table.item(row, c)
                if it:
                    it.setForeground(QColor(COLORS['critical']))

        self._frame_table.setRowHeight(row, 24)

    # ── Frame table interactions ───────────────────────────────────────────────

    def _on_cell_clicked(self, row: int, col: int):
        """Toggle checkbox when clicking the ✓ column."""
        if col != 1:
            return
        item = self._frame_table.item(row, 1)
        if item is None:
            return
        new_state = Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        item.setCheckState(new_state)
        idx = item.data(Qt.UserRole)
        if 0 <= idx < len(self._frames):
            self._frames[idx]["include"] = (new_state == Qt.Checked)
        included = sum(1 for f in self._frames if f.get("include", True))
        self._update_frame_info(len(self._frames), included)

    def _frame_context_menu(self, pos: QPoint):
        row = self._frame_table.rowAt(pos.y())
        if row < 0:
            return
        idx_item = self._frame_table.item(row, 0)
        if not idx_item:
            return
        data_idx = self._frame_table.item(row, 1)
        frame_idx = data_idx.data(Qt.UserRole) if data_idx else None

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background:{COLORS['bg_elevated']}; border:1px solid {COLORS['border_bright']};
                    border-radius:6px; padding:4px; }}
            QMenu::item {{ padding:7px 18px 7px 14px; border-radius:4px; color:{COLORS['text_primary']}; }}
            QMenu::item:selected {{ background:{COLORS['accent_cyan']}22; color:{COLORS['accent_cyan']}; }}
        """)

        act_include = menu.addAction("☑  Include this frame")
        act_exclude = menu.addAction("☐  Exclude this frame")
        menu.addSeparator()
        act_only    = menu.addAction("▶  Replay ONLY this frame")
        act_send    = menu.addAction("⚡ Send frame now (instant)")
        menu.addSeparator()
        act_copy    = menu.addAction("📋 Copy hex data")

        action = menu.exec_(self._frame_table.viewport().mapToGlobal(pos))

        if frame_idx is not None and 0 <= frame_idx < len(self._frames):
            frame = self._frames[frame_idx]
            if action == act_include:
                frame["include"] = True
                self._frame_table.item(row, 1).setCheckState(Qt.Checked)
            elif action == act_exclude:
                frame["include"] = False
                self._frame_table.item(row, 1).setCheckState(Qt.Unchecked)
            elif action == act_only:
                self._replay_single(frame)
            elif action == act_send:
                self._send_single_now(frame)
            elif action == act_copy:
                QApplication.instance().clipboard().setText(frame.get("data_hex",""))

        included = sum(1 for f in self._frames if f.get("include", True))
        self._update_frame_info(len(self._frames), included)

    def _select_rows(self, include: bool, direction_filter):
        for i in range(self._frame_table.rowCount()):
            chk = self._frame_table.item(i, 1)
            if chk is None:
                continue
            idx = chk.data(Qt.UserRole)
            if idx is not None and 0 <= idx < len(self._frames):
                frame = self._frames[idx]
                if direction_filter is None or frame.get("direction","").upper() == direction_filter:
                    frame["include"] = include
                    chk.setCheckState(Qt.Checked if include else Qt.Unchecked)
        included = sum(1 for f in self._frames if f.get("include", True))
        self._update_frame_info(len(self._frames), included)

    def _filter_frames(self):
        search = self._frame_search.text().strip().lower()
        sev_f  = self._sev_combo.currentText()
        dir_f  = self._dir_combo.currentText()

        for row in range(self._frame_table.rowCount()):
            idx_item = self._frame_table.item(row, 1)
            if idx_item is None:
                self._frame_table.setRowHidden(row, False)
                continue
            idx = idx_item.data(Qt.UserRole)
            if idx is None or idx >= len(self._frames):
                self._frame_table.setRowHidden(row, False)
                continue
            frame = self._frames[idx]

            hidden = False
            if sev_f not in ("All Severity", "") and \
               (frame.get("severity","") or "INFO").upper() != sev_f:
                hidden = True
            if dir_f not in ("All Dir", "") and \
               frame.get("direction","").upper() != dir_f:
                hidden = True
            if search:
                hay = (
                    frame.get("arb_id","").lower()
                    + frame.get("data_hex","").lower()
                    + frame.get("decoded","").lower()
                )
                if search not in hay:
                    hidden = True

            self._frame_table.setRowHidden(row, hidden)

    def _update_frame_info(self, total: int, included: int):
        excluded = total - included
        self._frame_info.setText(
            f"{total} frames total  •  {included} included  •  {excluded} excluded"
        )

    # ── Timing mode UI ────────────────────────────────────────────────────────

    def _on_timing_changed(self, idx: int) -> None:
        show_delay = (idx == 1)   # Custom Delay
        show_scale = (idx == 2)   # Scaled Timing
        for i in range(self._custom_delay_row.count()):
            w = self._custom_delay_row.itemAt(i).widget()
            if w:
                w.setVisible(show_delay)
        for i in range(self._scale_row.count()):
            w = self._scale_row.itemAt(i).widget()
            if w:
                w.setVisible(show_scale)

    def _get_timing_mode(self) -> str:
        idx = self._timing_mode.currentIndex()
        return ["original", "custom", "scaled", "burst"][idx]

    def _get_loop_count(self) -> int:
        txt = self._loop_combo.currentText()
        if "∞" in txt:
            return -1
        try:
            return int(txt.replace("×", "").strip())
        except ValueError:
            return 1

    # ── Dry Run ───────────────────────────────────────────────────────────────

    def _start_dry_run(self):
        frames = [f for f in self._frames if f.get("include", True)]
        if not frames:
            self.terminal.append_error("No frames selected.")
            return

        self.terminal.clear()
        iface        = self._iface.text().strip() or "vcan0"
        timing_mode  = self._get_timing_mode()
        delay_ms     = self._delay_spin.value()
        scale        = self._scale_spin.value()
        loop_count   = self._get_loop_count()
        total        = len(frames)

        mode_desc = {
            "original": f"Original Timing  (real inter-frame gaps from log)",
            "custom":   f"Custom Delay  {delay_ms:.1f}ms between frames",
            "scaled":   f"Scaled Timing  {scale:.2f}×  real-time",
            "burst":    "Burst Mode  (no inter-frame delay)",
        }.get(timing_mode, timing_mode)

        loop_desc = "∞ loops" if loop_count == -1 else f"{loop_count}× loop"
        self.terminal.append_info(
            f"DRY RUN — {total} frames × {loop_desc}  |  {mode_desc}"
        )

        total_time_s = 0.0
        for i, frame in enumerate(frames[:50]):   # preview first 50
            arb_id   = frame.get("arb_id","7E0")
            data_hex = (frame.get("data_hex") or "").replace(" ","").upper()
            delta_ms = frame.get("delta_ms", 0.0)
            ts_rel   = frame.get("ts_rel", 0.0)
            decoded  = frame.get("decoded","")
            severity = (frame.get("severity") or "INFO").upper()
            sev_color = _SEV_COLORS.get(severity, _SEV_COLORS["INFO"])

            if timing_mode == "original":
                gap = delta_ms
            elif timing_mode == "scaled":
                gap = delta_ms * scale
            elif timing_mode == "burst":
                gap = 0.0
            else:
                gap = delay_ms

            total_time_s += gap / 1000.0
            isotp_frs = build_isotp_frames(data_hex)
            note = f"  // {decoded[:40]}" if decoded else ""
            self.terminal.append(
                f"  [{i+1:>4}/{total}]  @{ts_rel:.4f}s  Δ{delta_ms:.1f}ms  "
                f"{arb_id}  {data_hex[:16]}  {note}",
                sev_color
            )
            for j, raw in enumerate(isotp_frs):
                label = "SF" if j == 0 else f"CF{j}"
                self.terminal.append(
                    f"    [{label}]  cansend {iface} {arb_id}#{raw}",
                    COLORS['accent_green']
                )
            if gap > 0:
                self.terminal.append(
                    f"    → wait {gap:.1f}ms", COLORS['text_muted']
                )

        if total > 50:
            self.terminal.append_info(f"  … {total - 50} more frames (truncated in preview)")

        est_total = sum(
            (f.get("delta_ms",0) * (scale if timing_mode == "scaled" else 1.0)
             if timing_mode in ("original","scaled") else delay_ms)
            for f in frames
        ) / 1000.0
        loops_factor = "∞" if loop_count == -1 else str(loop_count)
        self.terminal.append_info(
            f"Estimated duration per pass: {est_total:.3f}s  ×  {loops_factor} loops"
        )
        self.terminal.append_info("Click ▶ REPLAY ATTACK to send the frames.")

    # ── Replay ────────────────────────────────────────────────────────────────

    def _start_replay(self):
        frames = [f for f in self._frames if f.get("include", True)]
        if not frames:
            self.terminal.append_error("No frames selected for replay.")
            return

        iface      = self._iface.text().strip() or "vcan0"
        timing     = self._get_timing_mode()
        delay_ms   = self._delay_spin.value()
        scale      = self._scale_spin.value()
        loop_count = self._get_loop_count()

        mode_labels = {
            "original": "Original Timing",
            "custom":   f"Custom {delay_ms:.1f}ms",
            "scaled":   f"Scaled {scale:.2f}×",
            "burst":    "Burst",
        }
        self.terminal.clear()
        self.terminal.append_command(
            f"▶ REPLAY  {len(frames)} frames  |  iface={iface}  "
            f"timing={mode_labels.get(timing,'?')}  "
            f"loops={'∞' if loop_count == -1 else loop_count}"
        )

        self.cfg.set("can_interface", iface)

        self._worker = ReplayWorker(
            frames, iface,
            timing_mode=timing,
            delay_ms=delay_ms,
            scale_factor=scale,
            loop_count=loop_count,
            dry_run=False,
            doip_host=self._doip_host.text().strip() or "127.0.0.1",
            doip_port=self._doip_port.value()
        )
        self._worker.progress.connect(self._on_progress, Qt.QueuedConnection)
        self._worker.log_line.connect(
            lambda t, c: self.terminal.append(t, c), Qt.QueuedConnection
        )
        self._worker.stats_tick.connect(self._on_stats_tick, Qt.QueuedConnection)
        self._worker.finished.connect(self._on_replay_done, Qt.QueuedConnection)

        self._thread = threading.Thread(target=self._worker.run, daemon=True)
        self._thread.start()
        self._t_replay_start = time.monotonic()

        self._replay_btn.setEnabled(False)
        self._dry_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress_bar.setValue(0)
        self._progress_lbl.setText(f"▶  0 / {len(frames)}")

    def _stop_replay(self):
        if self._worker:
            self._worker.stop()
        self._stop_btn.setEnabled(False)
        self._progress_lbl.setText("Stopping …")

    def _replay_single(self, frame: dict):
        iface    = self._iface.text().strip() or "vcan0"
        arb_id   = frame.get("arb_id","7E0").upper()
        data_hex = (frame.get("data_hex") or "").replace(" ","").upper()

        if iface == "doip":
            from protocol_layer.doip_layer import DoIPClient
            from utils.config import get_config
            cfg = get_config().get_doip_params()
            try:
                doip_host = self._doip_host.text().strip() or "127.0.0.1"
                doip_port = self._doip_port.value()
                l_addr = int(cfg['logical_address'], 16) if isinstance(cfg['logical_address'], str) else cfg['logical_address']
                doip_client = DoIPClient(host=doip_host, port=doip_port, logical_address=l_addr)
                ok, err = doip_client.connect()
                if not ok:
                    self.terminal.append_error(f"DoIP connect failed: {err}")
                    return
                doip_client.activate_routing()
                payload = bytes.fromhex(data_hex)
                service = payload[0]
                data_bytes = payload[1:]
                t_addr = int(arb_id, 16) if arb_id and len(arb_id) <= 4 else int(cfg['target_address'], 16) if isinstance(cfg['target_address'], str) else cfg['target_address']
                cmd = f"doip_send {arb_id} {data_hex}"
                ok, resp = doip_client.send_uds(service, data_bytes, target_address=t_addr)
                if ok:
                    self.terminal.append(f"  SENT: {cmd}", COLORS['accent_green'])
                else:
                    self.terminal.append_error(f"DoIP send failed: {resp}")
                doip_client.close()
            except Exception as exc:
                self.terminal.append_error(f"DoIP exception: {exc}")
            return

        isotp    = build_isotp_frames(data_hex)
        if not isotp:
            self.terminal.append_error("Cannot build ISO-TP frame from this entry.")
            return
        for raw in isotp:
            cmd = ["cansend", iface, f"{arb_id}#{raw}"]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                self.terminal.append(f"  SENT: {' '.join(cmd)}", COLORS['accent_green'])
            except Exception as exc:
                self.terminal.append_error(f"cansend failed: {exc}")

    def _send_single_now(self, frame: dict):
        self._replay_single(frame)

    # ── Progress / stats callbacks ────────────────────────────────────────────

    def _on_progress(self, idx: int, total: int) -> None:
        pct = int((idx / total) * 100) if total > 0 else 0
        self._progress_bar.setValue(pct)
        self._progress_lbl.setText(f"▶  {idx + 1} / {total}")

        # Highlight current row in table if visible
        for row in range(self._frame_table.rowCount()):
            chk = self._frame_table.item(row, 1)
            if chk and chk.data(Qt.UserRole) == idx:
                self._frame_table.setCurrentCell(row, 0)
                self._frame_table.scrollTo(self._frame_table.model().index(row, 0))
                break

    def _on_stats_tick(self, stats: dict) -> None:
        sent    = stats.get("sent", 0)
        errors  = stats.get("errors", 0)
        elapsed = stats.get("elapsed", 0.0)
        fps     = stats.get("fps", 0.0)

        self._stat_sent.setText(f"Sent: {sent}")
        self._stat_errors.setText(f"Errors: {errors}")
        self._stat_fps.setText(f"{fps:.1f} fr/s")
        self._stat_elapsed.setText(f"{elapsed:.1f}s")

    def _on_replay_done(self, success: bool, msg: str) -> None:
        if success:
            self.terminal.append_success(msg)
        else:
            self.terminal.append_error(msg)
        self._replay_btn.setEnabled(True)
        self._dry_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress_bar.setValue(100 if success else self._progress_bar.value())
        self._progress_lbl.setText(msg[:60])

        elapsed = time.monotonic() - self._t_replay_start
        self._stat_elapsed.setText(f"{elapsed:.1f}s")

