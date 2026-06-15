"""
Advanced Tab
Combines DoIP discovery, XCP info, and UDS DID Reader with full response decoding.
Ported from fucyfuzz AdvancedFrame.
"""

import subprocess
import threading

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QDoubleSpinBox, QCheckBox,
    QGroupBox, QTabWidget, QTextEdit, QSplitter, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

from ui.widgets import (
    SectionHeader, GlowButton, SolidButton,
    TerminalWidget, StatusBadge
)
from ui.theme import COLORS
from utils.runner import CommandRunner
from utils.data_manager import DataManager
from utils.config import get_config


def _apply_combo_style(combo: QComboBox):
    """Apply explicit contrast stylesheet to any QComboBox in Advanced tab.

    The sub-tab QWidgets use background:transparent which causes QComboBox to
    inherit an invalid/white background making text invisible.  This fixes it.
    """
    combo.setStyleSheet(f"""
        QComboBox {{
            background-color: {COLORS['bg_input']};
            color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            padding: 5px 10px;
            font-size: 12px;
            min-width: 140px;
        }}
        QComboBox:focus {{
            border: 1px solid {COLORS['accent_cyan']};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 24px;
        }}
        QComboBox::down-arrow {{
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 6px solid {COLORS['text_secondary']};
            margin-right: 6px;
        }}
        QComboBox QAbstractItemView {{
            background-color: {COLORS['bg_elevated']};
            color: {COLORS['text_primary']};
            selection-background-color: {COLORS['border_bright']};
            selection-color: {COLORS['text_primary']};
            border: 1px solid {COLORS['border_bright']};
            padding: 4px;
            outline: none;
        }}
    """)


# ---------------------------------------------------------------------------
# Shared runner signals bridge
# ---------------------------------------------------------------------------
class _Bridge(QObject):
    log_line = pyqtSignal(str)


class AdvancedTab(QWidget):
    """
    Three sub-tabs:
      1. DoIP   — discovery
      2. XCP    — info / discovery / commands / dump
      3. DID Reader — UDS read_did / dump_dids with decoded response display
    """
    # Thread-safe signal for updating _response_text from worker threads
    _sig_response_append = pyqtSignal(str)
    _sig_response_clear  = pyqtSignal()

    def __init__(self, runner: CommandRunner, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.runner = runner
        self.dm     = data_manager
        self.cfg    = get_config()
        self._bridge = _Bridge()
        self._setup_ui()
        self._connect_runner()

    # ── UI ─────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # toolbar
        toolbar = QWidget()
        toolbar.setFixedHeight(48)
        toolbar.setStyleSheet(
            f"background-color: {COLORS['bg_secondary']};"
            f"border-bottom: 1px solid {COLORS['border']};"
        )
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(20, 0, 20, 0)
        self._status_badge = StatusBadge("IDLE", "idle")
        tb.addWidget(self._status_badge)
        tb.addSpacing(12)
        self._cmd_preview = QLabel("")
        self._cmd_preview.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; background: transparent;"
        )
        tb.addWidget(self._cmd_preview)
        tb.addStretch()
        self._run_btn  = SolidButton("▶  RUN", COLORS['accent_green'])
        self._kill_btn = GlowButton("■  KILL", COLORS['critical'], danger=True)
        self._kill_btn.setEnabled(False)
        self._run_btn.clicked.connect(self._run)
        self._kill_btn.clicked.connect(self.runner.kill)
        tb.addWidget(self._run_btn)
        tb.addSpacing(8)
        tb.addWidget(self._kill_btn)
        root.addWidget(toolbar)

        # splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {COLORS['border']}; width: 1px; }}"
        )

        # LEFT: sub-tabs
        left = QWidget()
        left.setMinimumWidth(320)
        left.setMaximumWidth(440)
        left.setStyleSheet(f"background-color: {COLORS['bg_secondary']};")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; background: {COLORS['bg_secondary']}; }}
            QTabBar::tab {{
                background: {COLORS['bg_secondary']};
                border: none;
                border-bottom: 2px solid transparent;
                padding: 6px 14px;
                color: {COLORS['text_secondary']};
                font-size: 10px;
                letter-spacing: 1px;
            }}
            QTabBar::tab:selected {{
                color: {COLORS['accent_cyan']};
                border-bottom: 2px solid {COLORS['accent_cyan']};
                background: {COLORS['bg_primary']};
            }}
        """)

        self._tabs.addTab(self._build_doip_tab(),    "DoIP")
        self._tabs.addTab(self._build_xcp_tab(),     "XCP")
        self._tabs.addTab(self._build_did_tab(),     "DID Reader")

        left_layout.addWidget(self._tabs)
        splitter.addWidget(left)

        # RIGHT: split terminal (top) + DID response (bottom)
        right = QWidget()
        right.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)

        right_split = QSplitter(Qt.Vertical)
        right_split.setStyleSheet(
            f"QSplitter::handle {{ background: {COLORS['border']}; height: 1px; }}"
        )

        self.terminal = TerminalWidget()
        right_split.addWidget(self.terminal)

        # DID response panel
        resp_widget = QWidget()
        resp_widget.setStyleSheet(f"background: {COLORS['bg_secondary']};")
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.setContentsMargins(8, 4, 8, 4)
        resp_layout.setSpacing(4)
        resp_hdr = QLabel("DID Response Decoded")
        resp_hdr.setStyleSheet(
            f"color: {COLORS['accent_cyan']}; font-size: 10px; letter-spacing: 2px; background: transparent;"
        )
        resp_layout.addWidget(resp_hdr)
        self._response_text = QTextEdit()
        self._response_text.setReadOnly(True)
        self._response_text.setStyleSheet(f"""
            QTextEdit {{
                background: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                color: {COLORS['accent_green']};
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 6px;
            }}
        """)
        resp_layout.addWidget(self._response_text)
        right_split.addWidget(resp_widget)
        right_split.setSizes([400, 200])

        rl.addWidget(right_split)
        splitter.addWidget(right)

        # Connect thread-safe signals for _response_text updates
        self._sig_response_append.connect(self._response_text.append,   type=Qt.QueuedConnection)
        self._sig_response_clear.connect(self._response_text.clear,     type=Qt.QueuedConnection)
        splitter.setSizes([360, 800])

        root.addWidget(splitter)

    # ── DoIP sub-tab ────────────────────────────────────────────────────────

    def _build_doip_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        layout.addWidget(SectionHeader("DoIP Discovery"))

        desc = QLabel(
            "Discovers DoIP-capable ECUs on the configured CAN interface.\n"
            "Uses the interface set in Config."
        )
        desc.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

        self._doip_blacklist_cb = QCheckBox("Blacklist IDs")
        self._doip_blacklist_cb.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        layout.addWidget(self._doip_blacklist_cb)

        self._doip_blacklist_ids = QLineEdit()
        self._doip_blacklist_ids.setPlaceholderText("0x123 0x456 ...")
        layout.addWidget(self._doip_blacklist_ids)

        self._doip_auto_bl = QCheckBox("Auto Blacklist")
        self._doip_auto_bl.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        layout.addWidget(self._doip_auto_bl)

        ab_row = QHBoxLayout()
        ab_row.addWidget(QLabel("Threshold:"))
        self._doip_abl_n = __import__('PyQt5.QtWidgets', fromlist=['QSpinBox']).QSpinBox()
        self._doip_abl_n.setValue(10)
        self._doip_abl_n.setRange(1, 1000)
        ab_row.addWidget(self._doip_abl_n)
        layout.addLayout(ab_row)
        layout.addStretch()
        return w

    # ── XCP sub-tab ─────────────────────────────────────────────────────────

    def _build_xcp_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        layout.addWidget(SectionHeader("XCP Protocol"))

        cmd_group = QGroupBox("Command")
        cmd_l = QVBoxLayout(cmd_group)
        self._xcp_subcmd = QComboBox()
        self._xcp_subcmd.addItems(["discovery", "commands", "info", "dump"])
        _apply_combo_style(self._xcp_subcmd)
        self._xcp_subcmd.currentTextChanged.connect(self._on_xcp_subcmd)
        cmd_l.addWidget(self._xcp_subcmd)
        layout.addWidget(cmd_group)

        ids_group = QGroupBox("CAN IDs")
        ids_l = QVBoxLayout(ids_group)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Request ID:"))
        self._xcp_req = QLineEdit("1000")
        r1.addWidget(self._xcp_req)
        ids_l.addLayout(r1)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Response ID:"))
        self._xcp_resp = QLineEdit("1001")
        r2.addWidget(self._xcp_resp)
        ids_l.addLayout(r2)
        layout.addWidget(ids_group)

        # Discovery
        self._xcp_disc_group = QGroupBox("Discovery Options")
        dl = QVBoxLayout(self._xcp_disc_group)
        self._xcp_bl_cb = QCheckBox("Blacklist IDs")
        self._xcp_bl_cb.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        dl.addWidget(self._xcp_bl_cb)
        self._xcp_bl_ids = QLineEdit()
        self._xcp_bl_ids.setPlaceholderText("0x100 0xabc ...")
        dl.addWidget(self._xcp_bl_ids)
        self._xcp_auto_bl = QCheckBox("Auto Blacklist")
        self._xcp_auto_bl.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        dl.addWidget(self._xcp_auto_bl)
        from PyQt5.QtWidgets import QSpinBox
        abl_row = QHBoxLayout()
        abl_row.addWidget(QLabel("Threshold:"))
        self._xcp_abl_n = QSpinBox()
        self._xcp_abl_n.setValue(10)
        abl_row.addWidget(self._xcp_abl_n)
        dl.addLayout(abl_row)
        layout.addWidget(self._xcp_disc_group)

        # Dump
        self._xcp_dump_group = QGroupBox("Memory Dump Options")
        dump_l = QVBoxLayout(self._xcp_dump_group)
        d1 = QHBoxLayout()
        d1.addWidget(QLabel("Start Address:"))
        self._xcp_start = QLineEdit("0x1fffb000")
        d1.addWidget(self._xcp_start)
        dump_l.addLayout(d1)
        d2 = QHBoxLayout()
        d2.addWidget(QLabel("Length (hex):"))
        self._xcp_len = QLineEdit("0x4800")
        d2.addWidget(self._xcp_len)
        dump_l.addLayout(d2)
        d3 = QHBoxLayout()
        d3.addWidget(QLabel("Output File:"))
        self._xcp_file = QLineEdit("bootloader.hex")
        d3.addWidget(self._xcp_file)
        browse = GlowButton("Browse", COLORS['accent_cyan'])
        browse.setFixedWidth(70)
        browse.clicked.connect(self._browse_xcp_dump)
        d3.addWidget(browse)
        dump_l.addLayout(d3)
        layout.addWidget(self._xcp_dump_group)

        self._on_xcp_subcmd("discovery")
        layout.addStretch()
        return w

    def _on_xcp_subcmd(self, cmd):
        self._xcp_disc_group.setVisible(cmd == "discovery")
        self._xcp_dump_group.setVisible(cmd == "dump")

    def _browse_xcp_dump(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save XCP Dump", "", "Hex Files (*.hex);;All Files (*)")
        if path:
            self._xcp_file.setText(path)

    # ── DID Reader sub-tab ───────────────────────────────────────────────────

    def _build_did_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        layout.addWidget(SectionHeader("UDS DID Reader"))

        # DID preset selector
        preset_group = QGroupBox("Select DID")
        pl = QVBoxLayout(preset_group)
        self._did_select = QComboBox()
        self._did_select.addItems([
            "Single DID: 0xF190 - VIN",
            "Single DID: 0xF180 - Boot SW",
            "Single DID: 0xF181 - App SW",
            "Single DID: 0xF186 - Session",
            "Single DID: 0xF187 - Part No",
            "Single DID: 0xF188 - ECU SW",
            "Single DID: 0xF198 - Shop Code",
            "Single DID: 0xF18C - Serial No",
            "Custom DID",
            "Scan Range: F180-F1FF",
        ])
        _apply_combo_style(self._did_select)
        self._did_select.currentTextChanged.connect(self._on_did_change)
        pl.addWidget(self._did_select)
        layout.addWidget(preset_group)

        # Custom DID
        self._custom_did_group = QGroupBox("Custom DID (4 hex digits, no 0x)")
        cdl = QVBoxLayout(self._custom_did_group)
        self._custom_did = QLineEdit()
        self._custom_did.setPlaceholderText("F190")
        cdl.addWidget(self._custom_did)
        layout.addWidget(self._custom_did_group)

        # Range
        self._range_group = QGroupBox("DID Range")
        rl = QVBoxLayout(self._range_group)
        rr = QHBoxLayout()
        rr.addWidget(QLabel("Start:"))
        self._range_start = QLineEdit("F180")
        rr.addWidget(self._range_start)
        rr.addWidget(QLabel("End:"))
        self._range_end = QLineEdit("F1FF")
        rr.addWidget(self._range_end)
        rl.addLayout(rr)
        layout.addWidget(self._range_group)

        # IDs + options
        ids_group = QGroupBox("ECU IDs & Options")
        il = QVBoxLayout(ids_group)
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Target ID:"))
        self._did_target = QLineEdit("0x7E0")
        r1.addWidget(self._did_target)
        il.addLayout(r1)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Response ID:"))
        self._did_resp = QLineEdit("0x7E8")
        r2.addWidget(self._did_resp)
        il.addLayout(r2)
        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Timeout (s):"))
        self._did_timeout = QDoubleSpinBox()
        self._did_timeout.setValue(0.2)
        self._did_timeout.setSingleStep(0.05)
        r3.addWidget(self._did_timeout)
        il.addLayout(r3)
        layout.addWidget(ids_group)

        self._read_btn = SolidButton("🔍  Read DID", COLORS['accent_purple'])
        self._read_btn.setFixedHeight(36)
        self._read_btn.clicked.connect(self._read_did)
        layout.addWidget(self._read_btn)

        self._on_did_change(self._did_select.currentText())
        layout.addStretch()
        return w

    def _on_did_change(self, selection):
        self._custom_did_group.setVisible(selection == "Custom DID")
        self._range_group.setVisible("Scan Range:" in selection)

    # ── Runner signals ────────────────────────────────────────────────────────

    def _connect_runner(self):
        self.runner.started.connect(self._on_started,                          type=Qt.QueuedConnection)
        self.runner.output_line.connect(self._on_runner_output,                type=Qt.QueuedConnection)
        self.runner.error_line.connect(self._on_runner_error,                  type=Qt.QueuedConnection)
        self.runner.finished.connect(self._on_finished,                        type=Qt.QueuedConnection)

    def _on_runner_output(self, line: str):
        self.terminal.append_output(line)

    def _on_runner_error(self, line: str):
        self.terminal.append_error(line)

    def _on_started(self, cmd):
        self._cmd_preview.setText(cmd[:80] + ("..." if len(cmd) > 80 else ""))
        self._status_badge.setText("RUNNING")
        self._status_badge.setStyleSheet(
            f"color: {COLORS['accent_yellow']};"
            f"background-color: {COLORS['accent_yellow']}22;"
            f"border: 1px solid {COLORS['accent_yellow']}66;"
            f"border-radius: 3px; padding: 2px 8px; font-size: 9px; letter-spacing: 1px;"
        )
        self._run_btn.setEnabled(False)
        self._kill_btn.setEnabled(True)

    def _on_finished(self, rc):
        self._status_badge.setText("IDLE")
        self._status_badge.setStyleSheet(
            f"color: {COLORS['text_secondary']};"
            f"background-color: {COLORS['text_secondary']}22;"
            f"border: 1px solid {COLORS['text_secondary']}66;"
            f"border-radius: 3px; padding: 2px 8px; font-size: 9px; letter-spacing: 1px;"
        )
        self._run_btn.setEnabled(True)
        self._kill_btn.setEnabled(False)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _run(self):
        if self.runner.is_running:
            self.terminal.append_error("A command is running. Kill it first.")
            return
        current = self._tabs.tabText(self._tabs.currentIndex())
        if current == "DoIP":
            args = self._build_doip_args()
        elif current == "XCP":
            args = self._build_xcp_args()
        else:
            self._read_did()
            return
        if args:
            self.runner.run(args, module=current.lower())
            self.terminal.append_command("fucyfuzz " + " ".join(str(a) for a in args))

    def _build_doip_args(self):
        iface = self.cfg.get('interface', 'can0')
        args = ["-i", iface, "doip", "discovery"]
        if self._doip_blacklist_cb.isChecked() and self._doip_blacklist_ids.text().strip():
            args += ["-blacklist"] + self._doip_blacklist_ids.text().strip().split()
        if self._doip_auto_bl.isChecked():
            args += ["-autoblacklist", str(self._doip_abl_n.value())]
        return args

    def _build_xcp_args(self):
        iface = self.cfg.get('interface', 'can0')
        cmd  = self._xcp_subcmd.currentText()
        req  = self._xcp_req.text().strip()
        resp = self._xcp_resp.text().strip()
        args = ["-i", iface, "xcp", cmd]
        if cmd == "discovery":
            if self._xcp_bl_cb.isChecked() and self._xcp_bl_ids.text().strip():
                args += ["-blacklist"] + self._xcp_bl_ids.text().strip().split()
            if self._xcp_auto_bl.isChecked():
                args += ["-autoblacklist", str(self._xcp_abl_n.value())]
        elif cmd in ("commands", "info"):
            args += [req, resp]
        elif cmd == "dump":
            args += [req, resp,
                     self._xcp_start.text().strip(),
                     self._xcp_len.text().strip(),
                     "-f", self._xcp_file.text().strip()]
        return args

    # ── DID Reader ────────────────────────────────────────────────────────────

    def _read_did(self):
        if self.runner.is_running:
            self.terminal.append_error("A command is running. Kill it first.")
            return

        iface      = self.cfg.get('interface', 'can0')
        selection  = self._did_select.currentText()
        target_id  = self._did_target.text().strip() or "0x7E0"
        resp_id    = self._did_resp.text().strip()   or "0x7E8"
        timeout    = str(self._did_timeout.value())

        if not target_id.startswith("0x"):
            target_id = "0x" + target_id

        if "Scan Range:" in selection:
            min_did = "0x" + self._range_start.text().strip()
            max_did = "0x" + self._range_end.text().strip()
            args = ["-i", iface, "uds", "dump_dids", target_id, resp_id,
                    "--min_did", min_did, "--max_did", max_did,
                    "-t", timeout]
        elif selection == "Custom DID":
            did_hex = self._custom_did.text().strip().replace("0x", "")
            if not did_hex:
                self.terminal.append_error("Please enter a custom DID.")
                return
            args = ["-i", iface, "uds", "read_did", target_id, resp_id, "0x" + did_hex.upper()]
        else:
            # e.g. "Single DID: 0xF190 - VIN" → 0xF190
            did_hex = selection.split(":")[1].split("-")[0].strip()
            args = ["-i", iface, "uds", "read_did", target_id, resp_id, did_hex]

        self._sig_response_clear.emit()
        self._sig_response_append.emit(f"▶ Reading DID...\n  Args: fucyfuzz {' '.join(args)}\n")
        self.terminal.append_command("fucyfuzz " + " ".join(args))

        # capture output async
        threading.Thread(
            target=self._run_did_and_decode,
            args=(args, selection),
            daemon=True
        ).start()

    def _run_did_and_decode(self, args, selection):
        import os
        from utils.runner import _drain_pipe
        try:
            kwargs = {}
            if hasattr(os, 'setsid'):
                kwargs['preexec_fn'] = os.setsid
            proc = subprocess.Popen(
                [binary] + [str(a) for a in args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                **kwargs,
            )
            self._did_proc = proc  # store for potential kill
            stop_event = threading.Event()
            output_lines = []

            def on_line(line):
                if line:
                    output_lines.append(line)
                    self.terminal.append_output(line)

            def on_progress(line):
                self.terminal.append_progress(line)

            _drain_pipe(proc.stdout, stop_event, on_line, on_progress, "did")
            proc.wait(timeout=10)

            full_output = "\n".join(output_lines)
            decoded = self._decode_did_output(full_output, selection)
            self._sig_response_append.emit(decoded)
        except Exception as e:
            self._sig_response_append.emit(f"ERROR: {e}")
        finally:
            self._did_proc = None


    def _decode_did_output(self, output: str, selection: str) -> str:
        """Best-effort human-readable decoding of UDS DID response output."""
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        result = []
        result.append("=" * 50)
        result.append("📊 UDS RESPONSE DECODED")
        result.append("=" * 50)

        # Identify DID from selection
        did_name = ""
        if "VIN"       in selection: did_name = "VIN"
        elif "Boot SW"  in selection: did_name = "Boot Software ID"
        elif "App SW"   in selection: did_name = "Application Software ID"
        elif "Session"  in selection: did_name = "Active Diagnostic Session"
        elif "Serial"   in selection: did_name = "ECU Serial Number"
        elif "Part No"  in selection: did_name = "ECU Part Number"

        if did_name:
            result.append(f"  DID type : {did_name}")

        found_hex = False
        for line in lines:
            if any(tok in line.lower() for tok in ["0x", "response", "did:", "value:", "data:"]):
                result.append(f"  Raw line : {line}")
                # Try to extract hex bytes
                import re
                hex_tokens = re.findall(r'\b([0-9a-fA-F]{2})\b', line)
                if hex_tokens:
                    ascii_repr = "".join(
                        chr(int(h, 16)) if 32 <= int(h, 16) <= 126 else "."
                        for h in hex_tokens
                    )
                    result.append(f"  ASCII    : {ascii_repr}")
                    found_hex = True

        if not found_hex:
            result.append("  (No decodable hex data found in output)")
        return "\n".join(result)
