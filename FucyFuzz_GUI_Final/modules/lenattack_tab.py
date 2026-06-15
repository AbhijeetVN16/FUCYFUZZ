"""
LEN Attack Module Tab — v2
===========================
DLC Length Attack: sends frames with incrementing DLC values to test
ECU robustness against malformed / unexpected frame lengths.

Key fixes vs v1:
  - Module name is always "lenattack" — NOT "lenattack-<iface>"
    (interface is passed separately as -i <iface> in subprocess mode,
     or handled by LenAttackEngine in built-in mode)
  - Built-in engine mode: no subprocess binary required for this module
  - Platform-aware interface selection (Linux / Windows)
  - Interface validated before any frames are sent
  - Non-blocking execution with stop-event and timeout
  - Structured per-frame logging (CSV + session logger)
  - Clear error messages — no stack traces shown in terminal
  - KILL button works immediately
"""

import threading
import platform
import logging

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox, QFileDialog,
    QFrame
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton, StatusBadge
from ui.theme import COLORS

log = logging.getLogger(__name__)

# ── Thread-safe signal bridge ─────────────────────────────────────────────────
class _Bridge(QObject):
    line_ready = pyqtSignal(str)
    err_ready  = pyqtSignal(str)
    done       = pyqtSignal(int)


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


class LenAttackTab(BaseModuleTab):
    MODULE_NAME = "lenattack"

    def __init__(self, runner, data_manager, parent=None):
        self._len_stop   = threading.Event()
        self._len_thread = None
        self._bridge     = _Bridge()
        super().__init__(runner, data_manager, parent)
        # Wire bridge signals to terminal (Qt queued — thread-safe)
        self._bridge.line_ready.connect(
            self.terminal.append_output, type=Qt.QueuedConnection
        )
        self._bridge.err_ready.connect(
            self.terminal.append_error, type=Qt.QueuedConnection
        )
        self._bridge.done.connect(
            self._on_engine_done, type=Qt.QueuedConnection
        )

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("LEN Attack Module"))

        # ── Interface ────────────────────────────────────────────────────────
        iface_group = QGroupBox("CAN Interface")
        iface_layout = QVBoxLayout(iface_group)

        row_if = QHBoxLayout()
        row_if.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        if _is_windows():
            self.iface_combo.addItems(["pcan", "virtual", "PCAN_USBBUS1"])
        else:
            self.iface_combo.addItems(["vcan0", "can0", "can1"])
        self.iface_combo.setEditable(True)
        row_if.addWidget(self.iface_combo)
        iface_layout.addLayout(row_if)

        # Load saved interface from config
        try:
            saved = self.cfg.get("interface", "vcan0" if not _is_windows() else "pcan")
            idx = self.iface_combo.findText(saved)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
            else:
                self.iface_combo.setCurrentText(saved)
        except Exception:
            pass

        # Interface status indicator
        self._iface_lbl = QLabel("Interface status: not checked")
        self._iface_lbl.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; background: transparent;"
        )
        iface_layout.addWidget(self._iface_lbl)

        check_btn = GlowButton("🔍 Check", COLORS["accent_cyan"])
        check_btn.setFixedHeight(28)
        check_btn.clicked.connect(self._check_interface)
        iface_layout.addWidget(check_btn)

        self._controls_layout.addWidget(iface_group)

        # ── Target(s) ────────────────────────────────────────────────────────
        tgt_group = QGroupBox("Target CAN ID(s)")
        tgt_layout = QVBoxLayout(tgt_group)

        t1 = QHBoxLayout()
        t1.addWidget(QLabel("Single ID (hex):"))
        self.target_id = QLineEdit("0x123")
        self.target_id.setPlaceholderText("e.g. 0x7E0")
        t1.addWidget(self.target_id)
        tgt_layout.addLayout(t1)

        self.use_range = QCheckBox("Use ID Range instead")
        self.use_range.toggled.connect(self._on_range_toggle)
        tgt_layout.addWidget(self.use_range)

        t2 = QHBoxLayout()
        t2.addWidget(QLabel("Range:"))
        self.target_range = QLineEdit("0x100-0x1FF")
        self.target_range.setPlaceholderText("e.g. 0x100-0x1FF or 0x100,0x200,0x300")
        self.target_range.setEnabled(False)
        t2.addWidget(self.target_range)
        tgt_layout.addLayout(t2)

        self._controls_layout.addWidget(tgt_group)

        # ── DLC options ───────────────────────────────────────────────────────
        opts_group = QGroupBox("DLC Options")
        opts_layout = QVBoxLayout(opts_group)

        o1 = QHBoxLayout()
        o1.addWidget(QLabel("Min DLC:"))
        self.min_dlc = QSpinBox()
        self.min_dlc.setRange(0, 8)
        self.min_dlc.setValue(0)
        o1.addWidget(self.min_dlc)
        opts_layout.addLayout(o1)

        o2 = QHBoxLayout()
        o2.addWidget(QLabel("Max DLC:"))
        self.max_dlc = QSpinBox()
        self.max_dlc.setRange(0, 8)
        self.max_dlc.setValue(8)
        o2.addWidget(self.max_dlc)
        opts_layout.addLayout(o2)

        o3 = QHBoxLayout()
        o3.addWidget(QLabel("Payload Pattern:"))
        self.pattern = QComboBox()
        self.pattern.addItems(["rand", "zeros", "ones", "incr", "decr", "alt"])
        o3.addWidget(self.pattern)
        opts_layout.addLayout(o3)

        # Pattern descriptions
        pat_desc = QLabel(
            "rand=random  zeros=0x00  ones=0xFF  incr=00→FF  decr=FF→00  alt=AA/55"
        )
        pat_desc.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 9px; background: transparent;"
        )
        pat_desc.setWordWrap(True)
        opts_layout.addWidget(pat_desc)

        self._controls_layout.addWidget(opts_group)

        # ── Timing & Control ──────────────────────────────────────────────────
        ctrl_group = QGroupBox("Timing & Control")
        ctrl_layout = QVBoxLayout(ctrl_group)

        c1 = QHBoxLayout()
        c1.addWidget(QLabel("Delay between frames (s):"))
        self.delay = QDoubleSpinBox()
        self.delay.setDecimals(3)
        self.delay.setSingleStep(0.001)
        self.delay.setRange(0.0, 10.0)
        self.delay.setValue(0.005)
        c1.addWidget(self.delay)
        ctrl_layout.addLayout(c1)

        c2 = QHBoxLayout()
        c2.addWidget(QLabel("Timeout (s):"))
        self.timeout = QSpinBox()
        self.timeout.setRange(5, 3600)
        self.timeout.setValue(60)
        c2.addWidget(self.timeout)
        ctrl_layout.addLayout(c2)

        self.repeat = QCheckBox("Repeat until KILL (--repeat)")
        ctrl_layout.addWidget(self.repeat)

        self._controls_layout.addWidget(ctrl_group)

        # ── Logging ───────────────────────────────────────────────────────────
        log_group = QGroupBox("Log Output (optional)")
        log_layout = QVBoxLayout(log_group)

        lf = QHBoxLayout()
        self.log_file = QLineEdit()
        self.log_file.setPlaceholderText("logs/lenattack.csv  (blank = no file)")
        lf.addWidget(self.log_file)
        browse_btn = GlowButton("Browse", COLORS["accent_cyan"])
        browse_btn.setFixedWidth(70)
        browse_btn.clicked.connect(self._browse_log)
        lf.addWidget(browse_btn)
        log_layout.addLayout(lf)

        self._controls_layout.addWidget(log_group)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _on_range_toggle(self, checked: bool):
        self.target_id.setEnabled(not checked)
        self.target_range.setEnabled(checked)

    def _browse_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Log File", "logs/lenattack.csv",
            "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.log_file.setText(path)

    def _get_iface(self) -> str:
        return self.iface_combo.currentText().strip() or (
            "pcan" if _is_windows() else "vcan0"
        )

    def _check_interface(self):
        iface = self._get_iface()
        from utils.lenattack_engine import validate_interface
        v = validate_interface(iface)
        if v.ok:
            self._iface_lbl.setText(f"✅  {v.reason}")
            self._iface_lbl.setStyleSheet(
                f"color: {COLORS.get('accent_green', '#00c896')}; "
                f"font-size: 10px; background: transparent;"
            )
        else:
            self._iface_lbl.setText(f"❌  {v.reason}")
            self._iface_lbl.setStyleSheet(
                f"color: {COLORS.get('critical', '#ff4d6d')}; "
                f"font-size: 10px; background: transparent;"
            )
            for hint_line in v.setup_hint.splitlines():
                self.terminal.append_error(f"  {hint_line}")

    def _parse_targets(self):
        """Returns (list_of_ids, error_str). error_str='' on success."""
        from utils.lenattack_engine import parse_targets
        if self.use_range.isChecked():
            spec = self.target_range.text().strip()
        else:
            spec = self.target_id.text().strip()
        return parse_targets(spec)

    # ── Run / Kill ────────────────────────────────────────────────────────────

    def run_command(self):
        """Override base: always use built-in LenAttackEngine — no subprocess."""
        if self._len_thread and self._len_thread.is_alive():
            self.terminal.append_error(
                "LenAttack is already running — click KILL to stop."
            )
            return

        iface = self._get_iface()

        # Validate interface first
        from utils.lenattack_engine import validate_interface
        v = validate_interface(iface)
        if not v.ok:
            self.terminal.append_error("─" * 55)
            self.terminal.append_error("  CAN INTERFACE NOT AVAILABLE")
            self.terminal.append_error("─" * 55)
            for ln in v.error_lines():
                self.terminal.append_error(f"  {ln}")
            self.terminal.append_error("─" * 55)
            return

        # Parse targets
        targets, err = self._parse_targets()
        if err:
            self.terminal.append_error(f"[TARGET ERROR] {err}")
            return
        if not targets:
            self.terminal.append_error(
                "[TARGET ERROR] No valid CAN IDs. "
                "Enter a hex ID like 0x123 or a range like 0x100-0x1FF."
            )
            return

        # Validate DLC range
        min_d = self.min_dlc.value()
        max_d = self.max_dlc.value()
        if min_d > max_d:
            self.terminal.append_error(
                f"[CONFIG ERROR] min_dlc ({min_d}) > max_dlc ({max_d}). "
                "Please fix the DLC range."
            )
            return

        # Build engine
        self._len_stop = threading.Event()

        def cb(line: str):
            if "[ERROR]" in line:
                self._bridge.err_ready.emit(line)
            else:
                self._bridge.line_ready.emit(line)

        from utils.lenattack_engine import LenAttackEngine
        engine = LenAttackEngine(
            iface=iface,
            targets=targets,
            min_dlc=min_d,
            max_dlc=max_d,
            pattern=self.pattern.currentText(),
            repeat=self.repeat.isChecked(),
            delay=self.delay.value(),
            timeout=float(self.timeout.value()),
            stop_event=self._len_stop,
            status_cb=cb,
            log_path=self.log_file.text().strip() or None,
        )

        # Update UI
        tgt_str = f"0x{targets[0]:X}" if len(targets) == 1 else f"{len(targets)} targets"
        cmd_preview = (
            f"lenattack {tgt_str} --min-dlc {min_d} --max-dlc {max_d} "
            f"--pattern {self.pattern.currentText()} -i {iface}"
        )
        self._update_cmd_preview(cmd_preview.split())
        self.terminal.append_command(cmd_preview)

        self._status_badge.setText("RUNNING")
        self._run_btn.setEnabled(False)
        self._kill_btn.setEnabled(True)

        # Launch thread + watcher
        self._len_thread = engine.start_in_thread()

        def _watch():
            self._len_thread.join()
            self._bridge.done.emit(0)

        threading.Thread(target=_watch, daemon=True).start()

    def kill_command(self):
        """Stop the running engine immediately."""
        self._len_stop.set()
        self.runner.kill()   # also kill any subprocess if running
        self.terminal.append_output("[INFO] Stop signal sent to LenAttack engine.")

    def _on_engine_done(self, rc: int):
        """Called from Qt main thread when engine thread finishes."""
        self._status_badge.setText("IDLE")
        self._run_btn.setEnabled(True)
        self._kill_btn.setEnabled(False)
        if rc == 0:
            self.terminal.append_success("LenAttack finished successfully.")
        else:
            self.terminal.append_error(f"LenAttack exited with error (rc={rc}).")

    # ── build_args: kept for compatibility / subprocess fallback ──────────────

    def build_args(self):
        """
        Returns subprocess-mode CLI args.
        Module name is 'lenattack' — interface is passed as -i <iface>.
        Never uses the broken 'lenattack-<iface>' format.
        """
        iface = self._get_iface()
        targets, err = self._parse_targets()
        if err:
            self.terminal.append_error(f"[TARGET ERROR] {err}")
            return None

        target_str = self.target_id.text().strip()
        if self.use_range.isChecked():
            target_str = self.target_range.text().strip()

        args = [
            "lenattack",
            target_str,
            "--min-dlc", str(self.min_dlc.value()),
            "--max-dlc", str(self.max_dlc.value()),
            "--pattern", self.pattern.currentText(),
            "-i", iface,
        ]
        if self.repeat.isChecked():
            args.append("--repeat")
        if self.log_file.text().strip():
            args += ["--log", self.log_file.text().strip()]

        return args

    def update_msg_list(self, msg_names: list):
        """Called when a DBC is loaded — populates target ID hint."""
        if msg_names and hasattr(self, "target_id"):
            self.target_id.setPlaceholderText(
                msg_names[0] if msg_names else "0x123"
            )
