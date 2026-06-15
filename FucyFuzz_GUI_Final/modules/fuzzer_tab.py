"""
Fuzzer Module Tab — v2
======================
Integrates with FuzzerEngine for random/bruteforce/mutate modes.

Key fixes:
  - MutateFuzzer runs in its own thread with stop-event — NO hang/freeze
  - RandomFuzzer and BruteforceFuzzer also use stop-events
  - CAN interface validated before any fuzzer starts
  - Clear error messages shown in terminal (no stack traces)
  - All fuzzers log to session logger + optional CSV/TXT file
  - KILL button properly stops all fuzzer threads
"""

import threading
import logging

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QHBoxLayout, QVBoxLayout, QGroupBox, QFileDialog, QCheckBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton
from ui.theme import COLORS

log = logging.getLogger(__name__)


# ── Thread-safe signal bridge (emit to Qt from fuzzer thread) ──────────────────
class _FuzzerBridge(QObject):
    line_ready = pyqtSignal(str)    # general output
    err_ready  = pyqtSignal(str)    # error output
    done       = pyqtSignal(int)    # rc: 0=ok, non-zero=error


class FuzzerTab(BaseModuleTab):
    MODULE_NAME = "fuzzer"

    def __init__(self, runner, data_manager, parent=None):
        self._fuzz_stop   = threading.Event()
        self._fuzz_thread = None
        self._bridge      = _FuzzerBridge()
        super().__init__(runner, data_manager, parent)
        # Wire bridge signals to terminal (thread-safe via Qt queued conn)
        self._bridge.line_ready.connect(self.terminal.append_output,
                                        type=Qt.QueuedConnection)
        self._bridge.err_ready.connect(self.terminal.append_error,
                                       type=Qt.QueuedConnection)
        self._bridge.done.connect(self._on_fuzzer_done,
                                  type=Qt.QueuedConnection)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("Fuzzer Module"))

        # ── Interface ────────────────────────────────────────────────────────
        iface_group = QGroupBox("CAN Interface")
        iface_layout = QHBoxLayout(iface_group)
        iface_layout.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(["vcan0", "can0", "can1"])
        self.iface_combo.setEditable(True)
        # Pre-populate from config
        iface_layout.addWidget(self.iface_combo)
        self._controls_layout.addWidget(iface_group)
        # Set from config
        try:
            saved = self.cfg.get('interface', 'vcan0')
            idx = self.iface_combo.findText(saved)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
            else:
                self.iface_combo.setCurrentText(saved)
        except Exception:
            pass

        # ── CAN ID ───────────────────────────────────────────────────────────
        id_group = QGroupBox("Target CAN ID")
        id_layout = QHBoxLayout(id_group)
        id_layout.addWidget(QLabel("CAN ID (hex):"))
        self.can_id_edit = QLineEdit("0x7E0")
        self.can_id_edit.setPlaceholderText("e.g. 0x7E0")
        id_layout.addWidget(self.can_id_edit)
        self._controls_layout.addWidget(id_group)

        # ── Fuzz Mode ─────────────────────────────────────────────────────────
        cmd_group = QGroupBox("Fuzz Mode")
        cmd_layout = QVBoxLayout(cmd_group)
        self.subcmd = QComboBox()
        self.subcmd.addItems(["random", "bruteforce", "mutate", "replay", "identify"])
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_group)

        # ── Random options ────────────────────────────────────────────────────
        self._random_group = QGroupBox("Random Fuzzer Options")
        rng_layout = QVBoxLayout(self._random_group)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Min DLC:"))
        self.min_dlc = QSpinBox()
        self.min_dlc.setRange(0, 8)
        self.min_dlc.setValue(1)
        r1.addWidget(self.min_dlc)
        r1.addWidget(QLabel("Max DLC:"))
        self.max_dlc = QSpinBox()
        self.max_dlc.setRange(1, 8)
        self.max_dlc.setValue(8)
        r1.addWidget(self.max_dlc)
        rng_layout.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Seed (int, optional):"))
        self.rand_seed = QLineEdit()
        self.rand_seed.setPlaceholderText("e.g. 42 (leave blank for random)")
        r2.addWidget(self.rand_seed)
        rng_layout.addLayout(r2)

        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Max Frames (0=unlimited):"))
        self.rand_max = QSpinBox()
        self.rand_max.setRange(0, 1000000)
        self.rand_max.setValue(500)
        r3.addWidget(self.rand_max)
        rng_layout.addLayout(r3)

        r4 = QHBoxLayout()
        r4.addWidget(QLabel("Delay (s):"))
        self.rand_delay = QDoubleSpinBox()
        self.rand_delay.setDecimals(3)
        self.rand_delay.setSingleStep(0.001)
        self.rand_delay.setValue(0.01)
        r4.addWidget(self.rand_delay)
        rng_layout.addLayout(r4)

        r5 = QHBoxLayout()
        r5.addWidget(QLabel("Log File (optional):"))
        self.rand_log = QLineEdit()
        self.rand_log.setPlaceholderText("logs/fuzzer_random.csv")
        r5.addWidget(self.rand_log)
        rng_layout.addLayout(r5)

        self._controls_layout.addWidget(self._random_group)

        # ── Bruteforce options ────────────────────────────────────────────────
        self._brute_group = QGroupBox("Bruteforce Fuzzer Options")
        brute_layout = QVBoxLayout(self._brute_group)

        b1 = QHBoxLayout()
        b1.addWidget(QLabel("Pattern ('..'\u200b=wildcard):"))
        self.brute_pattern = QLineEdit("7f..")
        self.brute_pattern.setPlaceholderText("e.g. 12ab..78  ('..'\u200b=all 256 values)")
        b1.addWidget(self.brute_pattern)
        brute_layout.addLayout(b1)

        b2 = QHBoxLayout()
        b2.addWidget(QLabel("Delay (s):"))
        self.brute_delay = QDoubleSpinBox()
        self.brute_delay.setDecimals(3)
        self.brute_delay.setValue(0.005)
        b2.addWidget(self.brute_delay)
        brute_layout.addLayout(b2)

        self._controls_layout.addWidget(self._brute_group)

        # ── Mutate options ────────────────────────────────────────────────────
        self._mutate_group = QGroupBox("Mutate Fuzzer Options")
        mutate_layout = QVBoxLayout(self._mutate_group)

        m1 = QHBoxLayout()
        m1.addWidget(QLabel("Base patterns (space-sep):"))
        self.mutate_patterns = QLineEdit("7f00 12ab00")
        self.mutate_patterns.setPlaceholderText("e.g. 7f.. 12ab.... (hex + '..' wildcards)")
        m1.addWidget(self.mutate_patterns)
        mutate_layout.addLayout(m1)

        m2 = QHBoxLayout()
        m2.addWidget(QLabel("Mutation rate (0.0–1.0):"))
        self.mutate_rate = QDoubleSpinBox()
        self.mutate_rate.setRange(0.01, 1.0)
        self.mutate_rate.setSingleStep(0.05)
        self.mutate_rate.setValue(0.2)
        m2.addWidget(self.mutate_rate)
        mutate_layout.addLayout(m2)

        m3 = QHBoxLayout()
        m3.addWidget(QLabel("Max Frames (0=unlimited):"))
        self.mutate_max = QSpinBox()
        self.mutate_max.setRange(0, 1000000)
        self.mutate_max.setValue(1000)
        m3.addWidget(self.mutate_max)
        mutate_layout.addLayout(m3)

        m4 = QHBoxLayout()
        m4.addWidget(QLabel("Timeout (s):"))
        self.mutate_timeout = QSpinBox()
        self.mutate_timeout.setRange(10, 3600)
        self.mutate_timeout.setValue(300)
        m4.addWidget(self.mutate_timeout)
        mutate_layout.addLayout(m4)

        m5 = QHBoxLayout()
        m5.addWidget(QLabel("Delay (s):"))
        self.mutate_delay = QDoubleSpinBox()
        self.mutate_delay.setDecimals(3)
        self.mutate_delay.setValue(0.01)
        m5.addWidget(self.mutate_delay)
        mutate_layout.addLayout(m5)

        self._controls_layout.addWidget(self._mutate_group)

        # ── Replay/Identify options ───────────────────────────────────────────
        self._file_group = QGroupBox("Log File (Replay / Identify)")
        file_layout = QVBoxLayout(self._file_group)
        fl = QHBoxLayout()
        self.log_file = QLineEdit()
        self.log_file.setPlaceholderText("path/to/log.txt")
        fl.addWidget(self.log_file)
        browse_btn = GlowButton("Browse", COLORS['accent_cyan'])
        browse_btn.setFixedWidth(70)
        browse_btn.clicked.connect(self._browse_log)
        fl.addWidget(browse_btn)
        file_layout.addLayout(fl)
        self._controls_layout.addWidget(self._file_group)

        self._on_subcmd_change("random")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _browse_log(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Log File", "", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.log_file.setText(path)

    def _on_subcmd_change(self, cmd):
        self._random_group.setVisible(cmd == "random")
        self._brute_group.setVisible(cmd == "bruteforce")
        self._mutate_group.setVisible(cmd == "mutate")
        self._file_group.setVisible(cmd in ("replay", "identify"))

    def _get_iface(self) -> str:
        return self.iface_combo.currentText().strip() or self.cfg.get('interface', 'vcan0')

    def _parse_can_id(self) -> int:
        txt = self.can_id_edit.text().strip()
        try:
            return int(txt, 16) if txt.startswith("0x") or txt.startswith("0X") else int(txt, 16)
        except ValueError:
            return 0x7E0

    # ── Run / Kill ────────────────────────────────────────────────────────────

    def run_command(self):
        """Override: route built-in modes to fuzzer engine; fall through for others."""
        mode = self.subcmd.currentText()

        if mode in ("random", "bruteforce", "mutate"):
            self._run_builtin_fuzzer(mode)
        else:
            # replay / identify — delegate to subprocess runner as before
            args = self.build_args()
            if args is None:
                return
            self.runner.run(args, module=self.MODULE_NAME)
            self._update_cmd_preview(args)

    def kill_command(self):
        """Stop both the subprocess runner AND any running fuzzer thread."""
        self.runner.kill()
        self._fuzz_stop.set()
        self.terminal.append_output("[INFO] Stop signal sent to fuzzer.")

    def _run_builtin_fuzzer(self, mode: str):
        """Launch the appropriate FuzzerEngine class in a daemon thread."""
        # Guard: don't start if already running
        if self._fuzz_thread and self._fuzz_thread.is_alive():
            self.terminal.append_error("Fuzzer is already running — click KILL first.")
            return

        # Validate interface before doing anything
        iface = self._get_iface()
        from utils.can_interface import check_interface
        status = check_interface(iface)
        if not status.ok:
            self.terminal.append_error("─" * 55)
            self.terminal.append_error("  CAN INTERFACE NOT AVAILABLE")
            self.terminal.append_error("─" * 55)
            for ln in status.user_message().splitlines():
                self.terminal.append_error(f"  {ln}")
            self.terminal.append_error("─" * 55)
            return

        can_id = self._parse_can_id()
        self._fuzz_stop = threading.Event()

        # Emit callback → terminal
        def cb(line: str):
            if "[ERROR]" in line:
                self._bridge.err_ready.emit(line)
            else:
                self._bridge.line_ready.emit(line)

        from utils.fuzzer_engine import RandomFuzzer, BruteforceFuzzer, MutateFuzzer

        try:
            if mode == "random":
                seed_txt = self.rand_seed.text().strip()
                seed = int(seed_txt) if seed_txt else None
                fuzzer = RandomFuzzer(
                    iface=iface,
                    can_id=can_id,
                    min_dlc=self.min_dlc.value(),
                    max_dlc=self.max_dlc.value(),
                    delay=self.rand_delay.value(),
                    max_frames=self.rand_max.value(),
                    timeout=300.0,
                    seed=seed,
                    stop_event=self._fuzz_stop,
                    status_cb=cb,
                    log_path=self.rand_log.text().strip() or None,
                )

            elif mode == "bruteforce":
                fuzzer = BruteforceFuzzer(
                    iface=iface,
                    can_id=can_id,
                    pattern=self.brute_pattern.text().strip(),
                    delay=self.brute_delay.value(),
                    timeout=600.0,
                    stop_event=self._fuzz_stop,
                    status_cb=cb,
                )

            elif mode == "mutate":
                patterns = self.mutate_patterns.text().strip().split()
                fuzzer = MutateFuzzer(
                    iface=iface,
                    can_id=can_id,
                    base_patterns=patterns,
                    mutation_rate=self.mutate_rate.value(),
                    delay=self.mutate_delay.value(),
                    max_frames=self.mutate_max.value(),
                    timeout=float(self.mutate_timeout.value()),
                    stop_event=self._fuzz_stop,
                    status_cb=cb,
                )
            else:
                return

        except Exception as exc:
            self.terminal.append_error(f"Failed to create fuzzer: {exc}")
            return

        # Update UI state
        self._status_badge.setText("RUNNING")
        self._run_btn.setEnabled(False)
        self._kill_btn.setEnabled(True)
        self.terminal.append_command(
            f"fuzzer {mode} iface={iface} id=0x{can_id:X}"
        )

        # Launch thread
        self._fuzz_thread = fuzzer.start_in_thread()

        # Monitor thread completion
        def _watch():
            self._fuzz_thread.join()
            self._bridge.done.emit(0)

        threading.Thread(target=_watch, daemon=True).start()

    def _on_fuzzer_done(self, rc: int):
        """Called from Qt thread when fuzzer thread completes."""
        self._status_badge.setText("IDLE")
        self._run_btn.setEnabled(True)
        self._kill_btn.setEnabled(False)
        if rc == 0:
            self.terminal.append_success("Fuzzer finished.")
        else:
            self.terminal.append_error(f"Fuzzer exited with code {rc}.")

    # ── build_args: only used for replay/identify (subprocess mode) ───────────

    def build_args(self):
        iface = self.get_interface()
        cmd = self.subcmd.currentText()
        args = ["-i", iface, "fuzzer", cmd]

        if cmd in ("replay", "identify"):
            lf = self.log_file.text().strip()
            if not lf:
                self.terminal.append_error("Please specify a log file.")
                return None
            args += [lf]

        return args

    def update_msg_list(self, msg_names: list):
        """Called when a DBC is loaded."""
        if msg_names and hasattr(self, 'brute_pattern'):
            self.brute_pattern.setPlaceholderText(
                ", ".join(msg_names[:3]) + " …"
            )
