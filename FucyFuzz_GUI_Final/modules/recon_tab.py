"""
Recon Module Tab
Provides:
  - Start Listener (passive CAN listener)
  - Master Demo — queues and runs every fucyfuzz module command in sequence
"""

import threading
import subprocess
import os

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QCheckBox, QGroupBox, QProgressBar,
    QSplitter, QFrame
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QObject

from ui.widgets import SectionHeader, GlowButton, SolidButton, TerminalWidget, StatusBadge
from ui.theme import COLORS
from utils.runner import CommandRunner
from utils.data_manager import DataManager
from utils.config import get_config


# ---------------------------------------------------------------------------
# Background worker that runs the master-demo command queue
# ---------------------------------------------------------------------------
class MasterDemoWorker(QObject):
    progress     = pyqtSignal(int, int, str)   # current, total, cmd_str
    log_line     = pyqtSignal(str)
    progress_log = pyqtSignal(str)
    finished     = pyqtSignal(int)             # commands executed

    def __init__(self, commands: list, binary: str, interface: str):
        super().__init__()
        self._commands  = commands
        self._binary    = binary
        self._interface = interface
        self._stop      = False

    def run(self):
        total = len(self._commands)
        executed = 0
        for i, args in enumerate(self._commands):
            if self._stop:
                break
            cmd_str = self._binary + " " + " ".join(str(a) for a in args)
            self.progress.emit(i + 1, total, cmd_str)
            self.log_line.emit(f"\n[MASTER DEMO] Step {i+1}/{total}: {cmd_str}")
            try:
                proc = subprocess.Popen(
                    [self._binary] + [str(a) for a in args],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )
                import time
                last_progress_time = 0.0
                for raw in iter(proc.stdout.readline, b''):
                    if not raw:
                        continue
                    is_progress = (b'\r' in raw)
                    raw_str = raw.decode('utf-8', errors='replace')
                    line = raw_str.replace('\r', '').replace('\x00', '').strip()
                    if not line:
                        continue
                    if is_progress:
                        now = time.time()
                        if now - last_progress_time < 0.1:
                            continue
                        last_progress_time = now
                        self.progress_log.emit(line)
                    else:
                        self.log_line.emit(line)
                proc.wait(timeout=30)
                executed += 1
            except FileNotFoundError:
                self.log_line.emit(f"  [ERROR] binary not found: {self._binary}")
                break
            except subprocess.TimeoutExpired:
                self.log_line.emit(f"  [TIMEOUT] command timed out, skipping")
                try:
                    proc.kill()
                except Exception:
                    pass
                executed += 1
            except Exception as e:
                self.log_line.emit(f"  [ERROR] {e}")
                executed += 1

        self.finished.emit(executed)

    def stop(self):
        self._stop = True


# ---------------------------------------------------------------------------
# Recon Tab
# ---------------------------------------------------------------------------
class ReconTab(QWidget):
    """
    Recon tab:
      - Start Listener  (listener [-r] on the configured interface)
      - Master Demo      (runs every fucyfuzz command in sequence)
    """

    def __init__(self, runner: CommandRunner, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.runner = runner
        self.dm     = data_manager
        self.cfg    = get_config()

        self._demo_worker  = None
        self._demo_thread  = None
        self._demo_running = False

        self._setup_ui()
        self._connect_runner()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── toolbar ───────────────────────────────────────────────────────────
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

        self._kill_btn = GlowButton("■  KILL", COLORS['critical'], danger=True)
        self._kill_btn.setEnabled(False)
        self._kill_btn.clicked.connect(self._kill)
        tb.addWidget(self._kill_btn)

        root.addWidget(toolbar)

        # ── body splitter ─────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {COLORS['border']}; width: 1px; }}"
        )

        # LEFT: controls
        left = QWidget()
        left.setMinimumWidth(300)
        left.setMaximumWidth(400)
        left.setStyleSheet(f"background-color: {COLORS['bg_secondary']};")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(14)

        left_layout.addWidget(SectionHeader("Reconnaissance"))

        # ── Listener ──────────────────────────────────────────────────────────
        listener_group = QGroupBox("Passive Listener")
        ll = QVBoxLayout(listener_group)

        lbl = QLabel(
            "Start a passive listener on the configured CAN interface.\n"
            "All frames will stream to the terminal."
        )
        lbl.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;"
        )
        lbl.setWordWrap(True)
        ll.addWidget(lbl)

        self._raw_mode = QCheckBox("Raw mode (-r)")
        self._raw_mode.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent;")
        self._raw_mode.setChecked(True)
        ll.addWidget(self._raw_mode)

        self._listener_btn = SolidButton("▶  Start Listener", COLORS['accent_cyan'])
        self._listener_btn.setFixedHeight(36)
        self._listener_btn.clicked.connect(self._run_listener)
        ll.addWidget(self._listener_btn)

        left_layout.addWidget(listener_group)

        # ── Master Demo ───────────────────────────────────────────────────────
        demo_group = QGroupBox("Master Demo — Run All Tests")
        dl = QVBoxLayout(demo_group)

        demo_lbl = QLabel(
            "Queues and runs every fucyfuzz module command in sequence:\n"
            "fuzzer (random/brute/mutate/replay/identify), lenattack,\n"
            "dcm (discovery/services/subfunc/dtc/testerpresent),\n"
            "uds (discovery/services/ecu_reset/testerpresent/\n"
            "     security_seed/dump_dids/read_mem)."
        )
        demo_lbl.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;"
        )
        demo_lbl.setWordWrap(True)
        dl.addWidget(demo_lbl)

        self._use_interface = QCheckBox("Pass interface via -i vcan0")
        self._use_interface.setStyleSheet(
            f"color: {COLORS['text_secondary']}; background: transparent;"
        )
        self._use_interface.setChecked(True)
        dl.addWidget(self._use_interface)

        # progress
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                height: 10px;
                text-align: center;
                font-size: 9px;
                color: {COLORS['text_secondary']};
            }}
            QProgressBar::chunk {{
                background: {COLORS['accent_cyan']};
                border-radius: 3px;
            }}
        """)
        dl.addWidget(self._progress_bar)

        self._progress_label = QLabel("Ready")
        self._progress_label.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 9px; background: transparent;"
        )
        dl.addWidget(self._progress_label)

        btn_row = QHBoxLayout()
        self._demo_btn = SolidButton("🚀  Run All Tests", COLORS['accent_purple'])
        self._demo_btn.setFixedHeight(38)
        self._demo_btn.clicked.connect(self._toggle_demo)
        btn_row.addWidget(self._demo_btn)
        dl.addLayout(btn_row)

        left_layout.addWidget(demo_group)
        left_layout.addStretch()

        splitter.addWidget(left)

        # RIGHT: terminal
        right = QWidget()
        right.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(16, 16, 16, 16)
        self.terminal = TerminalWidget()
        rl.addWidget(self.terminal)
        splitter.addWidget(right)
        splitter.setSizes([340, 800])

        root.addWidget(splitter)

    # ── Runner signals ────────────────────────────────────────────────────────

    def _connect_runner(self):
        self.runner.started.connect(self._on_started,  type=Qt.QueuedConnection)
        self.runner.output_line.connect(self._on_runner_output,  type=Qt.QueuedConnection)
        self.runner.error_line.connect(self._on_runner_error,   type=Qt.QueuedConnection)
        self.runner.progress_line.connect(self._on_runner_progress, type=Qt.QueuedConnection)
        self.runner.finished.connect(self._on_finished, type=Qt.QueuedConnection)

    @pyqtSlot(str)
    def _on_runner_output(self, line: str):
        if self.runner.cur_module == "listener":
            self.terminal.append_output(line)

    @pyqtSlot(str)
    def _on_runner_error(self, line: str):
        if self.runner.cur_module == "listener":
            self.terminal.append_error(line)

    @pyqtSlot(str)
    def _on_runner_progress(self, line: str):
        if self.runner.cur_module == "listener":
            self.terminal.append_progress(line)

    def _on_started(self, cmd: str):
        if self.runner.cur_module != "listener":
            return
        self._cmd_preview.setText(cmd[:80] + ("..." if len(cmd) > 80 else ""))
        self._status_badge.setText("RUNNING")
        self._status_badge.setStyleSheet(
            f"color: {COLORS['accent_yellow']};"
            f"background-color: {COLORS['accent_yellow']}22;"
            f"border: 1px solid {COLORS['accent_yellow']}66;"
            f"border-radius: 3px; padding: 2px 8px; font-size: 9px; letter-spacing: 1px;"
        )
        self._kill_btn.setEnabled(True)
        self._listener_btn.setEnabled(False)

    def _on_finished(self, rc: int):
        if self.runner.cur_module != "listener":
            return
        self._status_badge.setText("IDLE")
        self._status_badge.setStyleSheet(
            f"color: {COLORS['text_secondary']};"
            f"background-color: {COLORS['text_secondary']}22;"
            f"border: 1px solid {COLORS['text_secondary']}66;"
            f"border-radius: 3px; padding: 2px 8px; font-size: 9px; letter-spacing: 1px;"
        )
        self._kill_btn.setEnabled(False)
        self._listener_btn.setEnabled(True)
        if rc == 0:
            self.terminal.append_success("Listener exited cleanly.")
        else:
            self.terminal.append_error(f"Listener exited with code {rc}")

    # ── Listener ──────────────────────────────────────────────────────────────

    def _run_listener(self):
        if self.runner.is_running:
            self.terminal.append_error("A command is already running. Kill it first.")
            return
        args = ["listener"]
        if self._raw_mode.isChecked():
            args.append("-r")
        self.runner.run(args, module="listener")
        self.terminal.append_command("fucyfuzz " + " ".join(args))

    def _kill(self):
        if self._demo_running:
            self._stop_demo()
        else:
            self.runner.kill()

    # ── Master Demo ───────────────────────────────────────────────────────────

    def _build_demo_commands(self) -> list:
        """Build the full list of (args) tuples for the master demo."""
        iface = ["-i", self.cfg.get('interface', 'vcan0')] if self._use_interface.isChecked() else []

        cmds = []
        # Fuzzer
        cmds.append(["fuzzer", "random"]                                             + iface)
        cmds.append(["fuzzer", "random", "-min", "4", "-seed", "0xabc123", "-f", "log.txt"] + iface)
        cmds.append(["fuzzer", "brute",  "0x123", "12ab..78"]                       + iface)
        cmds.append(["fuzzer", "mutate", "7f..", "12ab...."]                        + iface)

        # LenAttack
        cmds.append(["lenattack", "0x123"]                                          + iface)
        cmds.append(["lenattack", "0x123", "--min-dlc", "0", "--max-dlc", "8",
                     "--pattern", "rand"]                                           + iface)

        # DCM
        cmds.append(["dcm", "discovery"]                                            + iface)
        cmds.append(["dcm", "discovery", "-autoblacklist", "10"]                    + iface)
        cmds.append(["dcm", "services", "0x7E0", "0x7E8"]                          + iface)
        cmds.append(["dcm", "subfunc",  "0x7E0", "0x7E8", "0x22", "2", "3"]        + iface)
        cmds.append(["dcm", "dtc",      "0x7E0", "0x7E8"]                          + iface)
        cmds.append(["dcm", "testerpresent", "0x7E0"]                              + iface)

        # UDS
        cmds.append(["uds", "discovery"]                                            + iface)
        cmds.append(["uds", "discovery", "-autoblacklist", "10"]                    + iface)
        cmds.append(["uds", "services", "0x7E0", "0x7E8"]                          + iface)
        cmds.append(["uds", "ecu_reset",  "1", "0x7E0", "0x7E8"]                  + iface)
        cmds.append(["uds", "testerpresent", "0x7E0"]                              + iface)
        cmds.append(["uds", "security_seed", "0x3", "0x1", "0x7E0", "0x7E8",
                     "-r", "1", "-d", "0.5"]                                        + iface)
        cmds.append(["uds", "dump_dids", "0x7E0", "0x7E8"]                         + iface)
        cmds.append(["uds", "read_mem",  "0x7E0", "0x7E8",
                     "--start_addr", "0x0200", "--mem_length", "0x10000"]           + iface)

        return cmds

    def _toggle_demo(self):
        if self._demo_running:
            self._stop_demo()
        else:
            self._start_demo()

    def _start_demo(self):
        commands = self._build_demo_commands()
        binary   = self.cfg.get('binary_path', './fucyfuzz')

        self._demo_running = True
        self._demo_btn.setText("⏹  Stop Demo")
        self._demo_btn.setStyleSheet(
            f"background-color: {COLORS['critical']}; color: white; border: none;"
        )
        self._progress_bar.setValue(0)
        self._progress_bar.setMaximum(len(commands))
        self._progress_label.setText(f"0 / {len(commands)} commands")
        self.terminal.clear()
        self.terminal.append_command(f"Starting Master Demo — {len(commands)} commands")

        self._demo_worker = MasterDemoWorker(
            commands, binary, self.cfg.get('interface', 'vcan0')
        )
        self._demo_worker.progress.connect(self._on_demo_progress,              type=Qt.QueuedConnection)
        self._demo_worker.log_line.connect(self._on_demo_log_line,              type=Qt.QueuedConnection)
        self._demo_worker.progress_log.connect(self._on_demo_progress_log,      type=Qt.QueuedConnection)
        self._demo_worker.finished.connect(self._on_demo_finished,              type=Qt.QueuedConnection)

        self._demo_thread = threading.Thread(target=self._demo_worker.run, daemon=True)
        self._demo_thread.start()

        self._kill_btn.setEnabled(True)

    def _on_demo_log_line(self, line: str):
        self.terminal.append(line)

    def _on_demo_progress_log(self, line: str):
        self.terminal.append_progress(line)

    def _stop_demo(self):
        if self._demo_worker:
            self._demo_worker.stop()
        self._demo_running = False
        self._demo_btn.setText("🚀  Run All Tests")
        self._demo_btn.setStyleSheet("")
        self._kill_btn.setEnabled(False)
        self.terminal.append_error("Master Demo stopped by user.")
        self._progress_label.setText("Stopped")

    def _on_demo_progress(self, current: int, total: int, cmd: str):
        self._progress_bar.setValue(current)
        self._progress_bar.setMaximum(total)
        short = cmd[:70] + ("..." if len(cmd) > 70 else "")
        self._progress_label.setText(f"{current} / {total}  —  {short}")

    def _on_demo_finished(self, executed: int):
        self._demo_running = False
        self._demo_btn.setText("🚀  Run All Tests")
        self._demo_btn.setStyleSheet("")
        self._kill_btn.setEnabled(False)
        self.terminal.append_success(
            f"Master Demo complete — {executed} commands executed."
        )
        self._progress_label.setText(f"Done — {executed} commands")
        self._progress_bar.setValue(self._progress_bar.maximum())
