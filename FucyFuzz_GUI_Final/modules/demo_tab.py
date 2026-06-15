"""
Demo Tab
Quick-access fuzzing demos:
  - Speed Fuzz    (CAN ID 0x244, mutate pattern)
  - Indicator Fuzz (CAN ID 0x188)
  - Door Fuzz     (CAN ID 0x19B)
Each can be toggled on/off; stopping sends a reset frame.
Ported from fucyfuzz DemoFrame.
"""

import subprocess
import threading

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QGroupBox, QSplitter
)
from PyQt5.QtCore import Qt

from ui.widgets import SectionHeader, GlowButton, SolidButton, TerminalWidget, StatusBadge
from ui.theme import COLORS
from utils.runner import CommandRunner
from utils.data_manager import DataManager
from utils.config import get_config


class DemoTab(QWidget):
    """
    Three pre-configured vehicle fuzzing demos.
    Each button toggles a fuzzer run / sends a reset frame when stopped.
    """

    def __init__(self, runner: CommandRunner, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.runner = runner
        self.dm     = data_manager
        self.cfg    = get_config()

        self._speed_proc     = None
        self._indicator_proc = None
        self._door_proc      = None

        self._speed_active     = False
        self._indicator_active = False
        self._door_active      = False

        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

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
        tb.addStretch()
        root.addWidget(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background: {COLORS['border']}; width: 1px; }}"
        )

        # LEFT
        left = QWidget()
        left.setMinimumWidth(300)
        left.setMaximumWidth(420)
        left.setStyleSheet(f"background-color: {COLORS['bg_secondary']};")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(16, 16, 16, 16)
        ll.setSpacing(14)

        ll.addWidget(SectionHeader("Demo Commands"))

        note = QLabel(
            "Pre-configured vehicle fuzzing demos.\n"
            "Interface is read from global Config.\n"
            "Stopping any demo sends a safe reset frame."
        )
        note.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;"
        )
        note.setWordWrap(True)
        ll.addWidget(note)

        # Speed fuzz
        speed_group = QGroupBox("Speed Gauge Fuzz  (0x244)")
        sg = QVBoxLayout(speed_group)
        desc = QLabel("Mutates CAN ID 0x244 to confuse the instrument cluster speed gauge.")
        desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        desc.setWordWrap(True)
        sg.addWidget(desc)
        self._speed_btn = SolidButton("▶  Start Speed Fuzz", COLORS['accent_cyan'])
        self._speed_btn.setFixedHeight(36)
        self._speed_btn.clicked.connect(self._toggle_speed)
        sg.addWidget(self._speed_btn)
        ll.addWidget(speed_group)

        # Indicator fuzz
        ind_group = QGroupBox("Indicator Fuzz  (0x188)")
        ig = QVBoxLayout(ind_group)
        desc2 = QLabel("Mutates CAN ID 0x188 to fuzz turn indicator signals.")
        desc2.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        desc2.setWordWrap(True)
        ig.addWidget(desc2)
        self._ind_btn = SolidButton("▶  Start Indicator Fuzz", COLORS['accent_cyan'])
        self._ind_btn.setFixedHeight(36)
        self._ind_btn.clicked.connect(self._toggle_indicator)
        ig.addWidget(self._ind_btn)
        ll.addWidget(ind_group)

        # Door fuzz
        door_group = QGroupBox("Door Lock Fuzz  (0x19B)")
        dg = QVBoxLayout(door_group)
        desc3 = QLabel("Mutates CAN ID 0x19B to fuzz door lock state messages.")
        desc3.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        desc3.setWordWrap(True)
        dg.addWidget(desc3)
        self._door_btn = SolidButton("▶  Start Door Fuzz", COLORS['accent_cyan'])
        self._door_btn.setFixedHeight(36)
        self._door_btn.clicked.connect(self._toggle_door)
        dg.addWidget(self._door_btn)
        ll.addWidget(door_group)

        ll.addStretch()
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

    # ── Internal runner ───────────────────────────────────────────────────────

    def _run_bg(self, args: list) -> subprocess.Popen:
        """Launch binary in background, drain stdout via chunk reader."""
        import os
        binary = self.cfg.get('binary_path', './fucyfuzz')
        cmd = [binary] + [str(a) for a in args]
        self.terminal.append_command(" ".join(cmd))
        try:
            kwargs = {}
            if hasattr(os, 'setsid'):
                kwargs['preexec_fn'] = os.setsid
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                **kwargs,
            )
            stop_evt = threading.Event()
            proc._stop_event = stop_evt  # attach for cleanup
            threading.Thread(
                target=self._stream_chunked,
                args=(proc, stop_evt),
                daemon=True,
            ).start()
            return proc
        except FileNotFoundError:
            self.terminal.append_error(f"Binary not found: {binary}")
            return None
        except Exception as e:
            self.terminal.append_error(str(e))
            return None

    def _stream_chunked(self, proc, stop_event):
        """Chunk-based pipe reader — efficient, never blocks GUI."""
        from utils.runner import _drain_pipe
        _drain_pipe(
            proc.stdout,
            stop_event,
            on_line=lambda line: self.terminal.append_output(line) if line else None,
            on_progress=lambda line: self.terminal.append_progress(line),
            label="demo",
        )
        try:
            proc.wait(timeout=2)
        except Exception:
            pass

    def _kill_proc(self, proc):
        """Kill a subprocess cleanly: SIGTERM → 2s → SIGKILL."""
        import os, signal as _sig
        if proc is None:
            return
        # Signal the drain thread to stop
        stop_evt = getattr(proc, '_stop_event', None)
        if stop_evt:
            stop_evt.set()
        try:
            if hasattr(os, 'killpg'):
                os.killpg(proc.pid, _sig.SIGTERM)
            else:
                proc.terminate()
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(proc.pid, _sig.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass
        try:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
        except Exception:
            pass

    def _send_reset(self, args: list):
        """Fire-and-forget reset frame."""
        import os
        binary = self.cfg.get('binary_path', './fucyfuzz')
        try:
            kwargs = {}
            if hasattr(os, 'setsid'):
                kwargs['preexec_fn'] = os.setsid
            subprocess.Popen(
                [binary] + [str(a) for a in args],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                **kwargs,
            )
        except Exception:
            pass


    def _set_status(self, text: str, color: str):
        self._status_badge.setText(text)
        self._status_badge.setStyleSheet(
            f"color: {color}; background-color: {color}22;"
            f"border: 1px solid {color}66;"
            f"border-radius: 3px; padding: 2px 8px; font-size: 9px; letter-spacing: 1px;"
        )

    # ── Speed fuzz ────────────────────────────────────────────────────────────

    def _toggle_speed(self):
        if not self._speed_active:
            self._speed_active = True
            self._speed_btn.setText("⏹  Stop Speed Fuzz  (Reset → 0)")
            self._speed_btn.setStyleSheet(f"background-color: {COLORS['critical']}; color: white; border: none;")
            self._speed_proc = self._run_bg(["fuzzer", "mutate", "244", "..", "-d", "0.5"])
            self._set_status("SPEED FUZZ RUNNING", COLORS['accent_yellow'])
        else:
            self._stop_speed()

    def _stop_speed(self):
        if self._speed_proc:
            threading.Thread(target=self._kill_proc, args=(self._speed_proc,), daemon=True).start()
            self._speed_proc = None
        self._speed_active = False
        self._speed_btn.setText("▶  Start Speed Fuzz")
        self._speed_btn.setStyleSheet("")
        self._send_reset(["send", "message", "0x244#00"])
        self.terminal.append_success("Speed fuzz stopped — speed reset to 0")
        self._set_status("IDLE", COLORS['text_secondary'])

    # ── Indicator fuzz ────────────────────────────────────────────────────────

    def _toggle_indicator(self):
        if not self._indicator_active:
            self._indicator_active = True
            self._ind_btn.setText("⏹  Stop Indicator Fuzz  (Reset OFF)")
            self._ind_btn.setStyleSheet(f"background-color: {COLORS['critical']}; color: white; border: none;")
            self._indicator_proc = self._run_bg(["fuzzer", "mutate", "188", ".", "-d", "0.5"])
            self._set_status("INDICATOR FUZZ RUNNING", COLORS['accent_yellow'])
        else:
            self._stop_indicator()

    def _stop_indicator(self):
        if self._indicator_proc:
            threading.Thread(target=self._kill_proc, args=(self._indicator_proc,), daemon=True).start()
            self._indicator_proc = None
        self._indicator_active = False
        self._ind_btn.setText("▶  Start Indicator Fuzz")
        self._ind_btn.setStyleSheet("")
        self._send_reset(["send", "message", "0x188#00"])
        self.terminal.append_success("Indicator fuzz stopped — indicators OFF")
        self._set_status("IDLE", COLORS['text_secondary'])

    # ── Door fuzz ─────────────────────────────────────────────────────────────

    def _toggle_door(self):
        if not self._door_active:
            self._door_active = True
            self._door_btn.setText("⏹  Stop Door Fuzz  (Reset Closed)")
            self._door_btn.setStyleSheet(f"background-color: {COLORS['critical']}; color: white; border: none;")
            self._door_proc = self._run_bg(["fuzzer", "mutate", "19B", "........", "-d", "0.5"])
            self._set_status("DOOR FUZZ RUNNING", COLORS['accent_yellow'])
        else:
            self._stop_door()

    def _stop_door(self):
        if self._door_proc:
            threading.Thread(target=self._kill_proc, args=(self._door_proc,), daemon=True).start()
            self._door_proc = None
        self._door_active = False
        self._door_btn.setText("▶  Start Door Fuzz")
        self._door_btn.setStyleSheet("")
        self._send_reset(["send", "message", "0x19B#00.00.00.00"])
        self.terminal.append_success("Door fuzz stopped — doors reset closed")
        self._set_status("IDLE", COLORS['text_secondary'])
