"""
Base class for all FucyFuzz module tabs.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSplitter, QFrame, QPushButton, QScrollArea
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
import time

from ui.widgets import (
    GlowButton, SolidButton, TerminalWidget, SectionHeader,
    CardFrame, StatusBadge
)
from ui.theme import COLORS
from utils.runner import CommandRunner
from utils.data_manager import DataManager
from utils.config import get_config


class BaseModuleTab(QWidget):
    """
    All module tabs inherit from this.
    Provides:
      - build_args() -> list  (override in subclass)
      - left panel: controls
      - right panel: terminal
      - run / kill buttons
    """

    command_run  = pyqtSignal(str)   # emits command string when executed
    fault_found  = pyqtSignal(str, str, str, str)  # severity, module, fault, cmd

    MODULE_NAME = "module"
    # Set to True in subclasses that pass -i <iface> and need the CAN
    # interface to be present before launching (e.g. UDS, Fuzzer).
    # Send, Dump, Listener etc. do NOT pass -i, so leave this False.
    REQUIRES_INTERFACE = False

    def __init__(self, runner: CommandRunner, data_manager: DataManager, parent=None):
        super().__init__(parent)
        self.runner = runner
        self.dm     = data_manager
        self.cfg    = get_config()
        # ── Fault rate-limiter (token bucket) ─────────────────────────────
        self._fault_rate_tokens = 10
        self._fault_rate_last   = time.monotonic()
        self._FAULT_RATE_MAX    = 10
        self._FAULT_RATE_REFILL = 1.0
        # ── ECU response monitor ──────────────────────────────────────────
        try:
            from utils.ecu_response_monitor import ECUResponseMonitor
            self._ecu_monitor = ECUResponseMonitor()
        except Exception:
            self._ecu_monitor = None
        # ── Real-time seed analysis engine ────────────────────────────────
        try:
            from utils.realtime_seed_engine import RealtimeSeedEngine
            self._seed_engine = RealtimeSeedEngine()
        except Exception:
            self._seed_engine = None
        self._timeout_streak = 0
        self._setup_base_ui()
        self._connect_runner()

    def _setup_base_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Top toolbar ───────────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setFixedHeight(54)
        toolbar.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {COLORS['bg_secondary']}, stop:1 {COLORS['bg_card']});
            border-bottom: 1px solid {COLORS['border']};
        """)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(20, 0, 20, 0)
        tb_layout.setSpacing(10)

        self._status_badge = StatusBadge("IDLE", "idle")
        tb_layout.addWidget(self._status_badge)
        tb_layout.addSpacing(8)

        self._cmd_preview = QLabel("")
        self._cmd_preview.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 11px;
            font-family: 'Consolas', 'Courier New', monospace;
            background: {COLORS['bg_input']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            padding: 3px 8px;
        """)
        self._cmd_preview.setMinimumWidth(200)
        self._cmd_preview.setToolTip("Full command — hover to see, click copy button to copy")
        tb_layout.addWidget(self._cmd_preview)

        self._copy_cmd_btn = QPushButton("⎘")
        self._copy_cmd_btn.setFixedSize(28, 28)
        self._copy_cmd_btn.setToolTip("Copy command to clipboard")
        self._copy_cmd_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_elevated']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                color: {COLORS['accent_cyan']};
                font-size: 13px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {COLORS['accent_cyan']}22;
                border-color: {COLORS['accent_cyan']};
            }}
        """)
        self._copy_cmd_btn.clicked.connect(self._copy_command)
        tb_layout.addWidget(self._copy_cmd_btn)
        tb_layout.addStretch()

        self._run_btn = QPushButton("▶   RUN")
        self._run_btn.setFixedSize(100, 34)
        self._run_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {COLORS['accent_green']}, stop:1 #0ea57b);
                border: none;
                color: {COLORS['bg_primary']};
                border-radius: 6px;
                font-size: 13px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #15d99a, stop:1 {COLORS['accent_green']});
            }}
            QPushButton:pressed {{ background: #0b8a66; }}
            QPushButton:disabled {{
                background: {COLORS['text_muted']};
                color: {COLORS['bg_secondary']};
            }}
        """)

        self._kill_btn = QPushButton("■   KILL")
        self._kill_btn.setFixedSize(90, 34)
        self._kill_btn.setEnabled(False)
        self._kill_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {COLORS['critical']}66;
                color: {COLORS['critical']};
                border-radius: 6px;
                font-size: 13px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background: {COLORS['critical']}1a;
                border: 1px solid {COLORS['critical']};
            }}
            QPushButton:pressed {{ background: {COLORS['critical']}33; }}
            QPushButton:disabled {{
                border-color: {COLORS['text_muted']};
                color: {COLORS['text_muted']};
            }}
        """)

        self._run_btn.clicked.connect(self.run_command)
        self._kill_btn.clicked.connect(self.kill_command)

        tb_layout.addWidget(self._run_btn)
        tb_layout.addWidget(self._kill_btn)

        outer.addWidget(toolbar)

        # ── Content splitter ──────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {COLORS['border']}; width: 1px; }}")

        # Left: controls panel — wrapped in QScrollArea so groups never overlap
        self._controls_panel = QWidget()
        self._controls_panel.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {COLORS['bg_secondary']}, stop:1 {COLORS['bg_card']});
        """)
        self._controls_layout = QVBoxLayout(self._controls_panel)
        self._controls_layout.setContentsMargins(18, 18, 18, 18)
        self._controls_layout.setSpacing(14)

        self._build_controls()
        self._controls_layout.addStretch()

        # Scroll wrapper — allows controls to extend beyond panel height
        self._controls_scroll = QScrollArea()
        self._controls_scroll.setWidget(self._controls_panel)
        self._controls_scroll.setWidgetResizable(True)
        self._controls_scroll.setMinimumWidth(300)
        self._controls_scroll.setMaximumWidth(460)
        self._controls_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._controls_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._controls_scroll.setStyleSheet(f"""
            QScrollArea {{
                border: none;
                border-right: 1px solid {COLORS['border']};
                background: transparent;
            }}
            QScrollBar:vertical {{
                background: {COLORS['bg_secondary']}; width: 5px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['border_bright']}; border-radius: 3px; min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        splitter.addWidget(self._controls_scroll)

        # Right: terminal panel
        right = QWidget()
        right.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(18, 18, 18, 18)

        self.terminal = TerminalWidget()
        right_layout.addWidget(self.terminal)

        splitter.addWidget(right)
        splitter.setSizes([380, 800])

        outer.addWidget(splitter)

    def _build_controls(self):
        """Override in subclass to add widgets to self._controls_layout"""
        pass

    def build_args(self) -> list:
        """Override in subclass to return command args"""
        return []

    def get_interface(self) -> str:
        """Return the physical CAN channel, never None."""
        import platform
        _is_windows = platform.system().lower() == "windows"
        default = "PCAN_USBBUS1" if _is_windows else "vcan0"
        iface = self.cfg.get('interface', default)
        if not iface or str(iface).lower() in ('none', 'null', ''):
            iface = default
        return iface

    def get_driver(self) -> str:
        """Return the python-can driver string, auto-detected if missing."""
        from utils.config import _auto_driver_for_interface
        driver = self.cfg.get('driver', '')
        if not driver or str(driver).lower() in ('none', 'null', ''):
            driver = _auto_driver_for_interface(self.get_interface())
        return driver

    def run_command(self):
        if self.runner.is_running:
            self.terminal.append_error("Another command is running.")
            return
        args = self.build_args()
        if args is None:
            return

        # ── Pre-flight interface check (only for modules that use -i) ────────
        if self.REQUIRES_INTERFACE:
            iface = self.get_interface()
            try:
                idx = [str(a) for a in args].index('-i')
                iface = str(args[idx + 1])
            except (ValueError, IndexError):
                pass

            try:
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
            except ImportError:
                import os
                if not os.path.exists(f"/sys/class/net/{iface}"):
                    self.terminal.append_error(
                        f"CAN interface '{iface}' not found. "
                        "Run: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan "
                        "&& sudo ip link set up vcan0"
                    )
                    return
        # ─────────────────────────────────────────────────────────────────────

        self.runner.run(args, module=self.MODULE_NAME)
        self._update_cmd_preview(args)

    def _update_cmd_preview(self, args):
        cmd = "fucyfuzz " + " ".join(str(a) for a in args)
        self._full_cmd = cmd
        display = cmd if len(cmd) <= 100 else cmd[:97] + "..."
        self._cmd_preview.setText(display)
        self._cmd_preview.setToolTip(f"Command:\n{cmd}")

    def _copy_command(self):
        try:
            from PyQt5.QtWidgets import QApplication
            cmd = getattr(self, '_full_cmd', self._cmd_preview.text())
            QApplication.clipboard().setText(cmd)
            orig = self._copy_cmd_btn.text()
            self._copy_cmd_btn.setText("✓")
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(1200, lambda: self._copy_cmd_btn.setText(orig))
        except Exception:
            pass


    def kill_command(self):
        self.runner.kill()

    def _connect_runner(self):
        # started/finished modify GUI widgets → MUST be QueuedConnection.
        # output/progress/error just push to deques (thread-safe) → DirectConnection
        # avoids flooding the Qt event queue with thousands of queued signals.
        self.runner.started.connect(self._on_started,    type=Qt.QueuedConnection)
        self.runner.finished.connect(self._on_finished,  type=Qt.QueuedConnection)
        self.runner.output_line.connect(self._on_output,   type=Qt.DirectConnection)
        self.runner.error_line.connect(self._on_error,     type=Qt.DirectConnection)
        self.runner.progress_line.connect(self._on_progress, type=Qt.DirectConnection)

    @pyqtSlot(str)
    def _on_started(self, cmd: str):
        # Only the tab that owns this run should process _on_started.
        # All tabs share one runner, so all receive this signal.
        if self.runner.cur_module != self.MODULE_NAME:
            return
        try:
            self.dm.start_session(self.MODULE_NAME, cmd)
            # Reset seed engine for new session
            if self._seed_engine is not None:
                self._seed_engine.reset()
            self.terminal.append_command(cmd)
            self._status_badge.setText("RUNNING")
            self._status_badge.setStyleSheet(f"""
                color: {COLORS['accent_yellow']};
                background: {COLORS['accent_yellow']}18;
                border: 1px solid {COLORS['accent_yellow']}55;
                border-radius: 4px; padding: 3px 10px;
                font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
            """)
            self._run_btn.setEnabled(False)
            self._kill_btn.setEnabled(True)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("_on_started error: %s", exc)

    @pyqtSlot(str)
    def _on_output(self, line: str):
        try:
            active = self.dm.active_module
            if active and active != self.MODULE_NAME:
                return
            # Terminal push is thread-safe (deque)
            self.terminal.append_output(line)
            # Fault parsing and ECU monitor are lightweight and exception-safe
            try:
                self._parse_output_for_faults(line)
            except Exception:
                pass
            try:
                if self._ecu_monitor:
                    result = self._ecu_monitor.process_line(line)
                    if result:
                        self._handle_monitor_result(result, line)
            except Exception as e:
                import logging
                logging.getLogger(__name__).exception("ECU Monitor error: %s", e)
        except Exception:
            pass

    @pyqtSlot(str)
    def _on_progress(self, line: str):
        try:
            active = self.dm.active_module
            if active and active != self.MODULE_NAME:
                return
            self.terminal.append_progress(line)
        except Exception:
            pass

    @pyqtSlot(str)
    def _on_error(self, line: str):
        try:
            active = self.dm.active_module
            if active and active != self.MODULE_NAME:
                return
            self.terminal.append_error(line)
            
            if "CC_PACKET" in line:
                try:
                    self._parse_output_for_faults(line)
                except Exception:
                    pass
                try:
                    if self._ecu_monitor:
                        result = self._ecu_monitor.process_line(line)
                        if result:
                            # Actually update the dashboard!
                            self._handle_monitor_result(result, line)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).exception("ECU Monitor error: %s", e)
        except Exception:
            pass

    @pyqtSlot(int)
    def _on_finished(self, rc: int):
        # Only the owning tab should clean up on finish
        if self.runner.cur_module != self.MODULE_NAME:
            return
            
        if hasattr(self, '_silence_timer'):
            self._silence_timer.stop()
            
        try:
            self.dm.end_session()
            if rc == 0:
                self.terminal.append_success(f"Process exited cleanly (rc=0)")
            else:
                self.terminal.append_error(f"Process exited with code {rc}")

            self._status_badge.setText("IDLE")
            self._status_badge.setStyleSheet(f"""
                color: {COLORS['text_secondary']};
                background: {COLORS['text_secondary']}15;
                border: 1px solid {COLORS['text_secondary']}40;
                border-radius: 4px; padding: 3px 10px;
                font-size: 10px; font-weight: 700; letter-spacing: 1.5px;
            """)
            self._run_btn.setEnabled(True)
            self._kill_btn.setEnabled(False)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("_on_finished error: %s", exc)

    def _parse_output_for_faults(self, line: str):
        """
        Multi-layer fault detection (exception-safe wrapper).
        Token-bucket rate-limiter prevents GUI flooding during rapid output.
        """
        now = time.monotonic()
        elapsed = now - self._fault_rate_last
        if elapsed >= self._FAULT_RATE_REFILL:
            self._fault_rate_tokens = self._FAULT_RATE_MAX
            self._fault_rate_last   = now
        if self._fault_rate_tokens <= 0:
            return
        self._fault_rate_tokens -= 1
        try:
            self.__parse_output_for_faults_impl(line)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).debug("_parse_output_for_faults: %s", exc)

    def _check_silence(self):
        if not self._is_running or not self._ecu_monitor:
            return
        if self._crash_reported:
            return
            
        if self._ecu_monitor.check_silence(5.0):
            self._crash_reported = True
            self._handle_monitor_result({"type": "crash"}, "Silence monitor: No response for > 5s")

    def _handle_monitor_result(self, result: dict, raw_line: str):
        """Process structured ECU response events from ECUResponseMonitor."""
        t = result.get("type")

        if t == "reset":
            reset_type = result.get("reset_type", 0)
            self.dm.add_fault("critical", self.MODULE_NAME,
                f"ECU Reset confirmed (Type 0x{reset_type:02X})", raw_line)
            try:
                self.dm.push_ecu_event({
                    "type":   "crash",
                    "module": self.MODULE_NAME,
                    "raw":    f"Reset Type 0x{reset_type:02X}",
                })
            except AttributeError:
                pass

        elif t == "crash":
            self.dm.add_fault("critical", self.MODULE_NAME,
                "ECU crash/hang detected — >5s silence after request", raw_line)
            try:
                self.dm.push_ecu_event({
                    "type":   "hang",
                    "module": self.MODULE_NAME,
                    "raw":    raw_line,
                })
            except AttributeError:
                pass

        elif t == "nrc":
            # ── NRC: record + check for lockout ─────────────────────────────
            nrc = result["nrc"]
            try:
                self.dm.record_nrc(self.MODULE_NAME, nrc, raw_line)
            except AttributeError:
                pass
            # 0x36 = exceededNumberOfAttempts → security lockout
            if nrc == 0x36:
                self.dm.add_fault("critical", self.MODULE_NAME,
                    "Security lockout triggered (NRC 0x36 — exceededNumberOfAttempts)", raw_line)
                try:
                    self.dm.push_ecu_event({"type": "lockout", "nrc": nrc,
                                            "module": self.MODULE_NAME, "raw": raw_line})
                except AttributeError:
                    pass
            elif nrc == 0x25:
                self.dm.add_fault("high", self.MODULE_NAME,
                    "No response from subnet component (NRC 0x25)", raw_line)

        elif t == "seed":
            # ── Seed: run full real-time analysis engine ──────────────────────
            seed = result["seed"]
            self._timeout_streak = 0

            if self._seed_engine is not None:
                findings = self._seed_engine.add_seed(seed)
                # Push each new finding as a fault (unique text → no dedup swallowing)
                for f in findings:
                    sev = f["severity"]
                    self.dm.add_fault(sev, self.MODULE_NAME,
                                      f"{f['title']}: {f['detail']}", "")
                # Always push updated stats so dashboard refreshes even with no finding
                try:
                    self.dm.update_seed_stats({
                        **self._seed_engine.stats,
                        "module": self.MODULE_NAME,
                    })
                except AttributeError:
                    pass
            else:
                # Fallback: basic checks without engine
                if result.get("is_repeat"):
                    self.dm.add_fault("critical", self.MODULE_NAME,
                        f"Repeated seed: {seed.hex().upper()}", "")
                if seed == bytes(len(seed)):
                    self.dm.add_fault("critical", self.MODULE_NAME,
                        f"Zero seed: {seed.hex().upper()}", "")

        elif t == "timeout":
            # ── Timeout streak ────────────────────────────────────────────────
            self._timeout_streak += 1
            if self._timeout_streak == 3:
                self.dm.add_fault("high", self.MODULE_NAME,
                    "3 consecutive timeouts — ECU may be unresponsive", "")
                try:
                    self.dm.push_ecu_event({"type": "timeout_streak",
                                            "count": self._timeout_streak,
                                            "module": self.MODULE_NAME})
                except AttributeError:
                    pass
            elif self._timeout_streak >= 10 and self._timeout_streak % 5 == 0:
                self.dm.add_fault("critical", self.MODULE_NAME,
                    f"{self._timeout_streak} consecutive timeouts — ECU likely crashed", "")

        else:
            self._timeout_streak = 0

    def __parse_output_for_faults_impl(self, line: str):
        """
        Multi-layer fault detection:
        0. User-defined custom rules (highest priority)
        1. Exact pattern rules
        2. Heuristic keyword scan (fallback)
        Subclasses can extend via _extra_parse(line).
        """
        lower = line.lower()

        # Skip raw DoIP transport lines — disk-only, not UI events
        if any(p in lower for p in [
            'tcp connect', 'routing activation', 'doip frame',
            'payload_type=', 'vehicle announcement',
        ]):
            return

        # ── Layer 0: User-defined custom rules from Config tab ───────────────
        custom_rules = self.cfg.get('custom_rules', '')
        if custom_rules:
            for rule_line in custom_rules.splitlines():
                rule_line = rule_line.strip()
                if '|' not in rule_line:
                    continue
                parts = rule_line.split('|', 1)
                if len(parts) != 2:
                    continue
                sev, keyword = parts[0].strip().lower(), parts[1].strip().lower()
                if sev in ('critical', 'high', 'medium', 'low') and keyword and keyword in lower:
                    self._add_fault(sev, line, f"[Custom Rule] {line[:100]}")
                    return

        # ── Layer 1: Explicit high-confidence patterns ──────────────────────
        # UDS / DCM discovery hits
        if any(p in lower for p in [
            'found ecu', 'ecu found', 'ecu detected', 'active ecu',
            'discovered ecu', 'responds on', 'response from',
        ]):
            self._add_fault('low', line, "ECU discovered")
            return

        # Service enumeration hit
        if any(p in lower for p in [
            'found service', 'service found', 'supported service',
            'service 0x', 'supported:', 'service supported',
        ]):
            self._add_fault('low', line, "Service found")
            return

        # Positive security access
        if any(p in lower for p in [
            'security access granted', 'access granted', 'unlocked',
            'positive response to security', 'seed accepted',
        ]):
            self._add_fault('critical', line, "Security access granted")
            return

        # Seed issues (handled by subclass for deeper analysis, but catch obvious ones)
        if any(p in lower for p in [
            'same seed', 'repeated seed', 'identical seed',
            'seed is constant', 'seed does not change', 'low entropy',
            'weak seed', 'predictable seed', 'seed repeated',
            'non-random', 'not random',
        ]):
            self._add_fault('critical', line, "Weak/repeated seed detected")
            return

        # ECU crash / reset / hang indicators
        if any(p in lower for p in [
            'ecu reset positive response', 'reset sent successfully', 'closed after reset',
            'ecu restarted', 'ecu crashed', 'target crashed',
            'no response after', 'bus off', 'bus-off',
        ]):
            self._add_fault('critical', line, "ECU crash/reset detected")
            try:
                self.dm.push_ecu_event({
                    "type":   "crash",
                    "module": self.MODULE_NAME,
                    "raw":    line,
                })
            except AttributeError:
                pass
            return

        # Hang / freeze indicators
        if any(p in lower for p in [
            'hang', 'frozen', 'not responding', 'deadlock',
        ]):
            self._add_fault('high', line, "ECU hang/freeze detected")
            try:
                self.dm.push_ecu_event({
                    "type":   "hang",
                    "module": self.MODULE_NAME,
                    "raw":    line,
                })
            except AttributeError:
                pass
            return

        # Memory / DID leak
        if any(p in lower for p in [
            'read memory', 'memory dump', 'mem dump', 'did value',
            'read did', 'data identifier', 'vin:', 'vin =',
        ]):
            self._add_fault('medium', line, "Data read from ECU")
            return

        # DTC found
        if any(p in lower for p in ['dtc found', 'trouble code', 'dtc:', 'fault code']):
            self._add_fault('medium', line, "DTC found")
            return

        # ── Layer 2: Heuristic keyword fallback ─────────────────────────────
        severity = None
        if any(k in lower for k in [
            'crash', 'exception', 'segfault', 'panic', 'critical',
            'overflow', 'corruption',
        ]):
            severity = 'critical'
        elif any(k in lower for k in [
            'error', 'fail', 'unexpected response', 'timeout',
            'no response', 'refused', 'rejected',
        ]):
            severity = 'high'
        elif any(k in lower for k in [
            'warning', 'warn', 'anomaly', 'unexpected',
        ]):
            severity = 'medium'
        elif any(k in lower for k in [
            'found', 'discovered', 'detected', 'positive', 'success',
        ]):
            severity = 'low'

        if severity:
            self._add_fault(severity, line)

        # ── Layer 3: Subclass hook ───────────────────────────────────────────
        self._extra_parse(line)

    def _add_fault(self, severity: str, line: str, label: str = None):
        """Deduplicated fault adder — won't spam identical faults."""
        try:
            fault_text = label or line[:120]
            # Avoid adding the exact same fault text within the same session
            recent = self.dm.recent_faults(10)
            for f in recent:
                if f.fault == fault_text and f.module == self.MODULE_NAME:
                    return
            try:
                cmd = self._cmd_preview.text()
            except RuntimeError:
                cmd = ""
            self.dm.add_fault(
                severity=severity,
                module=self.MODULE_NAME,
                fault=fault_text,
                cmd=cmd,
            )
        except Exception as exc:
            import logging
            logging.getLogger(__name__).debug("_add_fault suppressed: %s", exc)

    def _extra_parse(self, line: str):
        """Hook for subclasses to add module-specific parsing."""
        pass
