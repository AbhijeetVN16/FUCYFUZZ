"""
FucyFuzz Main Window
"""

import os
import json
import platform as _platform
_IS_WINDOWS = _platform.system().lower() == "windows"
_BIN_DEFAULT = 'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz'
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QStackedWidget, QSizePolicy,
    QFileDialog, QMessageBox, QStatusBar, QAction, QMenu, QMenuBar,
    QPushButton
)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QIcon, QColor, QPalette

from ui.widgets import NavButton, GlowButton, SolidButton, StatusBadge
from ui.export_dialog import ExportDialog, ECUSessionPickerDialog, OverallReportDialog
from ui.theme import COLORS

from utils.runner import CommandRunner
from utils.data_manager import DataManager
from utils.config import get_config, ensure_app_dirs, APP_DIRS
from utils import export_manager
from utils.failure_cases_dialog import (
    FailureCasesDialog, add_failure_case, load_failure_cases, save_failure_cases
)

from modules.dashboard_tab  import DashboardTab
from modules.config_tab     import ConfigTab
from modules.uds_tab        import UDSTab
from modules.uds_fuzz_tab   import UDSFuzzTab
from modules.dcm_tab        import DCMTab
from modules.fuzzer_tab     import FuzzerTab
from modules.lenattack_tab  import LenAttackTab
from modules.send_tab       import SendTab
from modules.dump_listener_tab import DumpTab, ListenerTab
from modules.xcp_tab        import XCPTab
from modules.help_tab       import HelpTab
from modules.uds_response_tab import UDSResponseAnalyserTab
from modules.replay_tab     import ReplayTab
from modules.recon_tab      import ReconTab
from modules.demo_tab       import DemoTab
from modules.advanced_tab   import AdvancedTab
from modules.doip_tab       import DoIPTab
from modules.log_tab        import LogTab


class TitleBar(QWidget):
    """Premium gradient title bar"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 #070b10, stop:0.3 #0c1825, stop:0.7 #0c1825, stop:1 #070b10);
            border-bottom: 1px solid {COLORS['border']};
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(10)

        # Logo mark — gradient-style dot + name
        logo_dot = QLabel("◉")
        logo_dot.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 18px;
            background: transparent;
        """)
        layout.addWidget(logo_dot)

        name = QLabel("FUCYFUZZ")
        name.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 16px;
            font-weight: 800;
            letter-spacing: 5px;
            background: transparent;
        """)
        layout.addWidget(name)


        layout.addStretch()

        # CAN status indicator
        self._can_indicator = QLabel("○  CAN Bus Idle")
        self._can_indicator.setStyleSheet(f"""
            color: {COLORS['text_muted']};
            font-size: 11px;
            font-weight: 500;
            background: transparent;
            padding: 0 8px;
        """)
        layout.addWidget(self._can_indicator)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"background: {COLORS['border']}; max-width: 1px;")
        layout.addWidget(sep)

        # Action buttons — only Failures (Analyse Seeds removed)
        self._failures_btn = self._make_action_btn("📊  Failures", COLORS['critical'])
        layout.addWidget(self._failures_btn)

    def _make_action_btn(self, text, color):
        btn = QPushButton(text)
        btn.setFixedHeight(30)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: {color}15;
                border: 1px solid {color}55;
                color: {color};
                padding: 0 16px;
                border-radius: 5px;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {color}28;
                border: 1px solid {color}88;
            }}
            QPushButton:pressed {{
                background: {color}40;
            }}
        """)
        return btn

    def set_can_active(self, active: bool):
        if active:
            self._can_indicator.setText("●  CAN Bus Active")
            self._can_indicator.setStyleSheet(f"""
                color: {COLORS['success']};
                font-size: 11px; font-weight: 600;
                background: transparent; padding: 0 8px;
            """)
        else:
            self._can_indicator.setText("○  CAN Bus Idle")
            self._can_indicator.setStyleSheet(f"""
                color: {COLORS['text_muted']};
                font-size: 11px; font-weight: 500;
                background: transparent; padding: 0 8px;
            """)


class Sidebar(QWidget):
    """Premium left sidebar navigation"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(260)
        self.setStyleSheet(f"""
            QWidget {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #0a1018, stop:1 #0c1219);
                border-right: 1px solid {COLORS['border']};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 12)
        layout.setSpacing(0)

        self._buttons   = []
        self._callbacks = []

        def _section_label(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(f"""
                color: {COLORS['text_muted']};
                font-size: 9px;
                font-weight: 700;
                letter-spacing: 2.5px;
                padding: 14px 8px 4px 19px;
                background: transparent;
            """)
            return lbl

        def _add_nav(label, icon=""):
            btn = NavButton(label, icon)
            btn.clicked.connect(lambda checked, l=label: self._on_click(l))
            layout.addWidget(btn)
            self._buttons.append((label, btn))

        # ── OVERVIEW ──────────────────────────────────────────────────────────
        layout.addWidget(_section_label("OVERVIEW"))
        _add_nav("DASHBOARD")
        _add_nav("REPLAY")
        _add_nav("CONFIG")

        # ── ANALYSIS ──────────────────────────────────────────────────────────
        layout.addWidget(_section_label("ANALYSIS"))
        _add_nav("RECON")
        _add_nav("DEMO")
        _add_nav("ADVANCED")

        # ── ATTACK MODULES ────────────────────────────────────────────────────
        layout.addWidget(_section_label("ATTACK MODULES"))
        _add_nav("UDS")
        _add_nav("UDS FUZZ")
        _add_nav("DCM")
        _add_nav("FUZZER")
        _add_nav("LEN ATTACK")

        # ── TOOLS ─────────────────────────────────────────────────────────────
        layout.addWidget(_section_label("TOOLS"))
        _add_nav("SEND")
        _add_nav("DUMP")
        _add_nav("LISTENER")
        _add_nav("XCP")
        _add_nav("DoIP")

        layout.addStretch()

        # ── Bottom separator (invisible spacing — no white line artefact) ────
        layout.addSpacing(8)

        # HELP nav item
        _add_nav("HELP")
        _add_nav("LOGS")

        layout.addSpacing(4)

        self._on_click("DASHBOARD")

    def _on_click(self, label):
        for lbl, btn in self._buttons:
            btn.setChecked(lbl == label)
        for cb in self._callbacks:
            cb(label)

    def on_nav(self, callback):
        self._callbacks.append(callback)

    def select(self, label):
        self._on_click(label)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = get_config()
        self.dm  = DataManager(self)
        self._setup_runner()
        self._setup_ui()
        self._setup_menu()

    def _setup_runner(self):
        binary = self.cfg.get('binary_path', _BIN_DEFAULT)
        self.runner = CommandRunner(binary, self)

    def _setup_ui(self):
        self.setWindowTitle("FucyFuzz — CAN Bus Security Framework")
        self.setMinimumSize(1200, 750)
        self.resize(1400, 850)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Title bar
        self.title_bar = TitleBar()
        self.title_bar._failures_btn.clicked.connect(self._show_failure_cases)
        root.addWidget(self.title_bar)

        # Body
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        self.sidebar.on_nav(self._navigate)
        body.addWidget(self.sidebar)

        # Content stack
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
        body.addWidget(self._stack)

        root.addLayout(body)

        # Status bar
        self._status_bar = QStatusBar()
        self._status_bar.setStyleSheet(f"""
            QStatusBar {{
                background: {COLORS['bg_secondary']};
                border-top: 1px solid {COLORS['border']};
                color: {COLORS['text_secondary']};
                font-size: 10px;
                padding: 2px 12px;
            }}
        """)
        self.setStatusBar(self._status_bar)
        iface = self.cfg.get('interface', 'vcan0')
        try:
            from utils.can_interface import check_interface
            s = check_interface(iface)
            can_status = "UP ✅" if s.ok else "DOWN ❌"
        except Exception:
            can_status = "?"
        self._status_bar.showMessage(
            f"Ready  |  Interface: {iface}  [{can_status}]"
        )

        # Build all tabs
        self._tabs = {}
        self._build_tabs()
        # Give LogTab and ECU Monitor a reference to the SessionLogger bridge
        # ECU Monitor also registers its callback so it mirrors the Logs tab in real time
        log_tab = self._tabs.get('LOGS')
        if log_tab:
            log_tab.refresh_logger_connection()

        # Runner signals → status bar (QueuedConnection: runner emits from worker thread)
        self.runner.started.connect(lambda cmd: (
            self._status_bar.showMessage(f"Running: {cmd[:80]}"),
            self.title_bar.set_can_active(True)
        ), type=Qt.QueuedConnection)
        self.runner.finished.connect(lambda rc: (
            self._status_bar.showMessage(f"Finished (rc={rc})  |  Interface: {self.cfg.get('interface', 'vcan0')}"),
            self.title_bar.set_can_active(False)
        ), type=Qt.QueuedConnection)
        # Auto-record failure cases when a command exits non-zero
        self._last_run_cmd = ""
        self._last_run_module = "General"
        self.runner.started.connect(lambda cmd: setattr(self, '_last_run_cmd', cmd),
                                    type=Qt.QueuedConnection)
        self.runner.finished.connect(self._on_runner_finished, type=Qt.QueuedConnection)

        # ── FIX: Restart session logger + re-register GUI callbacks on every run ──
        # Each run calls start_session_logger() which creates a fresh SessionLogger
        # instance. The LogTab and ECU Monitor hold a callback reference to the OLD
        # instance, so they go dark after the first kill+restart.  We reconnect them
        # here via runner.started (QueuedConnection → always on GUI thread).
        self.runner.started.connect(self._refresh_session_logger, type=Qt.QueuedConnection)

    def _build_tabs(self):
        """Build all tabs. Each tab is isolated so one failure doesn't prevent others."""
        tab_map = [
            ("DASHBOARD",    DashboardTab(self.dm)),
            ("UDS ANALYSER",  UDSResponseAnalyserTab(self.dm)),
            ("REPLAY",       ReplayTab()),
            ("CONFIG",       ConfigTab()),
            ("RECON",        ReconTab(self.runner, self.dm)),
            ("DEMO",         DemoTab(self.runner, self.dm)),
            ("UDS",          UDSTab(self.runner, self.dm)),
            ("UDS FUZZ",     UDSFuzzTab(self.runner, self.dm)),
            ("DCM",          DCMTab(self.runner, self.dm)),
            ("FUZZER",       FuzzerTab(self.runner, self.dm)),
            ("LEN ATTACK",   LenAttackTab(self.runner, self.dm)),
            ("SEND",         SendTab(self.runner, self.dm)),
            ("DUMP",         DumpTab(self.runner, self.dm)),
            ("LISTENER",     ListenerTab(self.runner, self.dm)),
            ("XCP",          XCPTab(self.runner, self.dm)),
            ("DoIP",         DoIPTab(self.runner, self.dm)),
            ("ADVANCED",     AdvancedTab(self.runner, self.dm)),
            ("HELP",         HelpTab()),
            ("LOGS",         LogTab()),
        ]

        import logging as _log
        for label, widget_factory in tab_map:
            try:
                if callable(widget_factory) and not isinstance(widget_factory, QWidget):
                    widget = widget_factory
                else:
                    widget = widget_factory
                self._stack.addWidget(widget)
                self._tabs[label] = widget

                if label == "CONFIG":
                    try:
                        widget.config_changed.connect(self._on_config_changed)
                        widget.config_changed.connect(self._on_dbc_changed)
                    except Exception as e:
                        _log.getLogger(__name__).warning("CONFIG signal connect failed: %s", e)
                elif label == "LOGS":
                    try:
                        widget.export_requested.connect(self._show_export_dialog)
                    except Exception as e:
                        _log.getLogger(__name__).warning("LOGS signal connect failed: %s", e)
            except Exception as exc:
                _log.getLogger(__name__).error("Tab '%s' failed to build: %s", label, exc, exc_info=True)

    def _navigate(self, label):
        if label in self._tabs:
            self._stack.setCurrentWidget(self._tabs[label])

    def _on_config_changed(self):
        binary = self.cfg.get('binary_path', _BIN_DEFAULT)
        self.runner.binary_path = binary
        iface = self.cfg.get('interface', 'vcan0')
        self._status_bar.showMessage(f"Config saved  |  Interface: {iface}")

    def _on_dbc_changed(self):
        """Broadcast DBC message list to all tabs that have update_msg_list()."""
        msgs = self.cfg.get('dbc_messages', {})
        if not msgs:
            return
        msg_names = sorted(msgs.keys())
        for label in ("FUZZER", "LEN ATTACK", "SEND", "UDS", "DCM"):
            tab = self._tabs.get(label)
            if tab and hasattr(tab, 'update_msg_list'):
                try:
                    tab.update_msg_list(msg_names)
                except Exception:
                    pass

    def _setup_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet(f"""
            QMenuBar {{
                background: {COLORS['bg_primary']};
                border-bottom: 1px solid {COLORS['border']};
                color: {COLORS['text_secondary']};
                font-size: 11px;
                padding: 2px;
            }}
            QMenuBar::item {{ padding: 4px 10px; background: transparent; }}
            QMenuBar::item:selected {{ background: {COLORS['bg_elevated']}; color: {COLORS['text_primary']}; }}
            QMenu {{
                background: {COLORS['bg_elevated']};
                border: 1px solid {COLORS['border_bright']};
                color: {COLORS['text_primary']};
            }}
            QMenu::item {{ padding: 6px 20px; font-size: 11px; }}
            QMenu::item:selected {{ background: {COLORS['border_bright']}; }}
        """)

        # File menu
        file_menu = menubar.addMenu("File")
        export_action = QAction("Export Session Data...", self)
        export_action.triggered.connect(self._export_data)
        file_menu.addAction(export_action)

        export_failure_action = QAction("Export Failure Report...", self)
        export_failure_action.setShortcut("Ctrl+Shift+E")
        export_failure_action.triggered.connect(self._show_export_dialog)
        file_menu.addAction(export_failure_action)

        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        clear_action = QAction("Clear All Faults", self)
        clear_action.triggered.connect(self._clear_faults)
        tools_menu.addAction(clear_action)

        kill_action = QAction("Kill Running Process", self)
        kill_action.triggered.connect(self.runner.kill)
        tools_menu.addAction(kill_action)

        tools_menu.addSeparator()

        auto_init_action = QAction("⚡  Auto-Initialize CAN Interface", self)
        auto_init_action.setShortcut("Ctrl+Shift+I")
        auto_init_action.triggered.connect(self._auto_init_interface)
        tools_menu.addAction(auto_init_action)

        log_view_action = QAction("📋  View Session Logs", self)
        log_view_action.setShortcut("Ctrl+L")
        log_view_action.triggered.connect(
            lambda: (self._navigate("LOGS"), self.sidebar.select("LOGS"))
        )
        tools_menu.addAction(log_view_action)

        failures_action = QAction("📊  View Failure Cases...", self)
        failures_action.setShortcut("Ctrl+Shift+F")
        failures_action.triggered.connect(self._show_failure_cases)
        tools_menu.addAction(failures_action)

        debug_failures_action = QAction("🐛  Debug Failure Cases", self)
        debug_failures_action.triggered.connect(self._debug_failure_cases)
        tools_menu.addAction(debug_failures_action)

        # Help menu
        help_menu = menubar.addMenu("Help")
        docs_action = QAction("Open Documentation", self)
        docs_action.triggered.connect(lambda: self._navigate("HELP") or self.sidebar.select("HELP"))
        help_menu.addAction(docs_action)

        about_action = QAction("About FucyFuzz", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _export_terminal_logs(self):
        """Export current terminal logs to a .txt/.log file."""
        from datetime import datetime as _dt
        from PyQt5.QtWidgets import QFileDialog as _QFD, QMessageBox
        import os

        log_text = ""
        try:
            current_widget = self._stack.currentWidget()
            if hasattr(current_widget, 'terminal') and hasattr(current_widget.terminal, 'toPlainText'):
                log_text = current_widget.terminal.toPlainText()
        except Exception:
            pass

        if not log_text:
            log_text = "[No log content available]"

        timestamp = _dt.now().strftime("%Y%m%d_%H%M%S")
        default_name = "fucyfuzz_logs_" + timestamp + ".txt"
        path, _ = _QFD.getSaveFileName(
            self, "Export Logs", default_name,
            "Text Files (*.txt);;Log Files (*.log);;All Files (*)"
        )
        if not path:
            return
        try:
            ts_str = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
            sep = "=" * 60
            header = "# FucyFuzz Exported Logs\n# Timestamp: " + ts_str + "\n# " + sep + "\n\n"
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(header + log_text + "\n")
            self._status_bar.showMessage("Logs exported to " + os.path.basename(path))
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", "Could not write log file:\n" + str(exc))

    def _export_data(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Session Data", "fucyfuzz_session.json",
            "JSON Files (*.json);;All Files (*)"
        )
        if path:
            data = self.dm.export_json()
            with open(path, 'w') as f:
                f.write(data)
            self._status_bar.showMessage(f"Exported to {path}")

    def _show_export_dialog(self):
        """Show the main Export menu dialog."""
        dlg = ExportDialog(self)
        dlg.export_requested.connect(self._handle_export_action)
        dlg.exec_()

    def _handle_export_action(self, action: str):
        """Dispatch based on which export menu item was chosen."""
        if action == 'overall':
            dlg = OverallReportDialog(self)
            dlg.format_selected.connect(self._run_overall_export)
            dlg.exec_()
        elif action == 'failure':
            self._run_failure_export()
        elif action == 'ecu_session':
            self._run_ecu_session_export()

    def _get_ecu_export_data(self):
        """Collect ALL ECU Monitor data (every event ever shown in the table)."""
        return None
        return None

    def _get_ecu_session_data(self):
        """Collect ONLY the events from the most recent START WATCHING session."""
        return None
        return None

    def _get_ecu_past_sessions(self) -> list:
        """Return archived past sessions from ECU Monitor tab."""
        return None
        return []

    def _run_ecu_session_export(self):
        """
        Show the ECU Session Picker so the user can choose:
          - Live session  (events since last START WATCHING)
          - Any previous completed session (archived on STOP)
        Then export the chosen session as a landscape-A4 PDF.
        """
        live_data    = self._get_ecu_session_data() or {}
        past_sessions = self._get_ecu_past_sessions()

        # Guard: nothing at all
        if not live_data.get('events') and not past_sessions:
            QMessageBox.warning(
                self,
                "No ECU Session Data",
                "No ECU Monitor sessions found.\n\n"
                "Go to the UDS Analyser tab to review findings.\n"
                "trigger vulnerabilities, then press STOP or export live."
            )
            return

        dlg = ECUSessionPickerDialog(live_data, past_sessions, parent=self)
        dlg.session_selected.connect(self._export_chosen_ecu_session)
        dlg.exec_()

    def _export_chosen_ecu_session(self, session_data: dict):
        """Called after the user picks a session in ECUSessionPickerDialog."""
        from datetime import datetime
        ensure_app_dirs()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Build a meaningful default filename
        sess_start = session_data.get('session_start', stamp)
        safe_start = sess_start.replace(':', '').replace(' ', '_').replace('-', '')
        default_name = f"ECU_Session_{safe_start}.pdf"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save ECU Monitor Session Report",
            default_name,
            "PDF Report (*.pdf)"
        )
        if not path:
            return

        ok, msg = export_manager.export_ecu_session_pdf(session_data, path)
        self._finish_export(ok, msg, path)

    def _run_overall_export(self, fmt: str):
        """Generate Overall Report in PDF, ASC or MDF4 format."""
        from datetime import datetime
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filters = {
            'pdf': ("PDF Report (*.pdf)", f"FucyFuzz_Report_{stamp}.pdf"),
            'asc': ("Vector ASC (*.asc)", f"FucyFuzz_Report_{stamp}.asc"),
            'mf4': ("ASAM MDF4 (*.mf4)",  f"FucyFuzz_Report_{stamp}.mf4"),
            'blf': ("Vector BLF (*.blf)", f"FucyFuzz_Report_{stamp}.blf"),
            'pcap':("PCAP Capture (*.pcap)", f"FucyFuzz_Report_{stamp}.pcap"),
            'json':("JSON Logs (*.jsonl)", f"FucyFuzz_Report_{stamp}.jsonl"),
        }
        file_filter, default_name = filters[fmt]
        path, _ = QFileDialog.getSaveFileName(self, "Save Overall Report", default_name, file_filter)
        if not path:
            return

        ecu_data = self._get_ecu_export_data()
        if fmt == 'pdf':
            ok, msg = export_manager.export_overall_pdf(self.dm, path, ecu_data=ecu_data)
        elif fmt == 'asc':
            ok, msg = export_manager.export_logs_asc(self.dm, path, ecu_data=ecu_data)
        elif fmt == 'blf':
            ok, msg = export_manager.export_logs_blf(self.dm, path, ecu_data=ecu_data)
        elif fmt == 'pcap':
            ok, msg = export_manager.export_logs_pcap(self.dm, path, ecu_data=ecu_data)
        elif fmt == 'json':
            ok, msg = export_manager.export_json(self.dm, path)
        else:
            ok, msg = export_manager.export_logs_mf4(self.dm, path, ecu_data=ecu_data)

        self._finish_export(ok, msg, path)

    def _run_failure_export(self):
        """
        Generate Failure Report PDF.
        - Auto-saves a copy to  failure_reports/  next to main.py.
        - Also opens a Save-As dialog so the user can save wherever they want.
        """
        from datetime import datetime
        ensure_app_dirs()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # ── auto-save to failure_reports/ ─────────────────────────────────────
        auto_path = os.path.join(
            APP_DIRS['failure_reports'],
            f"Failure_Report_{stamp}.pdf"
        )
        ecu_data = self._get_ecu_export_data()
        ok_auto, msg_auto = export_manager.export_failure_pdf(
            self.dm, auto_path, ecu_data=ecu_data
        )
        if ok_auto:
            self._status_bar.showMessage(
                f"Failure report auto-saved → failure_reports/Failure_Report_{stamp}.pdf"
            )

        # ── optional Save-As ──────────────────────────────────────────────────
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Failure Report (custom location)",
            f"Failure_Report_{stamp}.pdf",
            "PDF Report (*.pdf)"
        )
        if path and path != auto_path:
            ok, msg = export_manager.export_failure_pdf(
                self.dm, path, ecu_data=ecu_data
            )
            self._finish_export(ok, msg, path)
        elif ok_auto:
            QMessageBox.information(
                self, "Failure Report Saved",
                f"Auto-saved to:\n{auto_path}"
            )

    def _run_save_log(self):
        """Save raw terminal logs as .log text file."""
        from datetime import datetime
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Logs",
            f"fucyfuzz_logs_{stamp}.log",
            "Log Files (*.log);;Text Files (*.txt)"
        )
        if not path:
            return
        ecu_data = self._get_ecu_export_data()
        ok, msg = export_manager.save_logs_text(self.dm, path, ecu_data=ecu_data)
        self._finish_export(ok, msg, path)

    def _run_log_export(self, fmt: str):
        """Export logs to ASC or MDF4."""
        from datetime import datetime
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == 'asc':
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Logs (.asc)",
                f"fucyfuzz_{stamp}.asc",
                "Vector ASC (*.asc)"
            )
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Logs (.mf4)",
                f"fucyfuzz_{stamp}.mf4",
                "ASAM MDF4 (*.mf4)"
            )
        if not path:
            return
        ecu_data = self._get_ecu_export_data()
        if fmt == 'asc':
            ok, msg = export_manager.export_logs_asc(self.dm, path, ecu_data=ecu_data)
        else:
            ok, msg = export_manager.export_logs_mf4(self.dm, path, ecu_data=ecu_data)
        self._finish_export(ok, msg, path)

    def _finish_export(self, ok: bool, msg: str, path: str):
        if ok:
            QMessageBox.information(self, "Export Complete", msg)
            self._status_bar.showMessage(f"Report exported → {path}")
        else:
            QMessageBox.critical(self, "Export Failed", msg)
            self._status_bar.showMessage("Export failed — see dialog for details")

    def _auto_init_interface(self):
        """Auto-initialize the configured CAN interface (cross-platform)."""
        iface   = self.cfg.get("interface", "can0")
        bitrate = int(self.cfg.get("bitrate", 500000))
        self._status_bar.showMessage(f"Initializing CAN interface '{iface}'2026")
        try:
            from utils.can_interface import auto_initialize_interface, check_interface
            ok, msg = auto_initialize_interface(iface, bitrate)
            if ok:
                status = check_interface(iface)
                can_ok = "UP 2705" if status.ok else "check manually"
                QMessageBox.information(
                    self, "Interface Ready",
                    f"{msg}\n\nStatus: {can_ok}"
                )
                self.title_bar.set_can_active(status.ok)
                self._status_bar.showMessage(
                    f"Interface '{iface}' initialized  [{can_ok}]"
                )
            else:
                QMessageBox.warning(
                    self, "Interface Setup Failed",
                    f"Could not initialize '{iface}':\n\n{msg}"
                )
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _clear_faults(self):
        reply = QMessageBox.question(
            self, "Clear Faults",
            "Clear all recorded faults and sessions?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.dm.clear()

    def _show_failure_cases(self):
        """Open the Failure Cases management dialog."""
        dlg = FailureCasesDialog(self)
        dlg.rerun_requested.connect(self._rerun_failure)
        dlg.exec_()

    def _rerun_failure(self, module: str, args: list):
        """Re-run a failure case command."""
        if self.runner.is_running:
            QMessageBox.warning(self, "Busy", "A command is already running. Kill it first.")
            return
        self.runner.run(args)
        self._status_bar.showMessage(f"Re-running [{module}]: fucyfuzz {' '.join(str(a) for a in args)}")

    def _debug_failure_cases(self):
        """Print failure cases summary to status bar / console."""
        cases = load_failure_cases()
        total = sum(len(v) for v in cases.values())
        msg = f"Failure cases: {len(cases)} modules, {total} total entries"
        for mod, fails in cases.items():
            msg += f" | {mod}: {len(fails)}"
        self._status_bar.showMessage(msg)
        QMessageBox.information(self, "Failure Cases Debug", msg)

    def _show_about(self):
        QMessageBox.about(self, "About FucyFuzz",
            "<h3 style='color:#00d4ff;'>FucyFuzz</h3>"
            "<p>CAN Bus Security Framework</p>"
            "<p>Version 1.0.0</p>"
            "<p>Professional automotive penetration testing tool.</p>"
            "<p style='color:#64748b;'>GUI built with PyQt5</p>"
        )

    def _refresh_session_logger(self, cmd: str = "") -> None:
        """
        Start a fresh SessionLogger for the new run and re-register all GUI
        callbacks that were bound to the previous (now-closed) instance.

        Called every time runner.started fires (QueuedConnection → GUI thread).
        """
        try:
            from utils.session_logger import start_session_logger
            from utils.config import APP_DIRS
            start_session_logger(APP_DIRS["logs"])
        except Exception:
            pass

        log_tab = self._tabs.get("LOGS")
        if log_tab and hasattr(log_tab, "refresh_logger_connection"):
            log_tab.refresh_logger_connection()


    def _on_runner_finished(self, rc: int):
        """Auto-record failure cases when a command exits non-zero."""
        if rc != 0 and self._last_run_cmd:
            # Infer module from command
            parts = self._last_run_cmd.split()
            module_cmds = {
                'fuzzer': 'Fuzzer', 'lenattack': 'LengthAttack',
                'dcm': 'DCM', 'uds': 'UDS', 'send': 'Send',
                'listener': 'Listener', 'dump': 'Dump', 'xcp': 'XCP',
                'doip': 'DoIP', 'uds_fuzz': 'UDS Fuzz',
            }
            module = 'General'
            for p in parts:
                if p.lower() in module_cmds:
                    module = module_cmds[p.lower()]
                    break
            from datetime import datetime
            entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'module':    module,
                'command':   self._last_run_cmd,
                'output':    '',
                'status':    f'failed (rc={rc})',
            }
            add_failure_case(module, entry)
            self._status_bar.showMessage(
                f"[{module}] Command failed (rc={rc}) — failure case recorded  |  "
                f"Interface: {self.cfg.get('interface', 'vcan0')}"
            )

    def closeEvent(self, event):
        if self.runner.is_running:
            self.runner.kill()
        event.accept()
