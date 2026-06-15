"""
Config Tab — clean, professional CAN interface setup (v25)
"""

import os
import subprocess
import platform

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QSpinBox, QPushButton,
    QGroupBox, QFileDialog, QScrollArea, QMessageBox,
    QPlainTextEdit, QCheckBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer

from ui.widgets import SectionHeader, GlowButton, SolidButton, CardFrame
from ui.theme import COLORS
from utils.config import get_config

_IS_WINDOWS = platform.system().lower() == "windows"

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_silent(cmd_list: list, timeout: int = 3):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd_list, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as exc:
        return -1, "", str(exc)

def _sep():
    """Thin horizontal separator line."""
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet(f"color: {COLORS['border']}; background: {COLORS['border']}; max-height: 1px;")
    return line


# ─────────────────────────────────────────────────────────────────────────────
#  ConfigTab
# ─────────────────────────────────────────────────────────────────────────────

class ConfigTab(QWidget):
    config_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loaded_db = None   # holds cantools db after _load_dbc()
        self.cfg = get_config()
        self._setup_ui()
        self._load_values()

    # ── UI construction ───────────────────────────────────────────────────────

    def _setup_ui(self):
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(14)

        layout.addWidget(SectionHeader("⚙  Configuration"))

        # ── 1. Binary ─────────────────────────────────────────────────────────
        layout.addWidget(self._build_binary_group())

        # ── 2. CAN Interface (what the tool uses to talk CAN) ─────────────────
        layout.addWidget(self._build_iface_group())

        # ── 3. Linux CAN Setup (bring the interface up) ───────────────────────
        if not _IS_WINDOWS:
            layout.addWidget(self._build_linux_can_setup())
        else:
            layout.addWidget(self._build_windows_note())

        # ── 4. Interface Status ───────────────────────────────────────────────
        layout.addWidget(self._build_status_group())

        # ── 5. Logging ────────────────────────────────────────────────────────
        layout.addWidget(self._build_logging_group())

        # ── 6. Custom fault rules ─────────────────────────────────────────────
        layout.addWidget(self._build_rules_group())

        # ── 7. DBC ───────────────────────────────────────────────────────────
        layout.addWidget(self._build_dbc_group())

        # ── 8. Save ───────────────────────────────────────────────────────────
        save_btn = SolidButton("💾   SAVE CONFIGURATION", COLORS['accent_cyan'])
        save_btn.setFixedHeight(40)
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)

        layout.addStretch()
        scroll.setWidget(content)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self._on_driver_change(self.driver.currentText())

    # ── Group builders ────────────────────────────────────────────────────────

    def _build_binary_group(self):
        grp = QGroupBox("FucyFuzz Binary")
        lay = QVBoxLayout(grp)
        _default = 'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz'
        row = QHBoxLayout()
        self.binary_path = QLineEdit()
        self.binary_path.setPlaceholderText(_default)
        row.addWidget(self.binary_path)
        b = GlowButton("Browse", COLORS['accent_cyan'])
        b.setFixedWidth(80)
        b.clicked.connect(self._browse_binary)
        row.addWidget(b)
        lay.addLayout(row)
        # Platform hint
        hint_text = (
            "Windows: select fucyfuzz.exe"
            if _IS_WINDOWS else
            "Linux: select the fucyfuzz binary (no extension); run  chmod +x fucyfuzz  first"
        )
        hint = QLabel(hint_text)
        hint.setWordWrap(True)
        hint.setStyleSheet(
            f"color:{COLORS.get('text_muted','#666')};font-size:9px;background:transparent;"
        )
        lay.addWidget(hint)
        return grp

    def _build_iface_group(self):
        """
        CAN Interface group — what FucyFuzz passes to python-can.
        Driver locked to socketcan on Linux.  Bitrate shown only when relevant.
        """
        grp = QGroupBox("CAN Interface")
        lay = QVBoxLayout(grp)
        lay.setSpacing(8)

        # Interface name
        r1 = QHBoxLayout()
        lbl_iface = QLabel("Interface:")
        lbl_iface.setFixedWidth(110)
        self.interface = QComboBox()
        self.interface.setEditable(True)
        if _IS_WINDOWS:
            self.interface.addItems(["PCAN_USBBUS1", "PCAN_USBBUS2", "can0", "vcan0"])
        else:
            self.interface.addItems(["vcan0", "can0"])
        r1.addWidget(lbl_iface)
        r1.addWidget(self.interface)
        lay.addLayout(r1)

        # Driver
        r2 = QHBoxLayout()
        lbl_drv = QLabel("Driver / Backend:")
        lbl_drv.setFixedWidth(110)
        self.driver = QComboBox()
        if _IS_WINDOWS:
            self.driver.addItems(["virtual", "pcan", "socketcan"])
        else:
            self.driver.addItems(["socketcan", "pcan", "virtual"])
        self.driver.currentTextChanged.connect(self._on_driver_change)
        r2.addWidget(lbl_drv)
        r2.addWidget(self.driver)
        lay.addLayout(r2)

        # Bitrate — always visible, used by save/canrc
        r3 = QHBoxLayout()
        lbl_br = QLabel("Bitrate:")
        lbl_br.setFixedWidth(110)
        self.bitrate = QComboBox()
        self.bitrate.addItems(["125000", "250000", "500000", "1000000"])
        self.bitrate.setCurrentText("500000")
        r3.addWidget(lbl_br)
        r3.addWidget(self.bitrate)
        r3.addStretch()
        lay.addLayout(r3)

        self._driver_help = QLabel("")
        self._driver_help.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        self._driver_help.setWordWrap(True)
        lay.addWidget(self._driver_help)

        # Write .canrc button inline here
        canrc_btn = GlowButton("📝  Write python-can config  (~/.canrc)", COLORS['accent_purple'])
        canrc_btn.setFixedHeight(30)
        canrc_btn.clicked.connect(self._write_canrc)
        lay.addWidget(canrc_btn)

        return grp

    def _build_linux_can_setup(self):
        """
        Single, clean CAN setup group for Linux.
        Dropdown selects vcan0 or can0 — each shows exactly the right controls
        and exactly one action button.
        """
        grp = QGroupBox("CAN Interface Setup")
        lay = QVBoxLayout(grp)
        lay.setSpacing(10)

        # ── Selector row ──────────────────────────────────────────────────────
        sel_row = QHBoxLayout()
        sel_lbl = QLabel("Select interface:")
        sel_lbl.setFixedWidth(110)
        self._setup_iface_combo = QComboBox()
        self._setup_iface_combo.addItems(["vcan0", "can0"])
        self._setup_iface_combo.setFixedWidth(120)
        self._setup_iface_combo.currentTextChanged.connect(self._on_setup_iface_changed)
        sel_row.addWidget(sel_lbl)
        sel_row.addWidget(self._setup_iface_combo)
        sel_row.addStretch()
        lay.addLayout(sel_row)

        lay.addWidget(_sep())

        # ── VCAN0 panel ───────────────────────────────────────────────────────
        self._vcan_panel = QWidget()
        vp = QVBoxLayout(self._vcan_panel)
        vp.setContentsMargins(0, 4, 0, 0)
        vp.setSpacing(8)

        vp_title = QLabel("Virtual CAN — no hardware required")
        vp_title.setStyleSheet(
            f"color: {COLORS['accent_cyan']}; font-weight: 700; font-size: 11px; background: transparent;")
        vp.addWidget(vp_title)

        cmds_vcan = QLabel(
            "Commands that will run:\n"
            "   sudo modprobe vcan\n"
            "   sudo ip link add dev vcan0 type vcan\n"
            "   sudo ip link set up vcan0")
        cmds_vcan.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; font-family: monospace; background: transparent;")
        vp.addWidget(cmds_vcan)

        vcan_btn_row = QHBoxLayout()
        self._vcan_up_btn = SolidButton("▶   Bring Up vcan0", COLORS['accent_green'])
        self._vcan_up_btn.setFixedHeight(34)
        self._vcan_up_btn.clicked.connect(self._bring_up_vcan0)
        vcan_btn_row.addWidget(self._vcan_up_btn)

        self._vcan_down_btn = GlowButton("■   Take Down vcan0", COLORS['critical'])
        self._vcan_down_btn.setFixedHeight(34)
        self._vcan_down_btn.clicked.connect(self._take_down_vcan0)
        vcan_btn_row.addWidget(self._vcan_down_btn)
        vcan_btn_row.addStretch()
        vp.addLayout(vcan_btn_row)

        lay.addWidget(self._vcan_panel)

        # ── CAN0 panel ────────────────────────────────────────────────────────
        self._can0_panel = QWidget()
        cp = QVBoxLayout(self._can0_panel)
        cp.setContentsMargins(0, 4, 0, 0)
        cp.setSpacing(8)

        cp_title = QLabel("Physical CAN — requires hardware (e.g. PCAN USB, Kvaser)")
        cp_title.setStyleSheet(
            f"color: {COLORS['accent_yellow']}; font-weight: 700; font-size: 11px; background: transparent;")
        cp.addWidget(cp_title)

        # Bitrate selector
        cp_br_row = QHBoxLayout()
        br_lbl = QLabel("Bitrate:")
        br_lbl.setFixedWidth(90)
        self._can0_bitrate = QComboBox()
        self._can0_bitrate.addItems(["125000", "250000", "500000", "1000000"])
        self._can0_bitrate.setCurrentText("500000")
        self._can0_bitrate.setFixedWidth(120)
        self._can0_bitrate.currentTextChanged.connect(self._refresh_can0_cmd_preview)
        cp_br_row.addWidget(br_lbl)
        cp_br_row.addWidget(self._can0_bitrate)
        cp_br_row.addStretch()
        cp.addLayout(cp_br_row)

        # restart-ms
        cp_rms_row = QHBoxLayout()
        rms_lbl = QLabel("restart-ms:")
        rms_lbl.setFixedWidth(90)
        rms_lbl.setToolTip("Auto bus-error recovery interval in ms. 0 = disabled.")
        self._can0_restart_ms = QLineEdit("100")
        self._can0_restart_ms.setFixedWidth(70)
        self._can0_restart_ms.textChanged.connect(self._refresh_can0_cmd_preview)
        cp_rms_row.addWidget(rms_lbl)
        cp_rms_row.addWidget(self._can0_restart_ms)
        cp_rms_row.addStretch()
        cp.addLayout(cp_rms_row)

        # Live command preview
        self._can0_cmd_preview = QLabel("")
        self._can0_cmd_preview.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; font-family: monospace; background: transparent;")
        self._can0_cmd_preview.setWordWrap(True)
        cp.addWidget(self._can0_cmd_preview)

        # Single action button
        can0_btn_row = QHBoxLayout()
        self._can0_apply_btn = SolidButton("▶   Apply CAN0 Settings", COLORS['accent_green'])
        self._can0_apply_btn.setFixedHeight(34)
        self._can0_apply_btn.clicked.connect(self._apply_can0)
        can0_btn_row.addWidget(self._can0_apply_btn)

        self._can0_down_btn = GlowButton("■   Take Down can0", COLORS['critical'])
        self._can0_down_btn.setFixedHeight(34)
        self._can0_down_btn.clicked.connect(self._take_down_can0)
        can0_btn_row.addWidget(self._can0_down_btn)
        can0_btn_row.addStretch()
        cp.addLayout(can0_btn_row)

        lay.addWidget(self._can0_panel)

        # Initial state
        self._can0_panel.setVisible(False)
        self._refresh_can0_cmd_preview()

        return grp

    def _build_windows_note(self):
        grp = QGroupBox("CAN Interface Setup")
        lay = QVBoxLayout(grp)
        lbl = QLabel(
            "CAN interface setup (ip link / modprobe) is supported on Linux only.\n"
            "On Windows, select your interface above (e.g. PCAN_USBBUS1) and "
            "use the PCAN Driver from peak-system.com.")
        lbl.setStyleSheet(
            f"color: {COLORS['accent_yellow']}; font-size: 10px; background: transparent;")
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        if hasattr(self, 'virtual_channel'):
            pass  # keep compat
        else:
            self.virtual_channel = QSpinBox()  # dummy, never shown
        return grp

    def _build_status_group(self):
        grp = QGroupBox("Interface Status")
        lay = QVBoxLayout(grp)
        lay.setSpacing(6)

        btn_row = QHBoxLayout()
        self._check_iface_btn = SolidButton("🔍  Check Interface", COLORS['accent_cyan'])
        self._check_iface_btn.setFixedHeight(32)
        self._check_iface_btn.clicked.connect(self._check_iface)
        btn_row.addWidget(self._check_iface_btn)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._iface_status_lbl = QLabel("Click 'Check Interface' to see current CAN status.")
        self._iface_status_lbl.setWordWrap(True)
        self._iface_status_lbl.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; "
            f"font-family: monospace; background: transparent;")
        lay.addWidget(self._iface_status_lbl)
        return grp

    def _build_logging_group(self):
        grp = QGroupBox("Logging")
        lay = QVBoxLayout(grp)
        row = QHBoxLayout()
        row.addWidget(QLabel("Log Directory:"))
        self.log_dir = QLineEdit()
        self.log_dir.setPlaceholderText("./logs")
        row.addWidget(self.log_dir)
        b = GlowButton("Browse", COLORS['accent_cyan'])
        b.setFixedWidth(80)
        b.clicked.connect(self._browse_log_dir)
        row.addWidget(b)
        lay.addLayout(row)
        return grp

    def _build_rules_group(self):
        grp = QGroupBox("Custom Output Rules  (ECU Monitor keyword detection)")
        lay = QVBoxLayout(grp)
        lbl = QLabel(
            "Format:  severity | keyword\n"
            "Severities: critical / high / medium / low\n"
            "Example:   critical | seed is constant")
        lbl.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        lay.addWidget(lbl)
        self.custom_rules = QPlainTextEdit()
        self.custom_rules.setFixedHeight(110)
        self.custom_rules.setPlaceholderText(
            "critical | seed is constant\nhigh | no response\nmedium | unexpected service")
        self.custom_rules.setStyleSheet(f"""
            QPlainTextEdit {{
                background: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                color: {COLORS['accent_green']};
                font-family: 'Courier New', monospace;
                font-size: 11px;
                padding: 6px;
            }}
        """)
        lay.addWidget(self.custom_rules)
        return grp

    def _build_dbc_group(self):
        grp = QGroupBox("DBC File  (optional — populates ID dropdowns)")
        lay = QVBoxLayout(grp)
        row = QHBoxLayout()
        self.dbc_path = QLineEdit()
        self.dbc_path.setPlaceholderText("Select .dbc file (optional)")
        row.addWidget(self.dbc_path)
        b = GlowButton("Browse", COLORS['accent_cyan'])
        b.setFixedWidth(80)
        b.clicked.connect(self._browse_dbc)
        row.addWidget(b)
        lay.addLayout(row)

        btn_row = QHBoxLayout()
        load_btn = SolidButton("Load DBC", COLORS['accent_purple'])
        load_btn.setFixedWidth(110)
        load_btn.clicked.connect(self._load_dbc)
        btn_row.addWidget(load_btn)

        self._analyze_btn = SolidButton("🔬 Analyze", COLORS['accent_cyan'])
        self._analyze_btn.setFixedWidth(110)
        self._analyze_btn.setEnabled(False)
        self._analyze_btn.setToolTip("Open CANdb++-style DBC Analyzer window")
        self._analyze_btn.clicked.connect(self._open_dbc_analyzer)
        btn_row.addWidget(self._analyze_btn)
        clr_btn = GlowButton("Clear", COLORS['text_muted'])
        clr_btn.setFixedWidth(80)
        clr_btn.clicked.connect(self._clear_dbc)
        btn_row.addWidget(clr_btn)
        self._dbc_status = QLabel("No DBC loaded")
        self._dbc_status.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; background: transparent;")
        btn_row.addWidget(self._dbc_status)
        btn_row.addStretch()
        lay.addLayout(btn_row)
        return grp

    def _on_setup_iface_changed(self, iface: str):
        if hasattr(self, '_vcan_panel'):
            self._vcan_panel.setVisible(iface == "vcan0")
        if hasattr(self, '_can0_panel'):
            self._can0_panel.setVisible(iface == "can0")

    def _on_driver_change(self, driver: str):
        helps = {
            "socketcan": (
                "Linux SocketCAN.\n"
                "  • vcan0 — virtual CAN (no hardware needed)\n"
                "  • can0  — physical CAN (PCAN USB via peak_usb kernel module)"
            ),
            "pcan": (
                "PEAK PCAN USB (Windows & Linux).\n"
                "  • Interface: PCAN_USBBUS1, PCAN_USBBUS2, …\n"
                "  • Install: pip install 'python-can[pcan]'"
            ),
            "virtual": (
                "python-can virtual bus — no hardware.\n"
                "  • In-process loopback; sender & receiver must share channel.\n"
                "  • Good for testing without hardware."
            ),
        }
        self._driver_help.setText(helps.get(driver, ""))

    def _refresh_can0_cmd_preview(self):
        """Update the live command preview in the can0 panel."""
        if not hasattr(self, '_can0_cmd_preview'):
            return
        try:
            br = self._can0_bitrate.currentText().strip() or "500000"
            rms = self._can0_restart_ms.text().strip() or "100"
        except Exception:
            br, rms = "500000", "100"
        lines = [
            "sudo ip link set can0 down",
            f"sudo ip link set can0 type can bitrate {br} restart-ms {rms}",
            "sudo ip link set can0 up",
        ]
        self._can0_cmd_preview.setText("Commands:\n" + "\n".join(f"   {l}" for l in lines))

    # ── Slots — vcan0 ─────────────────────────────────────────────────────────

    def _bring_up_vcan0(self):
        cmds = [
            ["sudo", "modprobe", "vcan"],
            ["sudo", "ip", "link", "add", "dev", "vcan0", "type", "vcan"],
            ["sudo", "ip", "link", "set", "up", "vcan0"],
        ]
        self._run_cmds_with_confirm(
            title="Bring Up vcan0",
            cmds=cmds,
            on_success=lambda: self._apply_preset("vcan0", "socketcan"),
        )

    def _take_down_vcan0(self):
        cmds = [
            ["sudo", "ip", "link", "set", "down", "vcan0"],
            ["sudo", "ip", "link", "delete", "vcan0"],
        ]
        self._run_cmds_with_confirm(title="Take Down vcan0", cmds=cmds)

    # ── Slots — can0 ──────────────────────────────────────────────────────────

    def _apply_can0(self):
        try:
            br  = self._can0_bitrate.currentText().strip()
            rms = self._can0_restart_ms.text().strip() or "100"
            int(br); int(rms)
        except (AttributeError, ValueError):
            QMessageBox.warning(self, "CAN0", "Invalid bitrate or restart-ms value.")
            return
        cmds = [
            ["sudo", "ip", "link", "set", "can0", "down"],
            ["sudo", "ip", "link", "set", "can0", "type", "can",
             "bitrate", br, "restart-ms", rms],
            ["sudo", "ip", "link", "set", "can0", "up"],
        ]
        self._run_cmds_with_confirm(
            title="Apply CAN0 Settings",
            cmds=cmds,
            on_success=lambda: self._apply_preset("can0", "socketcan"),
        )

    def _take_down_can0(self):
        cmds = [["sudo", "ip", "link", "set", "can0", "down"]]
        self._run_cmds_with_confirm(title="Take Down can0", cmds=cmds)

    # ── Shared command runner ─────────────────────────────────────────────────

    def _run_cmds_with_confirm(self, title: str, cmds: list, on_success=None):
        """Show a preview dialog, run commands, report result."""
        cmd_strs = [" ".join(c) for c in cmds]
        preview  = "\n".join(cmd_strs)
        reply = QMessageBox.question(
            self, title,
            f"The following commands will run:\n\n{preview}\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if reply != QMessageBox.Yes:
            return

        errors = []
        for cmd in cmds:
            rc, out, err = _run_silent(cmd)
            if rc != 0 and err:
                if "already exists" not in err and "File exists" not in err:
                    errors.append(err)

        if errors:
            QMessageBox.warning(self, title,
                                "Completed with warnings:\n\n" + "\n".join(errors))
        else:
            QMessageBox.information(self, title, f"✔  {title} — done.")
            if on_success:
                on_success()

        # Auto-refresh interface status
        QTimer.singleShot(300, self._check_iface)

    # ── Interface status ──────────────────────────────────────────────────────

    def _check_iface(self):
        """Run 'ip link show' and show parsed status for the selected interface."""
        iface = self.interface.currentText().strip()
        if not iface:
            return

        if _IS_WINDOWS:
            self._iface_status_lbl.setText("Interface status check not available on Windows.")
            return

        rc, out, err = _run_silent(["ip", "link", "show", iface])

        if rc != 0:
            # Interface not found
            self._set_status_label(
                f"✘  '{iface}' not found or not configured.\n"
                f"   Use the CAN Interface Setup section above to bring it up.",
                ok=False,
            )
            return

        # Parse state
        up   = "UP"    in out or "state UP"   in out
        down = "DOWN"  in out or "state DOWN" in out

        # Try to get bitrate for physical interfaces
        br_info = ""
        if iface.startswith("can"):
            rc2, out2, _ = _run_silent(["ip", "-details", "link", "show", iface])
            for line in out2.splitlines():
                line = line.strip()
                if "bitrate" in line:
                    br_info = f"\n   {line.strip()}"
                    break

        if up:
            self._set_status_label(
                f"✔  {iface} is UP and ready.{br_info}", ok=True)
        elif down:
            self._set_status_label(
                f"⚠  {iface} is DOWN.\n"
                f"   Use the CAN Interface Setup section above to bring it up.{br_info}",
                ok=False,
            )
        else:
            self._set_status_label(f"?  {iface} state unknown.\n{out[:200]}", ok=False)

    def _set_status_label(self, text: str, ok: bool):
        color = COLORS.get('success', '#00ff88') if ok else COLORS.get('critical', '#f43f5e')
        self._iface_status_lbl.setText(text)
        self._iface_status_lbl.setStyleSheet(
            f"color: {color}; font-size: 10px; font-family: monospace; background: transparent;")

    # ── Presets ───────────────────────────────────────────────────────────────

    def _apply_preset(self, iface: str, driver: str):
        if not driver or str(driver).lower() in ('none', 'null', ''):
            from utils.config import _auto_driver_for_interface
            driver = _auto_driver_for_interface(iface)
        idx = self.interface.findText(iface)
        if idx >= 0:
            self.interface.setCurrentIndex(idx)
        else:
            self.interface.addItem(iface)
            self.interface.setCurrentText(iface)
        idx = self.driver.findText(driver)
        if idx >= 0:
            self.driver.setCurrentIndex(idx)
        else:
            self.driver.addItem(driver)
            self.driver.setCurrentText(driver)

    # ── File dialogs ──────────────────────────────────────────────────────────

    def _browse_binary(self):
        if _IS_WINDOWS:
            filt = "Executable Files (*.exe);;All Files (*)"
        else:
            filt = "All Files (*)"
        p, _ = QFileDialog.getOpenFileName(self, "Select FucyFuzz Binary", "", filt)
        if p:
            self.binary_path.setText(p)

    def _browse_log_dir(self):
        p = QFileDialog.getExistingDirectory(self, "Select Log Directory")
        if p:
            self.log_dir.setText(p)

    def _browse_dbc(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select DBC File", "", "DBC Files (*.dbc);;All Files (*)")
        if p:
            self.dbc_path.setText(p)

    # ── DBC ───────────────────────────────────────────────────────────────────

    def _load_dbc(self):
        path = self.dbc_path.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "DBC Error", "Invalid DBC file path.")
            return
        try:
            import cantools
            db   = cantools.database.load_file(path)
            msgs = {msg.name: msg.frame_id for msg in db.messages}
            self.cfg.set('dbc_db_path', path)
            self.cfg.set('dbc_messages', msgs)
            self.cfg.set('dbc_path', path)
            count = len(msgs)
            self._dbc_status.setText(f"✓ {count} messages loaded")
            self._dbc_status.setStyleSheet(
                f"color: {COLORS['success']}; font-size: 10px; background: transparent;")
            self.config_changed.emit()
            self._loaded_db = db
            if hasattr(self, '_analyze_btn'):
                self._analyze_btn.setEnabled(True)
            QMessageBox.information(self, "DBC Loaded",
                                    f"Loaded {count} messages from {os.path.basename(path)}")
        except ImportError:
            QMessageBox.critical(self, "DBC Error",
                                 "cantools not installed.\nRun: pip install cantools")
        except Exception as exc:
            QMessageBox.critical(self, "DBC Error", str(exc))

    def _clear_dbc(self):
        self.cfg.set('dbc_db_path', '')
        self.cfg.set('dbc_messages', {})
        self.cfg.set('dbc_path', '')
        self._loaded_db = None
        if hasattr(self, '_analyze_btn'):
            self._analyze_btn.setEnabled(False)
        self._dbc_status.setText("No DBC loaded")
        self._dbc_status.setStyleSheet(
            f"color: {COLORS['text_muted']}; font-size: 10px; background: transparent;")
        self.config_changed.emit()

    def _open_dbc_analyzer(self):
        """Launch the Vector CANdb++-style DBC Analyzer window."""
        db   = getattr(self, '_loaded_db', None)
        path = self.dbc_path.text().strip() if hasattr(self, 'dbc_path') else ""
        if db is None:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Analyzer", "No DBC loaded. Load a DBC file first.")
            return
        from ui.dbc_analyzer import DBCAnalyzerWindow
        dlg = DBCAnalyzerWindow(db, path, self)
        dlg.show()

    # ── .canrc ────────────────────────────────────────────────────────────────

    def _write_canrc(self):
        iface   = self.interface.currentText().strip()
        driver  = self.driver.currentText().strip()
        bitrate = self.bitrate.currentText().strip()

        if not driver or str(driver).lower() in ('none', 'null', ''):
            from utils.config import _auto_driver_for_interface
            driver = _auto_driver_for_interface(iface)

        canrc_path = (
            os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), ".canrc")
            if _IS_WINDOWS else os.path.expanduser("~/.canrc")
        )
        content = (
            "[default]\n"
            f"interface = {driver}\n"
            f"channel = {iface}\n"
        )
        if driver in ("pcan", "kvaser", "ixxat", "vector", "usb2can"):
            content += f"bitrate = {bitrate}\n"

        try:
            with open(canrc_path, "w") as f:
                f.write(content)
            QMessageBox.information(
                self, "python-can config written",
                f"Saved to:\n{canrc_path}\n\nContents:\n{content}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Write Error", str(exc))

    # ── Load / Save ───────────────────────────────────────────────────────────

    def _load_values(self):
        self.binary_path.setText(self.cfg.get('binary_path', 'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz'))
        default_iface  = "PCAN_USBBUS1" if _IS_WINDOWS else "vcan0"
        default_driver = "virtual"      if _IS_WINDOWS else "socketcan"
        saved_iface    = self.cfg.get('interface', default_iface)
        saved_driver   = self.cfg.get('driver',    default_driver)

        if not saved_driver or str(saved_driver).lower() in ('none', 'null', ''):
            from utils.config import _auto_driver_for_interface
            saved_driver = _auto_driver_for_interface(saved_iface)

        idx = self.interface.findText(saved_iface)
        if idx >= 0:
            self.interface.setCurrentIndex(idx)
        else:
            self.interface.addItem(saved_iface)
            self.interface.setCurrentText(saved_iface)

        idx = self.driver.findText(saved_driver)
        if idx >= 0:
            self.driver.setCurrentIndex(idx)

        self.bitrate.setCurrentText(str(self.cfg.get('bitrate', 500000)))
        self.log_dir.setText(self.cfg.get('log_dir', './logs'))
        self.custom_rules.setPlainText(self.cfg.get('custom_rules', ''))
        saved_dbc = self.cfg.get('dbc_path', '')
        if saved_dbc:
            self.dbc_path.setText(saved_dbc)

        # Sync can0 bitrate dropdown with saved bitrate
        if hasattr(self, '_can0_bitrate'):
            saved_br = str(self.cfg.get('bitrate', 500000))
            idx2 = self._can0_bitrate.findText(saved_br)
            if idx2 >= 0:
                self._can0_bitrate.setCurrentIndex(idx2)

    def _save(self):
        iface  = self.interface.currentText().strip() or ("PCAN_USBBUS1" if _IS_WINDOWS else "vcan0")
        driver = self.driver.currentText().strip()    or ("virtual"      if _IS_WINDOWS else "socketcan")
        br     = int(self.bitrate.currentText()) if self.bitrate.currentText().isdigit() else 500000
        _bin_default = 'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz'
        self.cfg.update({
            'binary_path':  self.binary_path.text().strip() or _bin_default,
            'interface':    iface,
            'driver':       driver,
            'bitrate':      br,
            'log_dir':      self.log_dir.text().strip() or './logs',
            'max_log_lines': 0,
            'custom_rules': self.custom_rules.toPlainText().strip(),
        })
        QMessageBox.information(self, "Saved", "Configuration saved.")

    def get_binary_path(self) -> str:
        _bin_default = 'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz'
        return self.cfg.get('binary_path', _bin_default)

    # Compat shim — main_window may read virtual_channel
    @property
    def virtual_channel(self):
        if not hasattr(self, '_vc_spin'):
            self._vc_spin = QSpinBox()
        return self._vc_spin
