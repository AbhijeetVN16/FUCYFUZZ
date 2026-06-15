"""
Send Module Tab — Fixed & Stable
- VIN Read section removed (caused crashes via unsafe threading)
- Interface field shown for reference but NOT passed as -i (send module
  does not accept that flag — confirmed from binary help output)
- All terminal updates go through thread-safe TerminalWidget signals
"""

import logging

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QDoubleSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox,
    QTextEdit, QFileDialog
)

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton
from ui.theme import COLORS

log = logging.getLogger(__name__)


class SendTab(BaseModuleTab):
    MODULE_NAME = "send"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("Send Module"))

        # ── Send Mode ────────────────────────────────────────────────────────
        mode_group = QGroupBox("Send Mode")
        mode_layout = QVBoxLayout(mode_group)
        self.mode = QComboBox()
        self.mode.addItems(["message", "file"])
        self.mode.currentTextChanged.connect(self._on_mode_change)
        mode_layout.addWidget(self.mode)
        self._controls_layout.addWidget(mode_group)

        # ── Message mode ─────────────────────────────────────────────────────
        self._msg_group = QGroupBox("Messages")
        msg_layout = QVBoxLayout(self._msg_group)

        lbl = QLabel(
            "Enter one message per line:\n"
            "Format: <ID>#<data>  e.g. 0x7a0#c0.ff.ee.00"
        )
        lbl.setStyleSheet(
            f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;"
        )
        lbl.setWordWrap(True)
        msg_layout.addWidget(lbl)

        self.messages_edit = QTextEdit()
        self.messages_edit.setPlaceholderText(
            "0x7a0#c0.ff.ee.00.11.22.33.44\n123#de.ad.be.ef"
        )
        self.messages_edit.setFixedHeight(120)
        self.messages_edit.setStyleSheet(f"""
            background: {COLORS['bg_input']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            color: {COLORS['text_primary']};
            font-family: 'Courier New', monospace;
            font-size: 11px;
            padding: 6px;
        """)
        msg_layout.addWidget(self.messages_edit)

        self.periodic = QCheckBox("Periodic send (-p)")
        msg_layout.addWidget(self.periodic)
        self._controls_layout.addWidget(self._msg_group)

        # ── File mode ────────────────────────────────────────────────────────
        self._file_group = QGroupBox("Send from File")
        file_layout = QVBoxLayout(self._file_group)

        fl = QHBoxLayout()
        self.send_file = QLineEdit()
        self.send_file.setPlaceholderText("can_dump.txt")
        fl.addWidget(self.send_file)
        browse_btn = GlowButton("Browse", COLORS['accent_cyan'])
        browse_btn.setFixedWidth(70)
        browse_btn.clicked.connect(self._browse_file)
        fl.addWidget(browse_btn)
        file_layout.addLayout(fl)
        self._controls_layout.addWidget(self._file_group)

        # ── Common options ───────────────────────────────────────────────────
        common_group = QGroupBox("Common Options")
        cl = QVBoxLayout(common_group)

        c2 = QHBoxLayout()
        c2.addWidget(QLabel("Delay between msgs (s):"))
        self.delay = QDoubleSpinBox()
        self.delay.setValue(0.0)
        self.delay.setSingleStep(0.1)
        self.delay.setDecimals(3)
        c2.addWidget(self.delay)
        cl.addLayout(c2)

        self._controls_layout.addWidget(common_group)

        self._on_mode_change("message")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select CAN Dump File", "",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.send_file.setText(path)

    def _on_mode_change(self, mode: str):
        self._msg_group.setVisible(mode == "message")
        self._file_group.setVisible(mode == "file")

    # ── Core ──────────────────────────────────────────────────────────────────

    def build_args(self) -> list:
        mode = self.mode.currentText()

        # send <mode> — no -i flag (the binary's send subcommand does not
        # accept an interface argument; interface is handled at binary level)
        args = ["send", mode]

        if self.delay.value() > 0:
            args += ["-d", str(round(self.delay.value(), 3))]

        if mode == "message":
            msgs = [
                m.strip()
                for m in self.messages_edit.toPlainText().split('\n')
                if m.strip()
            ]
            if not msgs:
                self.terminal.append_error("No messages entered.")
                return None
            if self.periodic.isChecked():
                args.append("-p")
            args += msgs

        else:  # file mode
            f = self.send_file.text().strip()
            if not f:
                self.terminal.append_error("No file selected.")
                return None
            args.append(f)

        log.debug("SendTab build_args -> %s", args)
        return args

    def update_msg_list(self, msg_names: list):
        """Called when a DBC is loaded — shows message names as placeholder."""
        if msg_names and hasattr(self, 'messages_edit'):
            hint = "\n".join(f"# {n}" for n in msg_names[:5])
            self.messages_edit.setPlaceholderText(hint)
