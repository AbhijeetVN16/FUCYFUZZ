"""
XCP Module Tab
"""

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox, QFileDialog
)

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton
from ui.theme import COLORS


class XCPTab(BaseModuleTab):
    MODULE_NAME = "xcp"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("XCP Module"))

        cmd_group = QGroupBox("Command")
        cmd_layout = QVBoxLayout(cmd_group)
        self.subcmd = QComboBox()
        self.subcmd.addItems(["discovery", "commands", "info", "dump"])
        self.subcmd.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['bg_input']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 5px 10px;
                font-size: 12px;
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
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_group)

        # IDs
        ids_group = QGroupBox("CAN IDs")
        ids_layout = QVBoxLayout(ids_group)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Request ID (dec/hex):"))
        self.req_id = QLineEdit("1000")
        r1.addWidget(self.req_id)
        ids_layout.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Response ID (dec/hex):"))
        self.resp_id = QLineEdit("1001")
        r2.addWidget(self.resp_id)
        ids_layout.addLayout(r2)
        self._controls_layout.addWidget(ids_group)

        # Discovery
        self._disc_group = QGroupBox("Discovery Options")
        disc_layout = QVBoxLayout(self._disc_group)
        self.use_blacklist = QCheckBox("Blacklist IDs")
        disc_layout.addWidget(self.use_blacklist)
        self.blacklist_ids = QLineEdit()
        self.blacklist_ids.setPlaceholderText("0x100 0xabc ...")
        disc_layout.addWidget(self.blacklist_ids)
        self.use_autoblacklist = QCheckBox("Auto Blacklist")
        disc_layout.addWidget(self.use_autoblacklist)
        ab = QHBoxLayout()
        ab.addWidget(QLabel("Threshold:"))
        self.autoblacklist_n = QSpinBox()
        self.autoblacklist_n.setValue(10)
        ab.addWidget(self.autoblacklist_n)
        disc_layout.addLayout(ab)
        self._controls_layout.addWidget(self._disc_group)

        # Dump options
        self._dump_group = QGroupBox("Memory Dump Options")
        dump_layout = QVBoxLayout(self._dump_group)

        d1 = QHBoxLayout()
        d1.addWidget(QLabel("Start Address (hex):"))
        self.start_addr = QLineEdit("0x1fffb000")
        d1.addWidget(self.start_addr)
        dump_layout.addLayout(d1)

        d2 = QHBoxLayout()
        d2.addWidget(QLabel("Length (hex):"))
        self.dump_len = QLineEdit("0x4800")
        d2.addWidget(self.dump_len)
        dump_layout.addLayout(d2)

        d3 = QHBoxLayout()
        d3.addWidget(QLabel("Output File:"))
        self.dump_file = QLineEdit("bootloader.hex")
        d3.addWidget(self.dump_file)
        browse = GlowButton("Browse", COLORS['accent_cyan'])
        browse.setFixedWidth(70)
        browse.clicked.connect(self._browse)
        d3.addWidget(browse)
        dump_layout.addLayout(d3)
        self._controls_layout.addWidget(self._dump_group)

        self._on_subcmd_change("discovery")

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Dump", "", "Hex Files (*.hex);;All Files (*)")
        if path:
            self.dump_file.setText(path)

    def _on_subcmd_change(self, cmd):
        self._disc_group.setVisible(cmd == "discovery")
        self._dump_group.setVisible(cmd == "dump")

    def build_args(self):
        iface = self.get_interface()
        cmd  = self.subcmd.currentText()
        req  = self.req_id.text().strip()
        resp = self.resp_id.text().strip()
        args = ["-i", iface, "xcp", cmd]

        if cmd == "discovery":
            if self.use_blacklist.isChecked() and self.blacklist_ids.text().strip():
                args += ["-blacklist"] + self.blacklist_ids.text().strip().split()
            if self.use_autoblacklist.isChecked():
                args += ["-autoblacklist", str(self.autoblacklist_n.value())]

        elif cmd in ("commands", "info"):
            args += [req, resp]

        elif cmd == "dump":
            args += [req, resp,
                     self.start_addr.text().strip(),
                     self.dump_len.text().strip(),
                     "-f", self.dump_file.text().strip()]

        return args
