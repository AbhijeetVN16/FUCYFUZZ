"""
Dump and Listener Module Tabs
"""

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QDoubleSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox, QFileDialog
)

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton
from ui.theme import COLORS


class DumpTab(BaseModuleTab):
    MODULE_NAME = "dump"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("Dump Module"))

        opts_group = QGroupBox("Dump Options")
        opts_layout = QVBoxLayout(opts_group)

        o1 = QHBoxLayout()
        o1.addWidget(QLabel("Sample Rate (s):"))
        self.sample_rate = QDoubleSpinBox()
        self.sample_rate.setValue(1.0)
        self.sample_rate.setSingleStep(0.1)
        o1.addWidget(self.sample_rate)
        opts_layout.addLayout(o1)

        o2 = QHBoxLayout()
        o2.addWidget(QLabel("Output File:"))
        self.out_file = QLineEdit()
        self.out_file.setPlaceholderText("output.txt (optional)")
        o2.addWidget(self.out_file)
        browse = GlowButton("Browse", COLORS['accent_cyan'])
        browse.setFixedWidth(70)
        browse.clicked.connect(self._browse)
        o2.addWidget(browse)
        opts_layout.addLayout(o2)

        self.count_only = QCheckBox("Count only (-c)")
        opts_layout.addWidget(self.count_only)
        self._controls_layout.addWidget(opts_group)

        filter_group = QGroupBox("Filter by IDs (optional)")
        filter_layout = QVBoxLayout(filter_group)
        self.filter_ids = QLineEdit()
        self.filter_ids.setPlaceholderText("0x7E0 0x7E8 ...")
        filter_layout.addWidget(self.filter_ids)
        self._controls_layout.addWidget(filter_group)

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Dump", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.out_file.setText(path)

    def build_args(self):
        iface = self.get_interface()
        args = ["-i", iface, "dump", "-s", str(self.sample_rate.value())]
        if self.out_file.text().strip():
            args += ["-f", self.out_file.text().strip()]
        if self.count_only.isChecked():
            args.append("-c")
        ids = self.filter_ids.text().strip()
        if ids:
            args += ids.split()
        return args


class ListenerTab(BaseModuleTab):
    MODULE_NAME = "listener"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("Listener Module"))

        opts_group = QGroupBox("Listener Options")
        opts_layout = QVBoxLayout(opts_group)

        self.raw_mode = QCheckBox("Raw mode (-r)")
        opts_layout.addWidget(self.raw_mode)

        lbl = QLabel("Listens passively on the configured CAN interface.\n"
                      "All frames are displayed in the terminal.")
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 10px; background: transparent;")
        lbl.setWordWrap(True)
        opts_layout.addWidget(lbl)
        self._controls_layout.addWidget(opts_group)

    def build_args(self):
        iface = self.get_interface()
        args = ["-i", iface, "listener"]
        if self.raw_mode.isChecked():
            args.append("-r")
        return args
