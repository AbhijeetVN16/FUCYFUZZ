"""
DCM (Diagnostic Communication Manager) Module Tab
"""

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox
)

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader
from ui.theme import COLORS


class DCMTab(BaseModuleTab):
    MODULE_NAME = "dcm"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("DCM Module"))

        cmd_group = QGroupBox("Command")
        cmd_layout = QVBoxLayout(cmd_group)
        self.subcmd = QComboBox()
        self.subcmd.addItems(["discovery", "services", "subfunc", "dtc", "testerpresent"])
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_group)

        # IDs
        ids_group = QGroupBox("CAN IDs")
        ids_layout = QVBoxLayout(ids_group)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Request ID:"))
        self.req_id = QLineEdit("0x7E0")
        r1.addWidget(self.req_id)
        ids_layout.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Response ID:"))
        self.resp_id = QLineEdit("0x7E8")
        r2.addWidget(self.resp_id)
        ids_layout.addLayout(r2)
        self._controls_layout.addWidget(ids_group)

        # Discovery
        self._disc_group = QGroupBox("Discovery Options")
        disc_layout = QVBoxLayout(self._disc_group)

        self.use_blacklist = QCheckBox("Blacklist IDs")
        disc_layout.addWidget(self.use_blacklist)
        self.blacklist_ids = QLineEdit()
        self.blacklist_ids.setPlaceholderText("0x123 0x456 ...")
        disc_layout.addWidget(self.blacklist_ids)

        self.use_autoblacklist = QCheckBox("Auto Blacklist")
        disc_layout.addWidget(self.use_autoblacklist)
        ab_row = QHBoxLayout()
        ab_row.addWidget(QLabel("Threshold:"))
        self.autoblacklist_n = QSpinBox()
        self.autoblacklist_n.setValue(10)
        self.autoblacklist_n.setRange(1, 1000)
        ab_row.addWidget(self.autoblacklist_n)
        disc_layout.addLayout(ab_row)
        self._controls_layout.addWidget(self._disc_group)

        # SubFunc options
        self._subfunc_group = QGroupBox("SubFunction Options")
        sf_layout = QVBoxLayout(self._subfunc_group)

        sf1 = QHBoxLayout()
        sf1.addWidget(QLabel("Service (hex):"))
        self.service_id = QLineEdit("0x22")
        sf1.addWidget(self.service_id)
        sf_layout.addLayout(sf1)

        sf2 = QHBoxLayout()
        sf2.addWidget(QLabel("Sub-func index start:"))
        self.subfunc_start = QSpinBox()
        self.subfunc_start.setValue(2)
        self.subfunc_start.setRange(0, 255)
        sf2.addWidget(self.subfunc_start)
        sf_layout.addLayout(sf2)

        sf3 = QHBoxLayout()
        sf3.addWidget(QLabel("Sub-func index end:"))
        self.subfunc_end = QSpinBox()
        self.subfunc_end.setValue(3)
        self.subfunc_end.setRange(0, 255)
        sf3.addWidget(self.subfunc_end)
        sf_layout.addLayout(sf3)
        self._controls_layout.addWidget(self._subfunc_group)

        self._on_subcmd_change("discovery")

    def _on_subcmd_change(self, cmd):
        self._disc_group.setVisible(cmd == "discovery")
        self._subfunc_group.setVisible(cmd == "subfunc")

    def build_args(self):
        iface = self.get_interface()
        cmd = self.subcmd.currentText()
        req  = self.req_id.text().strip()
        resp = self.resp_id.text().strip()
        args = ["-i", iface, "dcm", cmd]

        if cmd == "discovery":
            if self.use_blacklist.isChecked() and self.blacklist_ids.text().strip():
                args += ["-blacklist"] + self.blacklist_ids.text().strip().split()
            if self.use_autoblacklist.isChecked():
                args += ["-autoblacklist", str(self.autoblacklist_n.value())]

        elif cmd == "services":
            args += [req, resp]

        elif cmd == "subfunc":
            args += [req, resp,
                     self.service_id.text().strip(),
                     str(self.subfunc_start.value()),
                     str(self.subfunc_end.value())]

        elif cmd == "dtc":
            args += [req, resp]

        elif cmd == "testerpresent":
            args += [req]

        return args

    def update_msg_list(self, msg_names: list):
        """Called when a DBC is loaded — no visual change needed for DCM."""
        pass
