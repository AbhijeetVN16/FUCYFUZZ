"""
UDS (Unified Diagnostic Services) Module Tab
"""

import re

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox, QWidget,
    QFrame
)
from PyQt5.QtCore import Qt

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton, CardFrame, SolidButton
from ui.theme import COLORS


def _is_valid_hex_id(val: str) -> bool:
    """Return True if val looks like 0x<hex digits>."""
    return bool(re.fullmatch(r'0[xX][0-9a-fA-F]+', val.strip()))


def _is_valid_hex_or_empty(val: str) -> bool:
    """Return True if val is empty OR a valid hex ID."""
    v = val.strip()
    return v == '' or _is_valid_hex_id(v)


class _ValidationError(Exception):
    pass


class UDSTab(BaseModuleTab):
    MODULE_NAME = "uds"

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("UDS Module"))

        # Sub-command selector
        cmd_group = QGroupBox("Command")
        cmd_layout = QVBoxLayout(cmd_group)

        self.subcmd = QComboBox()
        self.subcmd.addItems([
            "discovery",
            "services",
            "ecu_reset",
            "testerpresent",
            "security_seed",
            "dump_dids",
            "read_did",
            "read_mem",
        ])
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_group)

        # IDs
        ids_group = QGroupBox("CAN IDs")
        ids_layout = QVBoxLayout(ids_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Request ID:"))
        self.req_id = QLineEdit("0x7E0")
        self.req_id.setPlaceholderText("e.g. 0x7E0")
        row1.addWidget(self.req_id)
        ids_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Response ID:"))
        self.resp_id = QLineEdit("0x7E8")
        self.resp_id.setPlaceholderText("e.g. 0x7E8")
        row2.addWidget(self.resp_id)
        ids_layout.addLayout(row2)

        self._controls_layout.addWidget(ids_group)

        # Discovery options
        self._disc_group = QGroupBox("Discovery Options")
        disc_layout = QVBoxLayout(self._disc_group)

        self.use_blacklist = QCheckBox("Blacklist IDs")
        disc_layout.addWidget(self.use_blacklist)
        self.blacklist_ids = QLineEdit()
        self.blacklist_ids.setPlaceholderText("0x123 0x456 ...")
        disc_layout.addWidget(self.blacklist_ids)

        self.use_autoblacklist = QCheckBox("Auto Blacklist")
        disc_layout.addWidget(self.use_autoblacklist)
        auto_row = QHBoxLayout()
        auto_row.addWidget(QLabel("Threshold:"))
        self.autoblacklist_n = QSpinBox()
        self.autoblacklist_n.setValue(10)
        self.autoblacklist_n.setRange(1, 1000)
        auto_row.addWidget(self.autoblacklist_n)
        disc_layout.addLayout(auto_row)
        self._controls_layout.addWidget(self._disc_group)

        # ECU Reset options
        self._reset_group = QGroupBox("ECU Reset Options")
        reset_layout = QVBoxLayout(self._reset_group)
        rl = QHBoxLayout()
        rl.addWidget(QLabel("Reset Type:"))
        self.reset_type = QSpinBox()
        self.reset_type.setValue(1)
        self.reset_type.setRange(1, 255)
        rl.addWidget(self.reset_type)
        reset_layout.addLayout(rl)
        self._controls_layout.addWidget(self._reset_group)

        # Security Seed options
        self._seed_group = QGroupBox("Security Seed Options")
        seed_layout = QVBoxLayout(self._seed_group)

        sl1 = QHBoxLayout()
        sl1.addWidget(QLabel("Level:"))
        self.seed_level = QLineEdit("0x3")
        sl1.addWidget(self.seed_level)
        seed_layout.addLayout(sl1)

        sl2 = QHBoxLayout()
        sl2.addWidget(QLabel("Mode:"))
        self.seed_mode = QLineEdit("0x1")
        sl2.addWidget(self.seed_mode)
        seed_layout.addLayout(sl2)

        sl3 = QHBoxLayout()
        sl3.addWidget(QLabel("Retries:"))
        self.seed_retries = QSpinBox()
        self.seed_retries.setValue(1)
        sl3.addWidget(self.seed_retries)
        seed_layout.addLayout(sl3)

        sl4 = QHBoxLayout()
        sl4.addWidget(QLabel("Delay (s):"))
        self.seed_delay = QDoubleSpinBox()
        self.seed_delay.setDecimals(3)
        self.seed_delay.setRange(0.001, 60.0)
        self.seed_delay.setValue(0.5)
        self.seed_delay.setSingleStep(0.1)
        sl4.addWidget(self.seed_delay)
        seed_layout.addLayout(sl4)
        self._controls_layout.addWidget(self._seed_group)

        # DID options — dump_dids uses min/max range; read_did uses single DID
        self._did_group = QGroupBox("DID Options")
        did_layout = QVBoxLayout(self._did_group)

        # Single DID — only shown for read_did
        self._single_did_row = QHBoxLayout()
        self._single_did_row.addWidget(QLabel("DID:"))
        self.read_did_val = QLineEdit("0xF190")
        self._single_did_row.addWidget(self.read_did_val)
        did_layout.addLayout(self._single_did_row)

        # Min/Max DID — only shown for dump_dids
        self._min_did_row = QHBoxLayout()
        self._min_did_row.addWidget(QLabel("Min DID:"))
        self.min_did = QLineEdit()
        self.min_did.setPlaceholderText("optional, e.g. 0x6300")
        self._min_did_row.addWidget(self.min_did)
        did_layout.addLayout(self._min_did_row)

        self._max_did_row = QHBoxLayout()
        self._max_did_row.addWidget(QLabel("Max DID:"))
        self.max_did = QLineEdit()
        self.max_did.setPlaceholderText("optional, e.g. 0x6FFF")
        self._max_did_row.addWidget(self.max_did)
        did_layout.addLayout(self._max_did_row)

        dl4 = QHBoxLayout()
        dl4.addWidget(QLabel("Timeout (s):"))
        self.did_timeout = QDoubleSpinBox()
        self.did_timeout.setValue(0.1)
        self.did_timeout.setSingleStep(0.05)
        self.did_timeout.setDecimals(2)
        dl4.addWidget(self.did_timeout)
        did_layout.addLayout(dl4)

        # Inline validation label
        self._did_err_label = QLabel("")
        self._did_err_label.setStyleSheet(
            f"color: {COLORS['critical']}; font-size: 10px; background: transparent;"
        )
        self._did_err_label.setWordWrap(True)
        did_layout.addWidget(self._did_err_label)

        # Connect live validation
        self.req_id.textChanged.connect(self._refresh_preview)
        self.resp_id.textChanged.connect(self._refresh_preview)
        self.min_did.textChanged.connect(self._refresh_preview)
        self.max_did.textChanged.connect(self._refresh_preview)
        self.did_timeout.valueChanged.connect(self._refresh_preview)
        self.subcmd.currentTextChanged.connect(self._refresh_preview)

        self._controls_layout.addWidget(self._did_group)

        # Read Memory options
        self._mem_group = QGroupBox("Read Memory Options")
        mem_layout = QVBoxLayout(self._mem_group)

        ml1 = QHBoxLayout()
        ml1.addWidget(QLabel("Start Address:"))
        self.start_addr = QLineEdit("0x0200")
        ml1.addWidget(self.start_addr)
        mem_layout.addLayout(ml1)

        ml2 = QHBoxLayout()
        ml2.addWidget(QLabel("Memory Length:"))
        self.mem_length = QLineEdit("0x10000")
        ml2.addWidget(self.mem_length)
        mem_layout.addLayout(ml2)
        self._controls_layout.addWidget(self._mem_group)

        self._on_subcmd_change("discovery")

    def _on_subcmd_change(self, cmd):
        groups = {
            self._disc_group:  cmd == "discovery",
            self._reset_group: cmd == "ecu_reset",
            self._seed_group:  cmd == "security_seed",
            self._did_group:   cmd in ("dump_dids", "read_did"),
            self._mem_group:   cmd == "read_mem",
        }
        for grp, visible in groups.items():
            grp.setVisible(visible)

        if cmd == "dump_dids":
            # Show min/max, hide single DID
            self._set_row_visible(self._single_did_row, False)
            self._set_row_visible(self._min_did_row, True)
            self._set_row_visible(self._max_did_row, True)
        elif cmd == "read_did":
            # Show single DID, hide min/max
            self._set_row_visible(self._single_did_row, True)
            self._set_row_visible(self._min_did_row, False)
            self._set_row_visible(self._max_did_row, False)

        self._refresh_preview()

    def _set_row_visible(self, layout: QHBoxLayout, visible: bool):
        """Show/hide all widgets in an QHBoxLayout row."""
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item and item.widget():
                item.widget().setVisible(visible)

    def _refresh_preview(self):
        """Update command preview and inline validation."""
        try:
            args = self._build_dump_dids_args_safe()
            if args is not None:
                cmd = "fucyfuzz " + " ".join(str(a) for a in args)
                self._cmd_preview.setText(cmd[:120] + ("..." if len(cmd) > 120 else ""))
                self._did_err_label.setText("")
        except _ValidationError as e:
            self._did_err_label.setText(str(e))
        except Exception:
            pass

    def _build_dump_dids_args_safe(self):
        """
        Returns arg list for dump_dids, or None for other commands.
        Raises _ValidationError with a human-readable message on invalid input.
        """
        cmd = self.subcmd.currentText()
        if cmd != "dump_dids":
            return None

        iface = self.get_interface()
        req = self.req_id.text().strip()
        resp = self.resp_id.text().strip()

        # Validate IDs
        if not _is_valid_hex_id(req):
            raise _ValidationError(f"Request ID '{req}' must start with 0x and be valid hex (e.g. 0x733)")
        if not _is_valid_hex_id(resp):
            raise _ValidationError(f"Response ID '{resp}' must start with 0x and be valid hex (e.g. 0x633)")

        min_val = self.min_did.text().strip()
        max_val = self.max_did.text().strip()

        # min/max must BOTH be provided or BOTH empty
        if bool(min_val) != bool(max_val):
            raise _ValidationError("Min DID and Max DID must both be provided or both left empty.")

        if min_val:
            if not _is_valid_hex_id(min_val):
                raise _ValidationError(f"Min DID '{min_val}' must be valid hex (e.g. 0x6300)")
            if not _is_valid_hex_id(max_val):
                raise _ValidationError(f"Max DID '{max_val}' must be valid hex (e.g. 0x6FFF)")

            min_int = int(min_val, 16)
            max_int = int(max_val, 16)
            if max_int < min_int:
                raise _ValidationError(
                    f"Max DID (0x{max_int:04X}) must be >= Min DID (0x{min_int:04X})"
                )

            timeout = round(self.did_timeout.value(), 4)
            return ["-i", iface, "uds", "dump_dids", req, resp,
                    "--min_did", min_val, "--max_did", max_val,
                    "-t", str(timeout)]
        else:
            # Basic form — no range args
            return ["-i", iface, "uds", "dump_dids", req, resp]

    def build_args(self):
        try:
            return self._build_args_impl()
        except _ValidationError as e:
            self.terminal.append_error(f"Validation error: {e}")
            return None
        except Exception as e:
            self.terminal.append_error(f"Error building command: {e}")
            return None

    def _build_args_impl(self):
        iface = self.get_interface()
        cmd = self.subcmd.currentText()
        req = self.req_id.text().strip()
        resp = self.resp_id.text().strip()

        args = ["-i", iface, "uds", cmd]

        if cmd == "discovery":
            if self.use_blacklist.isChecked() and self.blacklist_ids.text().strip():
                args += ["-blacklist"] + self.blacklist_ids.text().strip().split()
            if self.use_autoblacklist.isChecked():
                args += ["-autoblacklist", str(self.autoblacklist_n.value())]

        elif cmd == "services":
            if not _is_valid_hex_id(req):
                raise _ValidationError(f"Request ID '{req}' must be valid hex (e.g. 0x7E0)")
            if not _is_valid_hex_id(resp):
                raise _ValidationError(f"Response ID '{resp}' must be valid hex (e.g. 0x7E8)")
            args += [req, resp]

        elif cmd == "ecu_reset":
            args += [str(self.reset_type.value()), req, resp]

        elif cmd == "testerpresent":
            args += [req]

        elif cmd == "security_seed":
            args += [
                self.seed_level.text().strip(),
                self.seed_mode.text().strip(),
                req, resp,
                "-r", str(self.seed_retries.value()),
                "-d", str(self.seed_delay.value()),
            ]

        elif cmd == "dump_dids":
            # Use the validated builder — raises _ValidationError if invalid
            built = self._build_dump_dids_args_safe()
            if built is None:
                return None
            return built

        elif cmd == "read_did":
            if not _is_valid_hex_id(req):
                raise _ValidationError(f"Request ID '{req}' must be valid hex")
            if not _is_valid_hex_id(resp):
                raise _ValidationError(f"Response ID '{resp}' must be valid hex")
            did = self.read_did_val.text().strip()
            if not _is_valid_hex_id(did):
                raise _ValidationError(f"DID '{did}' must be valid hex (e.g. 0xF190)")
            args += [req, resp, did]

        elif cmd == "read_mem":
            args += [req, resp,
                     "--start_addr", self.start_addr.text().strip(),
                     "--mem_length", self.mem_length.text().strip()]

        return args

    def update_msg_list(self, msg_names: list):
        """Called when a DBC is loaded — no visual change needed for UDS."""
        pass
