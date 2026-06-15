"""
UDS Fuzz Module Tab
"""

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QHBoxLayout, QVBoxLayout, QGroupBox, QFileDialog, QFrame
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread

import re
import math
import time
import threading
from collections import Counter
from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton, SolidButton
from ui.theme import COLORS


class UDSFuzzTab(BaseModuleTab):
    MODULE_NAME = "uds_fuzz"

    def __init__(self, runner, data_manager, parent=None):
        self._seeds_seen      = []     # seed strings collected during live run
        self._last_entropy_report = 0  # cooldown tracker (epoch seconds)
        self._entropy_reported_level = None  # track already-reported level
        self._seed_pattern = re.compile(
            r'seed[:\s=]+([0-9a-fA-F x]+)',
            re.IGNORECASE
        )
        super().__init__(runner, data_manager, parent)

    def _on_started(self, cmd):
        self._seeds_seen.clear()       # reset seed list on every new run
        self._last_entropy_report = 0  # cooldown tracker
        self._entropy_reported_level = None  # track what we already reported
        super()._on_started(cmd)

    def _extra_parse(self, line: str):
        """Extract seeds from output lines and analyze them for weaknesses."""
        match = self._seed_pattern.search(line)
        if not match:
            # Also try bare hex patterns like "0xABCD1234" on their own
            match = re.search(r'\b(0x[0-9a-fA-F]{2,16})\b', line)
            if not match:
                return

        seed_val = match.group(1).strip()
        
        # Ignore CAN IDs that get caught by the bare hex fallback
        if seed_val.upper() in ("0X7E0", "0X7E8", "0X7DF"):
            return

        self._seeds_seen.append(seed_val)
        count = len(self._seeds_seen)

        # ── Check 1: Identical seeds (most critical) ─────────────────────
        occurrences = self._seeds_seen.count(seed_val)
        if occurrences >= 2:
            self._add_fault(
                'critical',
                line,
                f"REPEATED SEED: '{seed_val}' seen {occurrences}x — seed is NOT random!"
            )
            return

        # ── Check 2: Analyze entropy once we have enough samples ─────────
        if count >= 5:
            self._analyze_seed_entropy()

    def _analyze_seed_entropy(self):
        """Compute basic entropy and repetition stats over collected seeds.
        Uses a 30-second cooldown to prevent repeated spam alerts.
        """
        # Cooldown: only re-analyze every 30 seconds
        now = time.monotonic()
        if now - self._last_entropy_report < 30.0:
            return
        self._last_entropy_report = now

        seeds = self._seeds_seen

        # Duplicate ratio
        unique = len(set(seeds))
        total  = len(seeds)
        dup_ratio = 1.0 - (unique / total)

        if dup_ratio > 0.3 and self._entropy_reported_level != 'dup_critical':
            self._entropy_reported_level = 'dup_critical'
            self._add_fault(
                'critical',
                f"Seed duplicate ratio: {dup_ratio:.0%} ({total - unique}/{total} duplicates)",
                f"HIGH DUPLICATE RATE: {dup_ratio:.0%} of seeds are repeated"
            )

        # Shannon entropy on seed values
        try:
            int_seeds = []
            for s in seeds:
                s_clean = s.strip().replace(' ', '')
                int_seeds.append(int(s_clean, 16) if s_clean.startswith('0x') else int(s_clean))

            all_bytes = []
            for v in int_seeds:
                all_bytes += [(v >> (i*8)) & 0xFF for i in range(4)]

            counts = Counter(all_bytes)
            total_bytes = len(all_bytes)
            entropy = -sum((c/total_bytes) * math.log2(c/total_bytes)
                           for c in counts.values() if c > 0)

            if entropy < 3.0:
                level = 'entropy_critical'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault(
                        'critical',
                        f"Seed entropy: {entropy:.2f} bits (max=8.0) — extremely predictable",
                        f"CRITICAL: Very low seed entropy ({entropy:.2f}/8.0 bits)"
                    )
            elif entropy < 5.0:
                level = 'entropy_high'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault(
                        'high',
                        f"Seed entropy: {entropy:.2f} bits (max=8.0) — below acceptable threshold",
                        f"LOW SEED ENTROPY: {entropy:.2f}/8.0 bits — seed may be predictable"
                    )
            elif entropy < 6.5:
                level = 'entropy_medium'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault(
                        'medium',
                        f"Seed entropy: {entropy:.2f} bits (max=8.0) — moderate, review RNG",
                        f"MEDIUM SEED ENTROPY: {entropy:.2f}/8.0 bits"
                    )

        except (ValueError, ZeroDivisionError):
            pass  # Can't parse seeds as numbers, skip entropy check

        # Sequential / incrementing pattern check
        try:
            int_seeds_sorted_by_order = []
            for s in seeds[-10:]:  # last 10
                s_clean = s.strip().replace(' ', '')
                int_seeds_sorted_by_order.append(
                    int(s_clean, 16) if s_clean.startswith('0x') else int(s_clean)
                )
            diffs = [abs(int_seeds_sorted_by_order[i+1] - int_seeds_sorted_by_order[i])
                     for i in range(len(int_seeds_sorted_by_order)-1)]
            if len(set(diffs)) == 1 and diffs[0] != 0 and self._entropy_reported_level != 'counter':
                self._entropy_reported_level = 'counter'
                self._add_fault(
                    'critical',
                    f"Seeds increment by constant value {hex(diffs[0])} — counter-based RNG!",
                    f"COUNTER-BASED SEED: constant delta={hex(diffs[0])}"
                )
        except (ValueError, IndexError):
            pass

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("UDS Fuzz Module"))

        # Sub-command
        cmd_group = QGroupBox("Fuzz Mode")
        cmd_layout = QVBoxLayout(cmd_group)
        self.subcmd = QComboBox()
        self.subcmd.addItems(["seed_randomness_fuzzer", "delay_fuzzer"])
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_group)

        # Common params
        common_group = QGroupBox("Target")
        common_layout = QVBoxLayout(common_group)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Request ID:"))
        self.req_id = QLineEdit("0x7E0")
        r1.addWidget(self.req_id)
        common_layout.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Response ID:"))
        self.resp_id = QLineEdit("0x7E8")
        r2.addWidget(self.resp_id)
        common_layout.addLayout(r2)

        self._controls_layout.addWidget(common_group)

        # Seed randomness options
        self._seed_group = QGroupBox("Seed Randomness Fuzzer Options")
        seed_layout = QVBoxLayout(self._seed_group)

        # Seed value 100311022701 is passed directly to the binary


        s2 = QHBoxLayout()
        s2.addWidget(QLabel("Delay (s):"))
        self.seed_delay = QDoubleSpinBox()
        self.seed_delay.setValue(0.05)      # Optimised: minimal delay for high-speed fuzzing
        self.seed_delay.setMinimum(0.0)
        self.seed_delay.setMaximum(60.0)
        self.seed_delay.setSingleStep(0.05)
        self.seed_delay.setDecimals(3)
        s2.addWidget(self.seed_delay)
        seed_layout.addLayout(s2)

        s3 = QHBoxLayout()
        s3.addWidget(QLabel("Retries (-r):"))
        self.seed_retries = QSpinBox()
        self.seed_retries.setValue(1)
        s3.addWidget(self.seed_retries)
        seed_layout.addLayout(s3)

        s4 = QHBoxLayout()
        s4.addWidget(QLabel("ID (-id):"))
        self.seed_id = QSpinBox()
        self.seed_id.setValue(2)
        s4.addWidget(self.seed_id)
        seed_layout.addLayout(s4)

        s5 = QHBoxLayout()
        s5.addWidget(QLabel("Mode (-m):"))
        self.seed_mode_combo = QComboBox()
        self.seed_mode_combo.addItems(["0 - Standard", "1 - Extended"])
        s5.addWidget(self.seed_mode_combo)
        seed_layout.addLayout(s5)
        self._controls_layout.addWidget(self._seed_group)

        # Delay fuzzer options
        self._delay_group = QGroupBox("Delay Fuzzer Options")
        delay_layout = QVBoxLayout(self._delay_group)

        # Seed value 100311022701 is passed directly to the binary


        d2 = QHBoxLayout()
        d2.addWidget(QLabel("Sub-func (hex):"))
        self.delay_subfunc = QLineEdit("0x03")
        d2.addWidget(self.delay_subfunc)
        delay_layout.addLayout(d2)
        self._controls_layout.addWidget(self._delay_group)

        self._on_subcmd_change("seed_randomness_fuzzer")

    def _on_subcmd_change(self, cmd):
        self._seed_group.setVisible(cmd == "seed_randomness_fuzzer")
        self._delay_group.setVisible(cmd == "delay_fuzzer")

    def build_args(self):
        iface = self.get_interface()
        cmd = self.subcmd.currentText()
        req = self.req_id.text().strip()
        resp = self.resp_id.text().strip()

        if cmd == "seed_randomness_fuzzer":
            mode = self.seed_mode_combo.currentIndex()
            return [
                "-i", iface,
                "uds_fuzz", "seed_randomness_fuzzer",
                "100311022701", req, resp,  # seed value fixed per protocol
                "-d", str(self.seed_delay.value()),
                "-r", str(self.seed_retries.value()),
                "-id", str(self.seed_id.value()),
                "-m", str(mode),
            ]
        else:
            return [
                "-i", iface,
                "uds_fuzz", "delay_fuzzer",
                "100311022701",  # seed value fixed per protocol
                self.delay_subfunc.text().strip(),
                req, resp,
            ]
