"""
FucyFuzz Export Dialog
Provides: Overall Report, Failure Report, ECU Session Report.
Save Log and Export Log have been removed (now inside LOGS tab).
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from ui.theme import COLORS, FONT_UI
from utils.report_generators import REPORTLAB_AVAILABLE


class ExportDialog(QDialog):
    """
    Modal export menu.
    Emits export_requested(action) where action is one of:
      'overall', 'failure', 'ecu_session'
    """

    export_requested = pyqtSignal(str)

    _DIALOG_SS = f"""
        QDialog {{
            background-color: {COLORS['bg_secondary']};
            border: 1px solid {COLORS['border_bright']};
            border-radius: 10px;
        }}
    """

    def __init__(self, parent=None):
        # Accept either (data_manager, parent) or (parent,) for backward compat
        super().__init__(parent)
        self.setWindowTitle("Export Report")
        self.setFixedSize(320, 260)
        self.setModal(True)
        self.setStyleSheet(self._DIALOG_SS)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setFixedHeight(50)
        hdr.setStyleSheet(f"""
            background: {COLORS['bg_elevated']};
            border-bottom: 1px solid {COLORS['border_bright']};
            border-radius: 10px 10px 0 0;
        """)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(18, 0, 18, 0)
        title = QLabel("Export / Save Report")
        title.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 14px; font-weight: 700;
            font-family: {FONT_UI}; background: transparent;
        """)
        hl.addWidget(title)
        layout.addWidget(hdr)

        # Menu items — Save Log and Export Log removed; both are in LOGS tab
        items = [
            ("overall",     "📋  Overall Report",              COLORS['accent_cyan']),
            ("failure",     "🔴  Failure Report (PDF)",        COLORS['critical']),
            ("ecu_session", "🛡  ECU Monitor Session Report",  COLORS['accent_orange']),
        ]

        for action, label, accent in items:
            btn = QPushButton(label)
            btn.setFixedHeight(44)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    border-bottom: 1px solid {COLORS['border']};
                    color: {COLORS['text_primary']};
                    font-size: 12px; font-family: {FONT_UI};
                    text-align: left; padding: 0 18px;
                }}
                QPushButton:hover {{
                    background: {accent}18;
                    color: {accent};
                    border-left: 3px solid {accent};
                    padding-left: 15px;
                }}
                QPushButton:pressed {{ background: {accent}30; }}
            """)
            if action == 'overall' and not REPORTLAB_AVAILABLE:
                btn.setEnabled(False)
                btn.setToolTip("Install reportlab: pip install reportlab")
                btn.setText(btn.text() + "  ⚠ reportlab missing")
            btn.clicked.connect(lambda _checked, a=action: self._pick(a))
            layout.addWidget(btn)

        layout.addStretch()

        # Cancel
        cancel = QPushButton("✕  Cancel")
        cancel.setFixedHeight(40)
        cancel.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_elevated']};
                border: none; border-radius: 0 0 10px 10px;
                color: {COLORS['text_secondary']};
                font-size: 12px; font-family: {FONT_UI};
            }}
            QPushButton:hover {{
                background: {COLORS['critical']}22;
                color: {COLORS['critical']};
            }}
        """)
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _pick(self, action: str):
        self.export_requested.emit(action)
        self.accept()


# ── OverallReportDialog (format picker: PDF / ASC / MF4) ─────────────────────

class OverallReportDialog(QDialog):
    """Format picker for the Overall Report."""

    format_selected = pyqtSignal(str)   # 'pdf', 'asc', 'mf4'

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Overall Report Format")
        self.setFixedSize(300, 240)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_bright']};
                border-radius: 10px;
            }}
        """)
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)

        title = QLabel("Choose Report Format")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"""
            color: {COLORS['text_primary']}; font-size: 14px;
            font-weight: 700; padding-bottom: 8px;
        """)
        layout.addWidget(title)

        for fmt, label, color in [
            ("pdf", "📄  PDF Report",        COLORS['accent_cyan']),
            ("asc", "📤  Vector ASC (.asc)", COLORS['accent_yellow']),
            ("mf4", "📊  ASAM MF4 (.mf4)",  COLORS['accent_purple']),
            ("blf", "📥  Vector BLF (.blf)", COLORS['accent_green']),
            ("pcap","🕸  PCAP Capture (.pcap)", COLORS['accent_pink']),
            ("json","📋  JSON Logs (.jsonl)", COLORS['accent_cyan']),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(40)
            enabled = (fmt != 'pdf') or REPORTLAB_AVAILABLE
            btn.setEnabled(enabled)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {color}22; border: 1px solid {color}66;
                    color: {color}; border-radius: 6px;
                    font-size: 12px; font-weight: 600; padding: 0 14px;
                    text-align: left;
                }}
                QPushButton:hover {{ background: {color}40; border-color: {color}; }}
                QPushButton:disabled {{ background: {COLORS['bg_elevated']}; color: {COLORS['text_muted']}; border-color: {COLORS['border']}; }}
            """)
            btn.clicked.connect(lambda _c, f=fmt: (self.format_selected.emit(f), self.accept()))
            layout.addWidget(btn)

        cancel = QPushButton("Cancel")
        cancel.setFixedHeight(34)
        cancel.setStyleSheet(f"""
            QPushButton {{
                background: transparent; border: 1px solid {COLORS['border']};
                color: {COLORS['text_muted']}; border-radius: 6px; font-size: 11px;
            }}
            QPushButton:hover {{ border-color: {COLORS['border_bright']}; color: {COLORS['text_primary']}; }}
        """)
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)


# ── ECUSessionPickerDialog ────────────────────────────────────────────────────

class ECUSessionPickerDialog(QDialog):
    """Pick live or archived ECU session to export."""

    session_selected = pyqtSignal(dict)

    def __init__(self, live_data: dict, past_sessions: list, parent=None):
        super().__init__(parent)
        self._live = live_data
        self._past = past_sessions
        self.setWindowTitle("Select ECU Session")
        self.setFixedSize(400, 320)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_bright']};
                border-radius: 10px;
            }}
        """)
        self._build()

    def _build(self):
        from PyQt5.QtWidgets import QRadioButton, QScrollArea, QButtonGroup
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        title = QLabel("Select ECU Monitor Session to Export")
        title.setStyleSheet(f"color:{COLORS['text_primary']};font-size:13px;font-weight:700;")
        layout.addWidget(title)

        self._group = QButtonGroup(self)
        self._sessions = []

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea{{border:none;background:transparent;}}")
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(4)

        # Live session
        if self._live.get('events'):
            rb = QRadioButton(f"Live session  ({len(self._live.get('events',[]))} events)")
            rb.setChecked(True)
            rb.setStyleSheet(f"color:{COLORS['accent_cyan']};font-size:12px;")
            self._group.addButton(rb, 0)
            inner_layout.addWidget(rb)
            self._sessions.append(self._live)

        # Past sessions
        for i, sess in enumerate(self._past[:15]):
            start = sess.get('session_start', f'Session {i+1}')
            n_ev  = len(sess.get('events', []))
            rb = QRadioButton(f"{start}  ({n_ev} events)")
            rb.setStyleSheet(f"color:{COLORS['text_primary']};font-size:12px;")
            self._group.addButton(rb, len(self._sessions))
            inner_layout.addWidget(rb)
            self._sessions.append(sess)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll)

        btn_row = QHBoxLayout()
        export_btn = QPushButton("Export Selected")
        export_btn.setFixedHeight(36)
        export_btn.setStyleSheet(f"""
            QPushButton {{
                background:{COLORS['accent_cyan']};color:{COLORS['bg_primary']};
                border:none;border-radius:6px;font-size:12px;font-weight:700;
            }}
            QPushButton:hover{{background:{COLORS['accent_blue']};}}
        """)
        export_btn.clicked.connect(self._export)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedHeight(36)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background:transparent;border:1px solid {COLORS['border']};
                color:{COLORS['text_muted']};border-radius:6px;font-size:12px;
            }}
        """)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(export_btn)
        layout.addLayout(btn_row)

    def _export(self):
        idx = self._group.checkedId()
        if 0 <= idx < len(self._sessions):
            self.session_selected.emit(self._sessions[idx])
        self.accept()
