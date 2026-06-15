"""
Reusable UI Components for FucyFuzz GUI
"""

import re as _re
from datetime import datetime as _datetime

from PyQt5.QtWidgets import (
    QPushButton, QLabel, QFrame, QHBoxLayout, QVBoxLayout,
    QWidget, QGraphicsDropShadowEffect, QSizePolicy,
    QDialog, QFileDialog, QMessageBox, QProgressBar, QScrollArea,
    QPlainTextEdit, QApplication, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter
)
from PyQt5.QtCore import (
    Qt, QSize, pyqtSignal, QPropertyAnimation, QEasingCurve,
    QThread, pyqtSlot
)
from PyQt5.QtGui import QColor, QFont, QPainter, QPen, QBrush, QLinearGradient, QTextCursor

# Register types required for safe cross-thread signal/slot queuing.
# On older PyQt5 builds (abi3), qRegisterMetaType is not exposed — in that
# case the QueuedConnection on TerminalWidget's internal signals is sufficient.
try:
    from PyQt5.QtCore import qRegisterMetaType
    qRegisterMetaType('QTextCursor')
    qRegisterMetaType('QTextBlock')
except (ImportError, AttributeError):
    try:
        from PyQt5.QtCore import QMetaType
        QMetaType.type('QTextCursor')
        QMetaType.type('QTextBlock')
    except Exception:
        pass

from ui.theme import COLORS, FONT_UI, FONT_MONO


class GlowButton(QPushButton):
    """Cyberpunk-style button with glow border effect — Qt5-safe hex alpha colors."""

    def __init__(self, text, color=COLORS['accent_cyan'], parent=None, danger=False):
        super().__init__(text, parent)
        self.base_color = COLORS['accent_pink'] if danger else color
        self._setup_style()

    def _hex_alpha(self, hex_color: str, alpha_pct: int) -> str:
        """Return hex color with alpha suffix e.g. #00d4ff → #00d4ff14 for 8%."""
        c = hex_color.strip()
        if not c.startswith('#') or len(c) not in (7, 9):
            return c
        alpha_byte = max(0, min(255, int(255 * alpha_pct / 100)))
        return f"{c[:7]}{alpha_byte:02x}"

    def _setup_style(self):
        c = self.base_color
        bg      = self._hex_alpha(c, 8)
        bg_hov  = self._hex_alpha(c, 20)
        bg_press= self._hex_alpha(c, 30)
        bd      = self._hex_alpha(c, 55)
        bd_hov  = self._hex_alpha(c, 90)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                border: 1px solid {bd};
                color: {c};
                padding: 6px 16px;
                border-radius: 6px;
                font-family: {FONT_UI};
                font-size: 12px;
                letter-spacing: 0.5px;
                font-weight: 600;
                min-height: 30px;
                text-align: center;
            }}
            QPushButton:hover {{
                background-color: {bg_hov};
                border: 1px solid {bd_hov};
            }}
            QPushButton:pressed {{
                background-color: {bg_press};
            }}
            QPushButton:disabled {{
                background-color: transparent;
                border-color: #333333;
                color: #555555;
            }}
        """)

    def set_active(self, active: bool):
        if active:
            c = self.base_color
            bg = self._hex_alpha(c, 22)
            bd = c
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg};
                    border: 1px solid {bd};
                    color: {c};
                    padding: 6px 16px;
                    border-radius: 4px;
                    font-family: {FONT_UI};
                    font-size: 12px;
                    letter-spacing: 0.5px;
                    font-weight: 700;
                    min-height: 30px;
                    text-align: center;
                }}
            """)
        else:
            self._setup_style()


class SolidButton(QPushButton):
    """Solid filled action button"""

    def __init__(self, text, color=COLORS['accent_cyan'], parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                border: 1px solid {color};
                color: #ffffff;
                padding: 8px 20px;
                border-radius: 6px;
                font-family: {FONT_UI};
                font-size: 12px;
                letter-spacing: 0.5px;
                font-weight: 700;
                min-height: 34px;
                text-align: center;
            }}
            QPushButton:hover {{
                background-color: {color}cc;
                border-color: #ffffff55;
            }}
            QPushButton:pressed {{
                background-color: {color}99;
            }}
            QPushButton:disabled {{
                background-color: #444444;
                border-color: #555555;
                color: #888888;
            }}
        """)


class StatCard(QFrame):
    """Premium dashboard stat card"""

    def __init__(self, title, value="0", subtitle="", accent=COLORS['accent_cyan'], parent=None):
        super().__init__(parent)
        self.accent = accent
        self._value_label = None
        self._setup(title, value, subtitle)

    def _setup(self, title, value, subtitle):
        self.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                    stop:0 {COLORS['bg_card']}, stop:1 {COLORS['bg_secondary']});
                border: 1px solid {COLORS['border']};
                border-top: 2px solid {self.accent};
                border-radius: 8px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(6)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 2.5px;
            background: transparent;
            border: none;
        """)
        layout.addWidget(title_lbl)

        self._value_label = QLabel(str(value))
        self._value_label.setStyleSheet(f"""
            color: {self.accent};
            font-size: 38px;
            font-weight: 800;
            background: transparent;
            border: none;
            letter-spacing: -1px;
            line-height: 1;
        """)
        layout.addWidget(self._value_label)

        if subtitle:
            sub_lbl = QLabel(subtitle)
            sub_lbl.setStyleSheet(f"""
                color: {COLORS['text_secondary']};
                font-size: 11px;
                background: transparent;
                border: none;
            """)
            layout.addWidget(sub_lbl)

        layout.addStretch()

    def set_value(self, val):
        if self._value_label:
            self._value_label.setText(str(val))


class SectionHeader(QLabel):
    """Bold section title with accent underline feel"""

    def __init__(self, text, parent=None):
        super().__init__(text.upper(), parent)
        self.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 2.5px;
            padding: 2px 0 6px 0;
            margin: 0;
            background: transparent;
            border-bottom: 1px solid {COLORS['border']};
        """)


class Divider(QFrame):
    """Horizontal divider line"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.HLine)
        self.setStyleSheet(f"background-color: {COLORS['border']}; border: none; max-height: 1px;")


class StatusBadge(QLabel):
    """Colored status badge — highly visible"""

    SEVERITY_COLORS = {
        'critical': COLORS['critical'],
        'high':     COLORS['high'],
        'medium':   COLORS['medium'],
        'low':      COLORS['low'],
        'info':     COLORS['accent_cyan'],
        'success':  COLORS['success'],
        'active':   COLORS['success'],
        'idle':     COLORS['text_secondary'],
        'running':  COLORS['accent_yellow'],
    }

    def __init__(self, text, severity='info', parent=None):
        super().__init__(text.upper(), parent)
        color = self.SEVERITY_COLORS.get(severity.lower(), COLORS['text_secondary'])
        self.setStyleSheet(f"""
            color: {color};
            background: {color}18;
            border: 1px solid {color}55;
            border-radius: 5px;
            padding: 3px 10px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.5px;
        """)
        self.setFixedHeight(22)
        self.setAlignment(Qt.AlignCenter)


# ANSI escape code stripper
_ANSI_RE = _re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and control characters from text."""
    text = _ANSI_RE.sub('', text)
    # Strip carriage returns and null bytes
    text = text.replace('\r\n', '\n').replace('\r', '').replace('\x00', '')
    return text.strip()


class TerminalWidget(QWidget):
    """
    Production-grade buffered terminal — physically cannot freeze the GUI.

    Architecture:
      Worker threads push into collections.deque (lock-free, O(1)).
      A 50ms QTimer on the main thread drains buffers in controlled batches.
      HTML lines are concatenated into ONE string → ONE appendHtml() call.
      Packet rows use QAbstractTableModel with a circular buffer.

    Guarantees:
      - append_*() methods are safe to call from ANY thread
      - GUI thread never processes more than MAX_BATCH items per tick
      - Memory is bounded: 5000 text lines, 10000 packet rows
      - Zero cross-thread Qt signals for output (only clear uses one)
    """

    _sig_clear = pyqtSignal()

    MAX_BATCH = 200          # max items per 50ms flush tick
    MAX_PACKETS = 10000      # circular packet buffer size

    def __init__(self, parent=None):
        super().__init__(parent)
        import collections
        self._auto_scroll = True
        self._log_mode = "Combined View"

        # ── Thread-safe buffers (deque is GIL-safe for append/popleft) ─────
        self._html_buf = collections.deque(maxlen=5000)
        self._packet_buf = collections.deque(maxlen=2000)
        self._progress_html = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(40)
        header.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {COLORS['bg_elevated']}, stop:1 {COLORS['bg_card']});
            border: 1px solid {COLORS['border']};
            border-bottom: 1px solid {COLORS['accent_cyan']}33;
            border-radius: 8px 8px 0 0;
        """)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(14, 0, 10, 0)
        h_layout.setSpacing(6)

        dots = QLabel("\u25cf \u25cf \u25cf")
        dots.setStyleSheet(
            f"color: {COLORS['border_bright']}; font-size: 9px; "
            f"background: transparent; letter-spacing: 3px;"
        )
        h_layout.addWidget(dots)
        h_layout.addSpacing(6)

        title = QLabel(">_  SYSTEM TERMINAL")
        title.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-family: {FONT_MONO};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 3px;
            background: transparent;
        """)
        h_layout.addWidget(title)
        h_layout.addStretch()

        def _mini_btn(label, color, tooltip=""):
            b = QPushButton(label)
            b.setFixedSize(72, 24)
            b.setToolTip(tooltip)
            b.setStyleSheet(f"""
                QPushButton {{
                    background: {color}18;
                    border: 1px solid {color}55;
                    border-radius: 4px;
                    color: {color};
                    font-size: 9px;
                    font-weight: 700;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    background: {color}30;
                    border-color: {color};
                }}
                QPushButton:checked {{
                    background: {color}40;
                    border-color: {color};
                }}
                QPushButton:pressed {{ background: {color}50; }}
            """)
            return b

        from PyQt5.QtWidgets import QComboBox
        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["Combined View", "Human Readable", "Machine Data"])
        self._filter_combo.setToolTip("Filter terminal output")
        self._filter_combo.setFixedHeight(24)
        self._filter_combo.setStyleSheet(f"""
            QComboBox {{
                background: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                color: {COLORS['text_secondary']};
                font-size: 10px;
                padding: 0px 8px;
            }}
            QComboBox::drop-down {{ border: none; }}
        """)
        self._filter_combo.currentTextChanged.connect(self._on_filter_changed)
        h_layout.addWidget(self._filter_combo)
        h_layout.addSpacing(6)

        self._clear_btn = _mini_btn("CLEAR", COLORS['critical'], "Clear terminal output")
        self._clear_btn.clicked.connect(self.clear)
        h_layout.addWidget(self._clear_btn)

        self._scroll_btn = _mini_btn("AUTO-SCR", COLORS['accent_cyan'], "Toggle auto-scroll")
        self._scroll_btn.setCheckable(True)
        self._scroll_btn.setChecked(True)
        self._scroll_btn.toggled.connect(self._on_autoscroll_toggle)
        h_layout.addWidget(self._scroll_btn)

        self._copy_btn = _mini_btn("COPY", COLORS['accent_green'], "Copy all logs to clipboard")
        self._copy_btn.clicked.connect(self._copy_logs)
        h_layout.addWidget(self._copy_btn)

        h_layout.addSpacing(4)
        layout.addWidget(header)

        # ── Text output ──────────────────────────────────────────────────
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(5000)
        self.output.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {COLORS['bg_input']};
                border: 1px solid {COLORS['border']};
                border-top: none;
                border-radius: 0 0 8px 8px;
                padding: 12px 14px;
                color: {COLORS['accent_green']};
                font-family: {FONT_MONO};
                font-size: 13px;
                selection-background-color: {COLORS['border_bright']};
            }}
        """)

        # ── Packet table (model/view for performance) ────────────────────
        from PyQt5.QtWidgets import QTableView
        from PyQt5.QtCore import QAbstractTableModel, QModelIndex

        class _PacketModel(QAbstractTableModel):
            HEADERS = ["Time", "Dir", "Protocol", "ID / Addr", "Data", "Note"]
            MAXROWS = 10000

            def __init__(self):
                super().__init__()
                import collections as _c
                self._rows = _c.deque(maxlen=self.MAXROWS)

            def rowCount(self, parent=QModelIndex()):
                return len(self._rows)

            def columnCount(self, parent=QModelIndex()):
                return 6

            def data(self, index, role=Qt.DisplayRole):
                if not index.isValid():
                    return None
                row_data = self._rows[index.row()]
                if role == Qt.DisplayRole:
                    return row_data[index.column()]
                if role == Qt.ForegroundRole:
                    direction = row_data[1]
                    if direction == 'RX':
                        return QColor(COLORS.get('accent_green', '#10d078'))
                    return QColor(COLORS.get('accent_cyan', '#00d4ff'))
                return None

            def headerData(self, section, orientation, role=Qt.DisplayRole):
                if orientation == Qt.Horizontal and role == Qt.DisplayRole:
                    return self.HEADERS[section]
                return None

            def append_batch(self, rows):
                if not rows:
                    return
                n = len(rows)
                overflow = len(self._rows) + n - self.MAXROWS
                if overflow > 0:
                    self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
                    for _ in range(overflow):
                        self._rows.popleft()
                    self.endRemoveRows()
                pos = len(self._rows)
                self.beginInsertRows(QModelIndex(), pos, pos + n - 1)
                self._rows.extend(rows)
                self.endInsertRows()

            def clear_all(self):
                self.beginResetModel()
                self._rows.clear()
                self.endResetModel()

        self._packet_model = _PacketModel()
        self.packet_table = QTableView()
        self.packet_table.setModel(self._packet_model)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setSelectionBehavior(QTableView.SelectRows)
        self.packet_table.setEditTriggers(QTableView.NoEditTriggers)

        _tbl_bg     = COLORS.get('bg_input', '#0e1520')
        _tbl_border = COLORS.get('border', '#1c2d42')
        _tbl_text   = COLORS.get('text_secondary', '#8fa8c8')
        _tbl_grid   = COLORS.get('border_bright', '#274060')
        _tbl_hdr_bg = COLORS.get('bg_secondary', '#0c1219')
        self.packet_table.setStyleSheet(f"""
            QTableView {{
                background-color: {_tbl_bg};
                border: 1px solid {_tbl_border};
                border-top: none;
                border-radius: 0 0 8px 8px;
                color: {_tbl_text};
                font-family: {FONT_MONO};
                font-size: 13px;
                gridline-color: {_tbl_grid};
            }}
            QHeaderView::section {{
                background-color: {_tbl_hdr_bg};
                color: {_tbl_text};
                border: none;
                border-right: 1px solid {_tbl_border};
                border-bottom: 1px solid {_tbl_border};
                padding: 4px;
                font-size: 10px;
                font-weight: 700;
            }}
        """)

        self.view_splitter = QSplitter(Qt.Vertical)
        self.view_splitter.addWidget(self.output)
        self.view_splitter.addWidget(self.packet_table)
        layout.addWidget(self.view_splitter)
        self._on_filter_changed(self._filter_combo.currentText())

        # ── Flush timer (THE key to GUI responsiveness) ──────────────────
        from PyQt5.QtCore import QTimer
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(50)   # 20 FPS
        self._flush_timer.timeout.connect(self._flush_buffers)
        self._flush_timer.start()

        self._sig_clear.connect(self._do_clear, Qt.QueuedConnection)

    # ── Timer-driven flush (main thread, max 20x/sec) ────────────────────

    def _flush_buffers(self):
        """Drain buffers. Build ONE html string. ONE appendHtml call."""
        # ── Text lines ───────────────────────────────────────────────────
        batch = []
        count = 0
        try:
            while count < self.MAX_BATCH:
                batch.append(self._html_buf.popleft())
                count += 1
        except IndexError:
            pass

        progress = self._progress_html
        self._progress_html = None

        if batch or progress is not None:
            # Build ONE combined HTML string for all lines
            if batch:
                combined = "<br>".join(h if h else "" for h in batch)
                self.output.appendHtml(combined)

            if progress is not None:
                cursor = self.output.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.removeSelectedText()
                cursor.insertHtml(progress)

            if self._auto_scroll:
                sb = self.output.verticalScrollBar()
                sb.setValue(sb.maximum())

        # ── Packet rows ──────────────────────────────────────────────────
        pkts = []
        count = 0
        try:
            while count < self.MAX_BATCH:
                pkts.append(self._packet_buf.popleft())
                count += 1
        except IndexError:
            pass

        if pkts:
            rows = []
            for pkt in pkts:
                ts = pkt.get('ts', '')
                if 'T' in ts:
                    ts = ts.split('T')[1][:12]
                direction = pkt.get('direction', '')
                transport = pkt.get('transport', '')
                if transport == 'CAN':
                    addr = pkt.get('arb_id', '')
                else:
                    addr = f"{pkt.get('src_addr', '')} \u2192 {pkt.get('dst_addr', '')}"
                data = pkt.get('data_hex', '')
                note = pkt.get('note', '')
                rows.append((ts, direction, transport, addr, data, note))
            self._packet_model.append_batch(rows)
            if self._auto_scroll:
                self.packet_table.scrollToBottom()

    # ── Slots ────────────────────────────────────────────────────────────

    def _do_clear(self):
        self.output.clear()
        self._packet_model.clear_all()
        self._html_buf.clear()
        self._packet_buf.clear()
        self._progress_html = None

    def _on_autoscroll_toggle(self, checked):
        self._auto_scroll = checked

    def _on_filter_changed(self, mode):
        self._log_mode = mode
        if not hasattr(self, 'packet_table'):
            return
        if mode == 'Human Readable':
            self.output.show()
            self.packet_table.hide()
        elif mode == 'Machine Data':
            self.output.hide()
            self.packet_table.show()
        else:
            self.output.show()
            self.packet_table.show()

    def _copy_logs(self):
        try:
            QApplication.clipboard().setText(self.output.toPlainText())
        except Exception:
            pass

    def toPlainText(self):
        try:
            return self.output.toPlainText()
        except Exception:
            return ""

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _ts():
        return _datetime.now().strftime('%H:%M:%S')

    @staticmethod
    def _clean(text):
        return _strip_ansi(text)

    @staticmethod
    def _safe(text):
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    # ── Public API — safe from ANY thread ────────────────────────────────
    #
    #   Every method below just pushes into a deque. Zero blocking.
    #   Zero Qt signals. Zero GUI thread interaction.
    #

    def append(self, text, color=None):
        text = self._clean(text)
        if not text:
            return
        safe = self._safe(text)
        c = color or COLORS.get('accent_green', '#10d078')
        self._html_buf.append(f'<span style="color:{c};">{safe}</span>')

    def clear(self):
        self._sig_clear.emit()

    def append_command(self, cmd):
        ts = self._ts()
        safe = self._safe(self._clean(cmd))
        self._html_buf.append(
            f'<span style="color:{COLORS["accent_cyan"]};">[{ts}] [CMD] {safe}</span>'
        )

    def _format_and_emit(self, text, replace=False):
        if not text:
            if not replace:
                self._html_buf.append("")
            return

        raw = text.strip()
        is_machine = False
        if raw.startswith('CC_PACKET'):
            is_machine = True
            try:
                import json
                pkt = json.loads(raw[10:])
                self._packet_buf.append(pkt)
            except Exception:
                pass
        elif raw.startswith('{') and raw.endswith('}'):
            is_machine = True
        elif '#' in raw and all(c in '0123456789abcdefABCDEF# .\r\n' for c in raw):
            is_machine = True
        elif _re.match(r'^0x[0-9a-fA-F]+\s', raw):
            is_machine = True

        if self._log_mode == "Human Readable" and is_machine:
            return
        if self._log_mode == "Machine Data" and not is_machine:
            return

        ts = self._ts()
        text = self._clean(text)
        if not text:
            return

        tl = text.lower()
        if is_machine:
            color = COLORS.get('accent_purple', '#a78bfa')
            prefix = f'[{ts}] [RAW] '
        elif tl.startswith('tx') or ' tx ' in tl or '\u2192' in text or '-> ' in text:
            color = COLORS.get('accent_cyan', '#00d4ff')
            prefix = f'[{ts}] [TX] '
        elif tl.startswith('rx') or ' rx ' in tl or '\u2190' in text or '<- ' in text:
            color = COLORS.get('success', '#00FF88')
            prefix = f'[{ts}] [RX] '
        else:
            color = COLORS.get('accent_green', '#10d078')
            prefix = f'[{ts}] [OUT] '

        safe = self._safe(text)
        html = f'<span style="color:{color};">{prefix}{safe}</span>'
        if replace:
            self._progress_html = html
        else:
            self._html_buf.append(html)

    def append_output(self, text):
        self._format_and_emit(text, replace=False)

    def append_progress(self, text):
        self._format_and_emit(text, replace=True)

    def append_error(self, text):
        if self._log_mode == "Machine Data":
            return
        ts = self._ts()
        text = self._clean(text)
        if not text:
            return
        safe = self._safe(text)
        self._html_buf.append(
            f'<span style="color:{COLORS["critical"]};">[{ts}] [ERR] {safe}</span>'
        )

    def append_info(self, text):
        ts = self._ts()
        text = self._clean(text)
        if not text:
            return
        safe = self._safe(text)
        self._html_buf.append(
            f'<span style="color:{COLORS["accent_yellow"]};">[{ts}] [INFO] {safe}</span>'
        )

    def append_success(self, text):
        ts = self._ts()
        text = self._clean(text)
        if not text:
            return
        safe = self._safe(text)
        self._html_buf.append(
            f'<span style="color:{COLORS["success"]};">[{ts}] [OK] {safe}</span>'
        )

    def append_tx(self, can_id, data):
        ts = self._ts()
        self._html_buf.append(
            f'<span style="color:{COLORS.get("accent_cyan","#00d4ff")};">'
            f'[{ts}] [TX] {can_id} -&gt; {data}</span>'
        )

    def append_rx(self, can_id, data):
        ts = self._ts()
        self._html_buf.append(
            f'<span style="color:{COLORS.get("success","#00FF88")};">'
            f'[{ts}] [RX] {can_id} &lt;- {data}</span>'
        )

    def append_did_found(self, did):
        ts = self._ts()
        self._html_buf.append(
            f'<span style="color:{COLORS.get("accent_green","#10d078")};">'
            f'[{ts}] [SUCCESS] DID discovered: {did}</span>'
        )



class CardFrame(QFrame):
    """Generic card frame"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
            }}
        """)

    def set_layout_margins(self, m=16, spacing=12):
        if self.layout():
            self.layout().setContentsMargins(m, m, m, m)
            self.layout().setSpacing(spacing)


class NavButton(QPushButton):
    """Premium sidebar navigation button"""

    # Map section names to Unicode icons
    _ICONS = {
        "DASHBOARD":   "⬡",
        "ECU MONITOR": "◎",
        "REPLAY":      "↺",
        "CONFIG":      "⚙",
        "RECON":       "◈",
        "DEMO":        "▶",
        "UDS":         "⬡",
        "UDS FUZZ":    "⚡",
        "DCM":         "◇",
        "FUZZER":      "≈",
        "LEN ATTACK":  "⚡",
        "SEND":        "➤",
        "DUMP":        "↓",
        "LISTENER":    "◉",
        "XCP":         "✦",
        "DoIP":        "◈",
        "ADVANCED":    "⊞",
        "HELP":        "?",
        "EXPORT":      "↑",
        "LOGS":        "📋",
    }

    def __init__(self, text, icon_char="", parent=None):
        super().__init__(parent)
        # Use our curated icon map, fallback to provided char
        icon = self._ICONS.get(text, icon_char) or icon_char
        self._label = text
        self._icon  = icon
        self.setCheckable(True)
        self.setFixedHeight(44)
        self._apply_style(False)

    def _apply_style(self, checked: bool):
        C = COLORS
        # Fixed-width icon column: pad to 2 chars so text always starts at the
        # same x-position regardless of icon width (⬡ vs 📋 vs ?)
        icon_padded = (self._icon + " ")[:2] if self._icon else "  "
        label_text = f"  {icon_padded}  {self._label}"
        self.setText(label_text)
        if checked:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                        stop:0 {C['accent_cyan']}1e, stop:1 transparent);
                    border: none;
                    border-left: 3px solid {C['accent_cyan']};
                    color: {C['accent_cyan']};
                    text-align: left;
                    padding-left: 16px;
                    padding-right: 8px;
                    font-size: 12px;
                    font-weight: 700;
                    letter-spacing: 0.6px;
                    border-radius: 0;
                    min-height: 44px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    border-left: 3px solid transparent;
                    color: {C['accent_blue']};
                    text-align: left;
                    padding-left: 16px;
                    padding-right: 8px;
                    font-size: 12px;
                    font-weight: 500;
                    letter-spacing: 0.4px;
                    border-radius: 0;
                    min-height: 44px;
                }}
                QPushButton:hover {{
                    background: {C['bg_elevated']};
                    color: {C['accent_cyan']};
                    border-left: 3px solid {C['border_bright']};
                }}
            """)

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        self._apply_style(checked)


# ══════════════════════════════════════════════════════════════════════════════
# Export Format Dialog — shown when user clicks Export Failure Report
# ══════════════════════════════════════════════════════════════════════════════

class ExportDialog(QDialog):
    """
    Main export menu — dropdown-style list matching the fucyfuzz (2) screenshots:
      Overall Report  → opens OverallReportDialog (PDF / ASC / MDF4)
      Failure Report  → straight to PDF failure report
      Save Logs (.log)→ save raw terminal logs as .log
      Export Logs (.asc)  → Vector ASC format
      Export Logs (.mf4)  → ASAM MDF4 format

    Emits export_requested(action: str)
      action ∈ { 'overall', 'failure', 'save_log', 'asc', 'mf4' }
    """

    export_requested = pyqtSignal(str)

    # ── shared stylesheet fragments ───────────────────────────────────────────
    _DIALOG_SS = f"""
        QDialog {{
            background-color: {COLORS['bg_secondary']};
            border: 1px solid {COLORS['border_bright']};
            border-radius: 8px;
        }}
    """
    _ITEM_SS = f"""
        QPushButton {{
            background-color: transparent;
            border: none;
            border-bottom: 1px solid {COLORS['border']};
            color: {COLORS['text_primary']};
            font-size: 12px;
            font-family: {FONT_UI};
            text-align: left;
            padding: 10px 16px;
        }}
        QPushButton:hover {{
            background-color: {COLORS['bg_elevated']};
            color: {COLORS['accent_cyan']};
        }}
        QPushButton:pressed {{
            background-color: {COLORS['border_bright']};
        }}
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Report")
        self.setFixedSize(300, 360)
        self.setModal(True)
        self.setStyleSheet(self._DIALOG_SS)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header bar ─────────────────────────────────────────────────────────
        hdr = QWidget()
        hdr.setFixedHeight(46)
        hdr.setStyleSheet(f"""
            background: {COLORS['bg_elevated']};
            border-bottom: 1px solid {COLORS['border_bright']};
            border-radius: 8px 8px 0 0;
        """)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(16, 0, 16, 0)
        title = QLabel("Export / Save")
        title.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 13px;
            font-weight: bold;
            font-family: {FONT_UI};
            background: transparent;
        """)
        hl.addWidget(title)
        layout.addWidget(hdr)

        # ── Menu items ─────────────────────────────────────────────────────────
        items = [
            ("overall",      "📋  Overall Report",               COLORS['accent_cyan']),
            ("failure",      "🔴  Failure Report",               COLORS['critical']),
            ("save_log",     "💾  Save Logs (.log)",              COLORS['accent_green']),
            ("asc",          "📤  Export Logs (.asc)",           COLORS['accent_yellow']),
            ("mf4",          "📊  Export Logs (.mf4)",           COLORS['accent_purple']),
            ("ecu_session",  "🛡  ECU Monitor Session Report",   COLORS['accent_orange']),
        ]

        for action, label, accent in items:
            btn = QPushButton(label)
            btn.setFixedHeight(42)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    border: none;
                    border-bottom: 1px solid {COLORS['border']};
                    color: {COLORS['text_primary']};
                    font-size: 12px;
                    font-family: {FONT_UI};
                    text-align: left;
                    padding: 0 16px;
                }}
                QPushButton:hover {{
                    background-color: {accent}18;
                    color: {accent};
                    border-left: 3px solid {accent};
                    padding-left: 13px;
                }}
                QPushButton:pressed {{
                    background-color: {accent}30;
                }}
            """)
            btn.clicked.connect(lambda checked, a=action: self._pick(a))
            layout.addWidget(btn)

        layout.addStretch()

        # ── Cancel ─────────────────────────────────────────────────────────────
        cancel = QPushButton("✕  Cancel")
        cancel.setFixedHeight(38)
        cancel.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['critical']};
                border: none;
                border-radius: 0 0 8px 8px;
                color: white;
                font-size: 12px;
                font-weight: bold;
                font-family: {FONT_UI};
            }}
            QPushButton:hover {{
                background-color: {COLORS['critical']}cc;
            }}
        """)
        cancel.clicked.connect(self.reject)
        layout.addWidget(cancel)

    def _pick(self, action: str):
        self.export_requested.emit(action)
        self.accept()


class OverallReportDialog(QDialog):
    """
    Second-level dialog for Overall Report format selection.
    Matches Image 1:
      ┌─ Overall Report Format ──────────────┐
      │   Select Overall Report Format        │
      │   ◉ PDF (Professional Report)         │
      │   ○ ASC (Vector Log)                  │
      │   ○ MDF4 (ASAM MDF)                   │
      │         [ Generate ]  [ Cancel ]      │
      └───────────────────────────────────────┘
    Emits format_selected('pdf' | 'asc' | 'mf4')
    """

    format_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Overall Report Format")
        self.setFixedSize(370, 260)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_bright']};
                border-radius: 8px;
            }}
        """)
        self._selected = 'pdf'
        self._build_ui()

    def _build_ui(self):
        from PyQt5.QtWidgets import QRadioButton, QButtonGroup
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(12)

        title = QLabel("Select Overall Report Format")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 14px;
            font-weight: bold;
            font-family: {FONT_UI};
            padding-bottom: 4px;
        """)
        layout.addWidget(title)

        radio_ss = f"""
            QRadioButton {{
                color: {COLORS['text_primary']};
                font-size: 12px;
                font-family: {FONT_UI};
                spacing: 10px;
                background: transparent;
                padding: 4px 0;
            }}
            QRadioButton::indicator {{
                width: 16px; height: 16px;
                border-radius: 8px;
                border: 2px solid {COLORS['border_bright']};
                background: transparent;
            }}
            QRadioButton::indicator:checked {{
                background: {COLORS['accent_cyan']};
                border: 2px solid {COLORS['accent_cyan']};
            }}
            QRadioButton:hover {{ color: {COLORS['accent_cyan']}; }}
        """

        self._group = QButtonGroup(self)
        options = [
            ('pdf',  '🖹  PDF (Professional Report)'),
            ('asc',  '⣾  ASC (Vector Log)'),
            ('mf4',  '≋  MDF4 (ASAM MDF)'),
        ]
        for i, (fmt, label) in enumerate(options):
            rb = QRadioButton(label)
            rb.setStyleSheet(radio_ss)
            rb.setProperty('fmt', fmt)
            if i == 0:
                rb.setChecked(True)
            self._group.addButton(rb, i)
            layout.addWidget(rb)

        layout.addStretch()

        # ── Buttons row ────────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        gen_btn = QPushButton("Generate")
        gen_btn.setFixedHeight(38)
        gen_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent_green']};
                border: none; border-radius: 5px;
                color: {COLORS['bg_primary']};
                font-size: 13px; font-weight: bold;
                font-family: {FONT_UI};
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_green']}cc; }}
            QPushButton:pressed {{ background-color: {COLORS['accent_green']}88; }}
        """)
        gen_btn.clicked.connect(self._generate)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedHeight(38)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['critical']};
                border: none; border-radius: 5px;
                color: white;
                font-size: 13px; font-weight: bold;
                font-family: {FONT_UI};
            }}
            QPushButton:hover {{ background-color: {COLORS['critical']}cc; }}
            QPushButton:pressed {{ background-color: {COLORS['critical']}88; }}
        """)
        cancel_btn.clicked.connect(self.reject)

        btn_row.addWidget(gen_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

    def _generate(self):
        checked = self._group.checkedButton()
        if checked:
            self.format_selected.emit(checked.property('fmt'))
        self.accept()


# ══════════════════════════════════════════════════════════════════════════════
# ECU Session Picker Dialog
# Lets the user choose: Live session OR one of the past completed sessions.
# ══════════════════════════════════════════════════════════════════════════════

class ECUSessionPickerDialog(QDialog):
    """
    Modal dialog that asks:
      ┌─ Select ECU Monitor Session ────────────────────────┐
      │  ◉ Live session  (N events, started HH:MM:SS)       │
      │  ○ Session 1  (N events  |  HH:MM – HH:MM)          │
      │  ○ Session 2  ...                                    │
      │         [ Export ]   [ Cancel ]                      │
      └──────────────────────────────────────────────────────┘

    Emits session_selected(session_data: dict) when confirmed.
    """

    session_selected = pyqtSignal(dict)

    def __init__(self, live_data: dict, past_sessions: list, parent=None):
        super().__init__(parent)
        self._live       = live_data
        self._past       = past_sessions      # most-recent first
        self._chosen     = None

        self.setWindowTitle("Select ECU Monitor Session")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['bg_secondary']};
                border: 1px solid {COLORS['border_bright']};
                border-radius: 8px;
            }}
        """)
        self._build_ui()

    # ── build ──────────────────────────────────────────────────────────────────
    def _build_ui(self):
        from PyQt5.QtWidgets import QRadioButton, QButtonGroup, QScrollArea
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # header
        hdr = QWidget()
        hdr.setFixedHeight(48)
        hdr.setStyleSheet(f"""
            background: {COLORS['bg_elevated']};
            border-bottom: 1px solid {COLORS['border_bright']};
            border-radius: 8px 8px 0 0;
        """)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(18, 0, 18, 0)
        title_lbl = QLabel("Select ECU Monitor Session")
        title_lbl.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 13px;
            font-weight: bold;
            font-family: {FONT_UI};
            background: transparent;
        """)
        hl.addWidget(title_lbl)
        layout.addWidget(hdr)

        # scrollable radio area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setStyleSheet(f"background: {COLORS['bg_secondary']};")
        scroll.setMaximumHeight(320)

        inner = QWidget()
        inner.setStyleSheet(f"background: {COLORS['bg_secondary']};")
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(18, 12, 18, 12)
        inner_layout.setSpacing(4)

        self._group = QButtonGroup(self)

        radio_ss = f"""
            QRadioButton {{
                color: {COLORS['text_primary']};
                font-size: 12px;
                font-family: {FONT_UI};
                spacing: 10px;
                background: transparent;
                padding: 8px 10px;
                border-radius: 4px;
            }}
            QRadioButton::indicator {{
                width: 16px; height: 16px;
                border-radius: 8px;
                border: 2px solid {COLORS['border_bright']};
                background: transparent;
            }}
            QRadioButton::indicator:checked {{
                background: {COLORS['accent_cyan']};
                border: 2px solid {COLORS['accent_cyan']};
            }}
            QRadioButton:hover {{
                background: {COLORS['bg_elevated']};
                color: {COLORS['accent_cyan']};
            }}
        """

        # ── Live session row ──────────────────────────────────────────────────
        live_events = len(self._live.get('events', []))
        live_start  = self._live.get('session_start', 'N/A')
        live_label  = f"🔴  Live session  ({live_events} events"
        if live_start != 'N/A':
            live_label += f"  |  started {live_start}"
        live_label += ")"

        live_rb = QRadioButton(live_label)
        live_rb.setStyleSheet(radio_ss)
        live_rb.setChecked(True)
        live_rb.toggled.connect(lambda on: self._select(self._live) if on else None)
        self._group.addButton(live_rb, 0)
        inner_layout.addWidget(live_rb)
        self._chosen = self._live

        # separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {COLORS['border']};")
        inner_layout.addWidget(sep)

        # ── Past sessions ─────────────────────────────────────────────────────
        if self._past:
            past_lbl = QLabel("Completed sessions:")
            past_lbl.setStyleSheet(f"""
                color: {COLORS['text_secondary']};
                font-size: 10px;
                letter-spacing: 1px;
                background: transparent;
                padding: 4px 0 2px 0;
            """)
            inner_layout.addWidget(past_lbl)

            for idx, sess in enumerate(self._past, start=1):
                n   = len(sess.get('events', []))
                st  = sess.get('session_start', '?')
                en  = sess.get('session_end',   '?')
                sid = sess.get('session_id', '')
                incomplete = '(incomplete)' in en

                # Show short session folder name
                folder_name = sid[-20:] if len(sid) > 20 else sid
                status_tag  = ' ⚠ incomplete' if incomplete else ''
                label = (
                    f"{'⚠ ' if incomplete else ''}Session {idx}"
                    f"  —  {n} events  |  {st}  →  {en}{status_tag}"
                )
                if folder_name:
                    label += f"\n  📂 ecu_sessions/{folder_name}"

                rb = QRadioButton(label)
                rb.setStyleSheet(radio_ss)
                rb.toggled.connect(
                    lambda on, s=sess: self._select(s) if on else None
                )
                self._group.addButton(rb, idx)
                inner_layout.addWidget(rb)
        else:
            no_lbl = QLabel("No completed sessions yet.")
            no_lbl.setStyleSheet(f"""
                color: {COLORS['text_muted']};
                font-size: 11px;
                font-style: italic;
                background: transparent;
                padding: 6px 0;
            """)
            inner_layout.addWidget(no_lbl)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll)

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_row = QWidget()
        btn_row.setFixedHeight(56)
        btn_row.setStyleSheet(f"""
            background: {COLORS['bg_elevated']};
            border-top: 1px solid {COLORS['border']};
            border-radius: 0 0 8px 8px;
        """)
        br = QHBoxLayout(btn_row)
        br.setContentsMargins(18, 10, 18, 10)
        br.setSpacing(10)
        br.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedWidth(90)
        cancel_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {COLORS['border_bright']};
                border-radius: 4px;
                color: {COLORS['text_secondary']};
                font-size: 12px;
                font-family: {FONT_UI};
                padding: 6px 0;
            }}
            QPushButton:hover {{
                background: {COLORS['bg_secondary']};
                color: {COLORS['text_primary']};
            }}
        """)
        cancel_btn.clicked.connect(self.reject)
        br.addWidget(cancel_btn)

        export_btn = QPushButton("Export →")
        export_btn.setFixedWidth(110)
        export_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['accent_cyan']};
                border: none;
                border-radius: 4px;
                color: {COLORS['bg_primary']};
                font-size: 12px;
                font-weight: bold;
                font-family: {FONT_UI};
                padding: 6px 0;
            }}
            QPushButton:hover {{
                background: {COLORS['accent_cyan']}cc;
            }}
            QPushButton:pressed {{
                background: {COLORS['accent_cyan']}88;
            }}
        """)
        export_btn.clicked.connect(self._confirm)
        br.addWidget(export_btn)

        layout.addWidget(btn_row)

    def _select(self, data: dict):
        self._chosen = data

    def _confirm(self):
        if self._chosen is not None:
            self.session_selected.emit(self._chosen)
            self.accept()
