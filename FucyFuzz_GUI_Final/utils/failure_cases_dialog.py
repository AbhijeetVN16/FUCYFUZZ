"""
Failure Cases Dialog
Full management UI ported from fucyfuzz main_app.py:
  - View all failure cases per module
  - Re-run any failure case
  - View details
  - Delete individual cases
  - Export all to CSV
  - Clear all
Persistent storage in failure_cases/failure_cases.json
"""

import os
import csv
import json
import time
from datetime import datetime

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QTabWidget, QWidget, QScrollArea, QFrame,
    QPushButton, QTextEdit, QFileDialog, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor

from ui.theme import COLORS
from ui.widgets import SolidButton, GlowButton
from utils.config import APP_DIRS, ensure_app_dirs


FAILURE_CASES_FILE = os.path.join(APP_DIRS['failure_cases'], 'failure_cases.json')


def load_failure_cases() -> dict:
    ensure_app_dirs()
    if not os.path.exists(FAILURE_CASES_FILE):
        return {}
    try:
        with open(FAILURE_CASES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_failure_cases(cases: dict):
    ensure_app_dirs()
    try:
        with open(FAILURE_CASES_FILE, 'w', encoding='utf-8') as f:
            json.dump(cases, f, indent=2, default=str)
    except Exception:
        pass


def add_failure_case(module: str, entry: dict):
    """Add a failure case for a module and persist immediately."""
    cases = load_failure_cases()
    if module not in cases:
        cases[module] = []
    # Dedup by timestamp + command
    for existing in cases[module]:
        if (existing.get('timestamp') == entry.get('timestamp') and
                existing.get('command') == entry.get('command')):
            return
    cases[module].append(entry)
    save_failure_cases(cases)


# ---------------------------------------------------------------------------
# Main Dialog
# ---------------------------------------------------------------------------
class FailureCasesDialog(QDialog):
    rerun_requested = pyqtSignal(str, list)   # module, args

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Failure Cases Management")
        self.resize(960, 700)
        self.setModal(True)
        self.setStyleSheet(f"background: {COLORS['bg_primary']}; color: {COLORS['text_primary']};")
        self._cases = load_failure_cases()
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setFixedHeight(52)
        hdr.setStyleSheet(f"background: {COLORS['critical']}33; border-bottom: 1px solid {COLORS['critical']};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(20, 0, 20, 0)
        title = QLabel("📊  FAILURE CASES MANAGEMENT")
        title.setStyleSheet(f"color: {COLORS['critical']}; font-size: 14px; font-weight: bold; background: transparent; letter-spacing: 2px;")
        hl.addWidget(title)
        hl.addStretch()
        total = sum(len(v) for v in self._cases.values())
        count_lbl = QLabel(f"Total: {total} failure cases")
        count_lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px; background: transparent;")
        hl.addWidget(count_lbl)
        root.addWidget(hdr)

        # Tab view per module
        self._module_tabs = QTabWidget()
        self._module_tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; background: {COLORS['bg_primary']}; }}
            QTabBar::tab {{
                background: {COLORS['bg_secondary']};
                border: none;
                border-bottom: 2px solid transparent;
                padding: 6px 14px;
                color: {COLORS['text_secondary']};
                font-size: 10px; letter-spacing: 1px;
            }}
            QTabBar::tab:selected {{
                color: {COLORS['critical']};
                border-bottom: 2px solid {COLORS['critical']};
                background: {COLORS['bg_primary']};
            }}
        """)

        if not self._cases:
            empty = QWidget()
            el = QVBoxLayout(empty)
            el.addStretch()
            lbl = QLabel("✅  No failure cases recorded yet.")
            lbl.setStyleSheet(f"color: {COLORS['accent_green']}; font-size: 13px; background: transparent;")
            lbl.setAlignment(Qt.AlignCenter)
            el.addWidget(lbl)
            el.addStretch()
            self._module_tabs.addTab(empty, "No Failures")
        else:
            for module, failures in self._cases.items():
                if failures:
                    tab = self._build_module_tab(module, failures)
                    self._module_tabs.addTab(tab, f"{module} ({len(failures)})")

        root.addWidget(self._module_tabs, 1)

        # Bottom action bar
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background: {COLORS['bg_secondary']}; border-top: 1px solid {COLORS['border']};")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(16, 0, 16, 0)
        bl.setSpacing(10)

        export_btn = SolidButton("⬇  Export All to CSV", COLORS['accent_cyan'])
        export_btn.setFixedHeight(32)
        export_btn.clicked.connect(self._export_csv)
        bl.addWidget(export_btn)

        clear_btn = GlowButton("🗑  Clear All", COLORS['critical'], danger=True)
        clear_btn.setFixedHeight(32)
        clear_btn.clicked.connect(self._clear_all)
        bl.addWidget(clear_btn)

        bl.addStretch()

        close_btn = SolidButton("Close", COLORS['text_secondary'])
        close_btn.setFixedHeight(32)
        close_btn.clicked.connect(self.accept)
        bl.addWidget(close_btn)

        root.addWidget(bar)

    def _build_module_tab(self, module: str, failures: list) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {COLORS['bg_primary']};")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)

        # Table
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["#", "Timestamp", "Status", "Command (preview)", "Actions"])
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(True)
        table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLORS['bg_card']};
                border: none;
                font-size: 11px;
                color: {COLORS['text_primary']};
            }}
            QTableWidget::item {{
                padding: 5px 8px;
                border-bottom: 1px solid {COLORS['border']};
            }}
            QTableWidget::item:selected {{ background: {COLORS['bg_elevated']}; }}
            QHeaderView::section {{
                background: {COLORS['bg_secondary']};
                color: {COLORS['accent_cyan']};
                font-size: 9px; letter-spacing: 1px;
                padding: 6px 8px;
                border: none;
                border-bottom: 1px solid {COLORS['border']};
            }}
        """)
        hh = table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        for i, f in enumerate(failures):
            table.insertRow(i)
            table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            table.setItem(i, 1, QTableWidgetItem(f.get('timestamp', '')))
            status = f.get('status', 'failure')
            st_item = QTableWidgetItem(status)
            st_item.setForeground(QColor(COLORS['critical'] if 'fail' in status.lower() else COLORS['accent_yellow']))
            table.setItem(i, 2, st_item)
            cmd = f.get('command', '')
            table.setItem(i, 3, QTableWidgetItem(cmd[:80] + ('...' if len(cmd) > 80 else '')))

            # Action buttons cell
            actions_widget = QWidget()
            actions_widget.setStyleSheet(f"background: {COLORS['bg_card']};")
            al = QHBoxLayout(actions_widget)
            al.setContentsMargins(4, 2, 4, 2)
            al.setSpacing(4)

            details_btn = QPushButton("Details")
            details_btn.setFixedHeight(24)
            details_btn.setStyleSheet(f"background: {COLORS['accent_cyan']}33; color: {COLORS['accent_cyan']}; border: 1px solid {COLORS['accent_cyan']}66; border-radius: 2px; font-size: 9px; padding: 0 6px;")
            details_btn.clicked.connect(lambda _, fail=f, mod=module: self._show_details(fail, mod))
            al.addWidget(details_btn)

            rerun_btn = QPushButton("Re-run")
            rerun_btn.setFixedHeight(24)
            rerun_btn.setStyleSheet(f"background: {COLORS['accent_green']}33; color: {COLORS['accent_green']}; border: 1px solid {COLORS['accent_green']}66; border-radius: 2px; font-size: 9px; padding: 0 6px;")
            rerun_btn.clicked.connect(lambda _, fail=f, mod=module: self._rerun(fail, mod))
            al.addWidget(rerun_btn)

            del_btn = QPushButton("Delete")
            del_btn.setFixedHeight(24)
            del_btn.setStyleSheet(f"background: {COLORS['critical']}33; color: {COLORS['critical']}; border: 1px solid {COLORS['critical']}66; border-radius: 2px; font-size: 9px; padding: 0 6px;")
            del_btn.clicked.connect(lambda _, fail=f, mod=module: self._delete(fail, mod))
            al.addWidget(del_btn)

            table.setCellWidget(i, 4, actions_widget)
            table.setRowHeight(i, 36)

        layout.addWidget(table)
        return w

    def _show_details(self, failure: dict, module: str):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Failure Details — {module}")
        dlg.resize(700, 500)
        dlg.setStyleSheet(f"background: {COLORS['bg_primary']}; color: {COLORS['text_primary']};")
        layout = QVBoxLayout(dlg)

        hdr = QLabel(f"📋  {module}  —  {failure.get('timestamp', '')}")
        hdr.setStyleSheet(f"color: {COLORS['critical']}; font-size: 12px; font-weight: bold; background: transparent;")
        layout.addWidget(hdr)

        info_parts = []
        for k, v in failure.items():
            if k not in ('output', 'case_details'):
                info_parts.append(f"{k}: {v}")
        if 'case_details' in failure and isinstance(failure['case_details'], dict):
            info_parts.append("\nCase Details:")
            for k, v in failure['case_details'].items():
                info_parts.append(f"  {k}: {v}")

        info = QTextEdit()
        info.setReadOnly(True)
        info.setPlainText("\n".join(info_parts))
        info.setStyleSheet(f"background: {COLORS['bg_card']}; color: {COLORS['text_primary']}; border: 1px solid {COLORS['border']}; font-family: 'Courier New'; font-size: 11px;")
        layout.addWidget(info, 1)

        if failure.get('output'):
            out_lbl = QLabel("Output:")
            out_lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent; font-size: 10px;")
            layout.addWidget(out_lbl)
            out = QTextEdit()
            out.setReadOnly(True)
            out.setPlainText(failure['output'][:3000])
            out.setFixedHeight(120)
            out.setStyleSheet(f"background: {COLORS['bg_card']}; color: {COLORS['accent_green']}; border: 1px solid {COLORS['border']}; font-family: 'Courier New'; font-size: 10px;")
            layout.addWidget(out)

        close = SolidButton("Close", COLORS['text_secondary'])
        close.setFixedHeight(32)
        close.clicked.connect(dlg.accept)
        layout.addWidget(close, 0, Qt.AlignRight)

        dlg.exec_()

    def _rerun(self, failure: dict, module: str):
        cmd = failure.get('command', '')
        if not cmd:
            QMessageBox.warning(self, "Re-run", "No command stored for this failure.")
            return
        # Extract args after the binary name
        parts = cmd.split()
        # Find module keyword
        module_cmds = ['fuzzer', 'lenattack', 'dcm', 'uds', 'send', 'listener', 'dump', 'xcp', 'doip', 'recon']
        args = []
        for i, p in enumerate(parts):
            if p.lower() in module_cmds:
                args = parts[i:]
                break
        if not args:
            args = parts  # fallback: pass whole command
        self.rerun_requested.emit(module, args)
        self.accept()

    def _delete(self, failure: dict, module: str):
        reply = QMessageBox.question(self, "Delete", "Delete this failure case?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        cases = load_failure_cases()
        if module in cases:
            cases[module] = [
                f for f in cases[module]
                if not (f.get('timestamp') == failure.get('timestamp') and
                        f.get('command') == failure.get('command'))
            ]
            if not cases[module]:
                del cases[module]
        save_failure_cases(cases)
        QMessageBox.information(self, "Deleted", "Failure case deleted.")
        self.accept()  # close and reopen for refresh

    def _export_csv(self):
        all_failures = []
        for mod, fails in self._cases.items():
            for f in fails:
                all_failures.append({**f, 'module': mod})

        if not all_failures:
            QMessageBox.information(self, "Export", "No failure cases to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Failure Cases CSV",
            f"failure_cases_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'module', 'status', 'command', 'output'])
                writer.writeheader()
                for entry in all_failures:
                    writer.writerow({
                        'timestamp': entry.get('timestamp', ''),
                        'module':    entry.get('module', ''),
                        'status':    entry.get('status', ''),
                        'command':   entry.get('command', '')[:200],
                        'output':    str(entry.get('output', ''))[:500].replace('\n', ' '),
                    })
            QMessageBox.information(self, "Exported", f"Exported {len(all_failures)} cases to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _clear_all(self):
        reply = QMessageBox.question(self, "Clear All",
                                     "Clear ALL failure cases? This cannot be undone.",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            save_failure_cases({})
            QMessageBox.information(self, "Cleared", "All failure cases cleared.")
            self.accept()
