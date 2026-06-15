#!/usr/bin/env python3
"""
FucyFuzz GUI — CAN Bus Security Framework
==========================================
Usage:
    python main.py
"""

import sys
import os
import logging
import traceback

# Force UTF-8 encoding for all subprocesses to prevent UnicodeEncodeError on Windows
os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['PYTHONUTF8'] = '1'

# Ensure the project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── App dirs + logging setup ──────────────────────────────────────────────────
from utils.config import ensure_app_dirs, APP_DIRS

dirs = ensure_app_dirs()

_log_fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=_log_fmt,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(dirs['logs'], 'fucyfuzz_app.log'),
            encoding='utf-8'
        ),
    ]
)
log = logging.getLogger(__name__)


# ── Global unhandled exception hook ──────────────────────────────────────────

def _excepthook(exc_type, exc_value, exc_tb):
    """
    Catch any uncaught exception on the main thread.
    Log it fully, show a user-friendly dialog, then let the app continue
    running if possible rather than crashing silently.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Let Ctrl-C exit normally
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return

    tb_str = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log.critical("Unhandled exception:\n%s", tb_str)

    # Try to show a Qt error dialog without crashing further
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance()
        if app:
            msg = QMessageBox()
            msg.setWindowTitle("FucyFuzz — Unexpected Error")
            msg.setIcon(QMessageBox.Critical)
            msg.setText(
                "<b>An unexpected error occurred.</b><br>"
                "The tool will attempt to continue running.<br><br>"
                f"<i>{exc_type.__name__}: {exc_value}</i>"
            )
            msg.setDetailedText(tb_str)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
    except Exception:
        pass  # If even the dialog crashes, just log and move on


sys.excepthook = _excepthook


# ── CAN pre-check ─────────────────────────────────────────────────────────────

def _report_can_status(iface: str = None):
    try:
        from utils.can_interface import list_can_interfaces, check_interface
        from utils.config import get_config
        if not iface:
            iface = get_config().get('interface', 'vcan0')
        avail  = list_can_interfaces()
        status = check_interface(iface)
        if status.ok:
            log.info("CAN interface '%s' is UP and ready.", iface)
        else:
            log.warning("CAN interface '%s' is NOT available: %s", iface, status.reason)
            if avail:
                log.info("Available: %s", ", ".join(avail))
    except Exception as e:
        log.debug("CAN pre-check skipped: %s", e)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("FucyFuzz starting — log root: %s", dirs['logs'])

    _report_can_status()

    # Start session logger (non-fatal if it fails)
    try:
        from utils.session_logger import start_session_logger
        sl = start_session_logger(dirs['logs'])
        # Store paths so the GUI can read them without importing session_logger
        os.environ["FUCYFUZZ_SESSION_LOG"]   = sl._log_path
        os.environ["FUCYFUZZ_SESSION_JSONL"] = sl._json_path
        os.environ["FUCYFUZZ_SESSION_CSV"]   = sl._csv_path
        os.environ["FUCYFUZZ_SESSION_DIR"]   = sl._session_dir
    except Exception as exc:
        log.warning("Session logger failed to start: %s", exc)

    try:
        from utils.log_manager import set_log_root
        set_log_root(dirs['logs'])
    except Exception:
        pass

    from PyQt5.QtWidgets import QApplication
    from PyQt5.QtCore import Qt

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("FucyFuzz")
    app.setApplicationVersion("3.1.0")
    app.setOrganizationName("FucyFuzz Security")

    # Install Qt-level exception handler for slots running in the GUI thread.
    # PyQt5 normally swallows slot exceptions; this surfaces them.
    try:
        import PyQt5.QtCore as _qc
        _orig_slot_exception = getattr(_qc, '_PyQtBoundSignal__call__', None)
    except Exception:
        pass

    # Register meta types needed for cross-thread signals
    try:
        from PyQt5.QtCore import qRegisterMetaType
        from PyQt5.QtGui import QTextCursor
        qRegisterMetaType('QTextCursor')
        qRegisterMetaType('QTextBlock')
    except (ImportError, AttributeError):
        try:
            from PyQt5.QtCore import QMetaType
            QMetaType.type('QTextCursor')
        except Exception:
            pass

    from ui.theme import GLOBAL_STYLESHEET
    app.setStyleSheet(GLOBAL_STYLESHEET)

    from ui.main_window import MainWindow
    try:
        window = MainWindow()
    except Exception as exc:
        log.critical("MainWindow failed to construct: %s", exc, exc_info=True)
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.critical(
            None, "Startup Error",
            f"FucyFuzz failed to start:\n\n{exc}\n\n"
            "Check fucyfuzz_app.log for details."
        )
        sys.exit(1)

    window.show()

    result = app.exec_()

    # Clean shutdown
    try:
        from utils.session_logger import stop_session_logger
        stop_session_logger()
    except Exception:
        pass

    try:
        from utils.log_manager import close_all
        close_all()
    except Exception:
        pass

    log.info("FucyFuzz exiting (rc=%d)", result)
    sys.exit(result)


if __name__ == "__main__":
    main()
