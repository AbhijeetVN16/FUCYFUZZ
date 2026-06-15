"""
ECU Log Watcher
Tails the ECU simulator's JSONL log file in real time and pushes
structured vulnerability/failure events directly into the DataManager.

The ECU simulator writes two files:
  logs/ecu_simulation.log   — human readable
  logs/ecu_simulation.jsonl — one JSON object per line (machine readable)

This module watches the JSONL file. Each line is a log record.
We care about:
  - level=WARNING  + vuln_info  → vulnerability triggered
  - level=ERROR    + failure_info → ECU failure/crash
  - level=WARNING  with [VULN] in message → catch-all for vuln lines
  - level=ERROR    with [FAILURE] in message → catch-all for failures
"""

import os
import json
import threading
import time

from PyQt5.QtCore import QObject, pyqtSignal

# Map ECU vuln actions → FucyFuzz severity
ACTION_SEVERITY = {
    "CRASH":                    "critical",
    "HANG":                     "critical",
    "BYPASS_SECURITY":          "critical",
    "MODIFY_RESPONSE":          "critical",   # static seed = critical
    "LOGIC_ERR":                "high",
    "ACCEPT_ILLEGAL_TRANSITION":"high",
    "ACCEPT_PROGRAMMING_SESSION":"high",
    "FORCED_RESPONSE":          "critical",
    "FAULTED":                  "critical",
}

# Map log levels → fallback severity
LEVEL_SEVERITY = {
    "CRITICAL": "critical",
    "ERROR":    "high",
    "WARNING":  "medium",
    "INFO":     "low",
}


class ECULogWatcher(QObject):
    """
    Watches ecu_simulation.jsonl in a background thread.
    Emits fault_detected whenever a vulnerability or failure is found.
    """

    fault_detected = pyqtSignal(str, str, str, str)
    # severity, module_name, fault_description, reproduce_cmd

    status_changed = pyqtSignal(str)   # e.g. "Watching: logs/ecu_simulation.jsonl"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._path        = None     # explicit path (optional)
        self._ptr_path    = None     # path to current_session.txt pointer file
        self._active_path = None     # the path actually being watched right now
        self._thread      = None
        self._running     = False
        self._pos         = 0        # byte offset we've read up to

    def set_log_path(self, path: str):
        """Set an explicit JSONL path. Overrides pointer-file mode."""
        self._path     = path
        self._ptr_path = None

    def set_pointer_file(self, ptr_path: str):
        """
        Set path to current_session.txt.
        The watcher will read this file to find the current session JSONL,
        and automatically switch to a new session whenever it changes.
        This means you never have to manually update the path again.
        """
        self._ptr_path = ptr_path
        self._path     = None

    def start(self):
        if self._running:
            return
        if not self._path and not self._ptr_path:
            self.status_changed.emit("No log path set")
            return
        self._running = True
        self._pos     = 0
        self._thread  = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()
        label = self._ptr_path if self._ptr_path else self._path
        # Emit from main thread here (before background thread starts doing work)
        self.status_changed.emit(f"Started — monitoring: {os.path.basename(label)}")

    def stop(self):
        self._running = False

    def restart(self):
        """Reset read position to beginning of current file."""
        self._pos = 0

    def _resolve_path(self) -> str:
        """
        Return the JSONL path to watch.
        If using pointer file mode, read current_session.txt to get latest path.
        """
        if self._ptr_path and os.path.exists(self._ptr_path):
            try:
                with open(self._ptr_path, 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
        return self._path

    def _get_current_size(self, path: str) -> int:
        try:
            return os.path.getsize(path) if os.path.exists(path) else 0
        except Exception:
            return 0

    def _watch(self):
        _waiting_reported = False
        while self._running:
            try:
                # Resolve which file to watch (may change between sessions)
                path = self._resolve_path()

                if not path:
                    if not _waiting_reported:
                        self.status_changed.emit("Waiting — no path resolved yet. Is the ECU simulator running?")
                        _waiting_reported = True
                    time.sleep(0.5)
                    continue

                if not os.path.exists(path):
                    if not _waiting_reported:
                        self.status_changed.emit(f"Waiting for file: {path}")
                        _waiting_reported = True
                    time.sleep(0.5)
                    continue

                # Reset waiting flag once file found
                if _waiting_reported:
                    self.status_changed.emit(f"File found — reading: {os.path.basename(path)}")
                    _waiting_reported = False

                # Detect session switch — new file appeared
                if path != self._active_path:
                    self._active_path = path
                    self._pos = 0
                    folder = os.path.basename(os.path.dirname(path))
                    self.status_changed.emit(f"New session detected: {folder}")

                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(self._pos)
                    lines_read = 0
                    while self._running:
                        # Check if session has switched
                        new_path = self._resolve_path()
                        if new_path != self._active_path:
                            self.status_changed.emit(f"Session switched → {os.path.basename(os.path.dirname(new_path))}")
                            break   # outer loop picks up new session

                        line = f.readline()
                        if not line:
                            if lines_read > 0:
                                self.status_changed.emit(f"Read {lines_read} lines — waiting for new data...")
                                lines_read = 0
                            time.sleep(0.1)
                            continue
                        self._pos = f.tell()
                        line = line.strip()
                        if line:
                            lines_read += 1
                            self._process_line(line)
            except Exception as e:
                self.status_changed.emit(f"Watcher error: {e}")
                time.sleep(1.0)

    def _process_line(self, line: str):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Not valid JSON — try plain text parsing
            self._process_plain_text(line)
            return

        level   = record.get("level", "")
        message = record.get("message", "")

        # ── Vulnerability trigger (WARNING + vuln_info) ──────────────────────
        vuln_info = record.get("vuln_info")
        if vuln_info:
            self._emit_vuln_fault(vuln_info, record)
            return

        # ── Failure / crash (ERROR + failure_info) ───────────────────────────
        failure_info = record.get("failure_info")
        if failure_info:
            self._emit_failure_fault(failure_info, record)
            return

        # ── Catch-all for [VULN] lines without vuln_info ─────────────────────
        if "[VULN]" in message:
            severity = LEVEL_SEVERITY.get(level, "medium")
            self.fault_detected.emit(
                severity,
                "ecu_simulator",
                message[:200],
                ""
            )
            return

        # ── Catch-all for [FAILURE] lines ─────────────────────────────────────
        if "[FAILURE]" in message and level in ("ERROR", "CRITICAL"):
            self.fault_detected.emit(
                "critical",
                "ecu_simulator",
                message[:200],
                ""
            )
            return

        # ── ECU crash / faulted state ──────────────────────────────────────────
        if level in ("ERROR", "CRITICAL") and any(k in message for k in [
            "CRASH", "FAULT", "FAULTED", "ECU CRASH", "OVERFLOW", "EXCEPTION"
        ]):
            self.fault_detected.emit(
                "critical",
                "ecu_simulator",
                message[:200],
                ""
            )

    def _emit_vuln_fault(self, vuln_info: dict, record: dict):
        vid      = vuln_info.get("id", "UNKNOWN")
        name     = vuln_info.get("name", "Unknown Vulnerability")
        action   = vuln_info.get("action", "UNKNOWN")
        log_msg  = vuln_info.get("log_message", "")
        payload  = vuln_info.get("input_payload", "")
        reproduce= vuln_info.get("reproduce", "")

        severity = ACTION_SEVERITY.get(action, "high")

        # Build a clean description
        description = f"{vid} '{name}' — {log_msg}" if log_msg else f"{vid} '{name}' — Action={action}"

        # Build reproduce command
        if reproduce:
            cmd = reproduce
        elif payload:
            try:
                from utils.config import get_config
                iface = get_config().get('interface', 'vcan0')
            except Exception:
                iface = 'vcan0'
            cmd = f"cansend {iface} 7E0#{payload}"
        else:
            cmd = f"Payload: {payload}"

        self.fault_detected.emit(severity, f"ecu/{vid}", description, cmd)

    def _emit_failure_fault(self, failure_info: dict, record: dict):
        ftype    = failure_info.get("failure_type", "UNKNOWN")
        desc     = failure_info.get("description", "")
        payload  = failure_info.get("input_payload", "")
        steps    = failure_info.get("reproduce_steps", [])

        severity = "critical" if ftype in (
            "BUFFER_OVERFLOW", "CRASH", "EXCEPTION", "FAULTED"
        ) else "high"

        description = f"[FAILURE:{ftype}] {desc}"
        cmd = " | ".join(steps) if steps else (f"Payload: {payload}" if payload else "")

        self.fault_detected.emit(severity, f"ecu/failure", description, cmd)

    def _process_plain_text(self, line: str):
        """Fallback parser for the human-readable .log file format."""
        upper = line.upper()
        if "[VULN]" in upper:
            # Extract vuln ID and message
            severity = "critical" if "CRASH" in upper or "BYPASS" in upper else "high"
            self.fault_detected.emit(severity, "ecu_simulator", line[:200], "")
        elif "[FAILURE]" in upper:
            self.fault_detected.emit("critical", "ecu_simulator", line[:200], "")
        elif "[EFFECT] ECU CRASH" in upper or "FAULTED" in upper:
            self.fault_detected.emit("critical", "ecu_simulator", line[:200], "")
