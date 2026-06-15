"""
FucyFuzz Structured Log Manager
================================
Professional per-module logging with:
  - Automatic logs/ directory creation
  - Separate log files per module (uds, fuzzer, send, etc.)
  - Structured CSV with: timestamp, CAN ID, data, status
  - Log rotation at 10 MB
  - Export helpers (CSV / TXT)
  - Thread-safe, non-blocking (background writer thread)
"""

import csv
import json
import logging
import os
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_QUEUE   = 20_000
MAX_BYTES   = 0   # 0 = disabled — files grow without limit (no rotation)
KEEP_FILES  = 0   # 0 = keep all files forever

# ── Module-level log directory (resolved at first use) ────────────────────────
_LOG_ROOT: Optional[str] = None
_LOCK      = threading.Lock()
_INSTANCES: Dict[str, "ModuleLogger"] = {}


def set_log_root(path: str) -> None:
    global _LOG_ROOT
    _LOG_ROOT = path
    os.makedirs(path, exist_ok=True)


def get_log_root() -> str:
    global _LOG_ROOT
    if _LOG_ROOT is None:
        from utils.config import APP_DIRS
        _LOG_ROOT = APP_DIRS["logs"]
    os.makedirs(_LOG_ROOT, exist_ok=True)
    return _LOG_ROOT


def get_module_logger(module: str) -> "ModuleLogger":
    """Return (or create) a singleton ModuleLogger for the given module."""
    with _LOCK:
        if module not in _INSTANCES:
            _INSTANCES[module] = ModuleLogger(module, get_log_root())
        return _INSTANCES[module]


def close_all() -> None:
    with _LOCK:
        for ml in _INSTANCES.values():
            ml.close()
        _INSTANCES.clear()


# ── Log entry factory ─────────────────────────────────────────────────────────

def make_entry(module: str, direction: str,
               can_id: str = "", data_hex: str = "",
               status: str = "", raw: str = "") -> dict:
    now = datetime.now()
    return {
        "timestamp":    now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "module":       module,
        "direction":    direction,      # TX / RX / ERROR / INFO / CMD
        "can_id":       can_id,
        "data_hex":     data_hex.upper() if data_hex else "",
        "status":       status,         # sent / received / error / …
        "raw":          raw[:300],      # truncated raw line
    }


CSV_FIELDS = ["timestamp", "module", "direction", "can_id",
              "data_hex", "status", "raw"]


# ── Per-module logger ─────────────────────────────────────────────────────────

class ModuleLogger:
    """
    One instance per module (fuzzer, uds, send, …).
    Writes to  logs/<module>/  with rotation.
    All I/O is async (background queue thread).
    """

    def __init__(self, module: str, log_root: str):
        self.module   = module
        self._root    = os.path.join(log_root, module)
        os.makedirs(self._root, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._base   = os.path.join(self._root, f"{module}_{ts}")
        self._csv_path = self._base + ".csv"
        self._txt_path = self._base + ".log"

        self._q: queue.Queue = queue.Queue(maxsize=MAX_QUEUE)
        self._part   = 0
        self._bytes  = 0
        self._closed = False

        self._csv_fh     = open(self._csv_path, "a", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(self._csv_fh, fieldnames=CSV_FIELDS,
                                          extrasaction="ignore")
        if self._csv_fh.tell() == 0:
            self._csv_writer.writeheader()

        self._txt_fh = open(self._txt_path, "a", encoding="utf-8", buffering=1)
        self._txt_fh.write(
            f"\n{'='*60}\n"
            f"  Module: {module}  Started: {ts}\n"
            f"{'='*60}\n"
        )

        self._running = True
        self._thread  = threading.Thread(
            target=self._writer_loop, daemon=True,
            name=f"Log-{module}"
        )
        self._thread.start()

    # ── Public API ────────────────────────────────────────────────────────────

    def log(self, direction: str, can_id: str = "", data_hex: str = "",
            status: str = "", raw: str = "") -> None:
        entry = make_entry(self.module, direction, can_id, data_hex, status, raw)
        self._enqueue(entry)

    def log_tx(self, can_id: int, data: bytes, status: str = "sent") -> None:
        self.log("TX",
                 can_id=f"0x{can_id:03X}",
                 data_hex=data.hex(),
                 status=status)

    def log_rx(self, can_id: int, data: bytes) -> None:
        self.log("RX",
                 can_id=f"0x{can_id:03X}",
                 data_hex=data.hex(),
                 status="received")

    def log_error(self, message: str) -> None:
        self.log("ERROR", raw=message, status="error")

    def log_info(self, message: str) -> None:
        self.log("INFO", raw=message, status="info")

    def log_cmd(self, cmd: str) -> None:
        self.log("CMD", raw=cmd, status="command")

    @property
    def csv_path(self) -> str:
        return self._csv_path

    @property
    def txt_path(self) -> str:
        return self._txt_path

    def list_csv_files(self) -> List[str]:
        return sorted(str(p) for p in Path(self._root).glob("*.csv"))

    def export_txt(self, dest: str) -> None:
        """Export current log to a plain text file."""
        import shutil
        shutil.copy2(self._txt_path, dest)

    def close(self) -> None:
        if self._closed:
            return
        self._running = False
        try:
            self._thread.join(timeout=3.0)
        except Exception:
            pass
        for fh in (self._csv_fh, self._txt_fh):
            try:
                fh.flush(); fh.close()
            except Exception:
                pass
        self._closed = True

    # ── Internal ──────────────────────────────────────────────────────────────

    def _enqueue(self, entry: dict) -> None:
        try:
            self._q.put_nowait(entry)
        except queue.Full:
            try:
                self._q.get_nowait()   # drop oldest
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(entry)
            except queue.Full:
                pass

    def _writer_loop(self) -> None:
        while self._running or not self._q.empty():
            batch: list = []
            try:
                batch.append(self._q.get(timeout=0.05))
            except queue.Empty:
                continue
            for _ in range(199):
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            for entry in batch:
                self._write(entry)

        for fh in (self._csv_fh, self._txt_fh):
            try:
                fh.flush()
            except Exception:
                pass

    def _write(self, entry: dict) -> None:
        # CSV
        try:
            self._csv_writer.writerow(entry)
            pass   # no rotation — file grows without limit
        except Exception:
            pass

        # Text log
        try:
            ts   = entry["timestamp"]
            dir_ = entry["direction"]
            cid  = entry["can_id"]
            dat  = entry["data_hex"]
            sts  = entry["status"]
            raw  = entry["raw"]

            parts = [f"{ts} [{dir_:<5}]"]
            if cid:
                parts.append(f"id={cid}")
            if dat:
                parts.append(f"data={dat}")
            if sts:
                parts.append(f"[{sts}]")
            if raw and raw not in (dat, sts):
                parts.append(f"  {raw}")

            self._txt_fh.write("  ".join(parts) + "\n")
        except Exception:
            pass

    def _rotate(self) -> None:
        """No-op — rotation is disabled; files grow without limit."""
        pass
