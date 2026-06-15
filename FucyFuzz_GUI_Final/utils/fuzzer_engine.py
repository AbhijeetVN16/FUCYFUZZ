"""
FucyFuzz Fuzzer Engine
======================
Pure-Python fuzzer backend for random, bruteforce, and mutate modes.

Design goals:
  - Non-blocking: all loops respect a stop event + timeout
  - Thread-safe: single sender lock, all state protected
  - Graceful: missing CAN interface → clear error, not crash
  - Loggable: every frame goes through the SessionLogger if active
"""

import os
import random
import re
import struct
import threading
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Iterator, Optional, Callable

from utils.can_interface import check_interface, NonBlockingCANSender

log = logging.getLogger(__name__)

# ── Types ─────────────────────────────────────────────────────────────────────

StatusCallback = Callable[[str], None]   # line → display in terminal


# ── Helpers ───────────────────────────────────────────────────────────────────

def _random_bytes(length: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(length))


def _expand_pattern(pattern: str) -> Iterator[bytes]:
    """
    Expand a pattern like '12ab..78' into concrete byte sequences.
    '..' is a wildcard — yields every 0x00–0xFF value for that position.
    Supports space-separated hex bytes and '..' wildcards.
    """
    pattern = pattern.strip()
    # Split on whitespace or dots-as-separators
    tokens = re.findall(r'\.{2}|[0-9a-fA-F]{2}', pattern)
    if not tokens:
        return

    fixed = []      # list of (is_wildcard, value)
    for tok in tokens:
        if tok == '..':
            fixed.append((True, 0))
        else:
            fixed.append((False, int(tok, 16)))

    # Count wildcards
    wc_indices = [i for i, (wc, _) in enumerate(fixed) if wc]

    if not wc_indices:
        # No wildcards — single frame
        yield bytes(v for _, v in fixed)
        return

    # Iterate over all wildcard combinations
    total = 256 ** len(wc_indices)
    for combo in range(total):
        frame = list(v for _, v in fixed)
        for pos, idx in enumerate(wc_indices):
            frame[idx] = (combo >> (8 * pos)) & 0xFF
        yield bytes(frame)


def _mutate_bytes(data: bytes, mutation_rate: float = 0.2) -> bytes:
    """Randomly mutate bytes in `data` with given per-byte probability."""
    out = bytearray(data)
    for i in range(len(out)):
        if random.random() < mutation_rate:
            action = random.randint(0, 3)
            if action == 0:
                out[i] = random.randint(0, 255)         # random byte
            elif action == 1:
                out[i] ^= random.randint(1, 255)        # bit-flip
            elif action == 2:
                out[i] = 0x00 if out[i] != 0 else 0xFF  # boundary
            else:
                out[i] = (out[i] + random.randint(1, 10)) & 0xFF  # increment
    return bytes(out)


# ── Log helpers ───────────────────────────────────────────────────────────────

def _log_frame(direction: str, can_id: int, data: bytes,
               status: str, module: str,
               severity: str = "", timestamp_tx: str = "",
               timestamp_rx: str = "") -> None:
    try:
        from utils.session_logger import get_session_logger, classify_severity
        sl = get_session_logger()
        if sl:
            decoded = f"status={status}"
            if not severity:
                severity = classify_severity(decoded)
            sl.log_raw(direction, arb_id=can_id, data_bytes=data,
                       decoded=decoded, module=module,
                       severity=severity,
                       timestamp_tx=timestamp_tx,
                       timestamp_rx=timestamp_rx)
    except Exception:
        pass


def _emit(cb: Optional[StatusCallback], msg: str) -> None:
    if cb:
        try:
            cb(msg)
        except Exception:
            pass


# ── Fuzzer classes ────────────────────────────────────────────────────────────

class BaseFuzzer:
    """Common state and lifecycle for all fuzzers."""

    MODULE = "fuzzer"

    def __init__(self, iface: str, can_id: int, delay: float,
                 stop_event: threading.Event,
                 status_cb: Optional[StatusCallback] = None,
                 log_path: Optional[str] = None):
        self.iface      = iface
        self.can_id     = can_id
        self.delay      = max(0.0, delay)
        self._stop      = stop_event
        self._cb        = status_cb
        self._log_path  = log_path
        self._log_fh    = None
        self._sent      = 0
        self._errors    = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def _open_log(self) -> None:
        if self._log_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self._log_path)),
                            exist_ok=True)
                self._log_fh = open(self._log_path, "a", encoding="utf-8")
                self._log_fh.write(
                    f"# FucyFuzz log — {self.__class__.__name__} "
                    f"iface={self.iface} id=0x{self.can_id:X} "
                    f"started={datetime.now().isoformat()}\n"
                    f"# timestamp,can_id,data_hex,status\n"
                )
            except Exception as e:
                _emit(self._cb, f"[WARN] Cannot open log file: {e}")

    def _write_log(self, can_id: int, data: bytes, status: str) -> None:
        if self._log_fh:
            try:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                self._log_fh.write(
                    f"{ts},0x{can_id:X},{data.hex().upper()},{status}\n"
                )
            except Exception:
                pass

    def _close_log(self) -> None:
        if self._log_fh:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            except Exception:
                pass
            self._log_fh = None

    def _check_stop(self) -> bool:
        return self._stop.is_set()

    def _send(self, sender: NonBlockingCANSender,
              can_id: int, data: bytes) -> bool:
        # Capture the exact TX timestamp before the frame hits the wire
        tx_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        ok, err = sender.send_frame(can_id, data)
        status  = "sent" if ok else f"error:{err}"
        _emit(self._cb,
              f"[TX] 0x{can_id:03X}#{data.hex().upper()}  {status}")
        _log_frame("TX", can_id, data, status, self.MODULE,
                   timestamp_tx=tx_ts)
        self._write_log(can_id, data, status)
        if ok:
            self._sent += 1
        else:
            self._errors += 1
        return ok

    def _summary(self) -> None:
        _emit(self._cb,
              f"[DONE] sent={self._sent} errors={self._errors}")

    def run(self) -> None:
        """Override in subclass."""
        raise NotImplementedError

    def start_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self._safe_run, daemon=True,
                             name=f"Fuzzer-{self.__class__.__name__}")
        t.start()
        return t

    def _safe_run(self):
        # Pre-flight interface check
        status = check_interface(self.iface)
        if not status.ok:
            _emit(self._cb, f"[ERROR] {status.user_message()}")
            return

        self._open_log()
        try:
            self.run()
        except Exception as exc:
            log.exception("Fuzzer error: %s", exc)
            _emit(self._cb, f"[ERROR] Fuzzer crashed: {exc}")
        finally:
            self._close_log()
            self._summary()


# ── Random fuzzer ─────────────────────────────────────────────────────────────

class RandomFuzzer(BaseFuzzer):
    """
    Sends random CAN frames on [can_id] with random DLC in [min_dlc, max_dlc].
    Stops when stop_event is set, max_frames reached, or timeout expires.
    """
    MODULE = "fuzzer.random"

    def __init__(self, iface: str, can_id: int,
                 min_dlc: int = 1, max_dlc: int = 8,
                 delay: float = 0.01,
                 max_frames: int = 0,         # 0 = unlimited
                 timeout: float = 300.0,      # 5 min default safety
                 seed: Optional[int] = None,
                 stop_event: Optional[threading.Event] = None,
                 status_cb: Optional[StatusCallback] = None,
                 log_path: Optional[str] = None):
        super().__init__(iface, can_id, delay,
                         stop_event or threading.Event(),
                         status_cb, log_path)
        self.min_dlc    = max(0, min(min_dlc, 8))
        self.max_dlc    = max(1, min(max_dlc, 8))
        self.max_frames = max_frames
        self.timeout    = timeout
        if seed is not None:
            random.seed(seed)
            _emit(status_cb, f"[INFO] Random seed set to {seed}")

    def run(self):
        _emit(self._cb, f"[START] RandomFuzzer iface={self.iface} "
              f"id=0x{self.can_id:X} dlc={self.min_dlc}-{self.max_dlc}")

        deadline = time.time() + self.timeout
        frame_n  = 0

        with NonBlockingCANSender(self.iface) as sender:
            ok, err = sender.open()
            if not ok:
                _emit(self._cb, f"[ERROR] {err}")
                return

            while not self._check_stop():
                if time.time() > deadline:
                    _emit(self._cb, "[INFO] Timeout reached — stopping.")
                    break
                if self.max_frames and frame_n >= self.max_frames:
                    _emit(self._cb, f"[INFO] Sent {frame_n} frames — done.")
                    break

                dlc  = random.randint(self.min_dlc, self.max_dlc)
                data = _random_bytes(dlc)
                self._send(sender, self.can_id, data)
                frame_n += 1

                if self.delay > 0:
                    # Interruptible sleep
                    end = time.time() + self.delay
                    while time.time() < end and not self._check_stop():
                        time.sleep(min(0.01, end - time.time()))


# ── Bruteforce fuzzer ─────────────────────────────────────────────────────────

class BruteforceFuzzer(BaseFuzzer):
    """
    Expands a pattern (e.g. '12ab..78') through all wildcard combinations
    and sends each as a CAN frame.
    """
    MODULE = "fuzzer.bruteforce"

    def __init__(self, iface: str, can_id: int,
                 pattern: str,
                 delay: float = 0.005,
                 timeout: float = 600.0,
                 stop_event: Optional[threading.Event] = None,
                 status_cb: Optional[StatusCallback] = None,
                 log_path: Optional[str] = None):
        super().__init__(iface, can_id, delay,
                         stop_event or threading.Event(),
                         status_cb, log_path)
        self.pattern = pattern
        self.timeout = timeout

    def run(self):
        _emit(self._cb, f"[START] BruteforceFuzzer iface={self.iface} "
              f"id=0x{self.can_id:X} pattern='{self.pattern}'")

        # Validate pattern
        tokens = re.findall(r'\.{2}|[0-9a-fA-F]{2}', self.pattern)
        if not tokens:
            _emit(self._cb, f"[ERROR] Invalid pattern: '{self.pattern}'. "
                  "Use hex bytes and '..' wildcards, e.g. '12ab..78'")
            return

        wc_count = sum(1 for t in tokens if t == '..')
        total    = 256 ** wc_count
        _emit(self._cb, f"[INFO] Pattern expands to {total:,} frames "
              f"({wc_count} wildcard positions)")

        deadline = time.time() + self.timeout

        with NonBlockingCANSender(self.iface) as sender:
            ok, err = sender.open()
            if not ok:
                _emit(self._cb, f"[ERROR] {err}")
                return

            for data in _expand_pattern(self.pattern):
                if self._check_stop():
                    break
                if time.time() > deadline:
                    _emit(self._cb, "[INFO] Timeout reached — stopping.")
                    break

                self._send(sender, self.can_id, data)

                if self.delay > 0:
                    end = time.time() + self.delay
                    while time.time() < end and not self._check_stop():
                        time.sleep(min(0.01, end - time.time()))


# ── Mutate fuzzer ─────────────────────────────────────────────────────────────

class MutateFuzzer(BaseFuzzer):
    """
    Mutates one or more base patterns and sends the mutated frames.
    NON-BLOCKING: respects stop_event and timeout — no infinite hangs.

    Key fix: removed blocking while-True loop; replaced with proper
    stop-event-driven loop with deadline enforcement.
    """
    MODULE = "fuzzer.mutate"

    def __init__(self, iface: str, can_id: int,
                 base_patterns: List[str],
                 mutation_rate: float = 0.2,
                 delay: float = 0.01,
                 max_frames: int = 1000,      # safety cap — 0 = unlimited
                 timeout: float = 300.0,
                 stop_event: Optional[threading.Event] = None,
                 status_cb: Optional[StatusCallback] = None,
                 log_path: Optional[str] = None):
        super().__init__(iface, can_id, delay,
                         stop_event or threading.Event(),
                         status_cb, log_path)
        self.base_patterns = base_patterns
        self.mutation_rate = mutation_rate
        self.max_frames    = max_frames
        self.timeout       = timeout

    def _parse_base(self, pattern: str) -> Optional[bytes]:
        """Parse a hex pattern (with optional '..' wildcards) into bytes."""
        tokens = re.findall(r'\.{2}|[0-9a-fA-F]{2}', pattern.strip())
        if not tokens:
            return None
        result = []
        for tok in tokens:
            result.append(random.randint(0, 255) if tok == '..' else int(tok, 16))
        return bytes(result)

    def run(self):
        _emit(self._cb, f"[START] MutateFuzzer iface={self.iface} "
              f"id=0x{self.can_id:X} patterns={self.base_patterns} "
              f"rate={self.mutation_rate} max={self.max_frames}")

        # Build seed corpus from patterns
        corpus: List[bytes] = []
        for pat in self.base_patterns:
            parsed = self._parse_base(pat)
            if parsed:
                corpus.append(parsed)
            else:
                _emit(self._cb, f"[WARN] Skipping invalid pattern: '{pat}'")

        if not corpus:
            _emit(self._cb, "[ERROR] No valid base patterns. "
                  "Use hex pairs and '..' wildcards, e.g. '7f.. 12ab....'")
            return

        _emit(self._cb, f"[INFO] Corpus size: {len(corpus)} base frame(s)")

        deadline  = time.time() + self.timeout
        frame_n   = 0

        with NonBlockingCANSender(self.iface) as sender:
            ok, err = sender.open()
            if not ok:
                _emit(self._cb, f"[ERROR] {err}")
                return

            # ── FIXED: non-blocking, stop-event-driven loop ────────────────
            while not self._check_stop():
                # Timeout guard — prevents indefinite hang
                if time.time() > deadline:
                    _emit(self._cb, f"[INFO] Timeout ({self.timeout}s) — stopping.")
                    break

                # Frame count guard
                if self.max_frames and frame_n >= self.max_frames:
                    _emit(self._cb, f"[INFO] Reached max_frames={self.max_frames} — stopping.")
                    break

                # Pick a random base and mutate it
                base    = random.choice(corpus)
                mutated = _mutate_bytes(base, self.mutation_rate)
                self._send(sender, self.can_id, mutated)
                frame_n += 1

                # Progress every 100 frames
                if frame_n % 100 == 0:
                    elapsed = time.time() - (deadline - self.timeout)
                    _emit(self._cb,
                          f"[INFO] Progress: {frame_n} frames sent "
                          f"({elapsed:.1f}s elapsed)")

                # Interruptible delay
                if self.delay > 0:
                    end = time.time() + self.delay
                    while time.time() < end and not self._check_stop():
                        time.sleep(min(0.005, end - time.time()))
