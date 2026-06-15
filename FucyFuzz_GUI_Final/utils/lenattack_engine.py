"""
FucyFuzz LenAttack Engine
==========================
Pure-Python DLC-length-attack backend.

What it does:
  Iterates DLC values from min_dlc to max_dlc (inclusive) and sends
  CAN frames with each DLC so the ECU must handle malformed / unexpected
  frame lengths.  Useful for testing length-check robustness.

Design:
  - Platform-aware: Linux SocketCAN (vcan0 / can0) + Windows PCAN / virtual
  - Non-blocking: stop-event + deadline enforced on every iteration
  - Structured logging: each frame → timestamp / CAN ID / DLC / payload / status
  - Thread-safe: single lock around the socket
  - Never hangs: timeout + stop-event respected everywhere

CLI format (used by subprocess mode / fucyfuzz binary):
    fucyfuzz lenattack 0x123 --min-dlc 0 --max-dlc 8 --pattern rand -i can0

Module name is always "lenattack" — interface is passed separately via -i.
"""

import os
import platform
import random
import struct
import sys
import threading
import time
import logging
from datetime import datetime
from typing import Optional, Callable, List, Tuple

log = logging.getLogger(__name__)

_IS_WINDOWS = sys.platform == "win32"


# ── Windows timer resolution (1 ms) ──────────────────────────────────────────
# On Windows, time.sleep() default resolution is ~15.6 ms which makes small
# delays (e.g. 0.001 s) wildly inaccurate.  timeBeginPeriod(1) raises the
# multimedia timer resolution to 1 ms for the lifetime of this call.

def _win_timer_begin() -> bool:
    """Set Windows multimedia timer period to 1 ms. Returns True if applied."""
    if not _IS_WINDOWS:
        return False
    try:
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
        return True
    except Exception:
        return False


def _win_timer_end():
    """Release the 1 ms Windows timer period."""
    if not _IS_WINDOWS:
        return
    try:
        import ctypes
        ctypes.windll.winmm.timeEndPeriod(1)
    except Exception:
        pass

# ── Types ─────────────────────────────────────────────────────────────────────
StatusCallback = Callable[[str], None]

PATTERNS = ("rand", "zeros", "ones", "incr", "decr", "alt")


# ── Payload generators ────────────────────────────────────────────────────────

def _build_payload(pattern: str, dlc: int) -> bytes:
    """Generate a payload of exactly `dlc` bytes according to pattern."""
    dlc = max(0, min(dlc, 8))
    if dlc == 0:
        return b""
    if pattern == "rand":
        return bytes(random.randint(0, 255) for _ in range(dlc))
    if pattern == "zeros":
        return b"\x00" * dlc
    if pattern == "ones":
        return b"\xff" * dlc
    if pattern == "incr":
        return bytes(i % 256 for i in range(dlc))
    if pattern == "decr":
        return bytes((255 - i) % 256 for i in range(dlc))
    if pattern == "alt":
        return bytes(0xAA if i % 2 == 0 else 0x55 for i in range(dlc))
    # fallback: random
    return bytes(random.randint(0, 255) for _ in range(dlc))


# ── Platform detection ────────────────────────────────────────────────────────

def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


# ── Interface validation ──────────────────────────────────────────────────────

class IfaceValidationResult:
    def __init__(self, ok: bool, reason: str = "", setup_hint: str = ""):
        self.ok         = ok
        self.reason     = reason
        self.setup_hint = setup_hint

    def __bool__(self):
        return self.ok

    def error_lines(self) -> List[str]:
        lines = [f"[IFACE ERROR] {self.reason}"]
        for ln in self.setup_hint.strip().splitlines():
            lines.append(f"  {ln}")
        return lines


def validate_interface(iface: str) -> IfaceValidationResult:
    """
    Platform-aware interface validation.
    Linux  → checks /sys/class/net/<iface>
    Windows → accepts pcan / virtual / com* without filesystem check
    """
    iface = (iface or "").strip()
    if not iface:
        return IfaceValidationResult(False, "No interface specified.",
                                     "Set an interface name (e.g. vcan0 / can0 / pcan).")

    if _is_windows():
        return _validate_windows(iface)

    if _is_linux():
        return _validate_linux(iface)

    # Unknown platform — warn but allow
    log.warning("Unknown platform '%s'; skipping interface validation.", platform.system())
    return IfaceValidationResult(True, f"'{iface}' accepted (platform unknown)")


def _validate_linux(iface: str) -> IfaceValidationResult:
    sys_path = f"/sys/class/net/{iface}"
    if not os.path.exists(sys_path):
        avail = _list_linux_ifaces()
        avail_str = ", ".join(avail) if avail else "none detected"
        if iface.startswith("vcan"):
            hint = (
                f"Virtual CAN '{iface}' not initialised.\n"
                f"Run:\n"
                f"  sudo modprobe vcan\n"
                f"  sudo ip link add dev {iface} type vcan\n"
                f"  sudo ip link set up {iface}\n"
                f"Available: {avail_str}"
            )
        else:
            hint = (
                f"Physical CAN '{iface}' not found.\n"
                f"Run:\n"
                f"  sudo ip link set {iface} type can bitrate 500000\n"
                f"  sudo ip link set up {iface}\n"
                f"Available: {avail_str}"
            )
        return IfaceValidationResult(
            False, f"'{iface}' not found (No such device)", hint
        )

    # Check UP flag
    flags_path = os.path.join(sys_path, "flags")
    try:
        flags = int(open(flags_path).read().strip(), 16)
        if not (flags & 0x1):
            return IfaceValidationResult(
                False, f"'{iface}' is DOWN",
                f"Bring it up with:  sudo ip link set up {iface}"
            )
    except Exception:
        pass

    return IfaceValidationResult(True, f"'{iface}' is UP")


def _validate_windows(iface: str) -> IfaceValidationResult:
    KNOWN_WIN = {"pcan", "virtual", "usb2can", "peak", "vector", "kvaser"}
    lower = iface.lower()
    if lower in KNOWN_WIN or lower.startswith("com") or lower.startswith("pcan"):
        return IfaceValidationResult(True, f"'{iface}' accepted (Windows)")
    # Try a loose check via python-can if installed
    try:
        import can
        # Attempting to peek at available channels (best-effort)
        return IfaceValidationResult(True, f"'{iface}' accepted by python-can")
    except ImportError:
        return IfaceValidationResult(
            False, f"python-can not installed",
            "Install with: pip install python-can"
        )


def _list_linux_ifaces() -> List[str]:
    try:
        all_ifaces = os.listdir("/sys/class/net")
        result = []
        for iface in sorted(all_ifaces):
            type_file = f"/sys/class/net/{iface}/type"
            try:
                if int(open(type_file).read().strip()) == 280:
                    result.append(iface)
            except Exception:
                if iface.startswith(("can", "vcan")):
                    result.append(iface)
        return result
    except Exception:
        return []


# ── CAN sender abstraction ────────────────────────────────────────────────────

class CANSender:
    """
    Thin wrapper around raw SocketCAN (Linux) or python-can (cross-platform).
    Provides send_frame(can_id, data) → (ok, errmsg).
    """

    def __init__(self, iface: str, timeout: float = 2.0):
        self.iface   = iface
        self.timeout = timeout
        self._sock   = None     # Linux raw socket
        self._bus    = None     # python-can Bus (Windows / fallback)
        self._lock   = threading.Lock()
        self._mode   = "none"   # "raw" | "pycan"

    def open(self) -> Tuple[bool, str]:
        """Open the CAN sender. Returns (ok, errmsg)."""
        if _is_linux():
            return self._open_raw()
        return self._open_pycan()

    def _open_raw(self) -> Tuple[bool, str]:
        """Linux raw SocketCAN socket."""
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_CAN, _socket.SOCK_RAW, _socket.CAN_RAW)
            s.settimeout(self.timeout)
            s.bind((self.iface,))
            self._sock = s
            self._mode = "raw"
            return True, "ok"
        except OSError as e:
            # Fallback to python-can if raw socket fails
            log.warning("Raw socket failed (%s), trying python-can fallback", e)
            return self._open_pycan()
        except Exception as e:
            return False, str(e)

    def _open_pycan(self) -> Tuple[bool, str]:
        """python-can Bus (cross-platform fallback)."""
        try:
            import can as pycan
        except ImportError:
            return False, (
                "python-can is not installed. "
                "Install with: pip install python-can"
            )
        try:
            # Auto-detect driver from channel name + OS
            ch_upper = channel.strip().upper()
            if _is_linux():
                interface = "socketcan"
            elif ch_upper.startswith("PCAN") or "PCAN" in ch_upper:
                interface = "pcan"
            elif ch_upper == "VIRTUAL":
                interface = "virtual"
            else:
                interface = "pcan"   # Windows default
            # Allow explicit override via iface containing ':'  e.g.  "pcan:PCAN_USBBUS1"
            if ":" in self.iface:
                parts     = self.iface.split(":", 1)
                interface = parts[0]
                channel   = parts[1]
            else:
                channel = self.iface

            self._bus  = pycan.interface.Bus(channel=channel, interface=interface)
            self._mode = "pycan"
            return True, "ok"
        except Exception as e:
            return False, f"python-can Bus open failed: {e}"

    def send_frame(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        """Send a single CAN frame. Returns (ok, errmsg). Never blocks > timeout."""
        with self._lock:
            if self._mode == "raw":
                return self._send_raw(can_id, data)
            if self._mode == "pycan":
                return self._send_pycan(can_id, data)
            return False, "Sender not open"

    def _send_raw(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        import socket as _socket
        try:
            data    = data[:8]
            dlc     = len(data)
            padded  = data + b'\x00' * (8 - dlc)
            frame   = struct.pack("=IB3x8s", can_id & 0x1FFFFFFF, dlc, padded)
            self._sock.send(frame)
            return True, "ok"
        except _socket.timeout:
            return False, "send timeout"
        except OSError as e:
            return False, f"send error: {e}"
        except Exception as e:
            return False, str(e)

    def _send_pycan(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        try:
            import can as pycan
            msg = pycan.Message(
                arbitration_id=can_id & 0x1FFFFFFF,
                data=list(data[:8]),
                is_extended_id=False
            )
            self._bus.send(msg, timeout=self.timeout)
            return True, "ok"
        except Exception as e:
            return False, str(e)

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            if self._bus:
                try:
                    self._bus.shutdown()
                except Exception:
                    pass
                self._bus = None
            self._mode = "none"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ── Logger ────────────────────────────────────────────────────────────────────

class LenAttackLogger:
    """
    Logs each transmitted frame to:
      - status callback (terminal display)
      - optional file (CSV)
      - SessionLogger (if active)
    """

    CSV_HEADER = "timestamp,can_id,dlc,payload_hex,pattern,status\n"

    def __init__(self, module: str, status_cb: Optional[StatusCallback],
                 log_path: Optional[str] = None):
        self._cb      = status_cb
        self._fh      = None
        self._module  = module

        if log_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log_path)),
                            exist_ok=True)
                self._fh = open(log_path, "a", encoding="utf-8")
                if self._fh.tell() == 0:
                    self._fh.write(self.CSV_HEADER)
            except Exception as e:
                self._emit(f"[WARN] Cannot open log file '{log_path}': {e}")

    def log_frame(self, can_id: int, dlc: int, payload: bytes,
                  pattern: str, status: str) -> None:
        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        hex_pay = payload.hex().upper() if payload else ""
        label   = "sent" if status == "ok" else f"error:{status}"

        # Terminal
        self._emit(
            f"[TX] id=0x{can_id:03X} dlc={dlc} "
            f"payload={hex_pay or '(empty)'} pattern={pattern} [{label}]"
        )

        # File
        if self._fh:
            try:
                self._fh.write(
                    f"{ts},0x{can_id:03X},{dlc},{hex_pay},{pattern},{label}\n"
                )
            except Exception:
                pass

        # Session logger
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.log_raw("TX", arb_id=can_id,
                           data_bytes=payload,
                           decoded=f"DLC={dlc} pattern={pattern} status={label}",
                           module=self._module)
        except Exception:
            pass

    def log_info(self, msg: str) -> None:
        self._emit(f"[INFO] {msg}")

    def log_error(self, msg: str) -> None:
        self._emit(f"[ERROR] {msg}")

    def _emit(self, line: str) -> None:
        if self._cb:
            try:
                self._cb(line)
            except Exception:
                pass
        log.debug("lenattack: %s", line)

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None


# ── Main engine ───────────────────────────────────────────────────────────────

class LenAttackEngine:
    """
    DLC Length Attack engine.

    For each target CAN ID, iterates DLC from min_dlc to max_dlc (inclusive),
    sends a frame with the specified payload pattern, logs it, and respects
    stop-event and timeout — no hanging, no silent crashes.

    Args:
        iface       : CAN interface name (vcan0, can0, pcan, virtual, …)
        targets     : list of CAN IDs to attack (integers)
        min_dlc     : smallest DLC to send (0–8)
        max_dlc     : largest DLC to send (0–8)
        pattern     : payload pattern name (rand, zeros, ones, incr, decr, alt)
        repeat      : if True, loop indefinitely until stopped
        delay       : seconds to wait between frames
        timeout     : hard deadline in seconds (enforced even with repeat=True)
        stop_event  : threading.Event — set to halt the engine
        status_cb   : callable(str) — receives status lines for display
        log_path    : optional CSV file path for structured logging
    """

    MODULE = "lenattack"

    def __init__(
        self,
        iface: str,
        targets: List[int],
        min_dlc: int          = 0,
        max_dlc: int          = 8,
        pattern: str          = "rand",
        repeat: bool          = False,
        delay: float          = 0.005,
        timeout: float        = 300.0,
        stop_event: Optional[threading.Event] = None,
        status_cb: Optional[StatusCallback]   = None,
        log_path: Optional[str]               = None,
    ):
        self.iface      = iface
        self.targets    = targets
        self.min_dlc    = max(0, min(min_dlc, 8))
        self.max_dlc    = max(0, min(max_dlc, 8))
        self.pattern    = pattern if pattern in PATTERNS else "rand"
        self.repeat     = repeat
        self.delay      = max(0.0, delay)
        self.timeout    = timeout
        self._stop      = stop_event or threading.Event()
        self._logger    = LenAttackLogger(self.MODULE, status_cb, log_path)
        self._sent      = 0
        self._errors    = 0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start_in_thread(self) -> threading.Thread:
        t = threading.Thread(
            target=self._safe_run, daemon=True, name="LenAttack"
        )
        t.start()
        return t

    def _safe_run(self) -> None:
        # Boost Windows timer resolution to 1 ms for accurate delays
        _timer_active = _win_timer_begin()
        try:
            self._safe_run_body()
        finally:
            if _timer_active:
                _win_timer_end()

    def _safe_run_body(self) -> None:
        # 1. Validate interface
        v = validate_interface(self.iface)
        if not v.ok:
            for line in v.error_lines():
                self._logger.log_error(line)
            return

        # 2. Validate arguments
        if not self.targets:
            self._logger.log_error(
                "No target CAN IDs specified. "
                "Provide at least one target ID (e.g. 0x123)."
            )
            return

        if self.min_dlc > self.max_dlc:
            self._logger.log_error(
                f"min_dlc ({self.min_dlc}) > max_dlc ({self.max_dlc}). "
                "Please set min_dlc ≤ max_dlc."
            )
            return

        # 3. Open CAN sender
        with CANSender(self.iface, timeout=2.0) as sender:
            ok, err = sender.open()
            if not ok:
                self._logger.log_error(
                    f"Cannot open CAN sender on '{self.iface}': {err}"
                )
                return

            self._logger.log_info(
                f"LenAttack started — iface={self.iface} "
                f"targets=[{', '.join(f'0x{t:X}' for t in self.targets)}] "
                f"dlc={self.min_dlc}→{self.max_dlc} "
                f"pattern={self.pattern} repeat={self.repeat}"
            )

            try:
                self._run_loop(sender)
            except Exception as exc:
                log.exception("LenAttackEngine error")
                self._logger.log_error(f"Unexpected error: {exc}")

        self._logger.log_info(
            f"LenAttack finished — sent={self._sent} errors={self._errors}"
        )
        self._logger.close()

    def _run_loop(self, sender: CANSender) -> None:
        deadline = time.time() + self.timeout

        while not self._stop.is_set():
            # ── one pass over all targets × all DLC values ─────────────────
            for target in self.targets:
                for dlc in range(self.min_dlc, self.max_dlc + 1):
                    if self._stop.is_set():
                        return
                    if time.time() > deadline:
                        self._logger.log_info(
                            f"Timeout ({self.timeout}s) reached — stopping."
                        )
                        return

                    payload = _build_payload(self.pattern, dlc)
                    ok, err = sender.send_frame(target, payload)
                    status  = "ok" if ok else err

                    self._logger.log_frame(target, dlc, payload,
                                           self.pattern, status)

                    if ok:
                        self._sent += 1
                    else:
                        self._errors += 1

                    # Interruptible delay — uses perf_counter for accuracy.
                    # On Windows, _win_timer_begin() raises timer resolution
                    # to 1 ms so time.sleep(0.001) actually sleeps ~1 ms.
                    if self.delay > 0:
                        end = time.perf_counter() + self.delay
                        while time.perf_counter() < end and not self._stop.is_set():
                            remaining = end - time.perf_counter()
                            if remaining <= 0:
                                break
                            # Sleep in 1 ms chunks so stop_event is checked often
                            time.sleep(min(0.001, remaining))

            # ── After one full pass ─────────────────────────────────────────
            if not self.repeat:
                break   # single-shot mode — done

            # repeat=True: continue from top of while loop


# ── Convenience: parse a target spec string ──────────────────────────────────

def parse_targets(spec: str) -> Tuple[List[int], str]:
    """
    Parse a target specification string into a list of CAN IDs.
    Supports:
      - Single ID:   "0x123"  or  "291"
      - Range:       "0x100-0x1FF"  or  "256-511"
      - Comma list:  "0x100,0x200,0x300"
    Returns (ids, error_message).  error_message is "" on success.
    """
    spec = spec.strip()
    ids: List[int] = []

    if not spec:
        return [], "Empty target specification."

    def _to_int(s: str) -> int:
        s = s.strip()
        return int(s, 16) if s.startswith(("0x", "0X")) else int(s, 0)

    # Range: contains '-' but not at start (negative numbers not valid CAN IDs)
    if "-" in spec and not spec.startswith("-"):
        parts = spec.split("-", 1)
        try:
            lo = _to_int(parts[0])
            hi = _to_int(parts[1])
            if lo > hi:
                return [], f"Range start {lo} > end {hi}."
            if hi > 0x7FF:
                return [], f"CAN ID {hi:#x} > 0x7FF (11-bit standard frame limit)."
            ids = list(range(lo, hi + 1))
        except ValueError as e:
            return [], f"Invalid range '{spec}': {e}"
        return ids, ""

    # Comma list
    if "," in spec:
        for tok in spec.split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                ids.append(_to_int(tok))
            except ValueError as e:
                return [], f"Invalid ID '{tok}': {e}"
        return ids, ""

    # Single ID
    try:
        ids.append(_to_int(spec))
    except ValueError as e:
        return [], f"Invalid CAN ID '{spec}': {e}"

    return ids, ""
