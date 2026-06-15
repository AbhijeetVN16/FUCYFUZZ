"""
FucyFuzz CAN Interface Manager
================================
Centralized SocketCAN interface detection, validation, and setup guidance.

All fuzzer modules should use check_interface() before attempting CAN ops.
This module never crashes — it returns structured results callers can handle.
"""

import os
import platform
import subprocess
import logging
import threading
import time
from typing import Tuple, Optional, List

log = logging.getLogger(__name__)

# ── Platform ──────────────────────────────────────────────────────────────────
_PLATFORM = platform.system().lower()
IS_LINUX   = _PLATFORM == "linux"
IS_WINDOWS = _PLATFORM == "windows"

# ── Constants ─────────────────────────────────────────────────────────────────
KNOWN_VIRTUAL   = {"vcan0", "vcan1"}
KNOWN_PHYSICAL  = {"can0", "can1", "can2"}
KNOWN_WINDOWS   = {"pcan", "virtual", "usb2can", "vector", "kvaser"}
DEFAULT_TIMEOUT = 2.0        # seconds for non-blocking ops


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _sys_path(iface: str) -> str:
    return f"/sys/class/net/{iface}"


def _iface_exists(iface: str) -> bool:
    return os.path.exists(_sys_path(iface))


def _iface_is_up(iface: str) -> bool:
    flags_file = os.path.join(_sys_path(iface), "flags")
    try:
        if os.path.exists(flags_file):
            flags = int(open(flags_file).read().strip(), 16)
            return bool(flags & 0x1)   # IFF_UP
    except Exception:
        pass
    # Fall back to operstate
    op_file = os.path.join(_sys_path(iface), "operstate")
    try:
        state = open(op_file).read().strip().lower()
        return state in ("up", "unknown")
    except Exception:
        return False


def _iface_type(iface: str) -> str:
    """Return 'vcan', 'can', or 'unknown'."""
    type_file = os.path.join(_sys_path(iface), "type")
    try:
        t = int(open(type_file).read().strip())
        # SocketCAN = 280 (ARPHRD_CAN)
        if t == 280:
            vcan_file = os.path.join(_sys_path(iface), "statistics")
            return "vcan" if iface.startswith("v") else "can"
    except Exception:
        pass
    return "unknown"


def list_can_interfaces() -> List[str]:
    """Return all CAN-family interfaces visible in /sys/class/net/."""
    try:
        all_ifaces = os.listdir("/sys/class/net")
        can_ifaces = []
        for iface in sorted(all_ifaces):
            type_file = f"/sys/class/net/{iface}/type"
            try:
                if int(open(type_file).read().strip()) == 280:
                    can_ifaces.append(iface)
            except Exception:
                # also capture vcan* by name when type file is missing
                if iface.startswith(("can", "vcan")):
                    can_ifaces.append(iface)
        return can_ifaces
    except Exception:
        return []


# ── Main validation entry point ───────────────────────────────────────────────

class IfaceStatus:
    """Result object from check_interface()."""

    def __init__(self, iface: str, ok: bool, reason: str, setup_hint: str = ""):
        self.iface      = iface
        self.ok         = ok
        self.reason     = reason
        self.setup_hint = setup_hint

    def __bool__(self):
        return self.ok

    def user_message(self) -> str:
        lines = [f"[CAN] Interface '{self.iface}': {self.reason}"]
        if self.setup_hint:
            for ln in self.setup_hint.strip().splitlines():
                lines.append(f"  {ln}")
        return "\n".join(lines)


def check_interface(iface: str) -> IfaceStatus:
    """
    Validate a CAN interface.
    Returns IfaceStatus with ok=True if the interface exists and is UP.
    Never raises — all errors are encoded in the returned object.
    Platform-aware: Linux uses /sys/class/net; Windows accepts known names.
    """
    iface = iface.strip()
    if not iface:
        return IfaceStatus(iface, False, "No interface name provided.",
                           "Set an interface name in the Config tab.")

    # Windows: accept known interface names without filesystem check
    if IS_WINDOWS:
        lower = iface.lower()
        # Accept PCAN_USBBUS*, pcan*, virtual, vector, kvaser, com*, usb2can
        if (any(lower.startswith(k) for k in KNOWN_WINDOWS)
                or lower.startswith("com")
                or lower.startswith("pcan_usb")
                or lower.startswith("pcan_pci")):
            return IfaceStatus(iface, True, f"'{iface}' accepted (Windows PCAN/CAN adapter)")
        return IfaceStatus(
            iface, False,
            f"'{iface}' is not a recognised Windows CAN interface.",
            (
                "Supported Windows channel names:\n"
                "  PCAN USB:  PCAN_USBBUS1, PCAN_USBBUS2, PCAN_USBBUS3 ...\n"
                "  PCAN PCI:  PCAN_PCIBUS1, PCAN_PCIBUS2 ...\n"
                "  Virtual:   virtual\n"
                "  Vector:    VECTOR_0, VECTOR_1 ...\n"
                "Check your PEAK PCAN driver is installed: https://www.peak-system.com/"
            )
        )

    if not _iface_exists(iface):
        # Try to give a helpful setup hint
        available = list_can_interfaces()
        avail_str = ", ".join(available) if available else "none detected"

        if iface.startswith("vcan"):
            hint = (
                f"Virtual CAN interface '{iface}' is not initialised.\n"
                f"Run these commands to create it:\n\n"
                f"  sudo modprobe vcan\n"
                f"  sudo ip link add dev {iface} type vcan\n"
                f"  sudo ip link set up {iface}\n\n"
                f"Available CAN interfaces: {avail_str}"
            )
        else:
            hint = (
                f"Physical CAN interface '{iface}' not found.\n"
                f"To bring up a SocketCAN device:\n\n"
                f"  sudo ip link set {iface} type can bitrate 500000\n"
                f"  sudo ip link set up {iface}\n\n"
                f"For virtual testing use vcan0 instead.\n"
                f"Available CAN interfaces: {avail_str}"
            )
        return IfaceStatus(iface, False,
                           f"not found (Errno 19: No such device)", hint)

    if not _iface_is_up(iface):
        hint = (
            f"Interface '{iface}' exists but is DOWN.\n"
            f"Bring it up with:\n\n"
            f"  sudo ip link set up {iface}\n"
        )
        return IfaceStatus(iface, False, "interface is DOWN", hint)

    return IfaceStatus(iface, True, "UP and ready")


def auto_initialize_interface(iface: str, bitrate: int = 500000) -> Tuple[bool, str]:
    """
    Cross-platform CAN interface initialization.

    Linux:
      - vcan*  → modprobe vcan + ip link add/set
      - can*   → ip link set type can bitrate N + ip link set up
      Also loads peak_usb kernel module if 'can0' requested and module missing.

    Windows:
      - Validates PCAN adapter availability via python-can.
      Returns (ok, message).  Never raises.
    """
    iface = iface.strip()

    if IS_WINDOWS:
        return _init_windows_pcan(iface)

    if IS_LINUX:
        if iface.startswith("vcan"):
            return try_setup_vcan(iface)
        return _init_linux_can(iface, bitrate)

    return False, f"Unsupported OS: {_PLATFORM}"


def _init_windows_pcan(iface: str) -> Tuple[bool, str]:
    """Try to connect to PCAN adapter via python-can."""
    try:
        import can as pycan
    except ImportError:
        return False, (
            "python-can not installed.\n"
            "  pip install python-can\n"
            "  pip install 'python-can[pcan]'"
        )
    channel = iface if iface else "PCAN_USBBUS1"
    try:
        bus = pycan.interface.Bus(channel=channel, interface="pcan", bitrate=500000)
        bus.shutdown()
        return True, f"PCAN adapter '{channel}' is available and ready."
    except Exception as exc:
        return False, (
            f"PCAN adapter not reachable: {exc}\n"
            f"  1. Plug in PCAN USB adapter\n"
            f"  2. Install PEAK driver from https://www.peak-system.com/\n"
            f"  3. Install python-can PCAN backend: pip install 'python-can[pcan]'"
        )


def _init_linux_can(iface: str, bitrate: int) -> Tuple[bool, str]:
    """Bring up a physical SocketCAN interface on Linux, loading peak_usb if needed."""
    # Load peak_usb module for PCAN hardware
    try:
        subprocess.run(["sudo", "modprobe", "peak_usb"],
                       capture_output=True, timeout=5)
    except Exception:
        pass  # not critical — continue

    cmds = [
        ["sudo", "ip", "link", "set", iface, "type", "can", "bitrate", str(bitrate)],
        ["sudo", "ip", "link", "set", "up",  iface],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=8)
            if r.returncode != 0:
                stderr = r.stderr.decode(errors="replace").strip()
                # "already up" / "file exists" are not real failures
                if not any(ok in stderr.lower() for ok in ("already", "file exist", "busy")):
                    return False, f"Command failed: {' '.join(cmd)}\n{stderr}"
        except subprocess.TimeoutExpired:
            return False, f"Timed out: {' '.join(cmd)}"
        except FileNotFoundError:
            return False, "sudo / ip not found — cannot auto-setup."
        except Exception as e:
            return False, str(e)

    if _iface_exists(iface) and _iface_is_up(iface):
        return True, f"Interface '{iface}' is UP (bitrate {bitrate})."
    return False, (
        f"Setup ran but '{iface}' still not visible.\n"
        f"  • Check that the PCAN adapter is plugged in\n"
        f"  • Try: sudo modprobe peak_usb\n"
        f"  • Then: sudo ip link set {iface} type can bitrate {bitrate} && sudo ip link set up {iface}"
    )


# ── Non-blocking send/receive helpers ─────────────────────────────────────────

def try_setup_vcan(iface: str = "vcan0") -> Tuple[bool, str]:
    """
    Attempt to bring up a vcan interface without sudo (will fail if no privs).
    Returns (success, message).
    """
    cmds = [
        ["sudo", "modprobe", "vcan"],
        ["sudo", "ip", "link", "add", "dev", iface, "type", "vcan"],
        ["sudo", "ip", "link", "set", "up", iface],
    ]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            if r.returncode != 0 and b"already exists" not in r.stderr:
                return False, f"Command failed: {' '.join(cmd)}\n{r.stderr.decode()}"
        except subprocess.TimeoutExpired:
            return False, f"Timed out running: {' '.join(cmd)}"
        except FileNotFoundError:
            return False, "sudo not found — cannot auto-setup."
        except Exception as e:
            return False, str(e)

    if _iface_exists(iface) and _iface_is_up(iface):
        return True, f"Interface '{iface}' is now UP."
    return False, f"Setup commands ran but '{iface}' still not visible."


# ── Thread-safe non-blocking CAN frame sender ─────────────────────────────────

class NonBlockingCANSender:
    """
    Wraps raw SocketCAN sends with:
      - timeout enforcement (never hangs)
      - thread safety (single lock)
      - graceful error handling
    """

    def __init__(self, iface: str, timeout: float = DEFAULT_TIMEOUT):
        self.iface   = iface
        self.timeout = timeout
        self._lock   = threading.Lock()
        self._sock   = None
        self._closed = False

    def open(self) -> Tuple[bool, str]:
        """Open the raw CAN socket. Returns (ok, errmsg).
        Linux: raw AF_CAN socket.
        Windows/other: python-can Bus fallback.
        """
        if IS_WINDOWS:
            return self._open_pycan()
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_CAN, _socket.SOCK_RAW, _socket.CAN_RAW)
            s.settimeout(self.timeout)
            s.bind((self.iface,))
            with self._lock:
                self._sock   = s
                self._closed = False
                self._mode   = "raw"
            return True, "ok"
        except OSError as e:
            log.warning("Raw socket failed (%s), trying python-can", e)
            return self._open_pycan()
        except Exception as e:
            return False, str(e)

    def _open_pycan(self) -> Tuple[bool, str]:
        try:
            import can as pycan
            interface = "socketcan" if IS_LINUX else "pcan"
            channel   = self.iface
            if ":" in self.iface:
                parts, channel = self.iface.split(":", 1), self.iface.split(":", 1)[1]
                interface = self.iface.split(":", 1)[0]
            self._bus  = pycan.interface.Bus(channel=channel, interface=interface)
            with self._lock:
                self._closed = False
                self._mode   = "pycan"
            return True, "ok"
        except ImportError:
            return False, "python-can not installed (pip install python-can)"
        except Exception as e:
            return False, f"python-can open failed: {e}"

    def send_frame(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        """
        Send a single CAN frame.  Returns (ok, errmsg).
        Never blocks indefinitely — respects self.timeout.
        """
        import struct
        import socket as _socket

        with self._lock:
            if self._closed or self._sock is None:
                return False, "Socket not open"
            try:
                # Pack standard CAN frame: <I4sB3x (id, data padded to 8, dlc)
                data = data[:8]
                dlc  = len(data)
                padded = data + b'\x00' * (8 - dlc)
                frame = struct.pack("=IB3x8s", can_id & 0x1FFFFFFF, dlc, padded)
                self._sock.send(frame)
                return True, "ok"
            except _socket.timeout:
                return False, "send timeout"
            except OSError as e:
                return False, f"send error: {e}"
            except Exception as e:
                return False, str(e)

    def recv_frame(self) -> Tuple[Optional[int], Optional[bytes], str]:
        """
        Receive a CAN frame with timeout.
        Returns (can_id, data, errmsg).  can_id=None on error/timeout.
        """
        import struct
        import socket as _socket

        with self._lock:
            if self._closed or self._sock is None:
                return None, None, "Socket not open"
            try:
                raw = self._sock.recv(16)
                can_id, dlc = struct.unpack_from("=IB", raw, 0)
                data = raw[4:4 + dlc]
                return can_id & 0x1FFFFFFF, data, "ok"
            except _socket.timeout:
                return None, None, "recv timeout"
            except OSError as e:
                return None, None, f"recv error: {e}"
            except Exception as e:
                return None, None, str(e)

    def close(self):
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock   = None
                self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
