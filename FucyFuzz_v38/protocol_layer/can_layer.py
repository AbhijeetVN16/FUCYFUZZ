"""
FucyFuzz CAN Layer
===================
Clean CAN send/receive API that uses VehicleConfig for all parameters.
Wraps utils/can_interface.py with vehicle-awareness.
"""

import json
import logging
import queue
import struct
import threading
import time
import platform
from typing import Tuple, Optional, List

log = logging.getLogger(__name__)

IS_LINUX   = platform.system().lower() == "linux"
IS_WINDOWS = platform.system().lower() == "windows"



# ── Async structured CAN frame logger ────────────────────────────────────────

class _FrameLogger:
    """Async writer for raw CAN frames to can_frames.jsonl."""
    def __init__(self):
        self._q      = queue.Queue(maxsize=50_000)
        self._path   = None
        self._lock   = threading.Lock()
        self._thread = threading.Thread(target=self._writer, daemon=True)
        self._thread.start()

    def set_session_path(self, path):
        with self._lock:
            self._path = path

    def log(self, direction: str, arb_id: int, data: bytes, iface: str, session: str = ""):
        with self._lock:
            if not self._path:
                return
        try:
            self._q.put_nowait({
                "ts": time.time(), "dir": direction,
                "arb_id": f"0x{arb_id:X}",
                "data": " ".join(f"{b:02X}" for b in data),
                "data_raw": list(data), "dlc": len(data),
                "iface": iface, "session": session,
            })
        except queue.Full:
            pass

    def _writer(self):
        while True:
            record = self._q.get()
            with self._lock:
                path = self._path
            if not path:
                continue
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception:
                pass


_frame_logger = _FrameLogger()


def get_frame_logger() -> _FrameLogger:
    return _frame_logger


class CANLayer:
    """
    Vehicle-config-aware CAN interface.
    Handles Linux SocketCAN and Windows python-can (PCAN).
    """

    def __init__(self, vehicle_config=None):
        self._cfg     = vehicle_config
        self._iface   = vehicle_config.can.interface if vehicle_config else "can0"
        self._bitrate = vehicle_config.can.bitrate   if vehicle_config else 500000
        self._timeout = (vehicle_config.can.timeout_ms / 1000.0) if vehicle_config else 0.1
        self._sock    = None
        self._bus     = None
        self._mode    = "none"
        self._lock    = threading.Lock()

    def open(self) -> Tuple[bool, str]:
        """Open the CAN interface. Auto-selects raw socket (Linux) or python-can."""
        if IS_LINUX:
            return self._open_raw()
        return self._open_pycan()

    def _open_raw(self) -> Tuple[bool, str]:
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_CAN, _socket.SOCK_RAW, _socket.CAN_RAW)
            s.settimeout(self._timeout)
            s.bind((self._iface,))
            with self._lock:
                self._sock = s
                self._mode = "raw"
            log.info("CAN raw socket opened: %s", self._iface)
            return True, "ok"
        except OSError as e:
            log.debug("Raw socket failed: %s — trying python-can", e)
            return self._open_pycan()
        except Exception as e:
            return False, str(e)

    def _open_pycan(self) -> Tuple[bool, str]:
        try:
            import can as pycan
            # Determine driver from channel name + OS
            if ":" in self._iface:
                interface, channel = self._iface.split(":", 1)
            else:
                channel   = self._iface
                ch_upper  = channel.strip().upper()
                if IS_WINDOWS:
                    if ch_upper.startswith("PCAN") or "PCAN" in ch_upper:
                        interface = "pcan"
                    elif ch_upper == "VIRTUAL":
                        interface = "virtual"
                    else:
                        interface = "pcan"   # safest Windows default
                else:
                    interface = "socketcan"

            bus_kwargs = dict(channel=channel, interface=interface)
            # Hardware adapters need bitrate
            if interface in ("pcan", "kvaser", "ixxat", "vector", "usb2can"):
                bus_kwargs["bitrate"] = self._bitrate

            self._bus = pycan.interface.Bus(**bus_kwargs)
            with self._lock:
                self._mode = "pycan"
            log.info("python-can bus opened: %s via %s", channel, interface)
            return True, "ok"
        except ImportError:
            return False, "python-can not installed. Run: pip install python-can"
        except Exception as exc:
            if IS_WINDOWS:
                return False, (
                    "python-can failed: " + str(exc) + "\n"
                    "  Ensure PCAN USB adapter is connected and Peak driver is installed.\n"
                    "  Install: pip install python-can 'python-can[pcan]'"
                )
            return False, "python-can failed: " + str(exc)

    def send(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        """Send a CAN frame. Returns (ok, error_string)."""
        with self._lock:
            if self._mode == "raw" and self._sock:
                ok, err = self._send_raw(can_id, data)
            elif self._mode == "pycan" and self._bus:
                ok, err = self._send_pycan(can_id, data)
            else:
                return False, "CAN not open"
        if ok:
            get_frame_logger().log("TX", can_id, data, self._iface)
        return ok, err

    def _send_raw(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        import socket as _socket
        try:
            data   = data[:8]
            dlc    = len(data)
            padded = data + b"\x00" * (8 - dlc)
            frame  = struct.pack("=IB3x8s", can_id & 0x1FFFFFFF, dlc, padded)
            self._sock.send(frame)
            return True, "ok"
        except _socket.timeout:
            return False, "send timeout"
        except OSError as e:
            return False, f"send error: {e}"

    def _send_pycan(self, can_id: int, data: bytes) -> Tuple[bool, str]:
        try:
            import can as pycan
            msg = pycan.Message(
                arbitration_id=can_id & 0x1FFFFFFF,
                data=list(data[:8]),
                is_extended_id=False
            )
            self._bus.send(msg, timeout=self._timeout)
            return True, "ok"
        except Exception as e:
            return False, str(e)

    def recv(self, timeout: float = None) -> Tuple[Optional[int], Optional[bytes], str]:
        """Receive a CAN frame. Returns (can_id, data, errmsg)."""
        to = timeout if timeout is not None else self._timeout
        with self._lock:
            if self._mode == "raw" and self._sock:
                can_id, data, err = self._recv_raw(to)
            elif self._mode == "pycan" and self._bus:
                can_id, data, err = self._recv_pycan(to)
            else:
                return None, None, "CAN not open"
        if can_id is not None and data is not None:
            get_frame_logger().log("RX", can_id, data, self._iface)
        return can_id, data, err

    def _recv_raw(self, timeout: float) -> Tuple[Optional[int], Optional[bytes], str]:
        import socket as _socket
        try:
            self._sock.settimeout(timeout)
            raw    = self._sock.recv(16)
            can_id, dlc = struct.unpack_from("=IB", raw, 0)
            data   = raw[4:4 + dlc]
            return can_id & 0x1FFFFFFF, data, "ok"
        except _socket.timeout:
            return None, None, "recv timeout"
        except OSError as e:
            return None, None, str(e)

    def _recv_pycan(self, timeout: float) -> Tuple[Optional[int], Optional[bytes], str]:
        try:
            msg = self._bus.recv(timeout=timeout)
            if msg is None:
                return None, None, "recv timeout"
            return msg.arbitration_id, bytes(msg.data), "ok"
        except Exception as e:
            return None, None, str(e)

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
        log.info("CAN layer closed.")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
