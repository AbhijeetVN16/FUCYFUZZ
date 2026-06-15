"""
FucyFuzz UDS Layer
===================
ISO 14229-1 UDS session management over CAN (ISO-TP).
Config-driven — all IDs come from VehicleConfig.can.

Features:
  - DiagnosticSessionControl
  - SecurityAccess (seed/key)
  - ReadDataByIdentifier
  - TesterPresent (keep-alive)
  - ReadDTCInformation
  - Configurable request/response IDs per vehicle
"""

import logging
import threading
import time
from typing import Tuple, Optional, List

log = logging.getLogger(__name__)

# UDS service IDs
SID_SESSION    = 0x10
SID_RESET      = 0x11
SID_CLEAR_DTC  = 0x14
SID_READ_DTC   = 0x19
SID_RDBI       = 0x22
SID_RMBA       = 0x23
SID_SA         = 0x27
SID_WDBI       = 0x2E
SID_RC         = 0x31
SID_TP         = 0x3E
SID_NRC        = 0x7F

NRC_NAMES = {
    0x10: "generalReject",          0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLength",
    0x22: "conditionsNotCorrect",   0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",   0x35: "invalidKey",
    0x36: "exceededAttempts",       0x37: "timeDelayNotExpired",
    0x78: "responsePending",        0x7E: "serviceNotInSession",
    0x7F: "serviceNotInSession",
}


class UDSSession:
    """
    Manages a UDS diagnostic session over CAN ISO-TP.
    Uses vehicle config for all IDs and timeouts.
    """

    def __init__(self, vehicle_config=None, timeout: float = 2.0):
        if vehicle_config:
            self._req_id  = vehicle_config.can.uds_request_id
            self._resp_id = vehicle_config.can.uds_response_id
            self._iface   = vehicle_config.can.interface
        else:
            self._req_id  = 0x7E0
            self._resp_id = 0x7E8
            self._iface   = "can0"
        self._timeout  = timeout
        self._isotp    = None
        self._tp_thread: Optional[threading.Thread] = None
        self._tp_running = False

    def open(self) -> Tuple[bool, str]:
        """Open ISO-TP session. Returns (ok, errmsg)."""
        import platform
        _is_windows = platform.system().lower() == "windows"

        try:
            import can as pycan
            import isotp

            # Auto-detect driver from channel + OS
            ch_upper = (self._iface or "").strip().upper()
            if _is_windows:
                if ch_upper.startswith("PCAN") or "PCAN" in ch_upper:
                    driver = "pcan"
                elif ch_upper == "VIRTUAL":
                    driver = "virtual"
                else:
                    driver = "pcan"
            else:
                driver = "socketcan"

            bus_kwargs = dict(channel=self._iface, interface=driver)
            if driver in ("pcan", "kvaser", "ixxat", "vector"):
                bus_kwargs["bitrate"] = 500000

            bus = pycan.interface.Bus(**bus_kwargs)
            addr = isotp.Address(
                isotp.AddressingMode.Normal_11bits,
                txid=self._req_id,
                rxid=self._resp_id
            )
            self._isotp = isotp.CanStack(bus=bus, address=addr,
                                          params={"stmin": 0, "blocksize": 8})
            self._tp_running = True
            self._tp_thread = threading.Thread(
                target=self._tp_loop, daemon=True, name="ISO-TP"
            )
            self._tp_thread.start()
            return True, "ok"
        except ImportError:
            return False, "python-isotp not installed. Run: pip install python-isotp"
        except Exception as exc:
            if _is_windows:
                msg = ("ISO-TP open failed: " + str(exc) + "\n"
                       "  Ensure PCAN adapter is connected and driver installed.\n"
                       "  Install: pip install python-can 'python-can[pcan]' python-isotp")
                return False, msg
            return False, "ISO-TP open failed: " + str(exc)

    def _tp_loop(self) -> None:
        while self._tp_running:
            try:
                if self._isotp:
                    self._isotp.process()
            except Exception:
                pass
            time.sleep(0.001)

    def send(self, req_id: int, payload: bytes) -> Tuple[bool, bytes]:
        """Send ISO-TP request and receive response."""
        if not self._isotp:
            ok, err = self.open()
            if not ok:
                return False, err.encode()
        try:
            self._isotp.send(payload)
            deadline = time.time() + self._timeout
            while time.time() < deadline:
                if self._isotp.available():
                    return True, bytes(self._isotp.recv())
                time.sleep(0.005)
            return False, b"\xff"  # timeout
        except Exception as e:
            return False, str(e).encode()

    def close(self) -> None:
        self._tp_running = False

    # ── High-level UDS methods ────────────────────────────────────────────────

    def session_control(self, session: int = 0x03) -> Tuple[bool, bytes]:
        """DiagnosticSessionControl. session: 01=default, 02=programming, 03=extended."""
        return self.send(self._req_id, bytes([SID_SESSION, session]))

    def tester_present(self) -> Tuple[bool, bytes]:
        return self.send(self._req_id, bytes([SID_TP, 0x00]))

    def ecu_reset(self, reset_type: int = 0x01) -> Tuple[bool, bytes]:
        return self.send(self._req_id, bytes([SID_RESET, reset_type]))

    def read_did(self, did: int) -> Tuple[bool, bytes]:
        return self.send(self._req_id,
                         bytes([SID_RDBI, (did >> 8) & 0xFF, did & 0xFF]))

    def request_seed(self, level: int = 0x01) -> Tuple[bool, bytes]:
        return self.send(self._req_id, bytes([SID_SA, level]))

    def send_key(self, level: int, key: bytes) -> Tuple[bool, bytes]:
        return self.send(self._req_id,
                         bytes([SID_SA, level + 1]) + key)

    def read_dtc(self, mask: int = 0xFF) -> Tuple[bool, bytes]:
        return self.send(self._req_id,
                         bytes([SID_READ_DTC, 0x02, mask]))

    @staticmethod
    def decode_nrc(resp: bytes) -> str:
        """Decode a negative response into human-readable text."""
        if len(resp) < 3 or resp[0] != SID_NRC:
            return ""
        sid = resp[1]
        nrc = resp[2]
        nrc_name = NRC_NAMES.get(nrc, f"0x{nrc:02X}")
        return f"NRC for SID 0x{sid:02X}: {nrc_name} (0x{nrc:02X})"
