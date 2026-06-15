"""
FucyFuzz DoIP Layer
====================
Diagnostics over IP (ISO 13400) client.
Handles vehicle announcement, routing activation, and UDS over DoIP.
Config-driven — parameters come from VehicleConfig.doip.
"""

import socket
import struct
import threading
import logging
from typing import Tuple, List, Optional

log = logging.getLogger(__name__)

# DoIP protocol constants
DOIP_VERSION        = 0x02
DOIP_VERSION_INV    = 0xFD
DOIP_VEHICLE_ANNOUNCE = 0x0004
DOIP_ROUTING_REQ    = 0x0005
DOIP_ROUTING_RSP    = 0x0006
DOIP_DIAG_MSG       = 0x8001
DOIP_DIAG_MSG_ACK   = 0x8002
DOIP_DIAG_MSG_NACK  = 0x8003


def _doip_header(payload_type: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI",
                       DOIP_VERSION, DOIP_VERSION_INV,
                       payload_type, len(payload)) + payload


class DoIPClient:
    """
    Minimal DoIP client for UDS-over-Ethernet diagnostics.
    Config-driven via VehicleConfig.doip.
    """

    def __init__(self, host: str, port: int = 13400,
                 logical_address: int = 0x0001,
                 timeout: float = 3.0):
        self.host            = host
        self.port            = port
        self.logical_address = logical_address
        self.timeout         = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, doip_config) -> "DoIPClient":
        return cls(
            host             = doip_config.host,
            port             = doip_config.port,
            logical_address  = doip_config.logical_address,
        )

    def connect(self) -> Tuple[bool, str]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            with self._lock:
                self._sock = s
            log.info("DoIP connected: %s:%d", self.host, self.port)
            return True, "ok"
        except Exception as e:
            return False, f"DoIP connect failed: {e}"

    def activate_routing(self) -> Tuple[bool, str]:
        """Send routing activation request."""
        payload  = struct.pack("!HBH", self.logical_address, 0x00, 0x0000)
        request  = _doip_header(DOIP_ROUTING_REQ, payload)
        try:
            with self._lock:
                if not self._sock:
                    return False, "Not connected"
                self._sock.sendall(request)
                resp = self._sock.recv(256)
            if len(resp) >= 8:
                rtype, = struct.unpack_from("!H", resp, 2)
                if rtype == DOIP_ROUTING_RSP:
                    return True, "Routing activated"
            return True, "Routing response received"
        except Exception as e:
            return False, str(e)

    def send_uds(self, service: int,
                 data: bytes = b"",
                 target_address: int = 0xE000) -> Tuple[bool, bytes]:
        """Send a UDS request over DoIP. Returns (ok, response_bytes)."""
        if not self._sock:
            ok, err = self.connect()
            if not ok:
                return False, err.encode()
            self.activate_routing()

        payload = struct.pack("!HH", self.logical_address, target_address)
        payload += bytes([service]) + data
        request  = _doip_header(DOIP_DIAG_MSG, payload)

        try:
            with self._lock:
                self._sock.sendall(request)
                resp = self._sock.recv(1024)

            if len(resp) < 8:
                return False, b"Response too short"

            rtype, rlen = struct.unpack_from("!HI", resp, 2)
            rdata = resp[8:8 + rlen]

            if rtype == DOIP_DIAG_MSG_ACK:
                # Positive ACK — read actual UDS response (may be separate packet)
                try:
                    uds_resp = self._sock.recv(1024)
                    if len(uds_resp) >= 8:
                        rtype2, rlen2 = struct.unpack_from("!HI", uds_resp, 2)
                        if rtype2 == DOIP_DIAG_MSG:
                            return True, uds_resp[8 + 4:]  # skip src+tgt addr
                except Exception:
                    pass
                return True, rdata

            if rtype == DOIP_DIAG_MSG_NACK:
                nack_code = rdata[2] if len(rdata) > 2 else 0xFF
                return False, bytes([0x7F, service, nack_code])

            return True, rdata

        except Exception as e:
            return False, str(e).encode()

    def discover(self) -> List[dict]:
        """UDP broadcast for DoIP vehicle announcements."""
        results = []
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(2.0)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            request = _doip_header(DOIP_VEHICLE_ANNOUNCE, b"")
            udp.sendto(request, ("<broadcast>", self.port))
            while True:
                try:
                    data, addr = udp.recvfrom(1024)
                    if len(data) >= 8:
                        results.append({
                            "ip":   addr[0],
                            "port": addr[1],
                            "data": data.hex(),
                        })
                except socket.timeout:
                    break
            udp.close()
        except Exception as e:
            log.debug("DoIP discovery: %s", e)
        return results

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
