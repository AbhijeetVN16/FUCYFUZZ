"""
ISO-TP Handler — safe wrapper around python-can + python-isotp.

Cross-platform:
  Linux  + vcan0/can0  → socketcan driver
  Windows + PCAN_USBBUS1 → pcan driver
  Windows + virtual      → virtual driver

If the CAN interface is unavailable, raises a clear RuntimeError instead
of crashing with Errno 19 or "Unknown interface type None".
"""

import platform
import threading
import time
import logging

log = logging.getLogger(__name__)

IS_WINDOWS = platform.system().lower() == "windows"
IS_LINUX   = platform.system().lower() == "linux"


def _resolve_driver(channel: str, driver_override: str = None) -> str:
    """
    Determine the correct python-can driver for a given channel string.

    Rules:
      - If driver_override is provided, use it directly.
      - Windows: PCAN_* / PCAN → "pcan"
                 virtual       → "virtual"
                 anything else → "pcan" (safest Windows default)
      - Linux:   vcan* / can*  → "socketcan"
                 anything else → "socketcan"
    """
    if driver_override:
        return driver_override

    ch = (channel or "").strip().upper()

    if IS_WINDOWS:
        if ch.startswith("PCAN") or "PCAN" in ch:
            return "pcan"
        if ch == "VIRTUAL" or ch == "":
            return "virtual"
        return "pcan"          # Windows default

    # Linux
    return "socketcan"


class IsoTpHandler:
    """
    Thin wrapper around python-isotp CanStack.

    Parameters
    ----------
    channel : str
        Physical channel string.
        Linux:   "vcan0", "can0", etc.
        Windows: "PCAN_USBBUS1", "PCAN_USBBUS2", etc.
    driver : str, optional
        python-can interface type.  If None, auto-detected from channel + OS.
    bitrate : int
        CAN bitrate (used by PCAN and other hardware adapters).
    txid, rxid : int
        CAN arbitration IDs for TX and RX.
    """

    def __init__(self, channel: str = None, driver: str = None,
                 bitrate: int = 500000, txid: int = 0x7E0, rxid: int = 0x7E8):

        # ── Resolve channel default ────────────────────────────────────────────
        if not channel:
            channel = "PCAN_USBBUS1" if IS_WINDOWS else "vcan0"

        # ── Resolve driver automatically ───────────────────────────────────────
        resolved_driver = _resolve_driver(channel, driver)

        log.info("IsoTpHandler: channel=%s  driver=%s  tx=0x%X  rx=0x%X",
                 channel, resolved_driver, txid, rxid)

        # ── Validate interface on Linux ────────────────────────────────────────
        if IS_LINUX:
            from utils.can_interface import check_interface
            status = check_interface(channel)
            if not status.ok:
                raise RuntimeError(
                    f"Cannot open ISO-TP on '{channel}': {status.reason}\n"
                    + status.setup_hint
                )

        # ── Import dependencies ────────────────────────────────────────────────
        try:
            import can
            import isotp
        except ImportError as exc:
            raise RuntimeError(
                f"Missing dependency: {exc}.\n"
                "Install with: pip install python-can python-isotp\n"
                "Windows PCAN:  pip install 'python-can[pcan]'"
            )

        # ── Open CAN bus ───────────────────────────────────────────────────────
        try:
            bus_kwargs = dict(channel=channel, interface=resolved_driver)
            # Hardware adapters need bitrate specified
            if resolved_driver in ("pcan", "kvaser", "ixxat", "vector", "usb2can"):
                bus_kwargs["bitrate"] = bitrate

            self.bus = can.interface.Bus(**bus_kwargs)
            log.info("CAN bus opened: driver=%s  channel=%s", resolved_driver, channel)

        except Exception as exc:
            if IS_WINDOWS and resolved_driver == "pcan":
                raise RuntimeError(
                    f"Failed to open PCAN adapter '{channel}': {exc}\n"
                    "  1. Plug in your PCAN USB adapter\n"
                    "  2. Install PEAK driver: https://www.peak-system.com/\n"
                    "  3. Install python-can PCAN backend: pip install 'python-can[pcan]'\n"
                    "  4. Verify channel name (PCAN_USBBUS1, PCAN_USBBUS2, ...)"
                ) from exc
            raise RuntimeError(
                f"Failed to open CAN bus ({resolved_driver}, {channel}): {exc}\n"
                f"  Linux: sudo ip link set up {channel}"
            ) from exc

        # ── Set up ISO-TP stack ────────────────────────────────────────────────
        address = isotp.Address(
            isotp.AddressingMode.Normal_11bits,
            txid=txid,
            rxid=rxid,
        )
        self.stack = isotp.CanStack(
            bus=self.bus,
            address=address,
            params={"stmin": 0, "blocksize": 8, "tx_padding": 0x00},
        )

        self.running = True
        self._thread = threading.Thread(target=self._process, daemon=True)
        self._thread.start()
        log.info("IsoTpHandler ready on %s (driver=%s) tx=0x%X rx=0x%X",
                 channel, resolved_driver, txid, rxid)

    def _process(self):
        _consecutive_errors = 0
        _MAX_ERRORS = 10
        while self.running:
            try:
                self.stack.process()
                _consecutive_errors = 0   # reset on success
            except OSError as exc:
                # Bus went away (e.g. after ECU reset) — stop gracefully
                log.info("ISO-TP: bus disconnected (%s) — stopping thread", exc)
                self.running = False
                break
            except Exception as exc:
                _consecutive_errors += 1
                if _consecutive_errors <= 3:
                    log.warning("ISO-TP process error: %s", exc)
                elif _consecutive_errors == _MAX_ERRORS:
                    log.error("ISO-TP: too many consecutive errors — stopping thread")
                    self.running = False
                    break
            time.sleep(0.001)

    def send(self, data: bytes) -> None:
        try:
            self.stack.send(data)
        except Exception as exc:
            log.warning("ISO-TP send error: %s", exc)
            raise

    def receive(self, timeout: float = 2.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.stack.available():
                    return self.stack.recv()
            except Exception as exc:
                log.warning("ISO-TP receive error: %s", exc)
                return None
            time.sleep(0.01)
        return None

    def shutdown(self) -> None:
        self.running = False
        # Always stop the processing thread BEFORE shutting down the bus.
        # This prevents the thread from accessing a closed bus socket.
        try:
            if self._thread.is_alive():
                self._thread.join(timeout=2.0)
        except Exception:
            pass
        # Now safe to close the bus
        try:
            self.bus.shutdown()
        except Exception:
            pass
        log.info("IsoTpHandler shutdown complete.")
