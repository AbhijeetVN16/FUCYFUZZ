"""
DoIP (Diagnostics over IP) Module Tab  —  ISO 13400
=====================================================
Full command parity with UDS tab. Operates over TCP/IP — NOT CAN.

Key differences from UDS/CAN tabs:
  • Uses ECU IP address + TCP port 13400 instead of CAN interface/IDs
  • The -i <iface> argument is still passed to satisfy binary CLI signature,
    but the DoIP runner injects --host / --port from saved config automatically.
  • A built-in self-contained DoIP engine (protocol_layer.doip_layer) is used
    as a direct fallback if the fucyfuzz binary fails due to the missing
    'doipclient' third-party dependency.

Supported sub-commands:
  discovery              scan for DoIP ECUs via UDP broadcast
  services               enumerate UDS services over DoIP
  ecu_reset              send ECU reset (ISO 14229 SID 0x11)
  testerpresent          send TesterPresent keep-alive (SID 0x3E)
  security_seed          capture security seeds (SID 0x27/0x67)
  dump_dids              enumerate DIDs by range (SID 0x22)
  seed_randomness_fuzzer fuzz seed randomness quality

CLI produced by build_args() — examples:
  fucyfuzz doip discovery
  fucyfuzz doip ecu_reset 1 0x7E0 0x7E8 --host 192.168.1.1 --port 13400
  fucyfuzz doip security_seed 0x3 0x1 0x7E0 0x7E8 -r 1 -d 0.5
  fucyfuzz doip dump_dids 0x7E0 0x7E8 --min_did 0x6300 --max_did 0x6fff -t 0.1
  fucyfuzz doip seed_randomness_fuzzer 2 2 0x7E0 0x7E8 -m 1 -t 10 -d 50 -id 4
"""

import math
import re
import time
import threading
import socket
import struct
from collections import Counter

from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QCheckBox, QHBoxLayout, QVBoxLayout, QGroupBox, QFrame,
    QPushButton
)
from PyQt5.QtCore import Qt, QTimer

from modules.base_tab import BaseModuleTab
from ui.widgets import SectionHeader, GlowButton, SolidButton
from ui.theme import COLORS


# ── Inline DoIP constants (no third-party deps) ───────────────────────────────
_DOIP_VER        = 0x02
_DOIP_VER_INV    = 0xFD
_TYPE_VEHICLE_ID = 0x0001   # vehicle identification request
_TYPE_ROUTING_REQ = 0x0005
_TYPE_ROUTING_RSP = 0x0006
_TYPE_DIAG       = 0x8001
_TYPE_DIAG_ACK   = 0x8002
_TYPE_DIAG_NACK  = 0x8003

_UDS_SA_REQ  = 0x27    # SecurityAccess request
_UDS_SA_RESP = 0x67    # SecurityAccess positive response
_UDS_TP      = 0x3E    # TesterPresent
_UDS_RESET   = 0x11    # ECUReset
_UDS_RDBI    = 0x22    # ReadDataByIdentifier
_UDS_NRC     = 0x7F    # NegativeResponse


def _pack_header(payload_type: int, payload: bytes) -> bytes:
    return struct.pack("!BBHI", _DOIP_VER, _DOIP_VER_INV,
                       payload_type, len(payload)) + payload


def _hex(v: str, default: int = 0) -> int:
    """Parse '0x1001' or '4097' → int safely."""
    try:
        v = v.strip()
        return int(v, 16) if v.lower().startswith('0x') else int(v, 10)
    except Exception:
        return default


class _DoIPEngine:
    """
    Self-contained DoIP/UDS engine using only Python stdlib (socket + struct).
    Used as a fallback when the fucyfuzz binary cannot import 'doipclient'.
    All public methods print human-readable output lines so they integrate
    naturally with the tab's terminal widget.
    """

    def __init__(self, host: str, port: int, logical_addr: int,
                 target_addr: int, timeout: float = 5.0):
        self.host         = host
        self.port         = port
        self.logical_addr = logical_addr
        self.target_addr  = target_addr
        self.timeout      = timeout
        self._sock        = None

    # ── Transport ─────────────────────────────────────────────────────────────

    def connect(self) -> tuple:
        """Returns (ok, msg)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            self._sock = s
            return True, f"Connected to {self.host}:{self.port}"
        except Exception as e:
            return False, f"Connection failed: {e}"

    def activate_routing(self) -> tuple:
        """Returns (ok, msg)."""
        if not self._sock:
            return False, "Not connected"
        try:
            payload = struct.pack("!HBH", self.logical_addr, 0x00, 0x0000)
            self._sock.sendall(_pack_header(_TYPE_ROUTING_REQ, payload))
            resp = self._recv_frame()
            if resp and resp[0] == _TYPE_ROUTING_RSP:
                code = resp[1][2] if len(resp[1]) > 2 else 0x00
                if code == 0x10:
                    return True, "Routing activated (successfully)"
                elif code == 0x11:
                    return True, "Routing activated (confirmation required)"
                return True, f"Routing response received (code=0x{code:02X})"
            return False, "No routing activation response"
        except Exception as e:
            return False, str(e)

    def _recv_frame(self) -> tuple:
        """Read one DoIP frame.  Returns (payload_type, data_bytes) or None."""
        if not self._sock:
            return None
        try:
            hdr = b''
            while len(hdr) < 8:
                chunk = self._sock.recv(8 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk
            _, _, ptype, plen = struct.unpack("!BBHI", hdr)
            data = b''
            while len(data) < plen:
                chunk = self._sock.recv(plen - len(data))
                if not chunk:
                    break
                data += chunk
            return ptype, data
        except Exception:
            return None

    def send_uds(self, payload: bytes, output_cb=None) -> tuple:
        """
        Send a UDS request over DoIP.
        Returns (ok, response_bytes).
        """
        if not self._sock:
            ok, msg = self.connect()
            if not ok:
                return False, msg.encode()
            ok, msg = self.activate_routing()
            if not ok:
                return False, msg.encode()

        if output_cb:
            import json, datetime
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            tx_pkt = {
                "transport": "DoIP", "direction": "TX",
                "src_addr": hex(self.logical_addr), "dst_addr": hex(self.target_addr),
                "arb_id": hex(self.target_addr), "data_hex": payload.hex().upper(), "ts": ts
            }
            output_cb("CC_PACKET " + json.dumps(tx_pkt))

        pkt = struct.pack("!HH", self.logical_addr, self.target_addr) + payload
        try:
            self._sock.sendall(_pack_header(_TYPE_DIAG, pkt))
            frame = self._recv_frame()
            if not frame:
                return False, b"No response (timeout)"
            ptype, data = frame
            
            resp_payload = b''
            if ptype == _TYPE_DIAG_ACK:
                # Read the actual UDS message (separate frame)
                frame2 = self._recv_frame()
                if frame2 and frame2[0] == _TYPE_DIAG:
                    resp_payload = frame2[1][4:]  # skip src+tgt logical addr
                else:
                    resp_payload = data
            elif ptype == _TYPE_DIAG_NACK:
                code = data[2] if len(data) > 2 else 0xFF
                resp_payload = bytes([_UDS_NRC, payload[0] if payload else 0, code])
            else:
                resp_payload = data
                
            if output_cb and resp_payload:
                import json, datetime
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                rx_pkt = {
                    "transport": "DoIP", "direction": "RX",
                    "src_addr": hex(self.target_addr), "dst_addr": hex(self.logical_addr),
                    "arb_id": hex(self.logical_addr), "data_hex": resp_payload.hex().upper(), "ts": ts
                }
                output_cb("CC_PACKET " + json.dumps(rx_pkt))
                
            return (ptype != _TYPE_DIAG_NACK), resp_payload
        except Exception as e:
            return False, str(e).encode()

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # ── High-level commands ────────────────────────────────────────────────────

    def run_ecu_reset(self, reset_type: int, output_cb):
        ok, msg = self.connect()
        output_cb(msg)
        if not ok:
            return
        ok, msg = self.activate_routing()
        output_cb(msg)
        if not ok:
            return
        output_cb(f"Sending ECU Reset (type=0x{reset_type:02X}) to {self.host}")
        ok, resp = self.send_uds(bytes([_UDS_RESET, reset_type]), output_cb=output_cb)
        if ok and len(resp) >= 2 and resp[0] == 0x51:
            output_cb(f"ECU Reset positive response: 0x{resp.hex()}")
        elif ok and len(resp) >= 3 and resp[0] == _UDS_NRC:
            output_cb(f"ECU Reset NRC: 0x{resp[2]:02X} — {resp.hex()}")
        else:
            output_cb(f"ECU Reset response: {'ERROR' if not ok else resp.hex()}")
        self.close()

    def run_tester_present(self, output_cb, interval: float = 2.0,
                           stop_event: threading.Event = None):
        ok, msg = self.connect()
        output_cb(msg)
        if not ok:
            return
        ok, msg = self.activate_routing()
        output_cb(msg)
        if not ok:
            return
        output_cb(f"TesterPresent loop started — sending to {self.host} every {interval}s")
        count = 0
        while True:
            if stop_event and stop_event.is_set():
                break
            ok, resp = self.send_uds(bytes([_UDS_TP, 0x00]), output_cb=output_cb)
            count += 1
            output_cb(f"Counter: {count}  |  "
                      f"{'OK 0x7E 0x00' if (ok and resp and resp[0]==0x7E) else resp.hex() if ok else 'no response'}")
            import time; time.sleep(interval)
        self.close()

    def run_security_seed(self, session: int, level: int,
                          output_cb, stop_event: threading.Event = None):
        """
        Continuously request security seeds from the ECU.
        session — UDS diagnostic session (1=default, 2=programming, 3=extended)
        level   — SecurityAccess level (odd numbers = requestSeed)
        """
        import time
        ok, msg = self.connect()
        output_cb(msg)
        if not ok:
            return
        ok, msg = self.activate_routing()
        output_cb(msg)
        if not ok:
            return
        # Enter the requested diagnostic session first
        if session != 1:
            ok, resp = self.send_uds(bytes([0x10, session]), output_cb=output_cb)
            if ok and resp and resp[0] == 0x50:
                output_cb(f"Session 0x{session:02X} entered OK")
            else:
                output_cb(f"Session 0x{session:02X} request: {resp.hex() if ok and resp else 'no response'}")
        output_cb(f"Security seed dump started (session=0x{session:02X} level=0x{level:02X}). Press KILL to stop.")
        count = 0
        while True:
            if stop_event and stop_event.is_set():
                break
            ok, resp = self.send_uds(bytes([_UDS_SA_REQ, level]), output_cb=output_cb)
            if ok and len(resp) >= 4 and resp[0] == _UDS_SA_RESP:
                seed_bytes = resp[2:]
                seed_hex   = '0x' + seed_bytes.hex().upper()
                count += 1
                output_cb(f"[Seed #{count}]  seed: {seed_hex}  (raw: {resp.hex()})")
            elif ok and len(resp) >= 3 and resp[0] == _UDS_NRC:
                output_cb(f"NRC 0x{resp[2]:02X} — {resp.hex()}")
            else:
                output_cb(f"No response to SecurityAccess request")
            time.sleep(0.5)
        output_cb(f"Security seed dump complete — {count} seeds captured")
        self.close()

    def run_dump_dids(self, min_did: int, max_did: int, timeout: float, output_cb,
                      stop_event: threading.Event = None):
        import time
        ok, msg = self.connect()
        output_cb(msg)
        if not ok:
            return
        ok, msg = self.activate_routing()
        output_cb(msg)
        if not ok:
            return
        output_cb(f"DID dump  0x{min_did:04X} → 0x{max_did:04X}  timeout={timeout}s")
        found = 0
        self._sock.settimeout(timeout)
        for did in range(min_did, max_did + 1):
            if stop_event and stop_event.is_set():
                break
            req = bytes([_UDS_RDBI, (did >> 8) & 0xFF, did & 0xFF])
            ok, resp = self.send_uds(req, output_cb=output_cb)
            if ok and len(resp) >= 3 and resp[0] == 0x62:
                found += 1
                output_cb(f"DID 0x{did:04X}  value={resp[3:].hex()}")
            time.sleep(0.005)
        output_cb(f"DID dump complete — {found} DIDs responded")
        self.close()

    def run_discovery(self, output_cb):
        """UDP broadcast vehicle identification request."""
        output_cb(f"DoIP UDP discovery on port {self.port} ...")
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.settimeout(2.0)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            req = _pack_header(_TYPE_VEHICLE_ID, b'')
            udp.sendto(req, ('255.255.255.255', self.port))
            found = 0
            while True:
                try:
                    data, addr = udp.recvfrom(1024)
                    found += 1
                    output_cb(f"ECU found — IP: {addr[0]}  port: {addr[1]}  data: {data[8:].hex()}")
                except socket.timeout:
                    break
            output_cb(f"Discovery complete — {found} ECU(s) found")
            udp.close()
        except Exception as e:
            output_cb(f"Discovery error: {e}")

    def run_services(self, output_cb, stop_event=None):
        """Brute-force enumerate supported UDS services over DoIP."""
        import time
        ok, msg = self.connect()
        output_cb(msg)
        if not ok:
            return
        ok, msg = self.activate_routing()
        output_cb(msg)
        if not ok:
            return
        output_cb("Service enumeration started (SID 0x00 → 0xFF) ...")
        found = []
        for sid in range(0x00, 0x100):
            if stop_event and stop_event.is_set():
                break
            ok, resp = self.send_uds(bytes([sid]), output_cb=output_cb)
            if ok and resp and resp[0] != _UDS_NRC:
                found.append(sid)
                output_cb(f"Service found: 0x{sid:02X}  resp={resp[:6].hex()}")
            time.sleep(0.01)
        output_cb(f"Service enumeration complete — {len(found)} service(s) supported: "
                  + " ".join(f"0x{s:02X}" for s in found))
        self.close()


class DoIPTab(BaseModuleTab):
    """
    DoIP tab — Ethernet-based UDS diagnostics (ISO 13400).

    Two execution paths:
      PATH 1 (normal):  fucyfuzz binary with --host / --port injected by runner.py
      PATH 2 (fallback): built-in _DoIPEngine via socket when binary raises
                         ModuleNotFoundError for 'doipclient'
    """

    MODULE_NAME = "doip"

    def __init__(self, runner, data_manager, parent=None):
        self._seeds_seen   = []
        self._seed_re      = re.compile(r'seed[\s:=]+([0-9a-fA-F x]+)', re.IGNORECASE)
        self._fallback_thread = None
        self._fallback_stop   = threading.Event()
        self._last_entropy_report = 0       # cooldown tracker
        self._entropy_reported_level = None  # dedup reported level
        super().__init__(runner, data_manager, parent)

    # ── Runner hooks ──────────────────────────────────────────────────────────

    def _on_started(self, cmd: str):
        self._seeds_seen.clear()
        self._last_entropy_report = 0
        self._entropy_reported_level = None
        self._fallback_stop.clear()
        super()._on_started(cmd)

    # Sub-commands that actually produce security seeds worth analysing
    _SEED_SUBCMDS = frozenset({'security_seed', 'seed_randomness_fuzzer'})

    def _extra_parse(self, line: str):
        """Live seed analysis — only active for security_seed / seed_randomness_fuzzer."""

        # Always check for the doipclient import error regardless of subcommand
        if 'ModuleNotFoundError' in line and 'doipclient' in line:
            self._add_fault(
                'high', line,
                "doipclient missing in binary — switching to built-in DoIP engine"
            )
            self.terminal.append(
                "⚠  'doipclient' not found in binary bundle. "
                "Switching to built-in DoIP engine (no extra packages needed).",
                COLORS.get('accent_yellow', '#facc15')
            )
            QTimer.singleShot(200, self._run_builtin_fallback)
            return

        # ── Format services output ────────────────────────────────────────────
        if line.startswith("Supported service 0x"):
            self.terminal.append(f"✔  {line}", COLORS.get('accent_green', '#00ff88'))
            return
        elif line.startswith("Identified Services:"):
            self.terminal.append(f"\n{line}", COLORS.get('accent_cyan', '#00d4ff'))
            return

        # ── Only analyse seeds when running a seed-related command ────────────
        # Any other command (dump_dids, services, ecu_reset, etc.) will produce
        # hex values in its output (DID addresses, service IDs, values…) that
        # must NOT be mistaken for security seeds.
        current_cmd = self.subcmd.currentText() if hasattr(self, 'subcmd') else ''
        if current_cmd not in self._SEED_SUBCMDS:
            return

        # Try the explicit "seed: 0x..." pattern first, then fall back to a
        # hex literal — but only on lines that actually look like seed output.
        # We require the line to contain a seed-related keyword so that
        # incidental hex numbers (counts, addresses, etc.) are ignored.
        _SEED_KEYWORDS = ('seed', 'security', 'captured', '0x67', '0x27')
        line_lower = line.lower()
        if not any(kw in line_lower for kw in _SEED_KEYWORDS):
            return

        m = self._seed_re.search(line)
        if not m:
            # Only fallback if it explicitly says 'positive response' to avoid catching logical addresses like 0x1000
            if 'positive response' in line_lower or '0x67' in line_lower:
                m = re.search(r'\b(0x[0-9a-fA-F]{4,16})\b', line)
            if not m:
                return

        val = m.group(1).strip()
        
        # Explicitly ignore standard DoIP/UDS logical addresses and sessions
        if val.lower() in ('0x1000', '0x0e00', '0x03', '0x01', '0x7e0', '0x7e8'):
            return

        self._seeds_seen.append(val)

        if self._seeds_seen.count(val) >= 2:
            self._add_fault(
                'critical', line,
                f"REPEATED DoIP SEED: '{val}' seen {self._seeds_seen.count(val)}× — NOT random!"
            )
            return

        if len(self._seeds_seen) >= 5:
            self._check_entropy()

    def _check_entropy(self):
        # Cooldown: only re-analyze every 30 seconds to avoid spam
        now = time.monotonic()
        if now - self._last_entropy_report < 30.0:
            return
        self._last_entropy_report = now

        seeds = self._seeds_seen
        unique    = len(set(seeds))
        total     = len(seeds)
        dup_ratio = 1.0 - unique / total

        if dup_ratio > 0.30 and self._entropy_reported_level != 'dup_critical':
            self._entropy_reported_level = 'dup_critical'
            self._add_fault(
                'critical',
                f"DoIP seed dup-ratio {dup_ratio:.0%}",
                f"HIGH DUPLICATE RATE (DoIP): {dup_ratio:.0%} repeated"
            )

        try:
            int_seeds = []
            for s in seeds:
                sc = s.strip().replace(' ', '')
                int_seeds.append(int(sc, 16) if sc.startswith('0x') else int(sc))
            all_bytes = []
            for v in int_seeds:
                all_bytes += [(v >> (i * 8)) & 0xFF for i in range(4)]
            counts = Counter(all_bytes)
            tb = len(all_bytes)
            H = -sum((c/tb)*math.log2(c/tb) for c in counts.values() if c > 0)
            if H < 3.0:
                level = 'entropy_critical'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault('critical',
                        f"DoIP seed entropy {H:.2f} bits",
                        f"CRITICAL: Very low DoIP seed entropy ({H:.2f}/8.0 bits)")
            elif H < 5.0:
                level = 'entropy_high'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault('high',
                        f"DoIP seed entropy {H:.2f} bits",
                        f"LOW DoIP SEED ENTROPY: {H:.2f}/8.0 bits")
            elif H < 6.5:
                level = 'entropy_medium'
                if self._entropy_reported_level != level:
                    self._entropy_reported_level = level
                    self._add_fault('medium',
                        f"DoIP seed entropy {H:.2f} bits",
                        f"MEDIUM DoIP SEED ENTROPY: {H:.2f}/8.0 bits")
        except (ValueError, ZeroDivisionError):
            pass

        try:
            last = []
            for s in seeds[-10:]:
                sc = s.strip().replace(' ', '')
                last.append(int(sc, 16) if sc.startswith('0x') else int(sc))
            diffs = [abs(last[i+1] - last[i]) for i in range(len(last)-1)]
            if len(set(diffs)) == 1 and diffs[0] != 0:
                self._add_fault('critical',
                    f"DoIP seeds increment by {hex(diffs[0])} — counter RNG",
                    f"COUNTER-BASED DoIP SEED: delta={hex(diffs[0])}")
        except (ValueError, IndexError):
            pass

    # ── Builtin fallback engine ───────────────────────────────────────────────

    def _get_engine(self) -> '_DoIPEngine':
        """Create a _DoIPEngine from current UI values."""
        host = self.doip_host.text().strip() or '127.0.0.1'
        port = self.doip_port.value() if hasattr(self, 'doip_port') else 13400
        la   = _hex(self.resp_id.text().strip(), 0x0E00)   # tester addr
        ta   = _hex(self.req_id.text().strip(),  0x1000)   # ECU target addr
        return _DoIPEngine(host, port, la, ta, timeout=5.0)

    def _run_builtin_fallback(self):
        """
        Called when binary fails with 'doipclient' missing.
        Runs the appropriate command using the built-in engine.
        """
        if self._fallback_thread and self._fallback_thread.is_alive():
            return

        cmd     = self.subcmd.currentText()
        req     = self.req_id.text().strip()
        resp    = self.resp_id.text().strip()
        engine  = self._get_engine()
        stop    = self._fallback_stop

        def _out(line: str):
            # Route through runner so it goes to session_logger AND the terminal GUI
            self.runner.output_line.emit(line)

        def _run():
            try:
                if cmd == "discovery":
                    engine.run_discovery(_out)
                elif cmd == "services":
                    engine.run_services(_out, stop_event=stop)
                elif cmd == "ecu_reset":
                    engine.run_ecu_reset(self.reset_type.value(), _out)
                elif cmd == "testerpresent":
                    engine.run_tester_present(_out, interval=2.0, stop_event=stop)
                elif cmd == "security_seed":
                    engine.run_security_seed(
                        session   = _hex(self.seed_session.text().strip(), 0x03),
                        level     = _hex(self.seed_level.text().strip(), 0x01),
                        output_cb = _out,
                        stop_event = stop,
                    )
                elif cmd == "dump_dids":
                    engine.run_dump_dids(
                        min_did   = _hex(self.min_did.text().strip(), 0x0000),
                        max_did   = _hex(self.max_did.text().strip(), 0xFFFF),
                        timeout   = 0.1,
                        output_cb = _out,
                        stop_event = stop,
                    )
                else:
                    _out(f"Built-in fallback: '{cmd}' not yet implemented; update fucyfuzz binary.")
            except Exception as exc:
                _out(f"Fallback engine error: {exc}")

        self._fallback_thread = threading.Thread(target=_run, daemon=True)
        self._fallback_thread.start()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_controls(self):
        self._controls_layout.addWidget(SectionHeader("DoIP Module  (Diagnostics over IP)"))

        # ── Sub-command ───────────────────────────────────────────────────────
        cmd_grp    = QGroupBox("Command")
        cmd_layout = QVBoxLayout(cmd_grp)
        self.subcmd = QComboBox()
        self.subcmd.addItems([
            "discovery",
            "services",
            "ecu_reset",
            "testerpresent",
            "security_seed",
            "dump_dids",
            "seed_randomness_fuzzer",
        ])
        self.subcmd.currentTextChanged.connect(self._on_subcmd_change)
        cmd_layout.addWidget(self.subcmd)
        self._controls_layout.addWidget(cmd_grp)

        # (IP address option removed per request)

        # ── DoIP Logical Addresses ─────────────────────────────────────────────
        # These map to the positional <target_addr> and <tester_addr> CLI args.
        self._ids_group = QGroupBox("DoIP Logical Addresses")
        ids_layout = QVBoxLayout(self._ids_group)

        ids_note = QLabel(
            "Target addr = ECU logical address (passed as 1st positional arg).\n"
            "Tester addr = client/tester logical address (2nd positional arg).\n"
            "Example:  fucyfuzz doip services 0x1000 0x0E00"
        )
        ids_note.setWordWrap(True)
        ids_note.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:9px;background:transparent;"
        )
        ids_layout.addWidget(ids_note)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Target Addr (ECU):"))
        self.req_id = QLineEdit("0x1000")
        self.req_id.setToolTip("ECU logical address — first positional argument")
        r1.addWidget(self.req_id)
        ids_layout.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Tester Addr (client):"))
        self.resp_id = QLineEdit("0x0E00")
        self.resp_id.setToolTip("Tester/client logical address — second positional argument")
        r2.addWidget(self.resp_id)
        ids_layout.addLayout(r2)

        self._controls_layout.addWidget(self._ids_group)

        # ── Discovery ─────────────────────────────────────────────────────────
        self._disc_group = QGroupBox("Discovery Options")
        disc_layout = QVBoxLayout(self._disc_group)
        disc_hint = QLabel(
            "Confirm ECU responds to UDS over DoIP.\n"
            "CLI:  fucyfuzz doip discovery\n"
            "The tool listens for UDP Vehicle Announcement automatically."
        )
        disc_hint.setWordWrap(True)
        disc_hint.setStyleSheet(
            f"color:{COLORS['text_secondary']};font-size:10px;background:transparent;"
        )
        disc_layout.addWidget(disc_hint)
        self._controls_layout.addWidget(self._disc_group)

        # ── ECU Reset ─────────────────────────────────────────────────────────
        self._reset_group = QGroupBox("ECU Reset Options")
        reset_layout = QVBoxLayout(self._reset_group)
        rl = QHBoxLayout()
        rl.addWidget(QLabel("Reset Type:"))
        self.reset_type = QSpinBox()
        self.reset_type.setRange(1, 255)
        self.reset_type.setValue(1)
        self.reset_type.setToolTip("1=hardReset  2=keyOffOnReset  3=softReset")
        rl.addWidget(self.reset_type)
        reset_layout.addLayout(rl)
        rt_hint = QLabel("1 = hardReset  |  2 = keyOffOnReset  |  3 = softReset")
        rt_hint.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:9px;background:transparent;"
        )
        reset_layout.addWidget(rt_hint)
        self._controls_layout.addWidget(self._reset_group)

        # ── Security Seed ─────────────────────────────────────────────────────
        # CLI: fucyfuzz doip security_seed <session> <level> <target> <tester> [-ip <ip>]
        self._seed_group = QGroupBox("Security Seed Options")
        seed_layout = QVBoxLayout(self._seed_group)
        seed_cli_hint = QLabel(
            "CLI: fucyfuzz doip security_seed <session> <level> <target> <tester> [-ip <ip>]\n"
            "Example (extended session, level 1):  security_seed 3 1 0x1000 0x0E00"
        )
        seed_cli_hint.setWordWrap(True)
        seed_cli_hint.setStyleSheet(
            f"color:{COLORS['text_muted']};font-size:9px;background:transparent;"
        )
        seed_layout.addWidget(seed_cli_hint)
        sl1 = QHBoxLayout()
        sl1.addWidget(QLabel("Session (e.g. 3=extended):"))
        self.seed_session = QLineEdit("3")
        self.seed_session.setToolTip("UDS diagnostic session: 1=default, 2=programming, 3=extended")
        sl1.addWidget(self.seed_session)
        seed_layout.addLayout(sl1)
        sl2 = QHBoxLayout()
        sl2.addWidget(QLabel("Level (e.g. 1):"))
        self.seed_level = QLineEdit("1")
        self.seed_level.setToolTip("Security access level (odd = requestSeed)")
        sl2.addWidget(self.seed_level)
        seed_layout.addLayout(sl2)
        self._controls_layout.addWidget(self._seed_group)

        # ── DID Dump ──────────────────────────────────────────────────────────
        self._did_group = QGroupBox("DID Dump Options")
        did_layout = QVBoxLayout(self._did_group)
        dl1 = QHBoxLayout()
        dl1.addWidget(QLabel("Min DID:"))
        self.min_did = QLineEdit("0x0000")
        dl1.addWidget(self.min_did)
        did_layout.addLayout(dl1)
        dl2 = QHBoxLayout()
        dl2.addWidget(QLabel("Max DID:"))
        self.max_did = QLineEdit("0xFFFF")
        dl2.addWidget(self.max_did)
        did_layout.addLayout(dl2)
        self._controls_layout.addWidget(self._did_group)

        # ── Seed Randomness Fuzzer ────────────────────────────────────────────
        # CLI: fucyfuzz doip seed_randomness_fuzzer <session> <level>
        #              <target> <tester> -t <num_seeds> [-d <delay_s>] [-ip <ip>]
        self._fuzz_group = QGroupBox("Seed Randomness Fuzzer Options")
        fuzz_layout = QVBoxLayout(self._fuzz_group)
        fhint = QLabel(
            "Collect multiple seeds after ECUReset and evaluate RNG quality.\n"
            "Detects: repeated seeds, low entropy, counter-based patterns.\n"
            "CLI: seed_randomness_fuzzer <session> <level> <target> <tester>\n"
            "     -t <num_seeds> [-d <delay_s>] [-ip <ip>]"
        )
        fhint.setWordWrap(True)
        fhint.setStyleSheet(
            f"color:{COLORS['text_secondary']};font-size:10px;background:transparent;"
        )
        fuzz_layout.addWidget(fhint)
        div = QFrame(); div.setFrameShape(QFrame.HLine)
        div.setStyleSheet(f"color:{COLORS['border']};")
        fuzz_layout.addWidget(div)
        f1 = QHBoxLayout()
        f1.addWidget(QLabel("Num Seeds (-t):"))
        self.fuzz_count = QSpinBox()
        self.fuzz_count.setRange(1, 999999)
        self.fuzz_count.setValue(50)
        self.fuzz_count.setToolTip("Number of seeds to collect (-t flag)")
        f1.addWidget(self.fuzz_count)
        fuzz_layout.addLayout(f1)
        f2 = QHBoxLayout()
        f2.addWidget(QLabel("Session (e.g. 3):"))
        self.fuzz_session = QSpinBox()
        self.fuzz_session.setRange(1, 127)
        self.fuzz_session.setValue(3)
        self.fuzz_session.setToolTip("Diagnostic session: 1=default, 2=programming, 3=extended")
        f2.addWidget(self.fuzz_session)
        fuzz_layout.addLayout(f2)
        f3 = QHBoxLayout()
        f3.addWidget(QLabel("Seed Level:"))
        self.fuzz_level = QSpinBox()
        self.fuzz_level.setRange(1, 99)
        self.fuzz_level.setValue(1)
        self.fuzz_level.setToolTip("Security access level to request seeds from")
        f3.addWidget(self.fuzz_level)
        fuzz_layout.addLayout(f3)
        f4 = QHBoxLayout()
        f4.addWidget(QLabel("Delay -d (seconds):"))
        self.fuzz_delay_s = QDoubleSpinBox()
        self.fuzz_delay_s.setDecimals(1)
        self.fuzz_delay_s.setRange(0.0, 3600.0)
        self.fuzz_delay_s.setValue(1.0)
        self.fuzz_delay_s.setToolTip("Delay in seconds between ECUReset and seed request (-d flag)")
        f4.addWidget(self.fuzz_delay_s)
        fuzz_layout.addLayout(f4)
        self._controls_layout.addWidget(self._fuzz_group)

        # Load saved values then set initial visibility
        self._load_doip_config()
        self._on_subcmd_change("discovery")

    # ── Config persistence ────────────────────────────────────────────────────

    def _load_doip_config(self):
        """Populate DoIP fields from saved config."""
        try:
            from utils.config import get_config
            cfg = get_config()
            # Load logical addresses into the IDs group
            self.req_id.setText(cfg.get('doip_target_addr', '0x1000'))
            self.resp_id.setText(cfg.get('doip_logical_addr', '0x0E00'))
        except Exception:
            pass

    def _save_doip_config(self):
        """Persist DoIP config whenever they change."""
        pass

    # ── Test Connection removed ───────────────────────────────────────────────

    # ── Visibility gating ─────────────────────────────────────────────────────

    def _on_subcmd_change(self, cmd: str):
        # _ids_group is always visible — all commands use target/tester addresses
        self._ids_group.setVisible(True)
        show = {
            self._disc_group:  cmd == "discovery",
            self._reset_group: cmd == "ecu_reset",
            self._seed_group:  cmd == "security_seed",
            self._did_group:   cmd == "dump_dids",
            self._fuzz_group:  cmd == "seed_randomness_fuzzer",
        }
        for grp, vis in show.items():
            grp.setVisible(vis)

    # ── CLI argument builder ──────────────────────────────────────────────────

    def build_args(self) -> list:
        """
        Build fucyfuzz CLI args matching the real binary's argparse layout.

        Real CLI signature (from fucyfuzz doip -h):
            fucyfuzz doip <subcmd> <target_addr> [<tester_addr>]

        Sub-command positional layouts:
            discovery           <target_addr>
            services            <target_addr> <tester_addr>
            ecu_reset           <reset_type> <target_addr> <tester_addr>
            testerpresent       <target_addr> <tester_addr>
            security_seed       <session> <level> <target_addr> <tester_addr>
            dump_dids           <target_addr> <tester_addr> [--min_did X] [--max_did Y]
            seed_randomness_fuzzer
                                <session> <level> <target_addr> <tester_addr>
                                -t <num_seeds> [-d <delay_s>]
        """
        cmd  = self.subcmd.currentText()
        req  = self.req_id.text().strip()   # target_addr  (ECU logical address)
        resp = self.resp_id.text().strip()  # tester_addr  (tester/client address)

        args = ["doip", cmd]

        if cmd == "discovery":
            # fucyfuzz doip discovery
            pass

        elif cmd == "services":
            # fucyfuzz doip services <tester_addr> <target_addr>
            args += [resp, req]

        elif cmd == "ecu_reset":
            # fucyfuzz doip ecu_reset <reset_type> <target_addr> <tester_addr>
            args += [str(self.reset_type.value()), req, resp]

        elif cmd == "testerpresent":
            # fucyfuzz doip testerpresent <target_addr> <tester_addr>
            args += [req, resp]

        elif cmd == "security_seed":
            # fucyfuzz doip security_seed <session> <level> <target_addr> <tester_addr>
            args += [
                self.seed_session.text().strip() or "3",
                self.seed_level.text().strip()   or "1",
                req, resp,
            ]

        elif cmd == "dump_dids":
            # fucyfuzz doip dump_dids <target_addr> <tester_addr>
            #          [--min_did X] [--max_did Y]
            args += [req, resp,
                     "--min_did", self.min_did.text().strip(),
                     "--max_did", self.max_did.text().strip(),
                     ]

        elif cmd == "seed_randomness_fuzzer":
            # fucyfuzz doip seed_randomness_fuzzer <session> <level>
            #          <target_addr> <tester_addr>
            #          -t <num_seeds> [-d <delay_s>]
            extra = ["-t", str(self.fuzz_count.value())]
            delay = self.fuzz_delay_s.value()
            if delay > 0:
                extra += ["-d", str(delay)]
            args += [
                str(self.fuzz_session.value()),
                str(self.fuzz_level.value()),
                req, resp,
            ] + extra

        return args

    def update_msg_list(self, msg_names: list):
        pass
