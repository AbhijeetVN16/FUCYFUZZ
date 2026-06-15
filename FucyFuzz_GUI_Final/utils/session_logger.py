"""
FucyFuzz Session Logger
=======================
Self-contained logging engine — independent of ECU simulator.

Per-session output in logs/session_<timestamp>/:
    session.log     human-readable text
    session.csv     structured: timestamp, direction, arb_id, data_hex, decoded, module
    session.jsonl   one JSON object per line (full detail for replay)

Global append log: logs/fucyfuzz.log

All I/O is done on a daemon thread; callers never block.
Queue is capped at MAX_QUEUE_SIZE — oldest entry dropped if full.
"""

import csv
import json
import logging
import os
import queue
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, Dict

log = logging.getLogger(__name__)

MAX_QUEUE_SIZE = 50_000
# No file-size limit — every session is a single unlimited set of files.
# Each GUI launch creates a brand-new session dir so there is no carry-over.
# No rotation — all session files grow without limit (disk is cheap).
# Old sessions are never auto-deleted.
KEEP_SESSIONS  = 0   # 0 = keep forever

# ── Severity Classification ────────────────────────────────────────────────────
# Used for both live fault entries and post-hoc log analysis.

SEVERITY_CRITICAL = "CRITICAL"   # ECU crash, total timeout, loss of comms
SEVERITY_HIGH     = "HIGH"       # Security bypass, critical unexpected behaviour
SEVERITY_LOW      = "LOW"        # Standard NRC / normal rejection
SEVERITY_INFO     = "INFO"       # Informational only

# Patterns that map to CRITICAL severity
_CRITICAL_PATTERNS = (
    "crash", "ecu reset", "ecu restarted", "bus off", "bus-off",
    "no response", "timeout", "exception", "overflow", "corruption",
    "segfault", "panic", "hang", "bypass_security", "security bypass",
    "access granted", "unlocked",
)

# Patterns that map to HIGH severity
_HIGH_PATTERNS = (
    "security access denied", "securityaccessdenied", "unauthorized",
    "illegal transition", "logic_err", "modify_response", "static seed",
    "deadbeef", "predictable seed", "weak seed", "repeated seed",
    "invalid key", "exceededattempts",
)

# Patterns that map to LOW severity (standard NRCs and normal rejections)
_LOW_PATTERNS = (
    "nrc=", "negativeresp", "negresp", "generalreject",
    "servicenotsupported", "subfnnotsupported", "incorrectmsglength",
    "conditionsnotcorrect", "requestoutofrange", "servicenot",
    "responsepending",
)


def classify_severity(text: str) -> str:
    """
    Classify a log line or decoded UDS string into a severity level.

    Returns one of SEVERITY_CRITICAL / SEVERITY_HIGH / SEVERITY_LOW / SEVERITY_INFO.
    """
    lower = text.lower()
    for pat in _CRITICAL_PATTERNS:
        if pat in lower:
            return SEVERITY_CRITICAL
    for pat in _HIGH_PATTERNS:
        if pat in lower:
            return SEVERITY_HIGH
    for pat in _LOW_PATTERNS:
        if pat in lower:
            return SEVERITY_LOW
    return SEVERITY_INFO

# ── UDS decode tables ─────────────────────────────────────────────────────────

_SID_NAMES: Dict[int, str] = {
    0x10: "DiagnosticSessionControl",  0x11: "ECUReset",
    0x14: "ClearDTCInformation",       0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",      0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",            0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",     0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",             0x7F: "NegativeResponse",
    0x50: "DiagSessCtrl_Resp",         0x51: "ECUReset_Resp",
    0x62: "ReadDataByID_Resp",         0x63: "ReadMemByAddr_Resp",
    0x67: "SecurityAccess_Resp",       0x6E: "WriteDataByID_Resp",
    0x7E: "TesterPresent_Resp",
}

_NRC_NAMES: Dict[int, str] = {
    0x10: "GeneralReject",             0x11: "ServiceNotSupported",
    0x12: "SubFnNotSupported",         0x13: "IncorrectMsgLength",
    0x22: "ConditionsNotCorrect",      0x31: "RequestOutOfRange",
    0x33: "SecurityAccessDenied",      0x35: "InvalidKey",
    0x36: "ExceededAttempts",          0x37: "TimeDelayNotExpired",
    0x78: "ResponsePending",           0x7E: "ServiceNotInSession",
}

_SESSION_TYPES: Dict[int, str] = {0x01: "Default", 0x02: "Programming", 0x03: "Extended"}
_RESET_TYPES:   Dict[int, str] = {0x01: "HardReset", 0x02: "KeyOffOn", 0x03: "SoftReset"}


def decode_uds(arb_id: int, data: bytes) -> str:
    """
    Return a fully human-readable description of a UDS frame.

    Covers all common SIDs including WriteDataByIdentifier (0x2E),
    TesterPresent (0x3E), SecurityAccess request/response (0x27/0x67),
    NegativeResponse (0x7F) with NRC names, and positive responses.
    Returns '' for non-UDS or unrecognised frames.
    """
    if not data:
        return ""
    sid = data[0]
    name = _SID_NAMES.get(sid, f"SID_0x{sid:02X}")
    try:
        # ── 0x7F  NegativeResponse ───────────────────────────────────────────
        if sid == 0x7F and len(data) >= 3:
            req_sid  = data[1]
            nrc_byte = data[2]
            req_name = _SID_NAMES.get(req_sid, f"SID_0x{req_sid:02X}")
            nrc_name = _NRC_NAMES.get(nrc_byte, f"0x{nrc_byte:02X}")
            return f"NegResp({req_name}) NRC={nrc_name}(0x{nrc_byte:02X})"

        # ── 0x10  DiagnosticSessionControl ──────────────────────────────────
        if sid == 0x10 and len(data) >= 2:
            sub = data[1] & 0x7F
            return f"{name}({_SESSION_TYPES.get(sub, f'type=0x{sub:02X}')})"

        # ── 0x50  DiagnosticSessionControl positive response ────────────────
        if sid == 0x50 and len(data) >= 2:
            sub = data[1] & 0x7F
            return f"DiagSessCtrl_OK({_SESSION_TYPES.get(sub, f'0x{sub:02X}')})"

        # ── 0x11  ECUReset ──────────────────────────────────────────────────
        if sid == 0x11 and len(data) >= 2:
            return f"{name}({_RESET_TYPES.get(data[1], f'type=0x{data[1]:02X}')})"

        # ── 0x22  ReadDataByIdentifier ──────────────────────────────────────
        if sid == 0x22 and len(data) >= 3:
            did = (data[1] << 8) | data[2]
            did_label = {0xF190: "VIN", 0xF197: "SystemName",
                         0xF18C: "ECU_Serial", 0xF187: "PartNumber"}.get(did, "")
            label = f"DID=0x{did:04X}" + (f"({did_label})" if did_label else "")
            return f"{name}({label})"

        # ── 0x62  ReadDataByIdentifier positive response ────────────────────
        if sid == 0x62 and len(data) >= 3:
            did   = (data[1] << 8) | data[2]
            val   = data[3:].hex().upper() if len(data) > 3 else ""
            did_label = {0xF190: "VIN", 0xF197: "SystemName",
                         0xF18C: "ECU_Serial", 0xF187: "PartNumber"}.get(did, "")
            label = f"DID=0x{did:04X}" + (f"({did_label})" if did_label else "")
            return f"ReadDID_OK({label} val={val})"

        # ── 0x2E  WriteDataByIdentifier ─────────────────────────────────────
        if sid == 0x2E and len(data) >= 3:
            did = (data[1] << 8) | data[2]
            payload = data[3:].hex().upper() if len(data) > 3 else ""
            did_label = {0xF190: "VIN", 0x0101: "Custom_0x0101"}.get(did, "")
            label = f"DID=0x{did:04X}" + (f"({did_label})" if did_label else "")
            length_note = f" len={len(data)-3}B" if len(data) > 3 else ""
            return f"{name}({label}{length_note} payload={payload[:16]}{'…' if len(payload)>16 else ''})"

        # ── 0x6E  WriteDataByIdentifier positive response ───────────────────
        if sid == 0x6E and len(data) >= 3:
            did = (data[1] << 8) | data[2]
            return f"WriteDID_OK(DID=0x{did:04X})"

        # ── 0x27  SecurityAccess request ────────────────────────────────────
        if sid == 0x27 and len(data) >= 2:
            sub  = data[1]
            kind = "RequestSeed" if sub % 2 == 1 else "SendKey"
            key_hex = data[2:].hex().upper() if len(data) > 2 else ""
            extra = f" key={key_hex}" if kind == "SendKey" and key_hex else ""
            return f"{name}(level=0x{sub:02X} {kind}{extra})"

        # ── 0x67  SecurityAccess positive response ──────────────────────────
        if sid == 0x67 and len(data) >= 2:
            sub  = data[1]
            seed = data[2:].hex().upper() if len(data) > 2 else ""
            if seed:
                return f"SecurityAccess_OK(level=0x{sub:02X} seed=0x{seed})"
            return f"SecurityAccess_OK(level=0x{sub:02X} KeyAccepted)"

        # ── 0x3E  TesterPresent ─────────────────────────────────────────────
        if sid == 0x3E and len(data) >= 1:
            sub = data[1] if len(data) > 1 else 0x00
            # Suppress noisy keep-alive from terminal if sub-function is 0x00
            if sub == 0x00:
                return ""   # returns '' → terminal suppresses this line
            return f"{name}(sub=0x{sub:02X})"

        # ── 0x7E  TesterPresent positive response ───────────────────────────
        if sid == 0x7E and len(data) >= 1:
            return ""   # suppress keep-alive ACKs from terminal

        # ── 0x19  ReadDTCInformation ────────────────────────────────────────
        if sid == 0x19 and len(data) >= 2:
            return f"{name}(sub=0x{data[1]:02X})"

        # ── 0x14  ClearDTCInformation ───────────────────────────────────────
        if sid == 0x14 and len(data) >= 3:
            group = (data[1] << 16) | (data[2] << 8) | (data[3] if len(data) > 3 else 0)
            return f"{name}(group=0x{group:06X})"

        return name
    except Exception:
        return name


_ARB_DATA_RE = re.compile(
    r'(0x[0-9a-fA-F]+|[0-9a-fA-F]{3,4})#([0-9a-fA-F.]+)'
)
_PAYLOAD_RE  = re.compile(r'[Pp]ayload=([0-9a-fA-F]+)')


def _parse_line(line: str):
    """Extract (arb_id_hex, data_bytes) from a fucyfuzz output line."""
    if line.startswith("CC_PACKET "):
        try:
            import json
            pkt = json.loads(line[10:])
            arb_str = pkt.get("arb_id") or pkt.get("src_addr") or ""
            data_hex = pkt.get("data_hex", "")
            return arb_str, bytes.fromhex(data_hex)
        except Exception:
            return "", b""

    m = _ARB_DATA_RE.search(line)
    if m:
        try:
            return m.group(1), bytes.fromhex(m.group(2).replace('.', ''))
        except Exception:
            pass
            
    m2 = _PAYLOAD_RE.search(line)
    if m2:
        try:
            return "", bytes.fromhex(m2.group(1))
        except Exception:
            pass
            
    # Aggressive fallback for DoIP/Ethernet CLI outputs lacking ID#DATA formatting
    import re
    # Match phrases like "TX: 1003", "SENT 500300", "RECV=0x1234"
    m3 = re.search(r'\b(?:tx|rx|sent|recv|response|sending|payload)[\s:=]+(?:0x)?([0-9a-fA-F]{2,})\b', line, re.IGNORECASE)
    if m3:
        hex_str = m3.group(1).replace(" ", "")
        if len(hex_str) % 2 == 0:
            try:
                return "", bytes.fromhex(hex_str)
            except Exception:
                pass
                
    return "", b""


def _infer_direction(line: str) -> str:
    lo = line.lower()
    if any(k in lo for k in ("sent", "[tx]", "tx ", "sending", "fuzz ", "  sent")):
        return "TX"
    if any(k in lo for k in ("rx ", "[rx]", "recv", "received", "[ok]", "response")):
        return "RX"
    if any(k in lo for k in ("error", "fail", "[err]", "[error]")):
        return "ERROR"
    if lo.startswith("$ "):
        return "CMD"
    return "INFO"


def _make_entry(direction, arb_id="", data_bytes=b"", decoded="",
                raw_line="", module="", session_id="",
                severity="", timestamp_tx="", timestamp_rx=""):
    """
    Build a log entry dict.

    High-precision timestamps:
      timestamp      — wall-clock when this entry was created (ms precision)
      timestamp_ms   — Unix epoch milliseconds for numeric sorting/diffing
      timestamp_tx   — Set when direction==TX; caller may supply an override
                       (e.g. the exact moment cansend was called)
      timestamp_rx   — Set when direction==RX; caller may supply an override
                       (e.g. the exact moment the response arrived)

    severity field — classified via classify_severity() if not supplied.
    """
    now = datetime.now()
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # ms precision

    # Auto-stamp TX / RX if caller did not provide an explicit override
    if direction == "TX" and not timestamp_tx:
        timestamp_tx = ts_str
    if direction == "RX" and not timestamp_rx:
        timestamp_rx = ts_str

    # Auto-classify severity from decoded text or raw line if not supplied
    if not severity:
        source = decoded or raw_line
        if direction == "VULN":
            # VULN entries carry severity from DataManager; default to HIGH
            severity = SEVERITY_HIGH
        elif source:
            severity = classify_severity(source)
        else:
            severity = SEVERITY_INFO

    return {
        "timestamp":    ts_str,
        "timestamp_ms": int(now.timestamp() * 1000),
        "timestamp_tx": timestamp_tx,
        "timestamp_rx": timestamp_rx,
        "direction":    direction,
        "arb_id":       arb_id,
        "data_hex":     data_bytes.hex().upper() if data_bytes else "",
        "decoded":      decoded,
        "raw_line":     raw_line,
        "module":       module,
        "session_id":   session_id,
        "severity":     severity,
    }


# ─────────────────────────────────────────────────────────────────────────────

# ── TX/RX Pair Buffer ─────────────────────────────────────────────────────────
# Matches a TX entry to the next RX from the same module and writes one paired
# row per round-trip to session_pairs.csv.
#
# Schema (one row = one complete UDS transaction):
#   seq | module | timestamp_tx | tx_arb_id | tx_data_hex | decoded_tx
#       | timestamp_rx | rx_arb_id | rx_data_hex | decoded_rx
#       | latency_ms | anomaly | session_id
#
# Rules:
#   • TX without a matching RX within PAIR_TIMEOUT_S → flushed with RX fields blank
#   • RX without a prior TX (broadcast / spontaneous) → flushed with TX fields blank
#   • Multiple RX per TX (e.g. discovery broadcast) → each RX gets its own row,
#     all sharing the same TX fields
#   • TesterPresent keep-alives (SID 0x3E / 0x7E) are suppressed (noise)

PAIR_TIMEOUT_S   = 2.0     # seconds before an unmatched TX is flushed
_SUPPRESS_SIDS   = {0x3E, 0x7E}   # TesterPresent req/resp — suppress from pairs

PAIRS_CSV_FIELDS = [
    "seq", "module",
    "timestamp_tx", "tx_arb_id", "tx_data_hex", "decoded_tx",
    "timestamp_rx", "rx_arb_id", "rx_data_hex", "decoded_rx",
    "latency_ms", "anomaly", "session_id",
]


class PairBuffer:
    """
    Buffers TX entries and matches them to the next RX from the same module.
    Thread-safe.  All writes go through the SessionLogger's existing async queue
    using a dedicated 'PAIR' direction sentinel so no extra thread is needed.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._pending: dict = {}   # module → [{"ts", "arb_id", "data_hex",
                                   #              "decoded", "wall_time"}, ...]
        self._seq     = 0

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _should_suppress(self, data_hex: str) -> bool:
        """Suppress TesterPresent keep-alives from the pairs log."""
        try:
            if data_hex and len(data_hex) >= 2:
                sid = int(data_hex[:2], 16)
                return sid in _SUPPRESS_SIDS
        except Exception:
            pass
        return False

    def push_tx(self, module: str, arb_id: str, data_hex: str,
                decoded: str, timestamp: str) -> None:
        if self._should_suppress(data_hex):
            return
        entry = {
            "ts":       timestamp,
            "arb_id":   arb_id,
            "data_hex": data_hex,
            "decoded":  decoded,
            "wall":     time.monotonic(),
        }
        with self._lock:
            self._pending.setdefault(module, []).append(entry)

    def push_rx(self, module: str, arb_id: str, data_hex: str,
                decoded: str, timestamp: str,
                flush_cb) -> None:
        """
        Match this RX to the oldest pending TX for the same module.
        flush_cb(pair_dict) is called with the completed pair (or orphan RX).
        Also flushes timed-out TX entries before matching.
        """
        if self._should_suppress(data_hex):
            return
        now = time.monotonic()
        with self._lock:
            pending = self._pending.get(module, [])

            # Flush timed-out TX entries first
            still_pending = []
            for tx in pending:
                if now - tx["wall"] > PAIR_TIMEOUT_S:
                    flush_cb(self._make_pair(tx, None, module))
                else:
                    still_pending.append(tx)
            self._pending[module] = still_pending

            # Match to oldest pending TX
            if self._pending.get(module):
                tx = self._pending[module].pop(0)
                flush_cb(self._make_pair(tx, {
                    "ts": timestamp, "arb_id": arb_id,
                    "data_hex": data_hex, "decoded": decoded,
                }, module))
            else:
                # Orphan RX (spontaneous / broadcast response)
                flush_cb(self._make_pair(None, {
                    "ts": timestamp, "arb_id": arb_id,
                    "data_hex": data_hex, "decoded": decoded,
                }, module))

    def flush_all(self, module: str, flush_cb) -> None:
        """Flush all remaining pending TX entries for a module (session end)."""
        with self._lock:
            for tx in self._pending.pop(module, []):
                flush_cb(self._make_pair(tx, None, module))

    def flush_all_modules(self, flush_cb) -> None:
        with self._lock:
            mods = list(self._pending.keys())
        for mod in mods:
            self.flush_all(mod, flush_cb)

    def _make_pair(self, tx: Optional[dict], rx: Optional[dict],
                   module: str) -> dict:
        seq = self.next_seq()
        latency = ""
        anomaly = ""
        if tx and rx:
            try:
                # Parse timestamps for latency
                fmt = "%Y-%m-%d %H:%M:%S.%f"
                t_tx = datetime.strptime(tx["ts"], fmt)
                t_rx = datetime.strptime(rx["ts"], fmt)
                latency = str(round((t_rx - t_tx).total_seconds() * 1000, 1))
            except Exception:
                pass
        elif tx and not rx:
            anomaly = "NO_RESPONSE"
        elif rx and not tx:
            anomaly = "UNSOLICITED_RX"

        return {
            "seq":          seq,
            "module":       module,
            "timestamp_tx": tx["ts"]       if tx else "",
            "tx_arb_id":    tx["arb_id"]   if tx else "",
            "tx_data_hex":  tx["data_hex"] if tx else "",
            "decoded_tx":   tx["decoded"]  if tx else "",
            "timestamp_rx": rx["ts"]       if rx else "",
            "rx_arb_id":    rx["arb_id"]   if rx else "",
            "rx_data_hex":  rx["data_hex"] if rx else "",
            "decoded_rx":   rx["decoded"]  if rx else "",
            "latency_ms":   latency,
            "anomaly":      anomaly,
        }



class SessionLogger:
    """
    Per-session logger.  All disk I/O is async (background thread + queue).
    Never blocks the calling thread.
    """

    CSV_FIELDS = ["timestamp", "timestamp_tx", "timestamp_rx", "direction",
                  "arb_id", "data_hex", "decoded", "module", "raw_line",
                  "severity"]

    def __init__(self, log_root: str, module: str = ""):
        self._module     = module
        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._session_dir = os.path.join(log_root, f"session_{self._session_id}")
        os.makedirs(self._session_dir, exist_ok=True)

        self._log_path  = os.path.join(self._session_dir, "session.log")
        self._csv_path  = os.path.join(self._session_dir, "session.csv")
        self._json_path = os.path.join(self._session_dir, "session.jsonl")
        self._global_log= os.path.join(log_root, "fucyfuzz.log")

        self._q: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._cbs: list = []
        self._cb_lock   = threading.Lock()

        self._log_fh    = open(self._log_path,   "a", encoding="utf-8", buffering=1)
        self._json_fh   = open(self._json_path,  "a", encoding="utf-8", buffering=1)
        self._global_fh = open(self._global_log, "a", encoding="utf-8", buffering=1)

        self._csv_fh     = open(self._csv_path, "a", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(
            self._csv_fh, fieldnames=self.CSV_FIELDS, extrasaction="ignore"
        )
        if self._csv_fh.tell() == 0:
            self._csv_writer.writeheader()

        self._csv_bytes = 0
        self._csv_part  = 0

        # ── Pairs log (TX/RX matched round-trips) ─────────────────────────────
        self._pairs_path = os.path.join(self._session_dir, "session_pairs.csv")
        self._pairs_fh   = open(self._pairs_path, "a", newline="", encoding="utf-8")
        self._pairs_writer = csv.DictWriter(
            self._pairs_fh, fieldnames=PAIRS_CSV_FIELDS, extrasaction="ignore"
        )
        if self._pairs_fh.tell() == 0:
            self._pairs_writer.writeheader()
        self._pair_buf = PairBuffer()

        banner = (
            f"\n{'='*72}\n"
            f"  FucyFuzz session  {self._session_id}\n"
            f"  Session dir: {self._session_dir}\n"
            f"{'='*72}\n"
        )
        for fh in (self._log_fh, self._global_fh):
            fh.write(banner)

        self._running = True
        # ── Wire CAN frame logger to this session ─────────────────────────
        try:
            from protocol_layer.can_layer import get_frame_logger
            import os as _os
            frames_path = _os.path.join(self._session_dir, "can_frames.jsonl")
            get_frame_logger().set_session_path(frames_path)
        except Exception:
            pass
        self._writer  = threading.Thread(
            target=self._writer_loop, daemon=True, name="FucyFuzz-Logger"
        )
        self._writer.start()

        _cleanup_old_sessions(log_root)

    # ── GUI callbacks ─────────────────────────────────────────────────────────

    def add_gui_callback(self, cb: Callable) -> None:
        with self._cb_lock:
            if cb not in self._cbs:
                self._cbs.append(cb)

    def remove_gui_callback(self, cb: Callable) -> None:
        with self._cb_lock:
            try:
                self._cbs.remove(cb)
            except ValueError:
                pass

    def _fire_gui(self, entry: dict) -> None:
        # We now want DoIP frames to show in the UI just like CAN frames
        with self._cb_lock:
            cbs = list(self._cbs)
        for cb in cbs:
            try:
                cb(entry)
            except Exception:
                pass

    # ── Public API ────────────────────────────────────────────────────────────

    def log_command(self, cmd: str, module: str = "") -> None:
        e = _make_entry("CMD", raw_line=cmd, decoded=f"Command: {cmd}",
                        module=module or self._module, session_id=self._session_id,
                        severity=SEVERITY_INFO)
        self._enqueue(e)

    def log_output_line(self, line: str, module: str = "") -> None:
        if 'CC_PACKET ' in line:
            import json
            try:
                idx = line.find('CC_PACKET ')
                pkt = json.loads(line[idx+10:])
                pkt["module"] = module or self._module
                pkt["session_id"] = self._session_id
                if "transport" not in pkt: pkt["transport"] = "CAN"
                
                ts_str = pkt.get("timestamp", pkt.get("ts", ""))
                if not pkt.get("timestamp"):
                    pkt["timestamp"] = ts_str
                    
                if ts_str and "timestamp_ms" not in pkt:
                    try:
                        from datetime import datetime
                        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                        pkt["timestamp_ms"] = int(dt.timestamp() * 1000)
                    except Exception:
                        pass
                
                if "timestamp_ms" not in pkt:
                    import time
                    pkt["timestamp_ms"] = int(time.time() * 1000)
                    
                if "raw_line" not in pkt: pkt["raw_line"] = line
                self._enqueue(pkt)
                return
            except Exception:
                pass
        
        arb_str, data = _parse_line(line)
        direction     = _infer_direction(line)
        
        mod    = module or self._module
        lo     = line.lower()
        # ── Suppress duplicate raw terminal strings for CAN frames ───────────
        # Since CC_PACKET now cleanly handles TX/RX natively, we want to hide 
        # the ugly "CAN TX 0x7..." terminal strings to keep the log Wireshark-clean.
        # But we must NOT suppress them for 'listener' and 'send' (which use raw tools).
        if direction in ("TX", "RX") and mod not in ("listener", "send", "xcp", "doip"):
            import re
            if arb_str or re.search(r"can\s+(tx|rx)", lo):
                return

        try:
            arb_int = int(arb_str, 16) if arb_str else 0
        except ValueError:
            arb_int = 0
        decoded  = decode_uds(arb_int, data) if data else ""
        severity = classify_severity(decoded or line)
        # Capture the precise moment this TX/RX line is processed
        ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        tx_ts  = ts_now if direction == "TX" else ""
        rx_ts  = ts_now if direction == "RX" else ""
        e = _make_entry(direction, arb_id=arb_str, data_bytes=data,
                        decoded=decoded, raw_line=line,
                        module=mod, session_id=self._session_id,
                        severity=severity, timestamp_tx=tx_ts, timestamp_rx=rx_ts)
        self._enqueue(e)

        # ── Route into TX/RX pair buffer ─────────────────────────────────────
        # Only route lines that carry actual frame data so that pure INFO/CMD
        # lines (connection banners, progress counters, etc.) don't pollute
        # the pairs file.  We require at least a data_hex to be present.
        data_hex = data.hex().upper() if data else ""
        if direction == "TX" and data_hex:
            self._pair_buf.push_tx(
                module=mod, arb_id=arb_str,
                data_hex=data_hex, decoded=decoded, timestamp=ts_now,
            )
        elif direction == "RX" and data_hex:
            self._pair_buf.push_rx(
                module=mod, arb_id=arb_str,
                data_hex=data_hex, decoded=decoded, timestamp=ts_now,
                flush_cb=self._write_pair,
            )

    def log_error_line(self, line: str, module: str = "") -> None:
        if 'CC_PACKET ' in line:
            import json
            try:
                idx = line.find('CC_PACKET ')
                pkt = json.loads(line[idx+10:])
                pkt["module"] = module or self._module
                pkt["session_id"] = self._session_id
                if "transport" not in pkt: pkt["transport"] = "CAN"
                if "timestamp" not in pkt: pkt["timestamp"] = pkt.get("ts", "")
                if "raw_line" not in pkt: pkt["raw_line"] = line
                self._enqueue(pkt)
                return
            except Exception:
                pass

        # Suppress known harmless python-can noise
        _NOISY = ("uptime library not available", "timestamps are relative to boot time")
        if any(s in line for s in _NOISY):
            return
        severity = classify_severity(line)
        e = _make_entry("ERROR", raw_line=line, decoded=line,
                        module=module or self._module, session_id=self._session_id,
                        severity=severity)
        self._enqueue(e)

    def log_raw(self, direction: str, arb_id: int = 0,
                data_bytes: bytes = b"", decoded: str = "",
                module: str = "", severity: str = "",
                timestamp_tx: str = "", timestamp_rx: str = "") -> None:
        """
        Low-level structured log entry.

        Parameters
        ----------
        direction    : TX / RX / ERROR / CMD / INFO / VULN
        arb_id       : CAN arbitration ID (integer)
        data_bytes   : raw payload bytes
        decoded      : human-readable UDS decode string
        module       : originating module name
        severity     : CRITICAL / HIGH / LOW / INFO — auto-classified if omitted
        timestamp_tx : ISO timestamp string for the TX moment (auto-set if TX)
        timestamp_rx : ISO timestamp string for the RX moment (auto-set if RX)
        """
        arb_hex = f"0x{arb_id:03X}" if arb_id else ""
        if not decoded and data_bytes:
            decoded = decode_uds(arb_id, data_bytes)
        if not severity:
            severity = classify_severity(decoded)
        # Capture precise moment for auto-stamping
        ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if direction == "TX" and not timestamp_tx:
            timestamp_tx = ts_now
        if direction == "RX" and not timestamp_rx:
            timestamp_rx = ts_now
        mod = module or self._module
        e = _make_entry(direction, arb_id=arb_hex, data_bytes=data_bytes,
                        decoded=decoded, module=mod,
                        session_id=self._session_id, severity=severity,
                        timestamp_tx=timestamp_tx, timestamp_rx=timestamp_rx)
        self._enqueue(e)

        # ── Route into TX/RX pair buffer ─────────────────────────────────────
        data_hex = data_bytes.hex().upper() if data_bytes else ""
        ts_now   = timestamp_tx or timestamp_rx or datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if direction == "TX" and data_hex:
            self._pair_buf.push_tx(
                module=mod, arb_id=arb_hex,
                data_hex=data_hex, decoded=decoded, timestamp=ts_now,
            )
        elif direction == "RX" and data_hex:
            self._pair_buf.push_rx(
                module=mod, arb_id=arb_hex,
                data_hex=data_hex, decoded=decoded, timestamp=ts_now,
                flush_cb=self._write_pair,
            )

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session_dir(self) -> str:  return self._session_dir
    @property
    def session_id(self) -> str:   return self._session_id
    @property
    def csv_path(self) -> str:     return self._csv_path
    @property
    def log_path(self) -> str:     return self._log_path
    @property
    def jsonl_path(self) -> str:   return self._json_path
    @property
    def pairs_path(self) -> str:   return self._pairs_path

    def flush_and_close(self) -> None:
        # Flush any unmatched TX entries before closing
        try:
            self._pair_buf.flush_all_modules(self._write_pair)
        except Exception:
            pass
        self._running = False
        try:
            self._writer.join(timeout=3.0)
        except Exception:
            pass
        for fh in (self._log_fh, self._csv_fh, self._json_fh,
                   self._global_fh, self._pairs_fh):
            try:
                fh.flush(); fh.close()
            except Exception:
                pass
        # Clear CAN frame logger session path
        try:
            from protocol_layer.can_layer import get_frame_logger
            get_frame_logger().set_session_path(None)
        except Exception:
            pass

    # ── Internal ──────────────────────────────────────────────────────────────

    def _enqueue(self, entry: dict) -> None:
        try:
            self._q.put_nowait(entry)
        except queue.Full:
            try:
                self._q.get_nowait()
            except queue.Empty:
                pass
            try:
                self._q.put_nowait(entry)
            except queue.Full:
                pass
        self._fire_gui(entry)

    def _writer_loop(self) -> None:
        while self._running or not self._q.empty():
            batch = []
            try:
                batch.append(self._q.get(timeout=0.01))
            except queue.Empty:
                continue
            for _ in range(499):
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            for entry in batch:
                self._write_entry(entry)
        for fh in (self._log_fh, self._csv_fh, self._json_fh, self._global_fh):
            try:
                fh.flush()
            except Exception:
                pass

    def _write_pair(self, pair: dict) -> None:
        """
        Write one TX/RX paired row to session_pairs.csv.

        Called synchronously from PairBuffer (which holds the SessionLogger
        lock for as little time as possible).  The write itself is direct
        (not queued) because pairs are only flushed when an RX arrives or
        the session ends — both of which are rare compared to the main queue
        throughput.  A try/except keeps it exception-safe.

        Anomaly tagging:
          NO_RESPONSE      — TX sent, no RX within PAIR_TIMEOUT_S
          UNSOLICITED_RX   — RX received with no prior TX (broadcast/spontaneous)
          REPEATED_SEED    — injected by doip_tab._extra_parse via mark_pair_anomaly()
          LATENCY_SPIKE    — injected when latency_ms > LATENCY_SPIKE_MS
        """
        try:
            # Latency spike detection
            LATENCY_SPIKE_MS = 500
            if not pair.get("anomaly"):
                try:
                    lat = float(pair.get("latency_ms") or 0)
                    if lat > LATENCY_SPIKE_MS:
                        pair = dict(pair)
                        pair["anomaly"] = f"LATENCY_SPIKE_{int(lat)}ms"
                except Exception:
                    pass

            # Add session_id
            row = dict(pair)
            row["session_id"] = self._session_id
            self._pairs_writer.writerow(row)
            self._pairs_fh.flush()   # keep file current without buffering delay
        except Exception:
            pass

    def _write_entry(self, entry: dict) -> None:
        ts   = entry.get("timestamp", "")
        dir_ = entry.get("direction", "")
        arb  = entry.get("arb_id", "")
        dat  = entry.get("data_hex", "")
        dec  = entry.get("decoded", "")
        raw  = entry.get("raw_line", "")
        mod  = entry.get("module", "")
        sev  = entry.get("severity", "")
        tx_t = entry.get("timestamp_tx", "")
        rx_t = entry.get("timestamp_rx", "")

        # ── Text log ────────────────────────────────────────────────────────
        arb_p  = f" arb={arb}"   if arb else ""
        dat_p  = f" data={dat}"  if dat else ""
        dec_p  = f" [{dec}]"     if dec else ""
        sev_p  = f" <{sev}>"     if sev and sev != "INFO" else ""
        tx_p   = f" tx@{tx_t}"   if tx_t else ""
        rx_p   = f" rx@{rx_t}"   if rx_t else ""
        txt = (f"{ts} [{dir_:<5}]{sev_p} [{mod:<10}]{arb_p}{dat_p}{dec_p}{tx_p}{rx_p}"
               + (f"  >{raw}" if raw and raw not in (dec, dat) else "")
               + "\n")
        try:
            self._log_fh.write(txt)
            self._global_fh.write(txt)
        except Exception:
            pass

        # ── CSV ─────────────────────────────────────────────────────────────
        try:
            row = {k: entry.get(k, "") for k in self.CSV_FIELDS}
            row["raw_line"] = (raw or "")[:300]
            self._csv_writer.writerow(row)
            # No rotation — files grow without limit per session
        except Exception:
            pass

        # ── JSONL ────────────────────────────────────────────────────────────
        try:
            self._json_fh.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass

    def _rotate_csv(self) -> None:
        """No-op — rotation is disabled; files grow without limit."""
        pass


# ── Cleanup ───────────────────────────────────────────────────────────────────

def _cleanup_old_sessions(log_root: str) -> None:
    """No-op — sessions are kept forever.  Disk space is the operator's concern."""
    pass


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[SessionLogger] = None
_lock = threading.Lock()


def get_session_logger() -> Optional[SessionLogger]:
    return _instance


def start_session_logger(log_root: str, module: str = "") -> SessionLogger:
    """
    Always start a FRESH session logger.

    A new timestamped session directory is created on every call.
    This means every GUI launch produces its own standalone log files
    (session.log, session.csv, session.jsonl) with no size restrictions.
    """
    global _instance
    with _lock:
        if _instance is not None:
            try:
                _instance.flush_and_close()
            except Exception:
                pass
        os.makedirs(log_root, exist_ok=True)
        _instance = SessionLogger(log_root, module)
    return _instance


def stop_session_logger() -> None:
    global _instance
    with _lock:
        if _instance is not None:
            try:
                _instance.flush_and_close()
            except Exception:
                pass
            _instance = None
