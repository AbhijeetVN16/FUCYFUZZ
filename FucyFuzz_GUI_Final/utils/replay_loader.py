"""
FucyFuzz Replay Loader  (utils/replay_loader.py)
================================================
Multi-format CAN log loader for the Replay Tab.

Supported formats
-----------------
  .jsonl  — FucyFuzz native session log (SessionLogger output)
  .log    — FucyFuzz text log  OR  candump log  (both auto-detected)
  .csv    — FucyFuzz CSV export
  .asc    — Vector ASC  (CANalyzer / CANdb++ captures)
  .blf    — Vector BLF  (requires python-can)
  .pcap   — Wireshark/socketcan capture  (DLT 227  CAN_SOCKETCAN)

Unified frame dict returned per frame
--------------------------------------
{
    ts_float:  float,   # Unix timestamp in absolute seconds
    ts_rel:    float,   # relative seconds from start of capture (for display)
    delta_ms:  float,   # inter-frame gap from previous frame (ms)  ← timing engine
    arb_id:    str,     # hex string  e.g. "7E0"
    dlc:       int,     # CAN DLC
    data_hex:  str,     # packed hex, no spaces  e.g. "02100100"
    direction: str,     # "TX" or "RX"
    channel:   str,     # CAN channel string  e.g. "1"
    decoded:   str,     # UDS human decode if available
    severity:  str,     # CRITICAL / HIGH / LOW / INFO
    include:   bool,    # checkbox default (True = include in replay)
    src_line:  int,     # source file line number (0 = unknown)
}

Public API
----------
    frames, meta = load_file(path)   # raises LoadError on failure
    frames, meta = auto_load(path)   # same, picks format by extension
"""

from __future__ import annotations

import csv
import json
import os
import re
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict, Any

# ─────────────────────────────────────────────────────────────────────────────

class LoadError(Exception):
    """Raised when a file cannot be parsed."""

_UDS_SID_MAP: Dict[int, str] = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDTCInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x2E: "WriteDataByIdentifier",
    0x3D: "WriteMemoryByAddress",
    0x3E: "TesterPresent",
    0x50: "DiagSessCtrl_Resp",
    0x51: "ECUReset_Resp",
    0x62: "ReadDataByID_Resp",
    0x67: "SecurityAccess_Resp",
    0x7E: "TesterPresent_Resp",
    0x7F: "NegativeResponse",
}

_NRC_MAP: Dict[int, str] = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x72: "generalProgrammingFailure",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}

_UDS_SESSION_NAMES: Dict[int, str] = {
    0x01: "DefaultSession",
    0x02: "ProgrammingSession",
    0x03: "ExtendedDiagnosticSession",
    0x40: "SafetySystemDiagnosticSession",
}


def _decode_uds(data_hex: str) -> str:
    """Best-effort UDS decode from raw hex data bytes."""
    if not data_hex or len(data_hex) < 2:
        return ""
    try:
        raw = bytes.fromhex(data_hex)
    except ValueError:
        return ""
    if not raw:
        return ""

    sid = raw[0]
    name = _UDS_SID_MAP.get(sid, f"SID_0x{sid:02X}")

    # Negative Response: 7F SID NRC
    if sid == 0x7F and len(raw) >= 3:
        req_sid = raw[1]
        nrc = raw[2]
        req_name = _UDS_SID_MAP.get(req_sid, f"0x{req_sid:02X}")
        nrc_name = _NRC_MAP.get(nrc, f"0x{nrc:02X}")
        return f"NegResponse({req_name}): {nrc_name}"

    # DiagnosticSessionControl (10) or Response (50)
    if sid in (0x10, 0x50) and len(raw) >= 2:
        sub = raw[1]
        sname = _UDS_SESSION_NAMES.get(sub, f"0x{sub:02X}")
        verb = "Request" if sid == 0x10 else "Accepted"
        return f"{name}[{verb}]: {sname}"

    # SecurityAccess (27) or Response (67)
    if sid in (0x27, 0x67) and len(raw) >= 2:
        sub = raw[1]
        kind = "RequestSeed" if (sub % 2 == 1) else "SendKey"
        return f"{name}[{kind}] sub=0x{sub:02X}"

    # ReadDataByIdentifier (22) or Response (62)
    if sid in (0x22, 0x62) and len(raw) >= 3:
        did = (raw[1] << 8) | raw[2]
        return f"{name}: DID=0x{did:04X}"

    # TesterPresent (3E) or Response (7E)
    if sid in (0x3E, 0x7E) and len(raw) >= 2:
        sub = raw[1]
        return f"{name} sub=0x{sub:02X}"

    # ECUReset (11)
    if sid == 0x11 and len(raw) >= 2:
        rst = {0x01: "HardReset", 0x02: "KeyOffOnReset", 0x03: "SoftReset"}
        return f"{name}: {rst.get(raw[1], f'0x{raw[1]:02X}')}"

    # Generic: just name + bytes
    rest = " ".join(f"{b:02X}" for b in raw[1:5])
    suffix = "…" if len(raw) > 5 else ""
    return f"{name} [{rest}{suffix}]"


def _make_frame(ts_float: float, arb_id: str, data_hex: str, direction: str = "TX",
                channel: str = "1", decoded: str = "", severity: str = "INFO",
                src_line: int = 0) -> Dict[str, Any]:
    data_hex = (data_hex or "").replace(" ", "").upper()
    if not decoded:
        decoded = _decode_uds(data_hex)
    return {
        "ts_float":  ts_float,
        "ts_rel":    0.0,
        "delta_ms":  0.0,
        "arb_id":    arb_id.upper().lstrip("0X") or "000",
        "dlc":       len(data_hex) // 2,
        "data_hex":  data_hex,
        "direction": direction.upper(),
        "channel":   channel,
        "decoded":   decoded,
        "severity":  severity.upper(),
        "include":   True,
        "src_line":  src_line,
    }


def _compute_deltas(frames: List[Dict]) -> None:
    """Fill ts_rel and delta_ms fields in-place after loading."""
    if not frames:
        return
    t0 = frames[0]["ts_float"]
    prev = t0
    for f in frames:
        t = f["ts_float"]
        f["ts_rel"] = round(t - t0, 6)
        f["delta_ms"] = round((t - prev) * 1000.0, 3)
        prev = t


def _parse_iso_ts(s: str) -> float:
    """Parse ISO 8601 timestamp string to Unix float. Returns current time on failure."""
    if not s:
        return time.time()
    try:
        s2 = s.replace("T", " ").replace("Z", "+00:00")
        if "+" not in s2 and "-" not in s2.split(" ")[-1]:
            dt = datetime.fromisoformat(s2)
        else:
            dt = datetime.fromisoformat(s2)
        # If naive, assume local
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except (ValueError, TypeError):
        try:
            return float(s)
        except (ValueError, TypeError):
            return time.time()


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def load_file(path: str) -> Tuple[List[Dict], Dict]:
    """
    Load any supported CAN log format.
    Returns (frames, meta) where meta = {format, count, time_range_s, filename, …}
    Raises LoadError on unrecoverable failure.
    """
    ext = Path(path).suffix.lower()
    loaders = {
        ".jsonl": _load_jsonl,
        ".log":   _load_log_auto,
        ".csv":   _load_csv,
        ".asc":   _load_asc,
        ".blf":   _load_blf,
        ".pcap":  _load_pcap,
        ".pcapng":_load_pcap,
    }
    loader = loaders.get(ext)
    if loader is None:
        raise LoadError(f"Unsupported format: {ext}  "
                        f"(supported: {', '.join(loaders)})")
    frames = loader(path)
    if not frames:
        raise LoadError(f"No CAN frames found in {Path(path).name}")

    frames.sort(key=lambda f: f["ts_float"])
    _compute_deltas(frames)

    ts0 = frames[0]["ts_float"]
    ts1 = frames[-1]["ts_float"]
    meta = {
        "format":       ext.lstrip(".").upper(),
        "filename":     Path(path).name,
        "count":        len(frames),
        "time_range_s": round(ts1 - ts0, 6),
        "ts_start":     datetime.fromtimestamp(ts0).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        "ts_end":       datetime.fromtimestamp(ts1).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        "tx_count":     sum(1 for f in frames if f["direction"] == "TX"),
        "rx_count":     sum(1 for f in frames if f["direction"] == "RX"),
    }
    return frames, meta


# Alias
auto_load = load_file


# ─────────────────────────────────────────────────────────────────────────────
# Format parsers
# ─────────────────────────────────────────────────────────────────────────────

def _load_jsonl(path: str) -> List[Dict]:
    frames = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                direction = (rec.get("direction") or "TX").upper()
                ts_str    = rec.get("ts") or rec.get("timestamp", "")
                ts_float  = _parse_iso_ts(ts_str)
                data_hex  = (rec.get("data_hex") or "").replace(" ", "").upper()
                arb_id    = (rec.get("arb_id") or "7E0").replace("0x", "").replace("0X", "")
                decoded   = rec.get("decoded", "") or rec.get("note", "")
                severity  = (rec.get("severity") or "INFO").upper()
                channel   = str(rec.get("channel") or rec.get("transport") or "CAN")

                if data_hex and direction in ("TX", "RX"):
                    frames.append(_make_frame(ts_float, arb_id, data_hex,
                                               direction, channel, decoded,
                                               severity, lineno))
    except OSError as e:
        raise LoadError(str(e))
    return frames


def _load_log_auto(path: str) -> List[Dict]:
    """Auto-detect candump (.log) vs FucyFuzz text log."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            sample = fh.read(512)
    except OSError as e:
        raise LoadError(str(e))

    # candump: "(1710628755.123456) vcan0 7E0#..."
    if re.search(r'\(\d+\.\d+\)\s+\w+\s+[0-9a-fA-F]+#', sample):
        return _load_candump(path)
    return _load_fucyfuzz_log(path)


_CANDUMP_RE = re.compile(
    r'^\((\d+\.\d+)\)\s+(\S+)\s+([0-9a-fA-F]{1,8})#([0-9a-fA-F]*)(?:\s+#\w+)?'
)

def _load_candump(path: str) -> List[Dict]:
    """Parse candump -l output: (ts) iface ID#DATA"""
    frames = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                m = _CANDUMP_RE.match(line)
                if not m:
                    continue
                ts      = float(m.group(1))
                channel = m.group(2)
                arb_id  = m.group(3).upper()
                data_hex = m.group(4).upper()
                frames.append(_make_frame(ts, arb_id, data_hex, "TX", channel,
                                           src_line=lineno))
    except OSError as e:
        raise LoadError(str(e))
    return frames


_LOG_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[\sT][\d:.]+)\s+\[(\w+)\s*\](.*)$'
)
_DATA_FIELD_RE  = re.compile(r'\bdata(?:_hex)?=([0-9a-fA-F]+)\b')
_ARBID_FIELD_RE = re.compile(r'\bid(?:=|:)\s*(?:0x)?([0-9a-fA-F]{2,8})\b', re.IGNORECASE)
_CAN_INLINE_RE  = re.compile(r'(?:0x)?([0-9a-fA-F]{3,8})#([0-9a-fA-F]{2,16})')

def _load_fucyfuzz_log(path: str) -> List[Dict]:
    """Parse FucyFuzz session .log text format."""
    frames = []
    base_time = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.rstrip()
                m = _LOG_LINE_RE.match(raw)
                if not m:
                    continue
                ts_str    = m.group(1)
                direction = m.group(2).strip().upper()
                rest      = m.group(3)

                if direction not in ("TX", "RX"):
                    continue

                ts_float = _parse_iso_ts(ts_str)
                if base_time is None:
                    base_time = ts_float

                # Try structured data= field first
                dm = _DATA_FIELD_RE.search(rest)
                if dm:
                    data_hex = dm.group(1).upper()
                    am = _ARBID_FIELD_RE.search(rest)
                    arb_id = am.group(1).upper() if am else "7E0"
                    frames.append(_make_frame(ts_float, arb_id, data_hex,
                                               direction, src_line=lineno))
                    continue

                # Try inline CAN ID#DATA
                cm = _CAN_INLINE_RE.search(rest)
                if cm:
                    arb_id   = cm.group(1).upper()
                    data_hex = cm.group(2).upper()
                    frames.append(_make_frame(ts_float, arb_id, data_hex,
                                               direction, src_line=lineno))
    except OSError as e:
        raise LoadError(str(e))
    return frames


def _load_csv(path: str) -> List[Dict]:
    """Parse FucyFuzz CSV (SessionLogger output)."""
    frames = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for lineno, row in enumerate(reader, 2):
                direction = (row.get("direction") or "").strip().upper()
                if direction not in ("TX", "RX"):
                    continue
                ts_str   = (row.get("ts") or row.get("timestamp") or "").strip()
                ts_float = _parse_iso_ts(ts_str)
                data_hex = (row.get("data_hex") or "").strip().replace(" ", "").upper()
                arb_id   = (row.get("arb_id") or "7E0").strip().replace("0x", "")
                decoded  = (row.get("decoded") or "").strip()
                severity = (row.get("severity") or "INFO").strip().upper()
                channel  = (row.get("channel") or "1").strip()
                if data_hex:
                    frames.append(_make_frame(ts_float, arb_id, data_hex,
                                               direction, channel, decoded,
                                               severity, lineno))
    except OSError as e:
        raise LoadError(str(e))
    return frames


# ── ASC (Vector CANalyzer) ────────────────────────────────────────────────────
# Two common variants:
#   Absolute: "   0.0001 1 7E0 Tx d 3 02 10 01"
#   With date: "date Thu Mar 16 22:39:15 2026\nbase hex  timestamps absolute"
_ASC_FRAME_RE = re.compile(
    r'^\s*([\d.]+)\s+(\d+)\s+([0-9a-fA-F]+)\s+(Tx|Rx|TX|RX)\s+d\s+(\d+)\s+((?:[0-9a-fA-F]{2}\s*)+)',
    re.IGNORECASE,
)
_ASC_DATE_RE = re.compile(
    r'^date\s+(.+)$', re.IGNORECASE
)

def _load_asc(path: str) -> List[Dict]:
    """Parse Vector ASC log format."""
    frames = []
    base_wall: float | None = None   # wall-clock epoch of first event
    asc_date_ts: float | None = None

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip()

                # Try to pick up the "date" header so we can give abs timestamps
                dm = _ASC_DATE_RE.match(line)
                if dm and asc_date_ts is None:
                    try:
                        asc_date_ts = datetime.strptime(
                            dm.group(1).strip(),
                            "%a %b %d %H:%M:%S %Y"
                        ).timestamp()
                    except ValueError:
                        pass
                    continue

                m = _ASC_FRAME_RE.match(line)
                if not m:
                    continue

                rel_sec  = float(m.group(1))
                channel  = m.group(2)
                arb_id   = m.group(3).upper()
                dir_str  = m.group(4).upper()[:2]       # TX or RX
                # m.group(5) = dlc (we ignore, compute from data)
                data_str = m.group(6).strip()
                data_hex = data_str.replace(" ", "").upper()

                if base_wall is None:
                    base_wall = asc_date_ts if asc_date_ts is not None else time.time()

                ts_float = base_wall + rel_sec
                frames.append(_make_frame(ts_float, arb_id, data_hex,
                                           dir_str, channel, src_line=lineno))
    except OSError as e:
        raise LoadError(str(e))
    return frames


# ── BLF (Vector Binary Log Format) ───────────────────────────────────────────

def _load_blf(path: str) -> List[Dict]:
    """Parse Vector BLF using python-can."""
    try:
        import can
    except ImportError:
        raise LoadError(
            "python-can is required to read BLF files.\n"
            "Install: pip install python-can"
        )
    frames = []
    try:
        with can.BLFReader(path) as reader:
            for msg in reader:
                direction = "RX" if getattr(msg, "is_rx", False) else "TX"
                arb_id    = f"{msg.arbitration_id:X}"
                data_hex  = msg.data.hex().upper()
                channel   = str(getattr(msg, "channel", 1) or 1)
                frames.append(_make_frame(
                    msg.timestamp, arb_id, data_hex, direction, channel
                ))
    except Exception as e:
        raise LoadError(f"BLF read failed: {e}")
    return frames


# ── PCAP (Wireshark / socketcan DLT 227) ─────────────────────────────────────
# Global header: <IHHIIII>  magic, ver_maj, ver_min, timezone, sigfigs, snaplen, network
# Packet record: <IIII>     ts_sec, ts_usec (or ts_nsec), incl_len, orig_len
# CAN socketcan payload: can_id(4LE), dlc(1), pad(3), data(8)

_PCAP_MAGIC_LE  = 0xa1b2c3d4
_PCAP_MAGIC_BE  = 0xd4c3b2a1
_PCAP_MAGIC_NS_LE = 0xa1b23c4d   # nanosecond variant
_PCAP_MAGIC_NS_BE = 0x4d3cb2a1
_DLT_CAN_SOCKETCAN = 227
_DLT_EN10MB = 1

def _load_pcap(path: str) -> List[Dict]:
    """Parse PCAP file with DLT_CAN_SOCKETCAN (227) or DLT_EN10MB (1) link type."""
    frames = []
    try:
        with open(path, "rb") as fh:
            raw_magic = fh.read(4)
            if len(raw_magic) < 4:
                raise LoadError("File too small to be a PCAP")

            magic = struct.unpack("<I", raw_magic)[0]
            if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE):
                endian = "<"
                nano   = (magic == _PCAP_MAGIC_NS_LE)
            elif magic in (_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE):
                endian = ">"
                nano   = (magic == _PCAP_MAGIC_NS_BE)
            else:
                raise LoadError(f"Not a valid PCAP file (magic=0x{magic:08X})")

            hdr = fh.read(20)  # remaining 20 bytes of global header
            if len(hdr) < 20:
                raise LoadError("Truncated PCAP header")
            _ver_maj, _ver_min, _tz, _sig, _snap, link_type = struct.unpack(
                endian + "HHiIII", hdr
            )
            if link_type not in (_DLT_CAN_SOCKETCAN, _DLT_EN10MB):
                raise LoadError(
                    f"PCAP link type {link_type} not supported. "
                    f"Expected DLT_CAN_SOCKETCAN ({_DLT_CAN_SOCKETCAN}) or DLT_EN10MB ({_DLT_EN10MB})."
                )

            lineno = 0
            while True:
                pkt_hdr = fh.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_frac, incl_len, _orig = struct.unpack(endian + "IIII", pkt_hdr)
                ts_float = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
                payload  = fh.read(incl_len)
                lineno  += 1

                if link_type == _DLT_CAN_SOCKETCAN:
                    if len(payload) < 8:
                        continue
                    can_id_raw = struct.unpack(endian + "I", payload[:4])[0]
                    dlc        = payload[4]
                    can_id     = can_id_raw & 0x1FFFFFFF  # strip EFF/RTR flags
                    data       = payload[8: 8 + min(dlc, 8)]
                    data_hex   = data.hex().upper()
                    arb_id     = f"{can_id:X}"
                    # Heuristic: ECU response IDs (7E8-7EF) → RX; others → TX
                    dir_str = "RX" if 0x7E8 <= can_id <= 0x7EF else "TX"
                    frames.append(_make_frame(ts_float, arb_id, data_hex,
                                               dir_str, src_line=lineno))
                elif link_type == _DLT_EN10MB:
                    # Ethernet frame parsing for DoIP
                    if len(payload) < 14: continue
                    eth_type = struct.unpack("!H", payload[12:14])[0]
                    if eth_type != 0x0800: continue # Only IPv4
                    
                    ip_offset = 14
                    if len(payload) < ip_offset + 20: continue
                    ip_hlen = (payload[ip_offset] & 0x0F) * 4
                    ip_proto = payload[ip_offset + 9]
                    if ip_proto != 6: continue # Only TCP
                    
                    tcp_offset = ip_offset + ip_hlen
                    if len(payload) < tcp_offset + 20: continue
                    tcp_sport, tcp_dport = struct.unpack("!HH", payload[tcp_offset:tcp_offset+4])
                    tcp_hlen = ((payload[tcp_offset + 12] >> 4) & 0x0F) * 4
                    
                    doip_offset = tcp_offset + tcp_hlen
                    if len(payload) < doip_offset + 8: continue
                    
                    # DoIP Header: Protocol Version (1 byte), Inv PV (1 byte), Type (2 bytes), Length (4 bytes)
                    pv, inv_pv, ptype, plen = struct.unpack("!BBHI", payload[doip_offset:doip_offset+8])
                    if pv != 0x02 or inv_pv != 0xFD: continue # Not DoIP ISO 13400-2:2012
                    
                    if ptype == 0x8001: # Diagnostic Message
                        if len(payload) < doip_offset + 8 + plen: continue
                        if plen < 4: continue # Requires source and target addresses
                        
                        src_addr, tgt_addr = struct.unpack("!HH", payload[doip_offset+8:doip_offset+12])
                        uds_payload = payload[doip_offset+12 : doip_offset+8+plen]
                        
                        # Determine direction based on ports and addresses
                        dir_str = "TX" if tcp_dport == 13400 else "RX"
                        arb_id = f"{tgt_addr:X}" if dir_str == "TX" else f"{src_addr:X}"
                        data_hex = uds_payload.hex().upper()
                        
                        # We use transport="DoIP" to indicate it requires the DoIP replay workflow.
                        # Wait, _make_frame defaults channel to "1". We'll overload channel with "DoIP".
                        frames.append(_make_frame(ts_float, arb_id, data_hex,
                                                   dir_str, channel="DoIP", src_line=lineno))

    except LoadError:
        raise
    except OSError as e:
        raise LoadError(str(e))
    return frames
