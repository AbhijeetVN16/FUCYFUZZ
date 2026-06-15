"""
Help Tab — FucyFuzz Complete Reference + Interactive UDS Decoder
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QScrollArea, QFrame, QTabWidget, QTextBrowser, QPushButton,
    QGridLayout, QPlainTextEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from ui.theme import COLORS, FONT_UI, FONT_MONO

# ─────────────────────────────────────────────────────────────────────────────
# UDS Service Database — all standard ISO 14229-1 services
# ─────────────────────────────────────────────────────────────────────────────
UDS_SERVICES = {
    0x10: {"name": "DiagnosticSessionControl",  "abbr": "DSC",
           "request":  "10 XX",  "response": "50 XX",
           "sub_fns": {0x01: "defaultSession", 0x02: "programmingSession",
                       0x03: "extendedDiagnosticSession", 0x04: "safetySystemDiagnosticSession"}},
    0x11: {"name": "ECUReset",                  "abbr": "ER",
           "request":  "11 XX",  "response": "51 XX",
           "sub_fns": {0x01: "hardReset", 0x02: "keyOffOnReset", 0x03: "softReset"}},
    0x14: {"name": "ClearDiagnosticInformation","abbr": "CDTCI",
           "request":  "14 GG GG GG", "response": "54"},
    0x19: {"name": "ReadDTCInformation",        "abbr": "RDTCI",
           "request":  "19 XX ...",   "response": "59 XX ...",
           "sub_fns": {0x01: "reportNumberOfDTCByStatusMask",
                       0x02: "reportDTCByStatusMask",
                       0x04: "reportDTCSnapshotRecordByDTCNumber",
                       0x06: "reportDTCExtDataRecordByDTCNumber"}},
    0x22: {"name": "ReadDataByIdentifier",      "abbr": "RDBI",
           "request":  "22 DI DI",   "response": "62 DI DI [data]",
           "dids": {0xF190: "VIN (Vehicle Identification Number)",
                    0xF180: "Boot Software Identification",
                    0xF181: "Application Software Identification",
                    0xF186: "Active Diagnostic Session",
                    0xF187: "Vehicle Manufacturer Spare Part Number",
                    0xF188: "Vehicle Manufacturer ECU Software Number",
                    0xF18B: "ECU Manufacturing Date",
                    0xF18C: "ECU Serial Number",
                    0xF192: "System Supplier ECU Hardware Number",
                    0xF193: "System Supplier ECU Hardware Version Number",
                    0xF194: "System Supplier ECU Software Number",
                    0xF198: "Vehicle Manufacturer Workshop Equipment Routine ID List",
                    0xF19E: "Supported Functionality Groups"}},
    0x23: {"name": "ReadMemoryByAddress",       "abbr": "RMBA",
           "request":  "23 AL MA.MA.MA LE.LE",  "response": "63 [data]"},
    0x27: {"name": "SecurityAccess",            "abbr": "SA",
           "request":  "27 XX [seed/key]",        "response": "67 XX [seed/key]",
           "sub_fns": {0x01: "requestSeed (level 1)",  0x02: "sendKey (level 1)",
                       0x03: "requestSeed (level 2)",  0x04: "sendKey (level 2)",
                       0x11: "requestSeed (level 11)", 0x12: "sendKey (level 11)"}},
    0x28: {"name": "CommunicationControl",      "abbr": "CC",
           "request":  "28 XX XX",  "response": "68 XX",
           "sub_fns": {0x00: "enableRxAndTx", 0x01: "enableRxAndDisableTx",
                       0x02: "disableRxAndEnableTx", 0x03: "disableRxAndTx"}},
    0x2E: {"name": "WriteDataByIdentifier",     "abbr": "WDBI",
           "request":  "2E DI DI [data]",  "response": "6E DI DI"},
    0x2F: {"name": "InputOutputControlByIdentifier", "abbr": "IOCBI",
           "request":  "2F DI DI XX [data]", "response": "6F DI DI [data]"},
    0x31: {"name": "RoutineControl",            "abbr": "RC",
           "request":  "31 XX RI RI [data]",  "response": "71 XX RI RI [data]",
           "sub_fns": {0x01: "startRoutine", 0x02: "stopRoutine",
                       0x03: "requestRoutineResults"}},
    0x34: {"name": "RequestDownload",           "abbr": "RD",
           "request":  "34 00 AL MA.MA LE.LE",  "response": "74 XX ML"},
    0x35: {"name": "RequestUpload",             "abbr": "RU",
           "request":  "35 00 AL MA.MA LE.LE",  "response": "75 XX ML"},
    0x36: {"name": "TransferData",              "abbr": "TD",
           "request":  "36 BC [data]",           "response": "76 BC [data]"},
    0x37: {"name": "RequestTransferExit",       "abbr": "RTE",
           "request":  "37",                     "response": "77"},
    0x3D: {"name": "WriteMemoryByAddress",      "abbr": "WMBA",
           "request":  "3D AL MA.MA LE.LE [data]", "response": "7D"},
    0x3E: {"name": "TesterPresent",             "abbr": "TP",
           "request":  "3E 00",  "response": "7E 00",
           "sub_fns": {0x00: "zeroSubFunction (respond)", 0x80: "zeroSubFunction (no response)"}},
    0x85: {"name": "ControlDTCSetting",         "abbr": "CDTCS",
           "request":  "85 XX",  "response": "C5 XX",
           "sub_fns": {0x01: "on", 0x02: "off"}},
    0x86: {"name": "ResponseOnEvent",           "abbr": "ROE",
           "request":  "86 XX ...", "response": "C6 XX ..."},
    0x87: {"name": "LinkControl",               "abbr": "LC",
           "request":  "87 XX XX",  "response": "C7 XX"},
}

# Negative Response Codes
NRC_CODES = {
    0x00: "positiveResponse",
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent",
    0x26: "failurePreventsExecutionOfRequestedAction",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
    0x81: "rpmTooHigh",
    0x82: "rpmTooLow",
    0x83: "engineIsRunning",
    0x84: "engineIsNotRunning",
    0x85: "engineRunTimeTooLow",
    0x86: "temperatureTooHigh",
    0x87: "temperatureTooLow",
    0x88: "vehicleSpeedTooHigh",
    0x89: "vehicleSpeedTooLow",
    0x8A: "throttle/PedalTooHigh",
    0x8B: "throttle/PedalTooLow",
    0x8C: "transmissionRangeNotInNeutral",
    0x8D: "transmissionRangeNotInGear",
    0x8F: "brakeSwitch(es)NotClosed",
    0x90: "shifterLeverNotInPark",
    0x91: "torqueConverterClutchLocked",
    0x92: "voltageTooHigh",
    0x93: "voltageTooLow",
}


def decode_uds_bytes(hex_str: str) -> list[dict]:
    """
    Parse a hex string (space-separated or continuous) and return
    a list of decoded frame dictionaries.
    """
    # Normalise: remove 0x prefixes, spaces, dashes
    cleaned = hex_str.upper().replace("0X", "").replace("-", " ").strip()
    # Split on spaces if present, else split every 2 chars
    if " " in cleaned:
        parts = cleaned.split()
    else:
        parts = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]

    parts = [p for p in parts if p]
    if not parts:
        return []

    try:
        data = [int(b, 16) for b in parts]
    except ValueError:
        return [{"error": f"Invalid hex: '{hex_str}'"}]

    results = []
    i = 0
    while i < len(data):
        sid = data[i]
        frame = {"offset": i, "sid": sid, "raw_bytes": parts[i:i+8]}

        # ── Positive response mirror (SID | 0x40 = positive response) ────────
        if sid >= 0x40 and (sid - 0x40) in UDS_SERVICES and sid not in UDS_SERVICES:
            req_sid = sid - 0x40
            svc = UDS_SERVICES[req_sid]
            frame["type"]    = "positive_response"
            frame["service"] = svc["name"]
            frame["abbr"]    = svc["abbr"]
            frame["detail"]  = f"Positive response to {svc['name']} (0x{req_sid:02X})"
            if req_sid == 0x10 and i + 1 < len(data):   # DSC
                sf = data[i + 1]
                frame["sub_fn"] = svc.get("sub_fns", {}).get(sf, f"subFunction=0x{sf:02X}")
            elif req_sid == 0x22 and i + 2 < len(data):  # RDBI
                did = (data[i+1] << 8) | data[i+2]
                did_name = svc.get("dids", {}).get(did, f"DID 0x{did:04X}")
                frame["did"] = did_name
                if i + 3 < len(data):
                    raw = bytes(data[i+3:])
                    frame["value_hex"] = raw.hex().upper()
                    try:
                        frame["value_ascii"] = raw.decode("ascii", errors="replace").rstrip("\x00")
                    except Exception:
                        pass
            elif req_sid == 0x27 and i + 1 < len(data):  # SA
                level = data[i + 1]
                frame["detail"] += f" — level 0x{level:02X}"
        # ── Negative response ──────────────────────────────────────────────────
        elif sid == 0x7F:
            frame["type"] = "negative_response"
            if i + 2 < len(data):
                req_sid = data[i + 1]
                nrc     = data[i + 2]
                svc     = UDS_SERVICES.get(req_sid, {})
                frame["service"]     = svc.get("name", f"Unknown service 0x{req_sid:02X}")
                frame["abbr"]        = svc.get("abbr", "??")
                frame["nrc"]         = nrc
                frame["nrc_name"]    = NRC_CODES.get(nrc, f"Unknown NRC 0x{nrc:02X}")
                frame["detail"]      = (
                    f"Negative response for {frame['service']} — "
                    f"NRC 0x{nrc:02X}: {frame['nrc_name']}"
                )
            else:
                frame["detail"] = "Negative response (truncated)"
        # ── Request ────────────────────────────────────────────────────────────
        elif sid in UDS_SERVICES:
            svc = UDS_SERVICES[sid]
            frame["type"]    = "request"
            frame["service"] = svc["name"]
            frame["abbr"]    = svc["abbr"]
            frame["detail"]  = svc["name"]
            if "sub_fns" in svc and i + 1 < len(data):
                sf = data[i + 1]
                sf_name = svc["sub_fns"].get(sf, f"subFunction=0x{sf:02X}")
                frame["sub_fn"] = sf_name
                frame["detail"] = f"{svc['name']} — {sf_name}"
            if sid == 0x22 and i + 2 < len(data):   # RDBI
                did = (data[i+1] << 8) | data[i+2]
                did_name = svc.get("dids", {}).get(did, f"DID 0x{did:04X}")
                frame["did"]    = did_name
                frame["detail"] = f"ReadDataByIdentifier — {did_name}"
            elif sid == 0x27 and i + 1 < len(data):  # SA
                level = data[i + 1]
                is_key = (level % 2 == 0)
                frame["detail"] = (
                    f"SecurityAccess — {'sendKey' if is_key else 'requestSeed'} "
                    f"level 0x{level:02X}"
                )
        else:
            frame["type"]   = "unknown"
            frame["detail"] = f"Unknown SID 0x{sid:02X}"

        results.append(frame)
        break   # single-frame parse (one service at a time)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# CSS used inside QTextBrowser pages
# ─────────────────────────────────────────────────────────────────────────────
def _html_wrap(body: str) -> str:
    C = COLORS
    return f"""<html><head><style>
body  {{ background:{C['bg_primary']}; color:{C['text_primary']};
         font-family:'Segoe UI',Ubuntu,sans-serif; font-size:13px;
         line-height:1.75; padding:0; margin:0; }}
h1    {{ color:{C['accent_cyan']}; font-size:20px; font-weight:800;
         border-bottom:2px solid {C['accent_cyan']}33; padding-bottom:10px; margin-bottom:16px; }}
h2    {{ color:{C['accent_cyan']}; font-size:16px; font-weight:700;
         border-bottom:1px solid {C['border']}; padding-bottom:8px; margin:22px 0 12px 0; }}
h3    {{ color:{C['accent_yellow']}; font-size:14px; font-weight:700; margin:18px 0 8px 0; }}
h4    {{ color:{C['accent_green']}; font-size:13px; font-weight:700; margin:14px 0 6px 0; }}
p     {{ color:{C['text_primary']}; margin:8px 0; }}
li    {{ color:{C['text_primary']}; margin:5px 0; }}
b, strong {{ color:#ffffff; }}
code  {{ background:{C['bg_elevated']}; color:{C['accent_green']};
         padding:2px 6px; border-radius:4px; font-family:'Consolas','Courier New',monospace; font-size:12px; }}
pre   {{ background:{C['bg_input']}; border:1px solid {C['border']};
         border-left:3px solid {C['accent_cyan']}; border-radius:6px;
         padding:14px 16px; color:{C['accent_green']};
         font-family:'Consolas','Courier New',monospace; font-size:12px;
         overflow:auto; margin:12px 0; }}
table {{ border-collapse:collapse; width:100%; margin:12px 0; }}
th    {{ background:{C['bg_elevated']}; color:{C['accent_cyan']};
         padding:8px 12px; text-align:left; font-size:11px;
         letter-spacing:1.5px; border-bottom:1px solid {C['border_bright']}; }}
td    {{ padding:8px 12px; border-bottom:1px solid {C['border']};
         color:{C['text_primary']}; vertical-align:top; }}
tr:hover td {{ background:{C['bg_elevated']}; }}
.card {{ background:{C['bg_card']}; border:1px solid {C['border']};
         border-radius:8px; padding:16px 20px; margin:12px 0; }}
.badge-cyan   {{ background:{C['accent_cyan']}18; color:{C['accent_cyan']};
                 border:1px solid {C['accent_cyan']}44; border-radius:4px;
                 padding:2px 8px; font-size:11px; font-weight:700; }}
.badge-green  {{ background:{C['accent_green']}18; color:{C['accent_green']};
                 border:1px solid {C['accent_green']}44; border-radius:4px;
                 padding:2px 8px; font-size:11px; font-weight:700; }}
.badge-yellow {{ background:{C['accent_yellow']}18; color:{C['accent_yellow']};
                 border:1px solid {C['accent_yellow']}44; border-radius:4px;
                 padding:2px 8px; font-size:11px; font-weight:700; }}
.badge-red    {{ background:{C['critical']}18; color:{C['critical']};
                 border:1px solid {C['critical']}44; border-radius:4px;
                 padding:2px 8px; font-size:11px; font-weight:700; }}
.note {{ background:{C['accent_yellow']}10; border-left:3px solid {C['accent_yellow']};
         border-radius:0 6px 6px 0; padding:10px 16px; margin:12px 0; color:{C['text_primary']}; }}
.tip  {{ background:{C['accent_cyan']}10; border-left:3px solid {C['accent_cyan']};
         border-radius:0 6px 6px 0; padding:10px 16px; margin:12px 0; color:{C['text_primary']}; }}
.warn {{ background:{C['critical']}10; border-left:3px solid {C['critical']};
         border-radius:0 6px 6px 0; padding:10px 16px; margin:12px 0; color:{C['text_primary']}; }}
</style></head><body>{body}</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Page content
# ─────────────────────────────────────────────────────────────────────────────
PAGE_GETTING_STARTED = """
<h1>🚀 Getting Started</h1>
<p>FucyFuzz is a professional CAN Bus Security Framework for automotive penetration testing and ECU vulnerability research.</p>

<div class="tip"><b>Quick Start:</b> Config → set binary path → choose interface → open a module → RUN</div>

<h2>Step 1 — Configure the Binary</h2>
<p>Go to <b>Config</b> tab and set the path to your <code>fucyfuzz</code> binary.</p>
<table>
<tr><th>OS</th><th>Binary name</th><th>Example path</th></tr>
<tr><td>Linux / macOS</td><td><code>fucyfuzz</code></td><td><code>./fucyfuzz</code></td></tr>
<tr><td>Windows</td><td><code>fucyfuzz.exe</code></td><td><code>C:/fucyfuzz.exe  or  C:/Tools/fucyfuzz.exe</code></td></tr>
</table>
<div class="note"><b>Cross-platform note:</b> FucyFuzz auto-detects your OS and selects the correct interface driver.
You do not need to change any code when switching between Ubuntu and Windows.</div>

<h2>Step 2 — CAN Interface Setup (OS-specific)</h2>

<h3>🐧 Linux — Virtual CAN (vcan0) for safe offline testing</h3>
<pre>sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
ip link show vcan0    # verify: state UNKNOWN</pre>

<h3>🐧 Linux — Physical CAN with PCAN USB hardware</h3>
<pre># Load the PEAK USB kernel module
sudo modprobe peak_usb

# Bring up the interface at 500 kbit/s (standard automotive)
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0
ip link show can0     # verify: state UP

# Optional: persist across reboots via /etc/network/interfaces or systemd-networkd</pre>
<div class="tip">FucyFuzz can auto-run these commands. Go to <b>Tools → Auto-Initialize CAN Interface</b>
or click <b>⚡ Setup Interface</b> in the Config tab.</div>

<h3>🪟 Windows — PCAN USB hardware</h3>
<pre>1. Download and install PEAK driver:
   https://www.peak-system.com/  → Downloads → Driver for PCAN-USB

2. Install python-can with PCAN backend:
   pip install python-can
   pip install "python-can[pcan]"

3. In Config tab set Interface to:  PCAN_USBBUS1
   (or PCAN_USBBUS2 for second adapter)</pre>
<div class="note"><b>Windows only:</b> no kernel modules or sudo needed.
The PEAK driver handles hardware access directly.</div>

<h2>Interface Reference</h2>
<table>
<tr><th>Interface</th><th>OS</th><th>Driver</th><th>Use Case</th></tr>
<tr><td><code>vcan0</code></td><td>Linux</td><td>socketcan</td><td>Virtual CAN — safe offline testing, no hardware needed</td></tr>
<tr><td><code>can0</code></td><td>Linux</td><td>socketcan</td><td>Physical SocketCAN (PCAN, Kvaser, IXXAT via peak_usb etc.)</td></tr>
<tr><td><code>PCAN_USBBUS1</code></td><td>Windows</td><td>pcan</td><td>PEAK PCAN USB adapter — channel 1</td></tr>
<tr><td><code>PCAN_USBBUS2</code></td><td>Windows</td><td>pcan</td><td>PEAK PCAN USB adapter — channel 2</td></tr>
<tr><td><code>virtual</code></td><td>Windows</td><td>virtual</td><td>python-can virtual bus (no hardware — testing only)</td></tr>
<tr><td><code>0</code></td><td>Windows</td><td>vector</td><td>Vector CANalyzer / CANoe channel 0</td></tr>
</table>

<h2>Step 3 — Standard CAN IDs to Know</h2>
<table>
<tr><th>Purpose</th><th>Request ID</th><th>Response ID</th><th>Notes</th></tr>
<tr><td>OBD-II Broadcast</td><td><code>0x7DF</code></td><td><code>0x7E8–0x7EF</code></td><td>All ECUs respond</td></tr>
<tr><td>Primary ECU (ECM)</td><td><code>0x7E0</code></td><td><code>0x7E8</code></td><td>Most common target</td></tr>
<tr><td>TCM (Transmission)</td><td><code>0x7E1</code></td><td><code>0x7E9</code></td><td></td></tr>
<tr><td>BCM (Body Control)</td><td><code>0x7E3</code></td><td><code>0x7EB</code></td><td></td></tr>
<tr><td>ADAS / ABS</td><td><code>0x713</code></td><td><code>0x71B</code></td><td>Varies by OEM</td></tr>
</table>

<h2>Step 4 — Navigate the Modules</h2>
<div class="card">
<b>ATTACK MODULES:</b> UDS · UDS FUZZ · DCM · FUZZER · LEN ATTACK<br>
<b>TOOLS:</b> SEND · DUMP · LISTENER · XCP · DoIP<br>
<b>ANALYSIS:</b> RECON · DEMO · ADVANCED (DID Reader + XCP + DoIP)<br>
<b>OVERVIEW:</b> DASHBOARD · ECU MONITOR · REPLAY · CONFIG
</div>
"""

PAGE_UDS_DECODER_CONTENT = """
<h1>🔬 UDS Message Reference</h1>
<p>ISO 14229-1 — Unified Diagnostic Services complete service reference with request/response format.</p>

<div class="note"><b>Use the interactive decoder above</b> to paste any hex bytes and get instant interpretation.</div>

<h2>Frame Structure</h2>
<div class="card">
<table>
<tr><th>Byte</th><th>Field</th><th>Description</th></tr>
<tr><td><code>B0</code></td><td>SID</td><td>Service Identifier — defines the diagnostic service</td></tr>
<tr><td><code>B1</code></td><td>Sub-Function / DID high</td><td>Depends on service</td></tr>
<tr><td><code>B2+</code></td><td>Parameters / Data</td><td>Service-specific payload</td></tr>
</table>
<br>
<b>Positive response:</b> SID + 0x40 (e.g. service 0x22 → response 0x62)<br>
<b>Negative response:</b> always starts with <code>7F SID NRC</code>
</div>

<h2>All UDS Services</h2>

<h3>0x10 — DiagnosticSessionControl (DSC)</h3>
<p>Controls the active diagnostic session on the ECU.</p>
<table>
<tr><th>Sub-Fn</th><th>Session</th><th>Description</th></tr>
<tr><td><code>01</code></td><td>defaultSession</td><td>Normal operating mode — limited services</td></tr>
<tr><td><code>02</code></td><td>programmingSession</td><td>Flash reprogramming enabled</td></tr>
<tr><td><code>03</code></td><td>extendedDiagnosticSession</td><td>Full diagnostic access — most services available</td></tr>
<tr><td><code>04</code></td><td>safetySystemDiagnosticSession</td><td>Safety-critical systems access</td></tr>
</table>
<pre>Request:  10 03       → Extended Diagnostic Session
Response: 50 03 00 19 01 F4   → Accepted (P2=25ms, P2*=500ms)</pre>

<h3>0x11 — ECUReset (ER)</h3>
<p>Triggers an ECU reset. Use with caution in production vehicles.</p>
<table>
<tr><th>Sub-Fn</th><th>Type</th><th>Description</th></tr>
<tr><td><code>01</code></td><td>hardReset</td><td>Full power cycle equivalent</td></tr>
<tr><td><code>02</code></td><td>keyOffOnReset</td><td>Simulates ignition off → on cycle</td></tr>
<tr><td><code>03</code></td><td>softReset</td><td>Software restart only</td></tr>
</table>
<pre>Request:  11 01   → Hard Reset
Response: 51 01   → Reset accepted</pre>

<h3>0x19 — ReadDTCInformation (RDTCI)</h3>
<p>Reads Diagnostic Trouble Codes (DTCs) from the ECU fault memory.</p>
<pre>Request:  19 02 FF   → Read all DTCs (any status)
Response: 59 02 FF [DTC1 status][DTC2 status]...</pre>

<h3>0x22 — ReadDataByIdentifier (RDBI)</h3>
<p>Reads a specific data record by DID (Data Identifier).</p>
<table>
<tr><th>DID</th><th>Name</th><th>Typical Format</th></tr>
<tr><td><code>F190</code></td><td>VIN</td><td>17 ASCII chars</td></tr>
<tr><td><code>F180</code></td><td>Boot Software ID</td><td>ASCII string</td></tr>
<tr><td><code>F181</code></td><td>Application Software ID</td><td>ASCII string</td></tr>
<tr><td><code>F186</code></td><td>Active Diagnostic Session</td><td>1 byte (01/02/03)</td></tr>
<tr><td><code>F18C</code></td><td>ECU Serial Number</td><td>ASCII string</td></tr>
<tr><td><code>F192</code></td><td>System Supplier HW Number</td><td>ASCII string</td></tr>
</table>
<pre>Request:  22 F1 90              → Read VIN
Response: 62 F1 90 31 47 31 4A 43 35 34 34 34 52 37 32 35 32 33 36 37 31
          → VIN = "1G1JC5444R7252367" (ASCII)</pre>

<h3>0x27 — SecurityAccess (SA)</h3>
<p>Two-step challenge/response authentication to unlock restricted ECU functions.</p>
<div class="warn"><b>Security Risk:</b> Weak or constant seeds indicate a vulnerable ECU RNG.</div>
<pre>Step 1 — Request Seed:
Request:  27 01        → requestSeed level 1
Response: 67 01 A3 F2  → seed = 0xA3F2

Step 2 — Send Key (computed from seed + secret algorithm):
Request:  27 02 B1 4C  → sendKey level 1 (computed)
Response: 67 02        → Access Granted</pre>

<h3>0x2E — WriteDataByIdentifier (WDBI)</h3>
<p>Writes data to a specific DID. Requires appropriate session and security access.</p>
<pre>Request:  2E F1 90 31 47 31 ...   → Write VIN
Response: 6E F1 90                → Write accepted</pre>

<h3>0x31 — RoutineControl (RC)</h3>
<p>Execute or query on-ECU routines (e.g. flash erase, coding verification).</p>
<pre>Request:  31 01 FF 00   → Start routine 0xFF00 (flash erase)
Response: 71 01 FF 00   → Routine started</pre>

<h3>0x34/0x36/0x37 — Download Sequence</h3>
<pre>34 00 44 00 00 80 00 01 00 00   → RequestDownload (addr=0x800000, len=0x10000)
74 20 0F A0                      → Accepted (maxBlockLen=0x0FA0)
36 01 [4000 bytes data]          → TransferData block 1
76 01                            → Block accepted
...repeat for all blocks...
37                               → RequestTransferExit
77                               → Transfer complete</pre>

<h3>0x3E — TesterPresent (TP)</h3>
<p>Keeps the diagnostic session alive. Send every 2–5 seconds when idle.</p>
<pre>Request:  3E 00   → TesterPresent (send response)
Response: 7E 00   → Acknowledged

Request:  3E 80   → TesterPresent (suppress response, bit 7 set)</pre>

<h2>Negative Response (0x7F) NRC Codes</h2>
<table>
<tr><th>NRC</th><th>Name</th><th>Meaning</th></tr>
<tr><td><code>10</code></td><td>generalReject</td><td>Request rejected for unspecified reason</td></tr>
<tr><td><code>11</code></td><td>serviceNotSupported</td><td>SID not supported by this ECU</td></tr>
<tr><td><code>12</code></td><td>subFunctionNotSupported</td><td>Sub-function not available</td></tr>
<tr><td><code>13</code></td><td>incorrectMessageLength</td><td>Wrong number of bytes in request</td></tr>
<tr><td><code>22</code></td><td>conditionsNotCorrect</td><td>Wrong session, engine state, etc.</td></tr>
<tr><td><code>31</code></td><td>requestOutOfRange</td><td>DID / address / parameter out of allowed range</td></tr>
<tr><td><code>33</code></td><td>securityAccessDenied</td><td>Security not unlocked — run 0x27 first</td></tr>
<tr><td><code>35</code></td><td>invalidKey</td><td>Wrong key sent in SecurityAccess step 2</td></tr>
<tr><td><code>36</code></td><td>exceededNumberOfAttempts</td><td>Too many failed security access attempts</td></tr>
<tr><td><code>37</code></td><td>requiredTimeDelayNotExpired</td><td>Wait before retrying SecurityAccess</td></tr>
<tr><td><code>78</code></td><td>responsePending</td><td>ECU still processing — wait for final response</td></tr>
<tr><td><code>7E</code></td><td>subFnNotSupportedInSession</td><td>Change session first</td></tr>
<tr><td><code>7F</code></td><td>serviceNotSupportedInSession</td><td>Switch to extended/programming session</td></tr>
</table>
"""

PAGE_ATTACK_MODULES = """
<h1>⚔️ Attack Modules</h1>

<h2>UDS Module</h2>
<p>Tests ECU diagnostic services per ISO 14229-1.</p>

<h3>Commands</h3>
<table>
<tr><th>Command</th><th>Purpose</th><th>Example</th></tr>
<tr><td><code>discovery</code></td><td>Scan bus for active ECUs</td><td><code>fucyfuzz uds discovery</code></td></tr>
<tr><td><code>services</code></td><td>Enumerate supported services</td><td><code>fucyfuzz uds services 0x7E0 0x7E8</code></td></tr>
<tr><td><code>ecu_reset</code></td><td>Trigger ECU reset</td><td><code>fucyfuzz uds ecu_reset 1 0x7E0 0x7E8</code></td></tr>
<tr><td><code>testerpresent</code></td><td>Keep session alive</td><td><code>fucyfuzz uds testerpresent 0x7E0</code></td></tr>
<tr><td><code>security_seed</code></td><td>Request security seed</td><td><code>fucyfuzz uds security_seed 0x3 0x1 0x7E0 0x7E8</code></td></tr>
<tr><td><code>dump_dids</code></td><td>Dump all readable DIDs</td><td><code>fucyfuzz uds dump_dids 0x7E0 0x7E8 --min_did 0xF180 --max_did 0xF1FF</code></td></tr>
<tr><td><code>read_did</code></td><td>Read single DID</td><td><code>fucyfuzz uds read_did 0x7E0 0x7E8 0xF190</code></td></tr>
<tr><td><code>read_mem</code></td><td>Read memory region</td><td><code>fucyfuzz uds read_mem 0x7E0 0x7E8 --start_addr 0x0200 --mem_length 0x100</code></td></tr>
</table>

<h2>UDS Fuzz Module</h2>
<p>Fuzzes UDS SecurityAccess seeds to detect RNG weaknesses.</p>
<table>
<tr><th>Mode</th><th>Description</th></tr>
<tr><td><code>seed_randomness_fuzzer</code></td><td>Collects many seeds, analyzes entropy, detects repeats and patterns</td></tr>
<tr><td><code>delay_fuzzer</code></td><td>Tests security lockout bypass via timing manipulation</td></tr>
</table>
<div class="warn"><b>Finding:</b> If CRITICAL seeds appear in output, the ECU RNG is weak or constant — a serious security vulnerability.</div>

<h2>DCM Module</h2>
<p>Diagnostic Communication Manager — similar to UDS but for Bosch/Mercedes DCM stacks.</p>
<pre>fucyfuzz dcm discovery
fucyfuzz dcm services 0x7E0 0x7E8
fucyfuzz dcm subfunc 0x7E0 0x7E8 0x22 2 3
fucyfuzz dcm dtc 0x7E0 0x7E8</pre>

<h2>Fuzzer Module</h2>
<table>
<tr><th>Mode</th><th>Description</th><th>Example</th></tr>
<tr><td><code>random</code></td><td>Send random CAN frames</td><td><code>fucyfuzz fuzzer random -min 4</code></td></tr>
<tr><td><code>brute</code></td><td>Brute-force a specific ID with pattern</td><td><code>fucyfuzz fuzzer brute 0x7E0 22F190..</code></td></tr>
<tr><td><code>mutate</code></td><td>Mutate known-valid frames</td><td><code>fucyfuzz fuzzer mutate 7f.. 12ab....</code></td></tr>
<tr><td><code>replay</code></td><td>Replay captured log</td><td><code>fucyfuzz fuzzer replay capture.txt</code></td></tr>
</table>
<p>Pattern syntax: <code>.</code> = random byte, hex digits = fixed byte</p>

<h2>Length Attack (LenAttack)</h2>
<p>Sends malformed frames with incorrect DLC to test ECU robustness.</p>
<pre>fucyfuzz lenattack 0x7E0 --min-dlc 0 --max-dlc 8 --pattern rand -i can0</pre>
"""

PAGE_TOOLS = """
<h1>🛠️ Tools</h1>

<h2>Send Module</h2>
<p>Send arbitrary CAN frames or replay log files.</p>
<pre># Format: ID#data (hex, dot-separated bytes)
0x7E0#02.10.03         → DSC extended session request
0x7E0#02.3E.00         → TesterPresent
0x7E0#03.22.F1.90      → Read VIN (RDBI)</pre>

<h3>UDS / VIN Read (Built-in)</h3>
<p>The Send tab has a built-in VIN reader using ISO-TP. Configure Request/Response IDs and click <b>Read VIN</b>. The response is automatically decoded.</p>
<div class="tip">Requires <code>python-can</code> and <code>python-isotp</code>: <code>pip install python-can python-isotp</code></div>

<h2>Dump Module</h2>
<p>Captures all CAN traffic on the bus to a file.</p>
<pre>fucyfuzz dump -s 1.0 -f capture.txt     # 1 Hz sample rate
fucyfuzz dump -c 0x7E0 0x7E8            # filter specific IDs</pre>

<h2>Listener</h2>
<p>Passive real-time CAN frame display.</p>
<pre>fucyfuzz listener          # formatted display
fucyfuzz listener -r       # raw bytes mode</pre>

<h2>XCP Module</h2>
<p>Universal Calibration Protocol — memory read/write for ECU calibration attacks.</p>
<table>
<tr><th>Command</th><th>Description</th></tr>
<tr><td><code>discovery</code></td><td>Find XCP-capable ECUs</td></tr>
<tr><td><code>commands</code></td><td>Enumerate supported XCP commands</td></tr>
<tr><td><code>info</code></td><td>Read ECU identification</td></tr>
<tr><td><code>dump</code></td><td>Memory dump via UPLOAD command sequence</td></tr>
</table>
<pre>fucyfuzz xcp dump 1000 1001 0x1fffb000 0x4800 -f bootloader.hex</pre>

<h2>DoIP Module</h2>
<p>Diagnostics over IP — discover ECUs that tunnel UDS over Ethernet.</p>
<pre>fucyfuzz doip discovery
fucyfuzz doip wakeup 0x7E0 0x7E8
fucyfuzz doip info 0x7E0 0x7E8</pre>

<h2>Replay Module</h2>
<p>Load and replay previously captured CAN logs. Supports selective replay, filtering, and timing adjustment.</p>
"""

PAGE_ADVANCED = """
<h1>⚙️ Advanced Features</h1>

<h2>RECON Tab — Automated Recon Suite</h2>
<p>Runs a comprehensive sequence of discovery and enumeration commands automatically.</p>
<div class="card">
<b>Included in Recon sequence:</b><br>
Fuzzer random/brute/mutate → LenAttack → DCM discovery/services/subfunc/DTC/TesterPresent →
UDS discovery/services/ECUReset/TesterPresent/SecuritySeed/DumpDIDs/ReadMemory
</div>
<p>Toggle <b>Pass interface via -i</b> to include the configured CAN interface flag in all commands.</p>

<h2>DEMO Tab — Vehicle Fuzzing Demos</h2>
<p>Pre-configured demos for common automotive attack scenarios.</p>
<table>
<tr><th>Demo</th><th>CAN ID</th><th>Effect</th></tr>
<tr><td>Speed Fuzz</td><td><code>0x244</code></td><td>Fuzzes instrument cluster speed display</td></tr>
<tr><td>Indicator Fuzz</td><td><code>0x188</code></td><td>Fuzzes turn indicator signals</td></tr>
<tr><td>Door Lock Fuzz</td><td><code>0x19B</code></td><td>Fuzzes door lock control signals</td></tr>
</table>

<h2>ADVANCED Tab — DID Reader</h2>
<p>Interactive DID reader with automatic response decoding.</p>
<ul>
<li>Select a preset DID (VIN, Boot SW, App SW…) or enter a custom 4-digit hex DID</li>
<li>Click <b>Read DID</b> — response decoded instantly in the response panel</li>
<li>Scan a DID range (e.g. F180–F1FF) to find all readable identifiers</li>
<li>Negative responses (NRC) are translated to human-readable names</li>
</ul>
<pre>fucyfuzz uds read_did 0x7E0 0x7E8 0xF190     → VIN
fucyfuzz uds dump_dids 0x7E0 0x7E8 --min_did 0xF180 --max_did 0xF1FF -t 0.2</pre>

<h2>ECU Monitor Tab</h2>
<p>Long-term passive monitoring of ECU behaviour.</p>
<ul>
<li>Click <b>START WATCHING</b> to begin recording ECU state changes</li>
<li>All anomalies, responses, and DTC changes are captured</li>
<li>Click <b>STOP</b> to end the session — it is automatically archived</li>
<li>Export any session as a detailed PDF report</li>
</ul>

<h2>Dashboard</h2>
<p>Real-time summary of all findings across all modules.</p>
<ul>
<li><b>Severity counters</b> (Critical / High / Medium / Low) update live</li>
<li><b>Fault log table</b> shows every detected anomaly with module, timestamp, and command</li>
<li>Click any fault row to see full context</li>
</ul>

<h2>DBC File Integration</h2>
<p>Load a <code>.dbc</code> file (Config tab) to populate ID dropdowns in Fuzzer, LenAttack, Send, UDS, and DCM tabs with human-readable message names.</p>
<div class="tip">Requires: <code>pip install cantools</code></div>

<h2>Export System</h2>
<table>
<tr><th>Export Type</th><th>Format</th><th>Content</th></tr>
<tr><td>Overall Report</td><td>PDF / ASC / MF4</td><td>Full session summary with all faults and stats</td></tr>
<tr><td>Failure Report</td><td>PDF</td><td>Only failed commands and their details</td></tr>
<tr><td>ECU Session</td><td>PDF</td><td>ECU Monitor session — events, anomalies, timeline</td></tr>
<tr><td>Save Logs</td><td>.log</td><td>Raw terminal output text</td></tr>
<tr><td>Export Logs</td><td>ASC / MF4</td><td>Industry-standard automotive log formats</td></tr>
</table>
"""


# ─────────────────────────────────────────────────────────────────────────────
# Interactive decoder result renderer
# ─────────────────────────────────────────────────────────────────────────────
def _render_decode_result(frames: list[dict]) -> str:
    C = COLORS
    if not frames:
        return f'<p style="color:{C["text_muted"]}; font-style:italic;">Enter hex bytes above and press Decode.</p>'

    parts = []
    for f in frames:
        if "error" in f:
            parts.append(
                f'<div class="warn">❌ {f["error"]}</div>'
            )
            continue

        ftype = f.get("type", "unknown")
        raw   = " ".join(f.get("raw_bytes", []))

        if ftype == "request":
            badge = f'<span class="badge-cyan">REQUEST</span>'
            color = C['accent_cyan']
        elif ftype == "positive_response":
            badge = f'<span class="badge-green">POSITIVE RESPONSE</span>'
            color = C['accent_green']
        elif ftype == "negative_response":
            badge = f'<span class="badge-red">NEGATIVE RESPONSE</span>'
            color = C['critical']
        else:
            badge = f'<span class="badge-yellow">UNKNOWN</span>'
            color = C['accent_yellow']

        svc_name = f.get("service", "Unknown")
        abbr     = f.get("abbr", "??")
        detail   = f.get("detail", "")
        sid      = f.get("sid", 0)

        html = f"""
<div class="card">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
    {badge}
    <span style="color:{color};font-size:16px;font-weight:800;">0x{sid:02X} — {svc_name}</span>
    <span style="color:{C['text_muted']};font-size:11px;">[{abbr}]</span>
  </div>
  <table style="margin:0;">
    <tr><td style="color:{C['text_secondary']};width:140px;">Raw Bytes</td>
        <td><code>{raw}</code></td></tr>
    <tr><td style="color:{C['text_secondary']};">Interpretation</td>
        <td style="color:{C['text_primary']};"><b>{detail}</b></td></tr>"""

        if "sub_fn" in f:
            html += f"""
    <tr><td style="color:{C['text_secondary']};">Sub-Function</td>
        <td style="color:{C['accent_yellow']};">{f['sub_fn']}</td></tr>"""

        if "did" in f:
            html += f"""
    <tr><td style="color:{C['text_secondary']};">DID</td>
        <td style="color:{C['accent_purple']};">{f['did']}</td></tr>"""

        if "value_hex" in f:
            html += f"""
    <tr><td style="color:{C['text_secondary']};">Value (hex)</td>
        <td><code>{f['value_hex']}</code></td></tr>"""

        if "value_ascii" in f:
            html += f"""
    <tr><td style="color:{C['text_secondary']};">Value (ASCII)</td>
        <td style="color:{C['accent_green']};font-size:15px;font-weight:700;">{f['value_ascii']}</td></tr>"""

        if "nrc_name" in f:
            html += f"""
    <tr><td style="color:{C['text_secondary']};">NRC Code</td>
        <td><code style="color:{C['critical']};">0x{f['nrc']:02X}</code>
            <span style="color:{C['text_primary']};margin-left:8px;">{f['nrc_name']}</span></td></tr>"""

        html += "</table></div>"
        parts.append(html)

    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# HelpTab widget
# ─────────────────────────────────────────────────────────────────────────────
class HelpTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        C = COLORS
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(58)
        header.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {C['bg_secondary']}, stop:0.5 {C['bg_card']}, stop:1 {C['bg_secondary']});
            border-bottom: 1px solid {C['border']};
        """)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(24, 0, 24, 0)

        icon_lbl = QLabel("📖")
        icon_lbl.setStyleSheet("font-size:20px; background:transparent;")
        hl.addWidget(icon_lbl)
        hl.addSpacing(8)

        title_lbl = QLabel("FUCYFUZZ DOCUMENTATION")
        title_lbl.setStyleSheet(f"""
            color:{C['accent_cyan']}; font-size:15px; font-weight:800;
            letter-spacing:3px; background:transparent;
        """)
        hl.addWidget(title_lbl)
        hl.addSpacing(16)

        subtitle = QLabel("CAN Bus Security Framework — Complete Reference")
        subtitle.setStyleSheet(f"color:{C['text_secondary']}; font-size:11px; background:transparent;")
        hl.addWidget(subtitle)
        hl.addStretch()
        layout.addWidget(header)

        # ── Main tab widget ────────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border:none; background:{C['bg_primary']}; }}
            QTabBar::tab {{
                background:{C['bg_secondary']}; border:none;
                border-bottom:2px solid transparent;
                padding:9px 16px; color:{C['text_secondary']};
                font-size:11px; font-weight:600; letter-spacing:0.5px;
                min-width:90px;
            }}
            QTabBar::tab:selected {{
                background:{C['bg_card']}; color:{C['accent_cyan']};
                border-bottom:2px solid {C['accent_cyan']};
            }}
            QTabBar::tab:hover:!selected {{
                color:{C['text_primary']}; background:{C['bg_elevated']};
            }}
        """)

        # ── Tab 1: Getting Started ─────────────────────────────────────────────
        tabs.addTab(self._make_html_page(PAGE_GETTING_STARTED), "🚀 Getting Started")

        # ── Tab 2: UDS Decoder (interactive) ──────────────────────────────────
        tabs.addTab(self._make_decoder_tab(), "🔬 UDS Decoder")

        # ── Tab 3: UDS Reference ──────────────────────────────────────────────
        tabs.addTab(self._make_html_page(PAGE_UDS_DECODER_CONTENT), "📋 UDS Reference")

        # ── Tab 4: Attack Modules ──────────────────────────────────────────────
        tabs.addTab(self._make_html_page(PAGE_ATTACK_MODULES), "⚔️ Attack Modules")

        # ── Tab 5: Tools ──────────────────────────────────────────────────────
        tabs.addTab(self._make_html_page(PAGE_TOOLS), "🛠️ Tools")

        # ── Tab 6: Advanced ───────────────────────────────────────────────────
        tabs.addTab(self._make_html_page(PAGE_ADVANCED), "⚙️ Advanced")

        layout.addWidget(tabs)

    def _make_html_page(self, body: str) -> QWidget:
        """Wrap HTML in a styled QTextBrowser inside a scroll area."""
        C = COLORS
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setStyleSheet(f"""
            QTextBrowser {{
                background:{C['bg_primary']}; border:none;
                color:{C['text_primary']};
                font-family:'Segoe UI',Ubuntu,sans-serif;
                font-size:13px; padding:24px 32px; line-height:1.7;
            }}
        """)
        browser.setHtml(_html_wrap(body))
        return browser

    def _make_decoder_tab(self) -> QWidget:
        """Interactive UDS hex decoder panel."""
        C = COLORS
        w = QWidget()
        w.setStyleSheet(f"background:{C['bg_primary']};")
        vlay = QVBoxLayout(w)
        vlay.setContentsMargins(24, 20, 24, 20)
        vlay.setSpacing(16)

        # ── Section title ─────────────────────────────────────────────────────
        title = QLabel("🔬  INTERACTIVE UDS MESSAGE DECODER")
        title.setStyleSheet(f"""
            color:{C['accent_cyan']}; font-size:14px; font-weight:800;
            letter-spacing:2px; background:transparent;
            border-bottom:1px solid {C['border']}; padding-bottom:10px;
        """)
        vlay.addWidget(title)

        subtitle = QLabel(
            "Paste any UDS hex bytes below to instantly decode the service, "
            "sub-function, DID, and response meaning."
        )
        subtitle.setStyleSheet(f"color:{C['text_secondary']}; font-size:12px; background:transparent;")
        subtitle.setWordWrap(True)
        vlay.addWidget(subtitle)

        # ── Input row ─────────────────────────────────────────────────────────
        input_frame = QFrame()
        input_frame.setStyleSheet(f"""
            QFrame {{ background:{C['bg_card']}; border:1px solid {C['border']};
                      border-radius:8px; }}
        """)
        input_lay = QHBoxLayout(input_frame)
        input_lay.setContentsMargins(16, 12, 16, 12)
        input_lay.setSpacing(10)

        hex_lbl = QLabel("HEX INPUT:")
        hex_lbl.setStyleSheet(f"color:{C['text_secondary']}; font-size:11px; font-weight:700; letter-spacing:1.5px; background:transparent;")
        input_lay.addWidget(hex_lbl)

        self._hex_input = QLineEdit()
        self._hex_input.setPlaceholderText(
            "e.g.  10 03   or   22 F1 90   or   7F 22 31   or   62 F1 90 31 47 31 4A..."
        )
        self._hex_input.setStyleSheet(f"""
            QLineEdit {{
                background:{C['bg_input']}; border:1px solid {C['border']};
                border-radius:6px; padding:10px 14px; color:{C['text_primary']};
                font-family:'Consolas','Courier New',monospace;
                font-size:13px; letter-spacing:1px;
            }}
            QLineEdit:focus {{ border:1px solid {C['accent_cyan']}; }}
        """)
        self._hex_input.returnPressed.connect(self._do_decode)
        input_lay.addWidget(self._hex_input)

        decode_btn = QPushButton("  DECODE  ")
        decode_btn.setFixedHeight(38)
        decode_btn.setStyleSheet(f"""
            QPushButton {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C['accent_cyan']}, stop:1 {C['accent_purple']});
                border:none; color:{C['bg_primary']};
                border-radius:6px; font-size:13px; font-weight:800;
                padding:0 20px; letter-spacing:1px;
            }}
            QPushButton:hover {{ opacity:0.9; }}
            QPushButton:pressed {{ background:{C['accent_cyan']}; }}
        """)
        decode_btn.clicked.connect(self._do_decode)
        input_lay.addWidget(decode_btn)

        clear_btn = QPushButton("✕")
        clear_btn.setFixedSize(38, 38)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background:transparent; border:1px solid {C['border']};
                color:{C['text_secondary']}; border-radius:6px; font-size:14px;
            }}
            QPushButton:hover {{ border-color:{C['critical']}; color:{C['critical']}; }}
        """)
        clear_btn.clicked.connect(self._clear_decoder)
        input_lay.addWidget(clear_btn)
        vlay.addWidget(input_frame)

        # ── Quick examples ─────────────────────────────────────────────────────
        ex_lbl = QLabel("Quick examples:")
        ex_lbl.setStyleSheet(f"color:{C['text_muted']}; font-size:10px; font-weight:700; letter-spacing:1px; background:transparent;")
        vlay.addWidget(ex_lbl)

        ex_row = QHBoxLayout()
        ex_row.setSpacing(8)
        examples = [
            ("10 03",               "DSC Extended Session"),
            ("22 F1 90",            "Read VIN"),
            ("27 01",               "SecurityAccess Seed"),
            ("3E 00",               "TesterPresent"),
            ("11 01",               "ECU Hard Reset"),
            ("7F 22 31",            "Neg: RDBI OutOfRange"),
            ("7F 27 35",            "Neg: SA InvalidKey"),
            ("62 F1 90 31 47 31 4A 43 35 34 34 34 52 37 32 35 32 33 36 37 31", "VIN Response"),
        ]
        for hex_val, label in examples:
            btn = QPushButton(label)
            btn.setFixedHeight(28)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background:{C['bg_elevated']}; border:1px solid {C['border']};
                    color:{C['text_secondary']}; border-radius:4px;
                    font-size:10px; font-weight:600; padding:0 10px;
                }}
                QPushButton:hover {{
                    background:{C['accent_cyan']}15; border-color:{C['accent_cyan']}55;
                    color:{C['accent_cyan']};
                }}
            """)
            btn.clicked.connect(lambda _, h=hex_val: self._load_example(h))
            ex_row.addWidget(btn)
        ex_row.addStretch()
        vlay.addLayout(ex_row)

        # ── Result panel ──────────────────────────────────────────────────────
        result_frame = QFrame()
        result_frame.setStyleSheet(f"""
            QFrame {{
                background:{C['bg_secondary']}; border:1px solid {C['border']};
                border-radius:8px;
            }}
        """)
        rf_lay = QVBoxLayout(result_frame)
        rf_lay.setContentsMargins(0, 0, 0, 0)

        res_header = QWidget()
        res_header.setFixedHeight(36)
        res_header.setStyleSheet(f"""
            background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {C['bg_elevated']}, stop:1 {C['bg_card']});
            border-radius:8px 8px 0 0;
            border-bottom:1px solid {C['border']};
        """)
        rh_lay = QHBoxLayout(res_header)
        rh_lay.setContentsMargins(16, 0, 16, 0)
        rh_lbl = QLabel("DECODED RESULT")
        rh_lbl.setStyleSheet(f"color:{C['accent_cyan']}; font-size:10px; font-weight:800; letter-spacing:2px; background:transparent;")
        rh_lay.addWidget(rh_lbl)
        rf_lay.addWidget(res_header)

        self._result_browser = QTextBrowser()
        self._result_browser.setStyleSheet(f"""
            QTextBrowser {{
                background:{C['bg_secondary']}; border:none;
                border-radius:0 0 8px 8px; padding:16px 20px;
                color:{C['text_primary']}; font-size:13px;
            }}
        """)
        self._result_browser.setMinimumHeight(220)
        initial_html = _html_wrap(
            f'<p style="color:{C["text_muted"]};font-style:italic;margin-top:20px;">'
            "Enter hex bytes above and press Decode — or click one of the quick example buttons.</p>"
        )
        self._result_browser.setHtml(initial_html)
        rf_lay.addWidget(self._result_browser)
        vlay.addWidget(result_frame)

        return w

    def _do_decode(self):
        text = self._hex_input.text().strip()
        if not text:
            return
        frames = decode_uds_bytes(text)
        result_html = _render_decode_result(frames)
        self._result_browser.setHtml(_html_wrap(result_html))

    def _load_example(self, hex_val: str):
        self._hex_input.setText(hex_val)
        self._do_decode()

    def _clear_decoder(self):
        self._hex_input.clear()
        C = COLORS
        self._result_browser.setHtml(_html_wrap(
            f'<p style="color:{C["text_muted"]};font-style:italic;margin-top:20px;">'
            "Enter hex bytes above and press Decode.</p>"
        ))
