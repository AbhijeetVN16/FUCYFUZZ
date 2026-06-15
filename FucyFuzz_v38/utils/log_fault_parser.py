"""
Log Fault Parser  —  v3  (Multi-Strategy Matching Engine)
==========================================================

ROOT CAUSE FIX
--------------
Previous versions required ALL keywords from log_message to appear in the
scanned line (AND logic).  For VULN-006:
  log_message = "Vulnerability triggered: Sent static seed 0xDEADBEEF"
  keywords    = ['vulnerability','triggered','sent','static','seed','deadbeef']
  actual live line = "SecurityAccess_OK(level=0x01 seed=0xDEADBEEF)"
               → 'vulnerability', 'triggered', 'sent', 'static' ABSENT → NO MATCH

The real decoded line from session_logger.decode_uds() NEVER contains all
the words from the ECU simulator's internal log_message — they are two
completely different strings.

FOUR-STRATEGY MATCHING ENGINE  (first highest-score wins)
----------------------------------------------------------
Score 4 — Strategy 1  TRIGGER CONDITION
  Match using UDS service NAME (from SID) + DID as "did=0xXXXX" + hex values.
  e.g. VULN-006: SID=0x27 → "securityaccess" in line  AND
                             "deadbeef" in line         → score=4

Score 3 — Strategy 3  HEX VALUES  (note: ordered before Strategy 2)
  The effect.values list concatenated to a hex string appears in the line.
  e.g. ["0xDE","0xAD","0xBE","0xEF"] → "deadbeef" → found in "seed=0xDEADBEEF"

Score 2 — Strategy 2  PARTIAL LOG_MESSAGE (N-gram, OR logic)
  At least one 2-gram or single important token from log_message appears.
  Fixes the AND-all bug.  Score is LOWER than hex-values so VULN-006 beats
  any vuln whose log_message happens to share a common word like "triggered".

Score 1 — Strategy 4  VULN NAME / ID
  The vuln name or id appears verbatim in the line.

LIVE PIPELINE  (base_tab → DataManager → ECU Monitor)
------------------------------------------------------
Every sub-process output line:
  stdout → base_tab._on_output() → _parse_output_for_faults(line)
    → dm.add_fault(sev, module, desc, cmd)
    → dm._log_fault_to_session_logger()  direction="VULN"
    → SessionLogger._fire_gui()          synchronous
    → _LogEntryBridge.on_entry()
    → entry_received(dict)               Qt QueuedConnection
    → ECUMonitorTab._on_log_entry()      VULN gate — main thread

Additionally, the DataManager.parse_terminal_line() method now accepts
a vuln_db parameter so live lines can be matched against VulnDB definitions.

LOG REPLAY PIPELINE
-------------------
  session.log / .csv / .jsonl
    → parse_file(path, vuln_db)
    → _iter_*_lines() → (ts, module, raw_line)
    → scan_line(raw_line, module, vuln_db)
       Priority: Strategy 1 → 3 → 2 → 4 → Layer-1 → Layer-2
    → FaultEvent

Public API (backward-compatible)
---------------------------------
  load_vuln_db(path)                       → VulnDB | None
  parse_file(path, vuln_db=None)           → Iterator[FaultEvent]
  scan_line(text, module='', vuln_db=None) → FaultEvent | None
  VulnDB.match_line(line, require_enabled) → VulnEntry | None
  VulnDB.match_trigger(line)               → VulnEntry | None   NEW
  action_to_severity(action)              → str
"""

import csv
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
#  Severity table
# ---------------------------------------------------------------------------

ACTION_SEVERITY: Dict[str, str] = {
    "CRASH":                      "critical",
    "BYPASS_SECURITY":            "critical",
    "HANG":                       "critical",
    "LOGIC_ERR":                  "high",
    "MODIFY_RESPONSE":            "high",
    "ACCEPT_ILLEGAL_TRANSITION":  "high",
    "STATIC_SEED":                "high",
}


def action_to_severity(action: str) -> str:
    return ACTION_SEVERITY.get(action.upper(), "medium")


# ---------------------------------------------------------------------------
#  UDS SID → service name  (mirrors session_logger.decode_uds output)
# ---------------------------------------------------------------------------

_SID_NAMES: Dict[str, str] = {
    "0x10": "diagnosticsessioncontrol",
    "0x11": "ecureset",
    "0x14": "cleardtcinformation",
    "0x19": "readdtcinformation",
    "0x22": "readdatabyidentifier",
    "0x23": "readmemorybyaddress",
    "0x27": "securityaccess",
    "0x28": "communicationcontrol",
    "0x2e": "writedatabyidentifier",
    "0x3d": "writememorybyaddress",
    "0x3e": "testerpresent",
    "0x7f": "negativeresponse",
}


# ---------------------------------------------------------------------------
#  VulnEntry with four-strategy scoring
# ---------------------------------------------------------------------------

@dataclass
class VulnEntry:
    id:          str
    name:        str
    description: str
    action:      str
    log_message: str
    enabled:     bool
    severity:    str
    sid:         str = ""   # e.g. "0x2E"
    did:         str = ""   # e.g. "0xF190"
    hex_values:  str = ""   # concatenated values, e.g. "DEADBEEF"
    # Derived (built in __post_init__)
    ngrams:      List[str] = field(default_factory=list)
    name_tokens: List[str] = field(default_factory=list)
    # SID service name for trigger matching
    _sid_name:   str = field(default="", repr=False)

    def __post_init__(self):
        # Strategy 1: resolve SID to service name
        self._sid_name = _SID_NAMES.get(self.sid.lower(), "") if self.sid else ""

        # Strategy 2: N-grams from log_message (OR logic — any one match is enough)
        tokens = re.findall(r"0x[0-9a-fA-F]+|[A-Za-z0-9_]{3,}", self.log_message)
        w = [t.lower() for t in tokens]
        ng: List[str] = []
        ng += w                                                           # 1-grams
        ng += [f"{w[i]} {w[i+1]}" for i in range(len(w) - 1)]           # 2-grams
        ng += [f"{w[i]} {w[i+1]} {w[i+2]}" for i in range(len(w) - 2)]  # 3-grams
        seen: set = set()
        self.ngrams = []
        for g in ng:
            if g not in seen:
                seen.add(g)
                self.ngrams.append(g)

        # Strategy 4: name / id tokens
        self.name_tokens = [
            t.lower()
            for t in re.findall(r"[A-Za-z0-9_]{3,}", self.name)
        ]

    # ── Four-strategy score ───────────────────────────────────────────────────

    def match_score(self, lower_line: str) -> int:
        """
        Return match score (0 = no match, 4 = highest).

        4 → Strategy 1  trigger condition (SID service name + optional DID/hex)
        3 → Strategy 3  hex values (effect.values as concatenated hex string)
        2 → Strategy 2  partial log_message N-gram (OR logic)
        1 → Strategy 4  vuln name / id direct
        0 → no match
        """
        # Strategy 1: trigger condition
        if self._s1(lower_line):
            return 4

        # Strategy 3: hex values (checked before ngrams to beat common-word ties)
        if self.hex_values and self.hex_values.lower() in lower_line:
            return 3

        # Strategy 2: N-gram OR match
        if self.ngrams and any(ng in lower_line for ng in self.ngrams):
            return 2

        # Strategy 4: name tokens (ALL must appear — these are distinctive)
        if (self.name_tokens
                and len(self.name_tokens) <= 4        # avoid over-broad names
                and all(t in lower_line for t in self.name_tokens)):
            return 1

        return 0

    def _s1(self, lower_line: str) -> bool:
        """
        Strategy 1: trigger condition match.

        All of the following that are non-empty must match:
          • SID → resolved to UDS service NAME (e.g. "securityaccess")
                   OR raw "0xXX" hex token as exact prefix
          • DID → "did=0xXXXX" OR "did=XXXX" pattern
          • hex_values → concatenated hex string present in line
        At least one trigger field must exist.
        """
        required = 0
        matched  = 0

        # SID via service name  (most reliable)
        if self.sid:
            required += 1
            if self._sid_name and self._sid_name in lower_line:
                matched += 1
            else:
                # Fallback: match "0xXX" as a hex-prefixed token not embedded in longer hex
                hex_digits = self.sid.lower().replace("0x", "")
                pattern = rf"(?<![0-9a-f])0x0*{re.escape(hex_digits)}(?![0-9a-f])"
                if re.search(pattern, lower_line):
                    matched += 1

        # DID via "did=0xXXXX" pattern
        if self.did:
            required += 1
            did_hex = self.did.lower().replace("0x", "")
            if (f"did=0x{did_hex}" in lower_line
                    or f"did={did_hex}" in lower_line):
                matched += 1

        # hex_values
        if self.hex_values:
            required += 1
            if self.hex_values.lower() in lower_line:
                matched += 1

        return required > 0 and matched == required


# ---------------------------------------------------------------------------
#  VulnDB
# ---------------------------------------------------------------------------

class VulnDB:
    """Parsed vulnerability profile with four-strategy matching."""

    def __init__(self, entries: Dict[str, "VulnEntry"],
                 ecu_profile: str = "", path: str = ""):
        self.entries:     Dict[str, VulnEntry] = entries
        self.ecu_profile: str = ecu_profile
        self.path:        str = path
        # Sort: enabled first, then by id for deterministic ordering
        self._sorted: List[VulnEntry] = sorted(
            entries.values(),
            key=lambda e: (not e.enabled, e.id),
        )

    def match_line(self, line: str,
                   require_enabled: bool = False) -> Optional[VulnEntry]:
        """
        Return the VulnEntry with the highest match score, or None.

        Strategy 1 (score=4) wins over Strategy 3 (score=3) over Strategy 2
        (score=2) over Strategy 4 (score=1).  Ties at equal score → first in
        sorted order (enabled-first, then id order).

        require_enabled=True  → live monitoring (ignore disabled entries)
        require_enabled=False → log replay (match any armed or historical entry)
        """
        lower     = line.lower()
        best      = None
        best_score = 0

        for entry in self._sorted:
            if require_enabled and not entry.enabled:
                continue
            sc = entry.match_score(lower)
            if sc > best_score:
                best_score = sc
                best       = entry
                if best_score == 4:
                    break   # can't beat trigger-condition match

        return best if best_score > 0 else None

    def match_trigger(self, line: str) -> Optional[VulnEntry]:
        """Strategy-1-only: used by the live decoded-frame checker."""
        lower = line.lower()
        for entry in self._sorted:
            if entry._s1(lower):
                return entry
        return None

    @property
    def enabled_count(self) -> int:
        return sum(1 for e in self.entries.values() if e.enabled)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for e in self.entries.values()
            if e.enabled and e.severity == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for e in self.entries.values()
            if e.enabled and e.severity == "high"
        )


# ---------------------------------------------------------------------------
#  load_vuln_db
# ---------------------------------------------------------------------------

def load_vuln_db(path: str) -> Optional[VulnDB]:
    """
    Parse vulnerabilities.json → VulnDB.

    Extracts effect.values as a concatenated hex string (e.g. DEADBEEF)
    for Strategy-3 matching.  Returns None on error.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        ecu_profile = raw.get("ecu_profile", "")
        entries: Dict[str, VulnEntry] = {}

        for v in raw.get("vulnerabilities", []):
            trigger = v.get("trigger", {})
            effect  = v.get("effect",  {})
            action  = effect.get("action", "").upper()
            sev     = action_to_severity(action)

            # Build hex_values from effect.values list  (e.g. VULN-006)
            val_list: List[str] = effect.get("values", [])
            hex_values = ""
            if val_list:
                try:
                    hex_values = "".join(
                        str(x).replace("0x", "").replace("0X", "")
                        for x in val_list
                        if isinstance(x, str) and x.startswith("0x")
                    ).upper()
                except Exception:
                    hex_values = ""

            entry = VulnEntry(
                id=v.get("id", ""),
                name=v.get("name", ""),
                description=v.get("description", ""),
                action=action,
                log_message=effect.get("log_message", ""),
                enabled=v.get("enabled", True),
                severity=sev,
                sid=trigger.get("sid", ""),
                did=trigger.get("did", trigger.get("data_identifier", "")),
                hex_values=hex_values,
            )
            if entry.id:
                entries[entry.id] = entry

        return VulnDB(entries, ecu_profile=ecu_profile, path=path)

    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("VulnDB load failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
#  FaultEvent — carries severity from log + high-precision TX/RX timestamps
# ---------------------------------------------------------------------------

@dataclass
class FaultEvent:
    severity:     str
    module:       str
    description:  str
    cmd:          str
    timestamp:    str
    vuln_id:      str = ""
    vuln_name:    str = ""
    # High-precision fields from the upgraded SessionLogger
    timestamp_tx: str = ""   # exact TX moment (ms precision)
    timestamp_rx: str = ""   # exact RX moment (ms precision)
    log_severity: str = ""   # raw severity tag from the log entry itself


# ---------------------------------------------------------------------------
#  Layer-1 explicit patterns  (no VulnDB needed — covers all six vulns)
# ---------------------------------------------------------------------------

# Each tuple: (label, severity, [patterns])
# Patterns are matched as substrings (case-insensitive).
# Longest-first sort ensures specific patterns beat generic ones.

_LAYER1_RAW: List[Tuple[str, str, List[str]]] = [
    # VULN-001
    ("Memory corruption / buffer overflow  [VULN-001]", "critical", [
        "memory corruption detected in vin buffer",
        "memory corruption", "vin buffer", "buffer overflow",
    ]),
    # VULN-002
    ("Security bypass via magic byte  [VULN-002]", "critical", [
        "security bypass triggered via magic byte",
        "security bypass triggered", "bypass_security",
    ]),
    # VULN-003
    ("Resource exhaustion / DoS hang  [VULN-003]", "critical", [
        "internal message queue overflow",
        "message queue overflow", "cpu at 100%",
        "force_p2_star_timeout",
    ]),
    # VULN-004
    ("ISO-TP reassembly fault  [VULN-004]", "critical", [
        "iso-tp reassembly engine exception",
        "iso-tp reassembly", "reassembly engine",
        "out_of_order_cf",
    ]),
    # VULN-005
    ("Unauthorized session transition  [VULN-005]", "high", [
        "unauthorized state transition to programming session",
        "unauthorized state transition",
        "accept_illegal_transition",
    ]),
    # VULN-006 — ALL forms of deadbeef / static seed
    ("Weak / static seed entropy  [VULN-006]", "high", [
        "vulnerability triggered: sent static seed 0xdeadbeef",
        "sent static seed 0xdeadbeef",
        "seed=0xdeadbeef",
        "seed 0xdeadbeef",
        "sent static seed",
        "static seed",
        "deadbeef",
        "constant seed",
        "predictable seed",
        "weak seed",
    ]),
    # Generic UDS security
    ("Security access granted", "critical", [
        "security access granted", "access granted", "unlocked",
        "positive response to security", "seed accepted",
    ]),
    ("Repeated / weak seed", "critical", [
        "repeated seed", "identical seed", "seed is constant",
        "seed does not change", "non-random", "same seed",
    ]),
    ("ECU crash / stop responding", "critical", [
        "ecu reset", "ecu restarted", "ecu crashed", "target crashed",
        "no response after", "bus off", "bus-off",
    ]),
    ("Security access denied", "high", [
        "securityaccessdenied", "security access denied",
        "nrc=securityaccessdenied",
    ]),
    ("ECU discovered", "low", [
        "found ecu", "ecu found", "ecu detected", "active ecu",
        "discovered ecu",
    ]),
    ("UDS service found", "low", [
        "service found", "supported service",
    ]),
    ("DTC found", "medium", [
        "dtc found", "trouble code", "dtc:", "fault code",
    ]),
]

# Flatten and sort longest-pattern-first so specific wins over generic
_L1_FLAT: List[Tuple[str, str, str]] = []
for _lbl, _sev, _pats in _LAYER1_RAW:
    for _p in _pats:
        _L1_FLAT.append((_p.lower(), _lbl, _sev))
_L1_FLAT.sort(key=lambda x: -len(x[0]))


# ---------------------------------------------------------------------------
#  Layer-2 heuristic fallback
# ---------------------------------------------------------------------------

_LAYER2: List[Tuple[str, List[str]]] = [
    ("critical", ["crash", "exception", "segfault", "panic",
                  "overflow", "corruption"]),
    ("high",     ["error", "fail", "timeout", "no response",
                  "refused", "rejected"]),
    ("medium",   ["warning", "warn", "anomaly", "unexpected"]),
    ("low",      ["found", "discovered", "detected"]),
]


# ---------------------------------------------------------------------------
#  Noise suppression
# ---------------------------------------------------------------------------

_SUPPRESS = frozenset([
    "uptime library not available",
    "timestamps are relative to boot time",
    # NOTE: "total captured:" and "seed received:" deliberately NOT suppressed —
    # these lines carry the deadbeef seed value needed for VULN-006 matching.
    "security seed dump started",
    "press ctrl+c to stop",
    "loading module",
    "fucyfuzz v",
    "-------------------",
    "testerpresent_resp",
    "testerpresent(sub=0x00)",
    "tester_present_resp",
])

_STRUCTURAL = re.compile(
    r"^\s*$"
    r"|^=+\s*$"
    r"|^-+\s*$"
    r"|fucyfuzz session\s"
    r"|session dir:"
)


# ---------------------------------------------------------------------------
#  scan_line  — public, single-line classifier
# ---------------------------------------------------------------------------

def scan_line(
    text: str,
    module: str = "",
    vuln_db: Optional[VulnDB] = None,
) -> Optional[FaultEvent]:
    """
    Classify a single log line and return a FaultEvent or None.

    Priority order
    --------------
    0.  Noise / structural suppression
    1.  VulnDB four-strategy match  (Strategies 1 > 3 > 2 > 4)
    2.  Layer-1 explicit patterns   (covers all six vulns without VulnDB)
    3.  Layer-2 heuristic fallback
    """
    if not text or not text.strip():
        return None

    lower = text.lower()

    # Suppress noise
    if any(s in lower for s in _SUPPRESS):
        return None
    if _STRUCTURAL.search(lower):
        return None

    mod = module or "log-replay"

    # ── VulnDB match ─────────────────────────────────────────────────────────
    if vuln_db:
        entry = vuln_db.match_line(text, require_enabled=False)
        if entry:
            return FaultEvent(
                severity=entry.severity,
                module=mod,
                description=f"[{entry.id}] {entry.name}  —  {entry.description}",
                cmd="",
                timestamp="",
                vuln_id=entry.id,
                vuln_name=entry.name,
            )

    # ── Layer-1 ──────────────────────────────────────────────────────────────
    for pattern, label, severity in _L1_FLAT:
        if pattern in lower:
            return FaultEvent(
                severity=severity, module=mod,
                description=label, cmd="", timestamp="",
            )

    # ── Layer-2 ──────────────────────────────────────────────────────────────
    for severity, patterns in _LAYER2:
        if any(p in lower for p in patterns):
            return FaultEvent(
                severity=severity, module=mod,
                description=text.strip()[:140],
                cmd="", timestamp="",
            )

    return None


# ---------------------------------------------------------------------------
#  File line iterators
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"^\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.\d]*)\]?"
    r"\s+\[(\w[\w. ]*?)\s*\]"
    r"\s+\[([\w. ]+?)\s*\]"
    r"\s+(.+)$"
)

# v2 log format: [TIMESTAMP] [DIR] <SEVERITY> [MODULE]  ...  tx@... rx@...
_LINE_RE_V2 = re.compile(
    r"^\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.\d]*)\]?"   # 1: timestamp
    r"\s+\[(\w[\w. ]*?)\]"                                     # 2: direction
    r"(?:\s+<(\w+)>)?"                                         # 3: optional severity
    r"\s+\[([\w. ]+?)\s*\]"                                    # 4: module
    r"(?:\s+tx@([\d:\- .]+?))?"                                # 5: optional tx timestamp
    r"(?:\s+rx@([\d:\- .]+?))?"                                # 6: optional rx timestamp
    r"\s*(.*)$"                                                 # 7: rest of line
)


def _iter_log_lines(path: str):
    """Yield (ts, module, text, severity, tx_ts, rx_ts)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip("\r\n")
            # Try new v2 format first
            m2 = _LINE_RE_V2.match(raw)
            if m2 and m2.group(3):   # has <SEVERITY> → definitely v2
                yield (m2.group(1).strip(), m2.group(4).strip(),
                       m2.group(7).strip(),
                       m2.group(3) or "",
                       (m2.group(5) or "").strip(),
                       (m2.group(6) or "").strip())
                continue
            # Legacy v1 format
            m = _LINE_RE.match(raw)
            if m:
                yield m.group(1).strip(), m.group(3).strip(), m.group(4).strip(), "", "", ""
            else:
                stripped = raw.strip()
                if stripped:
                    yield "", "", stripped, "", "", ""


def _iter_csv_lines(path: str):
    """Yield (ts, module, text, severity, tx_ts, rx_ts)."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        yielded: set = set()
        for row in reader:
            ts    = row.get("timestamp",    "")
            mod   = row.get("module",       "")
            sev   = row.get("severity",     "")
            tx_ts = row.get("timestamp_tx", "")
            rx_ts = row.get("timestamp_rx", "")
            for col in ("decoded", "raw_line"):
                val = (row.get(col) or "").strip()
                if val and val not in yielded:
                    yielded.add(val)
                    yield ts, mod, val, sev, tx_ts, rx_ts


def _iter_plain_lines(path: str):
    """Yield (ts, module, text, severity, tx_ts, rx_ts)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            stripped = raw.strip()
            if stripped:
                yield "", "", stripped, "", "", ""


def _iter_jsonl_lines(path: str):
    """
    Iterate JSONL log entries.  Yields (ts, module, raw_text, severity, tx_ts, rx_ts).

    Supports both the legacy format (no severity/timestamp_tx/timestamp_rx fields)
    and the new high-precision format produced by the upgraded SessionLogger.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                ts     = obj.get("timestamp", "")
                mod    = obj.get("module",    "")
                sev    = obj.get("severity",  "")
                tx_ts  = obj.get("timestamp_tx", "")
                rx_ts  = obj.get("timestamp_rx", "")
                for col in ("decoded", "raw_line"):
                    val = (obj.get(col) or "").strip()
                    if val:
                        yield ts, mod, val, sev, tx_ts, rx_ts
                        break
            except json.JSONDecodeError:
                if line:
                    yield "", "", line, "", "", ""


# ---------------------------------------------------------------------------
#  parse_file  — public generator
# ---------------------------------------------------------------------------

def parse_file(
    path: str,
    vuln_db: Optional[VulnDB] = None,
) -> Iterator[FaultEvent]:
    """
    Parse a FucyFuzz session file and yield FaultEvent objects.

    Accepts .log, .csv, .jsonl, or plain text.
    Handles both legacy (3-tuple) and new high-precision (6-tuple) formats.
    Thread-safe generator — drive from a QThread worker.
    Never raises.
    """
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".log":
            line_iter = _iter_log_lines(path)
        elif ext == ".csv":
            line_iter = _iter_csv_lines(path)
        elif ext == ".jsonl":
            line_iter = _iter_jsonl_lines(path)
        else:
            line_iter = _iter_plain_lines(path)
    except OSError:
        return

    last_cmd = ""
    for row in line_iter:
        # Unpack 6-tuple; fall back gracefully if only 3 values (legacy)
        if len(row) == 6:
            ts, module, raw_line, log_sev, tx_ts, rx_ts = row
        else:
            ts, module, raw_line = row[0], row[1], row[2]
            log_sev = tx_ts = rx_ts = ""

        if "command:" in raw_line.lower() or raw_line.startswith("$ "):
            last_cmd = raw_line.strip()

        event = scan_line(raw_line, module=module, vuln_db=vuln_db)
        if event is not None:
            event.timestamp    = ts
            event.cmd          = last_cmd
            event.timestamp_tx = tx_ts
            event.timestamp_rx = rx_ts
            event.log_severity = log_sev
            # Prefer the severity from the log entry if it's more specific
            if log_sev and log_sev.upper() in ("CRITICAL", "HIGH", "LOW", "INFO"):
                event.severity = log_sev.upper()
            yield event
