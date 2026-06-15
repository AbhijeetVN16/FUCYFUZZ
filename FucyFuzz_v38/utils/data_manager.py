"""
FucyFuzz Data Manager  —  v2 (Centralized Real-Time Dispatch)
=============================================================

Centralized logging architecture
----------------------------------
When add_fault() is called from any module tab's _parse_output_for_faults():

  STEP 1 — Store fault in list + attach to current session
  STEP 2 — Push VULN entry to SessionLogger
              → SessionLogger._fire_gui() [called synchronously, no extra thread]
              → All registered GUI callbacks receive the dict entry
              → LogTab._LogBridge.on_entry() emits entry_received(dict)  [Qt signal]
              → LogTab._on_entry() runs in MAIN THREAD (QueuedConnection)
              → ECUMonitorTab._on_log_entry() runs in MAIN THREAD (QueuedConnection)
  STEP 3 — fault_pushed(Fault) emitted
              → DashboardTab._on_fault_pushed()  [zero latency, main thread]
              → ECUMonitorTab._on_dm_fault_pushed()  [fallback / dedup guard]
  STEP 4 — faults_updated() emitted
              → DashboardTab.refresh()  [full stats rebuild, batched]

Key guarantee: every single output line from the System Terminal that triggers
_parse_output_for_faults() → _add_fault() → add_fault() will propagate in the
same Qt event loop cycle to BOTH ECU Monitor and Dashboard tabs via the signals
above, with zero polling and zero duplicate entries (dedup handled by the
receiving tabs using a keyed set).

parse_terminal_line() — NEW public helper
-----------------------------------------
Accepts a raw terminal line and applies the same multi-layer detection logic
used by base_tab._parse_output_for_faults(), then calls add_fault() if a
vulnerability is found.  This allows future callers (e.g. a dedicated watcher
thread) to feed lines directly to the DataManager without going through a tab.
"""

import json
import time as _time_mod
import uuid

# Alias kept at module level so existing call-sites using `time.X` still work
time = _time_mod
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from PyQt5.QtCore import QObject, pyqtSignal


@dataclass
class Fault:
    severity:  str           # critical / high / medium / low
    module:    str
    fault:     str
    cmd:       str
    time:      float = field(default_factory=_time_mod.time)
    status:    str = "open"
    id:        str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    hit_count: int = 1       # how many times this vuln has fired this session
    last_seen: float = field(default_factory=_time_mod.time)

    def time_str(self):
        return _time_mod.strftime('%H:%M:%S', _time_mod.localtime(self.last_seen))

    def severity_upper(self):
        return self.severity.upper()


@dataclass
class Session:
    id:       str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    module:   str = ""
    start:    float = field(default_factory=_time_mod.time)
    end:      Optional[float] = None
    cmd:      str = ""
    faults:   List[str] = field(default_factory=list)

    def duration(self):
        t = self.end or _time_mod.time()
        secs = int(t - self.start)
        return f"{secs//60}m {secs%60}s"


class DataManager(QObject):
    """
    Central data store. Emits signals on changes.

    Signals
    -------
    faults_updated()        — Full stats rebuild (Dashboard cards/charts)
    sessions_updated()      — Session list changed
    fault_pushed(Fault)     — Single fault object, zero-latency (Dashboard + ECU Monitor)
    """

    faults_updated   = pyqtSignal()
    sessions_updated = pyqtSignal()
    fault_pushed     = pyqtSignal(object)   # emits Fault — zero latency (first hit)
    fault_hit        = pyqtSignal(object)   # emits Fault — repeated hit (count updated)
    nrc_recorded      = pyqtSignal(str, int, str)   # module, nrc_code, raw_line
    seed_stats_updated = pyqtSignal(dict)            # fired after every seed with live stats
    ecu_event          = pyqtSignal(dict)            # crash/hang/suspicious events

    def __init__(self, parent=None):
        super().__init__(parent)
        self.faults:   List[Fault]   = []
        self.sessions: List[Session] = []
        self._current_session: Optional[Session] = None

        # Per-session dedup cache: "module::fault_text" → True
        # Prevents the same detection creating duplicate Fault objects.
        self._fault_dedup_keys: set = set()
        # Maps dedup_key → Fault object for efficient hit_count increment
        self._fault_index: dict = {}

    # ── Sessions ──────────────────────────────────────────────────────────────

    def start_session(self, module: str, cmd: str) -> Session:
        s = Session(module=module, cmd=cmd)
        self._current_session = s
        self.sessions.append(s)
        # Reset dedup cache at session start so previous runs don't suppress new ones
        self._fault_dedup_keys.clear()
        self._fault_index.clear()
        self.sessions_updated.emit()
        return s

    @property
    def active_module(self) -> str:
        """Return the module name of the currently running session, or empty string."""
        if self._current_session:
            return self._current_session.module
        return ""

    def end_session(self):
        if self._current_session:
            self._current_session.end = _time_mod.time()
            self._current_session = None
            self.sessions_updated.emit()

    # ── NRC tracking ─────────────────────────────────────────────────────────

    def record_nrc(self, module: str, nrc_code: int, raw_line: str = "") -> None:
        """Emit nrc_recorded signal so NRC panels update in real-time."""
        self.nrc_recorded.emit(module, nrc_code, raw_line)

    def update_seed_stats(self, stats: dict) -> None:
        """Emit seed_stats_updated — fires after every seed, carries full session stats."""
        self.seed_stats_updated.emit(stats)

    def push_ecu_event(self, event: dict) -> None:
        """Emit ecu_event for crashes, hangs, and other suspicious ECU behaviour."""
        self.ecu_event.emit(event)

    # ── Faults ────────────────────────────────────────────────────────────────

    def add_fault(self, severity: str, module: str, fault: str, cmd: str) -> Fault:
        """
        Record a vulnerability and propagate it to all live UI tabs via signals.

        Deduplication: identical (module, fault_text) pairs within the same
        session INCREMENT the existing Fault's hit_count and last_seen timestamp
        rather than being silently dropped or creating a duplicate row.
        This means:
          • First occurrence  → new Fault created, full signal chain fires
          • Subsequent hits   → Fault.hit_count += 1, Fault.last_seen updated,
                                fault_hit(Fault) signal emitted (lightweight)
        The cache is reset at session start and when clear() is called.
        """
        dedup_key = f"{module}::{fault}"
        if dedup_key in self._fault_dedup_keys:
            # Find the existing fault and increment its counter
            existing = self._fault_index.get(dedup_key)
            if existing is not None:
                existing.hit_count += 1
                existing.last_seen  = _time_mod.time()
                self.fault_hit.emit(existing)
            # Return a sentinel — callers should use fault_hit signal for updates
            return Fault(severity=severity, module=module, fault=fault, cmd=cmd)
        self._fault_dedup_keys.add(dedup_key)
        # Rotate cache to avoid unbounded growth over very long sessions
        if len(self._fault_dedup_keys) > 2000:
            self._fault_dedup_keys.clear()
            self._fault_index.clear()

        f = Fault(severity=severity, module=module, fault=fault, cmd=cmd)
        self._fault_index[dedup_key] = f
        self.faults.append(f)
        if self._current_session:
            self._current_session.faults.append(f.id)

        # ── STEP 2: Push VULN entry into SessionLogger ────────────────────────
        # _fire_gui() is called synchronously here (still in the caller's thread,
        # which is the main thread because _on_output/_on_error use QueuedConnection).
        # Every registered GUI callback (LogTab, ECUMonitorTab) receives the entry
        # immediately. They must not touch widgets directly — they emit Qt signals.
        self._log_fault_to_session_logger(f)

        # ── STEP 3: fault_pushed — zero-latency per-fault signal ──────────────
        self.fault_pushed.emit(f)

        # ── STEP 4: faults_updated — batched full stats refresh ───────────────
        self.faults_updated.emit()

        return f

    @staticmethod
    def _log_fault_to_session_logger(fault: 'Fault') -> None:
        """
        Push a direction="VULN" entry into the active SessionLogger.

        The severity tag from the Fault object is forwarded so that the log
        viewer and replay engine can filter/classify without re-parsing.

        The SessionLogger._fire_gui() call is synchronous — every registered
        GUI callback receives this entry in the same call stack before
        _log_fault_to_session_logger returns.  This is safe because all
        callbacks (LogTab._LogBridge.on_entry, ECUMonitorTab._LogEntryBridge.on_entry)
        only emit Qt signals and never touch widgets directly.
        """
        try:
            from utils.session_logger import get_session_logger, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_INFO
            sl = get_session_logger()
            if sl is None:
                return
            decoded = (
                f"[{fault.severity.upper()}] {fault.fault}"
                + (f"  |  cmd: {fault.cmd[:80]}" if fault.cmd else "")
            )
            # Map DataManager severity strings to SessionLogger constants
            _sev_map = {
                "critical": SEVERITY_CRITICAL,
                "high":     SEVERITY_HIGH,
                "medium":   SEVERITY_HIGH,   # treat medium as HIGH for clear segregation
                "low":      SEVERITY_LOW,
                "info":     SEVERITY_INFO,
            }
            sev = _sev_map.get(fault.severity.lower(), SEVERITY_HIGH)
            sl.log_raw(
                direction="VULN",
                arb_id=0,
                data_bytes=b"",
                decoded=decoded,
                module=fault.module,
                severity=sev,
            )
        except Exception:
            pass   # logging must NEVER crash the tool

    # ── Terminal line parser (centralized, mirrors base_tab logic) ────────────

    def parse_terminal_line(self, line: str, module: str = "terminal",
                            cmd: str = "", custom_rules: str = "") -> Optional[Fault]:
        """
        Apply the same multi-layer fault-detection logic as
        base_tab._parse_output_for_faults() and call add_fault() if a
        vulnerability is detected.

        Returns the Fault if one was created, else None.

        Layers:
          0. User-defined custom rules (highest priority)
          1. High-confidence explicit patterns
          2. Heuristic keyword scan (fallback)
        """
        lower = line.lower()

        # ── Layer 0: Custom rules ─────────────────────────────────────────────
        if custom_rules:
            for rule in custom_rules.splitlines():
                rule = rule.strip()
                if '|' not in rule:
                    continue
                parts = rule.split('|', 1)
                if len(parts) != 2:
                    continue
                sev, keyword = parts[0].strip().lower(), parts[1].strip().lower()
                if sev in ('critical', 'high', 'medium', 'low') and keyword and keyword in lower:
                    return self.add_fault(sev, module, f"[Custom Rule] {line[:120]}", cmd)

        # ── Layer 1: Explicit high-confidence patterns ────────────────────────
        if any(p in lower for p in [
            'found ecu', 'ecu found', 'ecu detected', 'active ecu',
            'discovered ecu', 'responds on', 'response from',
        ]):
            return self.add_fault('low', module, "ECU discovered", cmd)

        if any(p in lower for p in [
            'found service', 'service found', 'supported service',
            'service 0x', 'supported:', 'service supported',
        ]):
            return self.add_fault('low', module, "Service found", cmd)

        # ── VULN-001: VIN_Write_Overflow (CRASH → critical) ──────────────────
        if any(p in lower for p in [
            'memory corruption', 'vin buffer', 'memory corruption detected',
        ]):
            return self.add_fault('critical', module,
                                  "Memory corruption / buffer overflow (VULN-001)", cmd)

        # ── VULN-002: Security_Bypass_Magic_Byte (BYPASS_SECURITY → critical)
        if any(p in lower for p in [
            'security bypass triggered', 'magic byte', 'bypass_security',
        ]):
            return self.add_fault('critical', module,
                                  "Security bypass via magic byte (VULN-002)", cmd)

        # ── VULN-003: Resource_Exhaustion_DoS (HANG → critical) ─────────────
        if any(p in lower for p in [
            'internal message queue', 'message queue overflow', 'cpu at 100',
            'force_p2_star_timeout', 'resource exhaustion',
        ]):
            return self.add_fault('critical', module,
                                  "Resource exhaustion / DoS hang (VULN-003)", cmd)

        # ── VULN-004: ISO_TP_Segment_Overlap (CRASH → critical) ─────────────
        if any(p in lower for p in [
            'iso-tp reassembly', 'reassembly engine', 'out_of_order_cf',
        ]):
            return self.add_fault('critical', module,
                                  "ISO-TP reassembly fault (VULN-004)", cmd)

        # ── VULN-005: Diagnostic_Session_Leaking (LOGIC_ERR → high) ─────────
        if any(p in lower for p in [
            'unauthorized state transition', 'accept_illegal_transition',
            'illegal transition',
        ]):
            return self.add_fault('high', module,
                                  "Unauthorized session transition (VULN-005)", cmd)

        # ── VULN-006: Weak_Seed_Entropy (MODIFY_RESPONSE → high) ────────────
        if any(p in lower for p in [
            'static seed', 'sent static seed', 'deadbeef', 'seed 0xdeadbeef',
            'constant seed', 'seed=0xdeadbeef', 'vulnerability triggered: sent static',
        ]):
            return self.add_fault('high', module,
                                  "Weak/static seed entropy (VULN-006)", cmd)

        if any(p in lower for p in [
            'security access granted', 'access granted', 'unlocked',
            'positive response to security', 'seed accepted', 'security bypass',
        ]):
            return self.add_fault('critical', module, "Security access granted", cmd)

        if any(p in lower for p in [
            'same seed', 'repeated seed', 'identical seed',
            'seed is constant', 'seed does not change', 'low entropy',
            'weak seed', 'predictable seed', 'seed repeated',
            'non-random', 'not random',
        ]):
            return self.add_fault('critical', module, "Weak/repeated seed detected", cmd)

        if any(p in lower for p in [
            'ecu reset', 'ecu restarted', 'ecu crashed', 'target crashed',
            'no response after', 'bus off', 'bus-off',
        ]):
            return self.add_fault('critical', module, "ECU crash/reset detected", cmd)

        if any(p in lower for p in [
            'read memory', 'memory dump', 'mem dump', 'did value',
            'read did', 'data identifier', 'vin:', 'vin =',
        ]):
            return self.add_fault('medium', module, "Data read from ECU", cmd)

        if any(p in lower for p in ['dtc found', 'trouble code', 'dtc:', 'fault code']):
            return self.add_fault('medium', module, "DTC found", cmd)

        # ── Layer 2: Heuristic keyword scan ───────────────────────────────────
        severity = None
        if any(k in lower for k in [
            'crash', 'exception', 'segfault', 'panic', 'critical',
            'overflow', 'corruption',
        ]):
            severity = 'critical'
        elif any(k in lower for k in [
            'error', 'fail', 'unexpected response', 'timeout',
            'no response', 'refused', 'rejected',
        ]):
            severity = 'high'
        elif any(k in lower for k in ['warning', 'warn', 'anomaly', 'unexpected']):
            severity = 'medium'
        elif any(k in lower for k in ['found', 'discovered', 'detected', 'positive', 'success']):
            severity = 'low'

        if severity:
            return self.add_fault(severity, module, line[:120], cmd)

        return None

    # ── Session management helpers ────────────────────────────────────────────

    def resolve_fault(self, fault_id: str):
        for f in self.faults:
            if f.id == fault_id:
                f.status = "resolved"
        self.faults_updated.emit()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def total_faults(self) -> int:
        return len(self.faults)

    def open_faults(self) -> int:
        return sum(1 for f in self.faults if f.status == "open")

    def critical_faults(self) -> int:
        return sum(1 for f in self.faults if f.severity == "critical" and f.status == "open")

    def severity_counts(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in self.faults:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def module_counts(self) -> Dict[str, int]:
        counts = {}
        for f in self.faults:
            counts[f.module] = counts.get(f.module, 0) + 1
        return counts

    def recent_faults(self, n=20) -> List[Fault]:
        return sorted(self.faults, key=lambda f: f.time, reverse=True)[:n]

    # ── Serialization ─────────────────────────────────────────────────────────

    def export_json(self) -> str:
        data = {
            'faults':   [asdict(f) for f in self.faults],
            'sessions': [asdict(s) for s in self.sessions],
        }
        return json.dumps(data, indent=2)

    def clear(self):
        self.faults.clear()
        self.sessions.clear()
        self._fault_dedup_keys.clear()
        self._fault_index.clear()
        self._current_session = None
        self.faults_updated.emit()
        self.sessions_updated.emit()

    # ── Failure Cases (persistent) ────────────────────────────────────────────

    def load_failure_cases(self, path: str):
        import os
        if not os.path.exists(path):
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

    def save_failure_cases(self, cases: dict, path: str):
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(cases, f, indent=2, default=str)
        except Exception:
            pass
