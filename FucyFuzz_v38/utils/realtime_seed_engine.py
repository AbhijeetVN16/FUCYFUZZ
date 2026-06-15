"""
RealtimeSeedEngine
==================
Session-scoped seed analysis engine that runs after EVERY new seed
and emits structured findings immediately — no waiting for session end.

Detectors (all ECU-independent, work on raw bytes):
  REPEAT      — exact same seed bytes seen before
  ZERO        — all-zero seed (0x00...00)
  ALL_FF      — all-bytes-0xFF seed
  LOW_ENTROPY — Shannon entropy of bytes < 2.0 bits
  COUNTER     — seeds differ by a constant arithmetic delta (counter RNG)
  MONOTONE    — seeds monotonically increase or decrease for 5+ consecutive
  STATIC_HIGH — upper half of bytes never change across 5+ seeds
  DUP_RATE    — more than 20% of seeds seen so far are duplicates

Each finding is a dict:
    {
      "detector":  "REPEAT",              # detector name
      "severity":  "critical",            # critical / high / medium / low
      "title":     "Repeated seed",       # short display title
      "detail":    "0xABCD seen 3 times", # detail string for fault text
      "seed_hex":  "ABCD",                # hex of the offending seed
      "seed_no":   12,                    # which seed number in the session
    }

Usage:
    engine = RealtimeSeedEngine()
    findings = engine.add_seed(bytes.fromhex("AB12CD34"))
    stats    = engine.stats   # always up-to-date dict
"""

import math
from collections import Counter
from typing import List, Optional


# ── Entropy helper ────────────────────────────────────────────────────────────

def _byte_entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# ── Counter-RNG detector ──────────────────────────────────────────────────────

def _as_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _detect_counter(seeds: List[bytes], window: int = 6) -> Optional[int]:
    """
    Return the constant delta if the last `window` seeds form an arithmetic
    progression, else None.  Works on seeds of any width (big-endian int).
    """
    if len(seeds) < window:
        return None
    tail = [_as_int(s) for s in seeds[-window:]]
    deltas = [tail[i + 1] - tail[i] for i in range(len(tail) - 1)]
    if len(set(deltas)) == 1 and deltas[0] != 0:
        return deltas[0]
    return None


def _detect_monotone(seeds: List[bytes], run: int = 5) -> Optional[str]:
    """Return 'increasing' or 'decreasing' if last `run` seeds are monotone."""
    if len(seeds) < run:
        return None
    tail = [_as_int(s) for s in seeds[-run:]]
    if all(tail[i] < tail[i + 1] for i in range(len(tail) - 1)):
        return "increasing"
    if all(tail[i] > tail[i + 1] for i in range(len(tail) - 1)):
        return "decreasing"
    return None


def _detect_static_high(seeds: List[bytes], window: int = 5) -> Optional[int]:
    """
    Return the byte index up to which all bytes are static (never change)
    across the last `window` seeds, if any upper bytes are static.
    """
    if len(seeds) < window:
        return None
    tail = seeds[-window:]
    width = len(tail[0])
    if not all(len(s) == width for s in tail):
        return None
    # Find the last byte position that is constant across all seeds
    for i in range(width):
        vals = {s[i] for s in tail}
        if len(vals) > 1:
            return i if i > 0 else None
    return width  # all bytes static


# ── Main engine ───────────────────────────────────────────────────────────────

class RealtimeSeedEngine:
    """
    Accumulates seeds for a session. Call add_seed() after each seed is
    received. Returns a (possibly empty) list of Finding dicts and always
    keeps self.stats up to date.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self._seeds:     List[bytes] = []
        self._seed_set:  Counter     = Counter()   # seed_bytes → count
        self._findings:  list        = []          # all findings this session
        self._reported_counters: set = set()       # avoid re-firing same delta
        self._counter_active:    bool = False
        self._monotone_active:   bool = False

    # ── Public: add a seed, returns new findings ──────────────────────────────

    def add_seed(self, seed_bytes: bytes) -> list:
        """
        Process one new seed. Returns list of new Finding dicts (may be empty).
        self.stats is updated regardless.
        """
        self._seeds.append(seed_bytes)
        self._seed_set[seed_bytes] += 1
        n = len(self._seeds)
        count = self._seed_set[seed_bytes]
        hex_s = seed_bytes.hex().upper()
        findings = []

        # ── ZERO / ALL-FF ────────────────────────────────────────────────────
        if seed_bytes == bytes(len(seed_bytes)):
            findings.append(self._f("ZERO", "critical",
                "All-zero seed returned",
                f"0x{hex_s} (seed #{n}) — ECU may have a constant seed",
                hex_s, n))

        elif all(b == 0xFF for b in seed_bytes):
            findings.append(self._f("ALL_FF", "critical",
                "All-0xFF seed returned",
                f"0x{hex_s} (seed #{n}) — static or uninitialised seed",
                hex_s, n))

        # ── REPEAT ───────────────────────────────────────────────────────────
        elif count == 2:
            findings.append(self._f("REPEAT", "critical",
                "Repeated seed",
                f"0x{hex_s} seen again (seed #{n})",
                hex_s, n))
        elif count > 2 and count % 5 == 0:
            # Re-fire at every 5th recurrence so dashboard keeps updating
            findings.append(self._f("REPEAT", "critical",
                "Seed repeating frequently",
                f"0x{hex_s} now seen {count}× (seed #{n})",
                hex_s, n))

        # ── LOW ENTROPY (byte-level) ─────────────────────────────────────────
        if len(seed_bytes) >= 2:
            ent = _byte_entropy(seed_bytes)
            if ent < 1.0:
                findings.append(self._f("LOW_ENTROPY", "critical",
                    "Critically low entropy seed",
                    f"0x{hex_s} entropy={ent:.2f} bits (seed #{n})",
                    hex_s, n))
            elif ent < 2.0:
                findings.append(self._f("LOW_ENTROPY", "high",
                    "Low entropy seed",
                    f"0x{hex_s} entropy={ent:.2f} bits (seed #{n})",
                    hex_s, n))

        # ── COUNTER RNG (arithmetic progression) ─────────────────────────────
        delta = _detect_counter(self._seeds, window=5)
        if delta is not None and delta not in self._reported_counters:
            self._reported_counters.add(delta)
            findings.append(self._f("COUNTER", "critical",
                "Counter-based RNG detected",
                f"Seeds increment by constant Δ={delta} (seed #{n})",
                hex_s, n))
        # Keep firing every 10 seeds while counter is still active
        elif delta is not None and n % 10 == 0:
            findings.append(self._f("COUNTER", "critical",
                "Counter RNG still active",
                f"Δ={delta} constant over {n} seeds",
                hex_s, n))

        # ── MONOTONE RUN ─────────────────────────────────────────────────────
        direction = _detect_monotone(self._seeds, run=5)
        if direction and not self._monotone_active:
            self._monotone_active = True
            findings.append(self._f("MONOTONE", "high",
                f"Monotone {direction} seed stream",
                f"Last 5 seeds strictly {direction} (seed #{n})",
                hex_s, n))
        elif not direction:
            self._monotone_active = False

        # ── STATIC HIGH BYTES ─────────────────────────────────────────────────
        if n >= 5:
            static_up_to = _detect_static_high(self._seeds, window=5)
            if static_up_to and static_up_to > 0 and n % 5 == 0:
                findings.append(self._f("STATIC_HIGH", "medium",
                    "Seed upper bytes are static",
                    f"First {static_up_to} byte(s) constant across last 5 seeds (seed #{n})",
                    hex_s, n))

        # ── DUPLICATE RATE milestones ─────────────────────────────────────────
        if n >= 10:
            dup_count = n - len(self._seed_set)
            dup_rate  = dup_count / n
            if dup_rate >= 0.50 and n % 5 == 0:
                findings.append(self._f("DUP_RATE", "critical",
                    "Extremely high duplicate seed rate",
                    f"{dup_rate*100:.0f}% of {n} seeds are duplicates",
                    hex_s, n))
            elif dup_rate >= 0.20 and n % 10 == 0:
                findings.append(self._f("DUP_RATE", "high",
                    "High duplicate seed rate",
                    f"{dup_rate*100:.0f}% of {n} seeds are duplicates",
                    hex_s, n))

        self._findings.extend(findings)
        return findings

    # ── Public: current stats dict ────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        n = len(self._seeds)
        unique = len(self._seed_set)
        dups = n - unique
        dup_rate = dups / n if n else 0.0

        # Entropy of the whole seed stream (treat each seed as one symbol)
        if n >= 2:
            stream_entropy = -sum(
                (c / n) * math.log2(c / n) for c in self._seed_set.values()
            )
        else:
            stream_entropy = 0.0

        # Severity
        if dup_rate >= 0.50 or (n >= 5 and unique == 1):
            severity = "CRITICAL"
        elif dup_rate >= 0.20 or (n >= 3 and dups >= 1):
            severity = "HIGH"
        elif dups > 0:
            severity = "MEDIUM"
        elif n > 0:
            severity = "SAFE"
        else:
            severity = "—"

        return {
            "total":         n,
            "unique":        unique,
            "duplicates":    dups,
            "dup_rate":      dup_rate,
            "stream_entropy": stream_entropy,
            "severity":      severity,
            "findings_count": len(self._findings),
            "last_seed_hex": self._seeds[-1].hex().upper() if self._seeds else "—",
        }

    # ── Internal ─────────────────────────────────────────────────────────────

    @staticmethod
    def _f(detector, severity, title, detail, seed_hex, seed_no) -> dict:
        return {
            "detector": detector,
            "severity": severity,
            "title":    title,
            "detail":   detail,
            "seed_hex": seed_hex,
            "seed_no":  seed_no,
        }
