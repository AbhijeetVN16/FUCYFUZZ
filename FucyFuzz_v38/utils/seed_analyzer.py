"""
FucyFuzz Seed Analyzer  —  Dual-Mode Engine (v2)
=================================================

OVERVIEW
--------
Automatically selects the optimal analysis algorithm based on seed width:

  ┌────────────────────┬───────────────────────────────────────────────────┐
  │ Seed Width         │ Algorithm                                         │
  ├────────────────────┼───────────────────────────────────────────────────┤
  │ 16-bit  (0x0000-   │ ARRAY MODE — direct-address array of size 65,536  │
  │  0xFFFF, ≤2 bytes) │ • Each index IS a seed value → O(1) insert/lookup │
  │                    │ • O(65,536) one-pass scan for duplicates           │
  │                    │ • Memory: 65,536 × 8 bytes ≈ 256 KB (Python int)  │
  │                    │ • Missing-seed analysis available (all 65,536)     │
  ├────────────────────┼───────────────────────────────────────────────────┤
  │ 32-bit  (0x10000-  │ HASH MAP MODE — dict stores only observed seeds   │
  │  0xFFFFFFFF, 4 B)  │ • Domain = 4,294,967,296 values → array ≈ 16 GB  │
  │                    │ • dict: O(1) amortized insert/lookup               │
  │                    │ • Memory: O(unique_seeds) — typically kilobytes    │
  │                    │ • Missing-seed analysis skipped (infeasible)       │
  └────────────────────┴───────────────────────────────────────────────────┘

MODE SELECTION
--------------
Mode is detected automatically from the seed data:
  • If max(seeds) ≤ 0xFFFF  → ARRAY_16
  • If max(seeds) > 0xFFFF  → HASHMAP_32

The public API (analyze / analyze_file / format_report) is identical for both
modes. Callers in uds_tab.py and elsewhere require zero changes.

PARSING
-------
Same four auto-detected formats as v1:
  1. FucyFuzz session log  — "Seed received: XXXX"
  2. Raw CAN frame log     — "67 XX HH LL [...]"  (UDS 0x67 positive response)
  3. JSONL session log     — {"raw_line": "Seed received: XXXX"}
  4. CSV session log       — raw_line column with "Seed received: XXXX"

32-bit variants also matched:
  • "Seed received: HHHHHHHH"   (8 hex digits)
  • "67 XX B3 B2 B1 B0 [...]"   (4-byte seed in CAN frame)
"""

import re
import os
import json
from enum import Enum
from typing import List, Tuple, Optional, Dict, Union

# ── Mode enum ─────────────────────────────────────────────────────────────────

class SeedMode(Enum):
    ARRAY_16  = "16-bit Array"     # direct-address, size=65536
    HASHMAP_32 = "32-bit Hash Map" # dict, only observed values stored


# ── Constants ─────────────────────────────────────────────────────────────────

# 16-bit domain
ARRAY_SIZE_16   = 65_536          # 0x0000 – 0xFFFF
MAX_SEED_16     = ARRAY_SIZE_16 - 1
ARRAY_BYTES_16  = ARRAY_SIZE_16 * 8  # ~256 KB (CPython int list)

# 32-bit domain
MAX_SEED_32     = 0xFFFF_FFFF     # 4,294,967,295
DOMAIN_SIZE_32  = MAX_SEED_32 + 1 # 4,294,967,296

# Per-seed severity (repetition count thresholds) — same for both modes
SEV_LOW_MIN    =  2
SEV_MEDIUM_MIN =  6
SEV_HIGH_MIN   = 21

# Global verdict (duplicate-rate thresholds) — same for both modes
VERDICT_MEDIUM   = 0.10
VERDICT_HIGH     = 0.30
VERDICT_CRITICAL = 0.50

# Entropy / coverage thresholds (16-bit only — meaningful for bounded domain)
COVERAGE_HIGH   = 0.80
COVERAGE_MEDIUM = 0.40
COVERAGE_LOW    = 0.10

# Report display limits
MAX_MISSING_DISPLAY = 32
MAX_RARE_DISPLAY    = 20


# ── Regex patterns ────────────────────────────────────────────────────────────

# "Seed received: XXXX" — 1 to 8 hex digits (covers both 16-bit and 32-bit)
_SEED_RECV_RE = re.compile(
    r'[Ss]eed\s+received\s*:\s*([0-9a-fA-F]{1,8})\b',
    re.IGNORECASE
)

# "67 XX HH LL" — 2-byte seed (16-bit UDS 0x67 positive response)
_RAW_FRAME_67_16_RE = re.compile(
    r'\b67\s+[0-9a-fA-F]{2}\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})\b',
    re.IGNORECASE
)

# "67 XX B3 B2 B1 B0" — 4-byte seed (32-bit UDS 0x67 response)
_RAW_FRAME_67_32_RE = re.compile(
    r'\b67\s+[0-9a-fA-F]{2}'
    r'\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})'
    r'\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})\b',
    re.IGNORECASE
)


# ── File-format detectors ─────────────────────────────────────────────────────

def _looks_like_jsonl(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line.startswith('{') and line.endswith('}')
    return False

def _looks_like_csv(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return 'raw_line' in line and ',' in line
    return False


# ── Core parsers (return raw integer seed list) ───────────────────────────────

def _parse_session_log(text: str) -> Tuple[List[int], int, int]:
    seeds, skipped, seed_lines = [], 0, 0
    for raw in text.splitlines():
        m = _SEED_RECV_RE.search(raw)
        if m:
            seed_lines += 1
            try:
                v = int(m.group(1), 16)
                if 0 <= v <= MAX_SEED_32:
                    seeds.append(v)
                else:
                    skipped += 1
            except ValueError:
                skipped += 1
    return seeds, skipped, seed_lines

def _parse_raw_can_log(text: str) -> Tuple[List[int], int, int]:
    """
    Try 4-byte (32-bit) pattern first, fall back to 2-byte (16-bit).
    This ensures 32-bit ECUs are handled correctly without false truncation.
    """
    seeds, skipped, frame_lines = [], 0, 0
    for raw in text.splitlines():
        # Prefer 4-byte match — more specific pattern
        m4 = _RAW_FRAME_67_32_RE.search(raw)
        if m4:
            frame_lines += 1
            try:
                v = (int(m4.group(1), 16) << 24
                     | int(m4.group(2), 16) << 16
                     | int(m4.group(3), 16) << 8
                     | int(m4.group(4), 16))
                if 0 <= v <= MAX_SEED_32:
                    seeds.append(v)
                else:
                    skipped += 1
            except ValueError:
                skipped += 1
            continue

        # 2-byte fallback
        m2 = _RAW_FRAME_67_16_RE.search(raw)
        if m2:
            frame_lines += 1
            try:
                v = (int(m2.group(1), 16) << 8) | int(m2.group(2), 16)
                if 0 <= v <= MAX_SEED_16:
                    seeds.append(v)
                else:
                    skipped += 1
            except ValueError:
                skipped += 1

    return seeds, skipped, frame_lines

def _parse_jsonl(text: str) -> Tuple[List[int], int, int]:
    seeds, skipped, seed_lines = [], 0, 0
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        raw_line = obj.get('raw_line', '') or obj.get('decoded', '')
        m = _SEED_RECV_RE.search(raw_line)
        if m:
            seed_lines += 1
            try:
                v = int(m.group(1), 16)
                if 0 <= v <= MAX_SEED_32:
                    seeds.append(v)
                else:
                    skipped += 1
            except ValueError:
                skipped += 1
    return seeds, skipped, seed_lines

def _parse_csv(text: str) -> Tuple[List[int], int, int]:
    seeds, skipped, seed_lines = [], 0, 0
    lines = text.splitlines()
    if not lines:
        return seeds, skipped, seed_lines
    header = lines[0].strip().split(',')
    try:
        raw_col = header.index('raw_line')
    except ValueError:
        return _parse_session_log(text)
    for row in lines[1:]:
        parts = row.split(',')
        if raw_col >= len(parts):
            continue
        cell = parts[raw_col].strip().strip('"')
        m = _SEED_RECV_RE.search(cell)
        if m:
            seed_lines += 1
            try:
                v = int(m.group(1), 16)
                if 0 <= v <= MAX_SEED_32:
                    seeds.append(v)
                else:
                    skipped += 1
            except ValueError:
                skipped += 1
    return seeds, skipped, seed_lines


# ── Dispatcher ────────────────────────────────────────────────────────────────

def parse_seeds_from_text(text: str) -> Tuple[List[int], int, int]:
    """Auto-detect format and return (seeds, skipped, seed_lines)."""
    if _looks_like_jsonl(text):
        return _parse_jsonl(text)
    if _looks_like_csv(text):
        return _parse_csv(text)
    # Try raw CAN first — has 4-byte priority
    seeds, skipped, lc = _parse_raw_can_log(text)
    if seeds:
        return seeds, skipped, lc
    return _parse_session_log(text)

def parse_seeds_from_file(path: str) -> Tuple[List[int], int, int, str]:
    try:
        size = os.path.getsize(path)
        if size > 50 * 1024 * 1024:
            return [], 0, 0, f"File too large ({size // 1_048_576} MB). Max 50 MB."
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError as exc:
        return [], 0, 0, f"Cannot read file: {exc}"
    seeds, skipped, line_count = parse_seeds_from_text(text)
    return seeds, skipped, line_count, ""


# ── Mode detection ────────────────────────────────────────────────────────────

def detect_mode(seeds: List[int]) -> SeedMode:
    """
    Inspect the maximum value in the seed list to choose the algorithm.

      max(seeds) ≤ 0xFFFF → ARRAY_16   (16-bit, direct-address array)
      max(seeds) > 0xFFFF → HASHMAP_32 (32-bit, hash-map — saves ~16 GB)
    """
    if not seeds:
        return SeedMode.ARRAY_16  # default to 16-bit for empty input
    return SeedMode.ARRAY_16 if max(seeds) <= MAX_SEED_16 else SeedMode.HASHMAP_32


# ── Algorithm A: 16-bit Direct-Address Array ──────────────────────────────────

def build_frequency_array(seeds: List[int]) -> List[int]:
    """
    ARRAY MODE (16-bit only).

    Direct-address frequency array of fixed size 65,536.
    Index = seed value — no hashing needed.

    Complexity: O(n) insert, O(65,536) full scan.
    Memory:     65,536 × 8 bytes ≈ 256 KB (CPython list of ints).
    """
    freq: List[int] = [0] * ARRAY_SIZE_16
    for s in seeds:
        if 0 <= s <= MAX_SEED_16:
            freq[s] += 1
    return freq

def extract_duplicates_array(freq: List[int]) -> List[Tuple[int, int]]:
    """Duplicates from a 16-bit array: (seed_value, count) pairs, count > 1."""
    return sorted(
        [(i, freq[i]) for i in range(ARRAY_SIZE_16) if freq[i] > 1],
        key=lambda t: t[1], reverse=True,
    )


# ── Algorithm B: 32-bit Hash Map ──────────────────────────────────────────────

def build_frequency_map(seeds: List[int]) -> Dict[int, int]:
    """
    HASHMAP MODE (32-bit).

    dict-based frequency counter — stores ONLY observed seed values.

    Why not an array?
      A fixed array for the 32-bit domain would need:
        4,294,967,296 entries × 8 bytes ≈ 16 GB  — infeasible on any ECU test PC.

    This dict approach:
      • Stores at most len(seeds) unique entries (typically thousands)
      • O(1) amortized insert and lookup (Python dict uses open addressing)
      • Memory: O(unique_seeds) — typically kilobytes, never gigabytes

    Complexity: O(n) insert, O(unique_seeds) scan for duplicates.
    """
    freq: Dict[int, int] = {}
    for s in seeds:
        if 0 <= s <= MAX_SEED_32:
            freq[s] = freq.get(s, 0) + 1
    return freq

def extract_duplicates_map(freq: Dict[int, int]) -> List[Tuple[int, int]]:
    """Duplicates from a 32-bit hash map: (seed_value, count) pairs, count > 1."""
    return sorted(
        [(k, v) for k, v in freq.items() if v > 1],
        key=lambda t: t[1], reverse=True,
    )


# ── Shared helpers ────────────────────────────────────────────────────────────

def classify_seed(count: int) -> str:
    """Per-seed severity label based on repetition count (mode-independent)."""
    if count >= SEV_HIGH_MIN:   return "HIGH"
    if count >= SEV_MEDIUM_MIN: return "MEDIUM"
    if count >= SEV_LOW_MIN:    return "LOW"
    return "SAFE"


# ── Analysis result container ─────────────────────────────────────────────────

class SeedAnalysisResult:
    """
    Unified result object for both ARRAY_16 and HASHMAP_32 modes.

    The public attributes are identical regardless of which algorithm was used,
    so callers (uds_tab.py, format_report, report_generators) are unaffected.

    Mode-specific notes
    -------------------
    ARRAY_16:
      • freq is List[int] of length 65,536
      • missing_seeds is fully populated (all values 0x0000–0xFFFF not seen)
      • coverage_pct is meaningful (fraction of 65,536-value space observed)

    HASHMAP_32:
      • freq is Dict[int, int] mapping observed seed → count
      • missing_seeds = [] (enumerating 4B missing values is infeasible)
      • missing_count = DOMAIN_SIZE_32 - unique_count (exact, no enumeration)
      • coverage_pct = (unique_count / DOMAIN_SIZE_32) × 100
    """

    def __init__(
        self,
        seeds:      List[int],
        freq:       Union[List[int], Dict[int, int]],
        duplicates: List[Tuple[int, int]],
        skipped:    int,
        line_count: int,
        mode:       SeedMode,
    ):
        self.seeds      = seeds
        self.freq       = freq
        self.duplicates = duplicates
        self.skipped    = skipped
        self.line_count = line_count
        self.mode       = mode

        # ── Basic counts (mode-independent) ──────────────────────────────────
        self.total_samples = len(seeds)

        if mode == SeedMode.ARRAY_16:
            self.unique_count = sum(1 for c in freq if c > 0)           # type: ignore[arg-type]
        else:
            self.unique_count = len(freq)  # dict keys = unique seeds observed

        self.dup_seed_count        = len(duplicates)
        self.total_dup_occurrences = sum(c - 1 for _, c in duplicates)

        self.dup_rate = (
            self.total_dup_occurrences / self.total_samples
            if self.total_samples > 0 else 0.0
        )

        # ── Missing seed analysis ─────────────────────────────────────────────
        if mode == SeedMode.ARRAY_16:
            # Full enumeration is cheap for 65,536 entries
            self.missing_seeds = [i for i in range(ARRAY_SIZE_16) if freq[i] == 0]  # type: ignore[index]
            self.missing_count = len(self.missing_seeds)
            domain             = ARRAY_SIZE_16
        else:
            # 32-bit: never enumerate 4B missing values — compute count only
            self.missing_seeds = []
            self.missing_count = DOMAIN_SIZE_32 - self.unique_count
            domain             = DOMAIN_SIZE_32

        self.coverage_pct = (self.unique_count / domain) * 100.0 if domain else 0.0

        # ── Rare seeds (seen exactly once) ───────────────────────────────────
        if mode == SeedMode.ARRAY_16:
            self.rare_seeds = [
                (i, freq[i]) for i in range(ARRAY_SIZE_16) if freq[i] == 1  # type: ignore[index]
            ]
        else:
            self.rare_seeds = [(k, v) for k, v in freq.items() if v == 1]   # type: ignore[union-attr]

        # ── Dominant seed detection ───────────────────────────────────────────
        self.max_count           = duplicates[0][1] if duplicates else 0
        self.dominant_seed_value = duplicates[0][0] if duplicates else None
        self.dominant_present    = (
            (self.max_count / self.total_samples) > 0.50
            if self.total_samples else False
        )

        # ── Entropy indicator ─────────────────────────────────────────────────
        # For 16-bit: coverage of fixed 65,536-value space
        # For 32-bit: coverage of 4,294,967,296-value space
        cov = self.unique_count / domain if domain else 0.0
        if cov >= COVERAGE_HIGH:
            self.entropy_indicator = "HIGH"
        elif cov >= COVERAGE_MEDIUM:
            self.entropy_indicator = "MEDIUM"
        elif cov >= COVERAGE_LOW:
            self.entropy_indicator = "LOW"
        else:
            self.entropy_indicator = "CRITICAL"

        # ── Predictability risk ───────────────────────────────────────────────
        if self.dominant_present or self.dup_rate >= VERDICT_CRITICAL:
            self.predictability_risk = "CRITICAL"
        elif self.dup_rate >= VERDICT_HIGH:
            self.predictability_risk = "HIGH"
        elif self.dup_rate >= VERDICT_MEDIUM or self.dup_seed_count > 0:
            self.predictability_risk = "MEDIUM"
        else:
            self.predictability_risk = "LOW"

        # ── Overall verdict ───────────────────────────────────────────────────
        if self.dominant_present or self.dup_rate >= VERDICT_CRITICAL:
            self.overall_severity = "CRITICAL"
            self.overall_label    = "CRITICAL"
        elif self.dup_rate >= VERDICT_HIGH:
            self.overall_severity = "HIGH"
            self.overall_label    = "HIGH RISK"
        elif self.dup_rate >= VERDICT_MEDIUM or self.dup_seed_count > 0:
            self.overall_severity = "MEDIUM"
            self.overall_label    = "WEAK"
        else:
            self.overall_severity = "SAFE"
            self.overall_label    = "SAFE"


# ── Full pipeline (auto-mode, public API) ─────────────────────────────────────

def analyze(seeds: List[int], skipped: int = 0, line_count: int = 0) -> SeedAnalysisResult:
    """
    Run the full dual-mode analysis on an already-parsed seed list.

    Mode is chosen automatically:
      • max(seeds) ≤ 0xFFFF → ARRAY_16  (O(n) + 256 KB array)
      • max(seeds) > 0xFFFF → HASHMAP_32 (O(n) dict, O(unique) memory)
    """
    mode = detect_mode(seeds)

    if mode == SeedMode.ARRAY_16:
        freq       = build_frequency_array(seeds)
        duplicates = extract_duplicates_array(freq)
    else:
        freq       = build_frequency_map(seeds)
        duplicates = extract_duplicates_map(freq)

    return SeedAnalysisResult(seeds, freq, duplicates, skipped, line_count, mode)

def analyze_file(path: str) -> Tuple[Optional[SeedAnalysisResult], str]:
    """
    Parse a file, auto-detect seed width, choose algorithm, run analysis.
    Returns (SeedAnalysisResult, "") on success or (None, error_message) on failure.
    """
    seeds, skipped, line_count, err = parse_seeds_from_file(path)
    if err:
        return None, err
    if not seeds:
        return None, (
            "No UDS Security Access seeds (0x67 responses / 'Seed received') found.\n"
            "Ensure the file contains FucyFuzz session logs or raw CAN frame data."
        )
    result = analyze(seeds, skipped, line_count)
    assert result.total_samples == len(seeds), (
        f"Count mismatch: total_samples={result.total_samples} != len(seeds)={len(seeds)}"
    )
    return result, ""


# ── Professional report formatter ─────────────────────────────────────────────

def format_report(
    result:           SeedAnalysisResult,
    max_dup_rows:     int = 50,
    max_rare_rows:    int = MAX_RARE_DISPLAY,
    max_missing_show: int = MAX_MISSING_DISPLAY,
) -> List[Tuple[str, str]]:
    """
    Format analysis result as (text, color_key) pairs for the terminal widget.

    color_key values:
      'header'   — report title / dividers        (cyan)
      'section'  — section headings               (purple)
      'ok'       — safe / no issues               (green)
      'low'      — low severity                   (cyan)
      'medium'   — medium severity                (yellow)
      'high'     — high severity                  (orange)
      'critical' — critical severity              (red)
      'muted'    — secondary / informational      (muted)
      'output'   — normal text                    (green)

    Works identically for both ARRAY_16 and HASHMAP_32 results.
    Mode-specific differences are handled transparently via result.mode.
    """
    lines: List[Tuple[str, str]] = []

    def L(text: str, color: str = 'output'):
        lines.append((text, color))

    SEV_COLOR = {
        "CRITICAL": "critical",
        "HIGH":     "high",
        "MEDIUM":   "medium",
        "LOW":      "low",
        "SAFE":     "ok",
    }

    r         = result
    mode      = r.mode
    sev_color = SEV_COLOR.get(r.overall_severity, "output")

    # Mode labels for report header
    if mode == SeedMode.ARRAY_16:
        mode_line  = "  (16-bit Domain | Array-Based  O(1)  | 256 KB Memory)"
        domain_str = f"{ARRAY_SIZE_16:,}  (0x0000 – 0xFFFF)"
    else:
        mode_line  = "  (32-bit Domain | Hash Map O(n) | Memory: O(unique_seeds))"
        domain_str = f"{DOMAIN_SIZE_32:,}  (0x00000000 – 0xFFFFFFFF)"

    # ── HEADER ────────────────────────────────────────────────────────────────
    L("", 'output')
    L("━" * 60, 'header')
    L("  UDS SECURITY SEED ANALYSIS REPORT", 'header')
    L(mode_line, 'header')
    L("━" * 60, 'header')

    # ── Mode indicator block ──────────────────────────────────────────────────
    L("", 'output')
    L("  [ANALYSIS MODE]", 'section')
    L("  " + "─" * 44, 'muted')

    if mode == SeedMode.ARRAY_16:
        L("  Algorithm   : Direct-Address Array  (size = 65,536)", 'output')
        L("  Seed Width  : 16-bit  (0x0000 – 0xFFFF)", 'output')
        L("  Insert Cost : O(1)  — index = seed value, no hashing", 'output')
        L("  Scan Cost   : O(65,536)  — single pass over fixed array", 'output')
        L("  Memory      : 65,536 × 8 B ≈ 256 KB  (Python int list)", 'output')
        L("  Missing     : Available  (full 65,536-value domain)", 'ok')
    else:
        L("  Algorithm   : Hash Map  (dict — observed seeds only)", 'output')
        L("  Seed Width  : 32-bit  (0x00000000 – 0xFFFFFFFF)", 'output')
        L("  Insert Cost : O(1) amortized  (CPython open-addressing dict)", 'output')
        L(f"  Scan Cost   : O({r.unique_count:,})  — only observed entries", 'output')
        L(f"  Memory      : O(unique_seeds)  ≈ {r.unique_count * 100 // 1024 or 1} KB"
          "  (array would need ~16 GB)", 'output')
        L("  Missing     : Count only  (enumerating 4 B values is infeasible)", 'medium')

    # ── SECTION 1: SUMMARY STATISTICS ────────────────────────────────────────
    L("", 'output')
    L("  [SUMMARY STATISTICS]", 'section')
    L("  " + "─" * 44, 'muted')
    L(f"  Total Samples Processed      : {r.total_samples:>12,}", 'output')
    L(f"  Unique Seeds Observed        : {r.unique_count:>12,}", 'output')
    L(f"  Duplicate Seed Entries       : {r.dup_seed_count:>12,}", 'output')
    L(f"  Repeated Occurrences         : {r.total_dup_occurrences:>12,}", 'output')
    dup_pct = r.dup_rate * 100.0
    L(f"  Duplicate Rate               : {dup_pct:>11.2f} %", 'output')
    L(f"  Missing Seed Values          : {r.missing_count:>12,}", 'output')
    L(f"  Coverage of Seed Space       : {r.coverage_pct:>11.4f} %", 'output')
    L(f"  Skipped (invalid lines)      : {r.skipped:>12,}", 'muted')

    # ── SECTION 2: SECURITY ASSESSMENT ───────────────────────────────────────
    L("", 'output')
    L("  [SECURITY ASSESSMENT]", 'section')
    L("  " + "─" * 44, 'muted')

    ent_col = SEV_COLOR.get(r.entropy_indicator, 'output')
    L(f"  Entropy Indicator            : {r.entropy_indicator}", ent_col)

    dom_col    = 'critical' if r.dominant_present else 'ok'
    dom_str    = "YES" if r.dominant_present else "NO"
    dom_suffix = ""
    if r.dominant_present and r.dominant_seed_value is not None:
        dom_pct    = (r.max_count / r.total_samples * 100.0) if r.total_samples else 0.0
        seed_fmt   = (f"0x{r.dominant_seed_value:04X}" if mode == SeedMode.ARRAY_16
                      else f"0x{r.dominant_seed_value:08X}")
        dom_suffix = f"  ({seed_fmt} — {dom_pct:.1f}% of samples)"
    L(f"  Dominant Seed Presence       : {dom_str}{dom_suffix}", dom_col)

    risk_col = SEV_COLOR.get(r.predictability_risk, 'output')
    L(f"  Predictability Risk          : {r.predictability_risk}", risk_col)
    L("", 'output')
    L(f"  Overall Verdict              : {r.overall_label}", sev_color)

    # ── SECTION 3: TOP REPEATED SEEDS ────────────────────────────────────────
    L("", 'output')
    L("  [TOP REPEATED SEEDS]", 'section')
    L("  " + "─" * 44, 'muted')

    if r.dup_seed_count == 0:
        L("  ✅  No duplicate seeds detected.", 'ok')
        L("      Every captured seed value was unique.", 'muted')
    else:
        seed_col_hdr = "Seed (16-bit)" if mode == SeedMode.ARRAY_16 else "Seed (32-bit)"
        L(f"  {seed_col_hdr:<16}  {'Count':>10}  {'Severity':<10}  Bar", 'output')
        L("  " + "─" * 52, 'muted')
        shown = r.duplicates[:max_dup_rows]
        max_c = r.duplicates[0][1] if r.duplicates else 1
        for seed_val, count in shown:
            sev     = classify_seed(count)
            col     = SEV_COLOR.get(sev, 'output')
            bar_len = max(1, int((count / max_c) * 18))
            bar     = "█" * bar_len
            seed_fmt = (f"0x{seed_val:04X}" if mode == SeedMode.ARRAY_16
                        else f"0x{seed_val:08X}")
            L(f"  {seed_fmt:<16}  {count:>10,}  {sev:<10}  {bar}", col)
        if len(r.duplicates) > max_dup_rows:
            L(f"  … and {len(r.duplicates) - max_dup_rows:,} more (showing top {max_dup_rows})",
              'muted')

    # ── SECTION 4: LOW FREQUENCY / RARE SEEDS ────────────────────────────────
    L("", 'output')
    L("  [LOW FREQUENCY / RARE SEEDS]", 'section')
    L("  " + "─" * 44, 'muted')

    if not r.rare_seeds:
        L("  No rare seeds (all observed seeds appeared more than once).", 'muted')
    else:
        shown_rare = r.rare_seeds[:max_rare_rows]
        L(f"  Seeds seen exactly once : {len(r.rare_seeds):,}"
          f"  (showing first {min(len(r.rare_seeds), max_rare_rows)})", 'muted')
        if mode == SeedMode.ARRAY_16:
            rare_str = "  " + "  ".join(f"0x{sv:04X}" for sv, _ in shown_rare)
        else:
            rare_str = "  " + "  ".join(f"0x{sv:08X}" for sv, _ in shown_rare)
        L(rare_str, 'low')
        if len(r.rare_seeds) > max_rare_rows:
            L(f"  … and {len(r.rare_seeds) - max_rare_rows:,} more rare seeds not shown.", 'muted')

    # ── SECTION 5: MISSING SEEDS (NOT OBSERVED) ──────────────────────────────
    L("", 'output')
    L("  [MISSING SEEDS (NOT OBSERVED)]", 'section')
    L("  " + "─" * 44, 'muted')
    L(f"  Total Possible Seeds         : {domain_str}", 'output')
    L(f"  Total Missing Seeds          : {r.missing_count:>12,}", 'output')
    L(f"  Total Observed Seeds         : {r.unique_count:>12,}", 'output')

    if mode == SeedMode.ARRAY_16:
        if r.missing_count == 0:
            L("  ✅  Full 16-bit space covered — all 65,536 values observed.", 'ok')
        elif r.missing_count == ARRAY_SIZE_16:
            L("  ✘  No seeds observed — cannot evaluate coverage.", 'critical')
        else:
            shown_miss = r.missing_seeds[:max_missing_show]
            miss_str   = ", ".join(f"0x{v:04X}" for v in shown_miss)
            L("", 'output')
            L("  Example Missing Seeds:", 'muted')
            L(f"  {miss_str}", 'muted')
            if r.missing_count > max_missing_show:
                L(f"  … ({r.missing_count - max_missing_show:,} more not shown)", 'muted')
            L("", 'output')
            L("  Note: A healthy RNG covers the 16-bit space uniformly over time.", 'muted')
    else:
        # 32-bit: never list individual missing values — would be billions
        L("", 'output')
        L("  ⚠  Missing seed enumeration is not available for 32-bit seeds.", 'medium')
        L("     (Listing up to 4,294,967,296 values is not feasible.)", 'muted')
        L(f"     Coverage: {r.coverage_pct:.6f} % of the 32-bit domain observed.", 'output')
        L("     A healthy 32-bit PRNG has near-zero coverage even after", 'muted')
        L("     millions of samples — duplicates are the primary indicator.", 'muted')

    # ── FOOTER ────────────────────────────────────────────────────────────────
    L("", 'output')
    L("━" * 60, 'header')
    L("", 'output')

    return lines
