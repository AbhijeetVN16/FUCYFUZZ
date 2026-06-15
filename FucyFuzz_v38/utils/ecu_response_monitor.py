"""
ECUResponseMonitor
------------------
Parses raw fucyfuzz output lines and extracts structured ECU response data.

Recognised seed line formats (all from real fucyfuzz binary output):
  Seed received: DEADBEEF
  Seed received: 0xDEADBEEF
  SecurityAccess_OK(level=0x03 seed=0xABCD1234)
  [Seed #1]  seed: 0xABCD  (raw: 6703ABCD)
  Seed: 0xABCD
  [RX] 7E8: 67 03 AB CD EF 01
  Response: [67 03 AB CD]
  seed=0xABCD
"""

import re
import time
import math
from collections import Counter, deque

# ── Seed patterns — ordered most-specific to least-specific ──────────────────
# Matches: "Seed received: DEADBEEF" or "Seed received: 0xDEADBEEF"
_SEED_RECEIVED_RE = re.compile(
    r'[Ss]eed\s+received\s*[:\-]\s*(?:0x)?([0-9a-fA-F]{2,16})', re.I
)
# Matches: "seed=0xABCD1234" or "seed=ABCD1234" (inside SecurityAccess_OK(...))
_SEED_EQ_RE = re.compile(
    r'[Ss]eed\s*=\s*(?:0x)?([0-9a-fA-F]{2,16})', re.I
)
# Matches: "seed: 0xABCD" or "Seed: ABCD"
_SEED_COLON_RE = re.compile(
    r'[Ss]eed\s*:\s*(?:0x)?([0-9a-fA-F]{2,16})', re.I
)
# Matches raw 0x67 SecurityAccess positive response frame bytes
# "67 03 AB CD EF" — captures bytes after the sub-function byte
_SA_FRAME_RE = re.compile(
    r'67\s+[0-9a-fA-F]{2}\s+((?:[0-9a-fA-F]{2}\s*){1,8})', re.I
)
# Matches: "[RX] 7E8: 67 03 AB CD" — full [RX] line with 0x67 response
_RX_SA_RE = re.compile(
    r'\[RX\][^:]*:.*?\b67\s+[0-9a-fA-F]{2}\s+((?:[0-9a-fA-F]{2}\s*)+)', re.I
)

_NRC_HEX_RE  = re.compile(r'7[Ff]\s+[0-9a-fA-F]{2}\s+([0-9a-fA-F]{2})')
_NRC_TAG_RE  = re.compile(r'[Nn][Rr][Cc][=:\s]+0[xX]([0-9a-fA-F]{2})')
_TIMEOUT_RE  = re.compile(r'timeout|no response|timed out|no reply', re.I)
_POSITIVE_RE = re.compile(r'[Pp]ositive|service accepted', re.I)
_RX_FRAME_RE = re.compile(r'\[RX\][^:]*:[0-9a-fA-F\s]+', re.I)


def _try_parse_seed(hex_str: str):
    """Clean and parse a hex string to bytes. Returns None on failure."""
    cleaned = hex_str.strip().replace(' ', '').replace('0x', '').replace('0X', '')
    if not cleaned:
        return None
    # Must be even length to be valid bytes
    if len(cleaned) % 2 != 0:
        cleaned = cleaned.zfill(len(cleaned) + 1)
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


class ECUResponseMonitor:
    """
    Stateful response monitor. Feed every output line to .process_line().
    Exposes aggregated stats suitable for direct dashboard binding.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.total_rx       = 0
        self.total_tx       = 0
        self.total_timeouts = 0
        self.positive_count = 0
        self.negative_count = 0
        self.nrc_counts     = Counter()
        self.seeds_seen     = []
        self.seed_set       = set()
        self._recent_ts     = deque(maxlen=120)

    def process_line(self, line: str) -> dict:
        """
        Parse one output line. Returns a result dict or None.
        Tries all seed formats before falling back to NRC/timeout/positive.
        """
        if 'CC_PACKET ' in line:
            import json
            try:
                idx = line.find('CC_PACKET ')
                pkt = json.loads(line[idx+10:])
                note = pkt.get('note', '') or pkt.get('decoded', '') or ''
                
                # Check for timeout
                if pkt.get('severity') == 'CRITICAL' and _TIMEOUT_RE.search(note):
                    self.total_timeouts += 1
                    return {"type": "timeout"}
                
                # Check for seed
                data_hex = pkt.get('data_hex', '').replace(' ', '').upper()
                seed_bytes = None
                if 'security' in note.lower() and 'seed' in note.lower():
                    if len(data_hex) >= 6 and data_hex.startswith('67'):
                        seed_bytes = _try_parse_seed(data_hex[4:])
                
                if seed_bytes is None:
                    seed_bytes = self._extract_seed(note)
                    
                if seed_bytes is not None:
                    is_repeat = seed_bytes in self.seed_set
                    self.seeds_seen.append(seed_bytes)
                    self.seed_set.add(seed_bytes)
                    self.total_rx += 1
                    self._recent_ts.append(time.time())
                    return {
                        "type":      "seed",
                        "seed":      seed_bytes,
                        "is_repeat": is_repeat,
                        "entropy":   self._entropy(seed_bytes),
                    }
                    
                # Check for NRC
                if data_hex.startswith('7F') and len(data_hex) >= 6:
                    nrc = int(data_hex[4:6], 16)
                    self.nrc_counts[nrc] += 1
                    self.negative_count  += 1
                    self.total_rx        += 1
                    self._recent_ts.append(time.time())
                    return {"type": "nrc", "nrc": nrc}
                    
                # Check for positive response
                if pkt.get('direction') == 'RX' and not data_hex.startswith('7F'):
                    self.positive_count += 1
                    self.total_rx       += 1
                    self._recent_ts.append(time.time())
                    return {"type": "positive"}
                    
            except Exception:
                pass

        # ── Timeout (check first — these lines never contain seeds) ──────────
        if _TIMEOUT_RE.search(line):
            self.total_timeouts += 1
            return {"type": "timeout"}

        # ── Seed: try all formats ─────────────────────────────────────────────
        seed_bytes = self._extract_seed(line)
        if seed_bytes is not None:
            is_repeat = seed_bytes in self.seed_set
            self.seeds_seen.append(seed_bytes)
            self.seed_set.add(seed_bytes)
            self.total_rx += 1
            self._recent_ts.append(time.time())
            return {
                "type":      "seed",
                "seed":      seed_bytes,
                "is_repeat": is_repeat,
                "entropy":   self._entropy(seed_bytes),
            }

        # ── NRC from raw bytes "7F XX YY" ─────────────────────────────────────
        m = _NRC_HEX_RE.search(line)
        if m:
            nrc = int(m.group(1), 16)
            self.nrc_counts[nrc] += 1
            self.negative_count  += 1
            self.total_rx        += 1
            self._recent_ts.append(time.time())
            return {"type": "nrc", "nrc": nrc}

        # ── NRC from tag "NRC=0x22" ────────────────────────────────────────────
        m = _NRC_TAG_RE.search(line)
        if m:
            nrc = int(m.group(1), 16)
            self.nrc_counts[nrc] += 1
            self.negative_count  += 1
            return {"type": "nrc", "nrc": nrc}

        # ── Positive response ─────────────────────────────────────────────────
        if _POSITIVE_RE.search(line) or (
            _RX_FRAME_RE.search(line) and '7f' not in line.lower()
        ):
            self.positive_count += 1
            self.total_rx       += 1
            self._recent_ts.append(time.time())
            return {"type": "positive"}

        return None

    def _extract_seed(self, line: str):
        """
        Try all seed patterns in priority order.
        Returns bytes on success, None if no seed found.
        """
        # 1. "Seed received: DEADBEEF" — most common fucyfuzz stdout format
        m = _SEED_RECEIVED_RE.search(line)
        if m:
            return _try_parse_seed(m.group(1))

        # 2. "seed=0xABCD" — inside SecurityAccess_OK(...) decoded lines
        m = _SEED_EQ_RE.search(line)
        if m:
            return _try_parse_seed(m.group(1))

        # 3. "Seed: 0xABCD" or "[Seed #1] seed: 0xABCD"
        m = _SEED_COLON_RE.search(line)
        if m:
            return _try_parse_seed(m.group(1))

        # 4. Raw [RX] frame with 0x67 (SecurityAccess positive response)
        m = _RX_SA_RE.search(line)
        if m:
            return _try_parse_seed(m.group(1).replace(' ', ''))

        # 5. Any line containing "67 XX <seed bytes>" raw hex (non-[RX] lines)
        if '67' in line.lower() and 'seed' not in line.lower():
            m = _SA_FRAME_RE.search(line)
            if m:
                return _try_parse_seed(m.group(1).replace(' ', ''))

        return None

    @property
    def duplicate_seed_count(self) -> int:
        return len(self.seeds_seen) - len(self.seed_set)

    @property
    def seed_entropy_avg(self) -> float:
        if not self.seeds_seen:
            return 0.0
        recent = self.seeds_seen[-20:]
        return sum(self._entropy(s) for s in recent) / len(recent)

    @property
    def response_rate_per_sec(self) -> float:
        now    = time.time()
        cutoff = now - 10.0
        recent = [t for t in self._recent_ts if t >= cutoff]
        return len(recent) / 10.0

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data or len(data) < 2:
            return 0.0
        c = Counter(data)
        n = len(data)
        return -sum((v / n) * math.log2(v / n) for v in c.values())
