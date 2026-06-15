# FucyFuzz — CAN Bus Security Framework (v2)

A graphical fuzzing and analysis tool for CAN bus / ECU security testing.

---

## What's Fixed in v2

### 🔴 Critical: SocketCAN Interface Fix
- **Error fixed**: `Could not access SocketCAN device vcan0 ([Errno 19] No such device)`
- Centralized interface validation via `utils/can_interface.py`
- Graceful error messages with exact setup commands shown in terminal
- Live interface status (UP / DOWN) shown in status bar and Config tab
- One-click "Setup vcan0" button in Config tab
- `setup_vcan.sh` convenience script for terminal users

### 🟠 High Priority: Fuzzer Stability
- **Random** fuzzer: proper stop-event, timeout, max-frames guard
- **Bruteforce** fuzzer: pattern expansion now validates tokens before running; clean error on invalid patterns
- Both modes use `NonBlockingCANSender` — never hang on missing interface

### 🚨 TOP PRIORITY: Mutate Mode — No More Freeze
- **Root cause**: blocking `while True` loop with no exit condition
- **Fix**: replaced with stop-event + deadline + max-frames guard
- `MutateFuzzer.run()` checks `stop_event.is_set()` on every iteration
- Timeout defaults to 300 s (configurable in UI); KILL button works instantly
- Progress logged every 100 frames

### 🔵 CAN Initialization Layer
- `utils/can_interface.py` — single source of truth for interface validation
- `check_interface(iface)` → returns `IfaceStatus` object (never raises)
- `list_can_interfaces()` — lists all CAN interfaces visible in `/sys/class/net/`
- `try_setup_vcan(iface)` — attempts auto-setup with sudo (if available)
- `NonBlockingCANSender` — timeout-enforced, thread-safe raw socket wrapper

### 🟢 Logging System Upgrade
- `utils/log_manager.py` — per-module structured logger
- Logs stored in `logs/<module>/` (created automatically)
- Each module gets its own `<module>_<timestamp>.csv` + `.log`
- CSV fields: `timestamp, module, direction, can_id, data_hex, status, raw`
- Log rotation at 10 MB; keeps last 10 rotated files
- TXT export via `ModuleLogger.export_txt(dest)`
- Global app log: `logs/fucyfuzz_app.log`

### 🖥️ UI/Terminal Improvements
- CAN interface status badge in title bar: `Interface: vcan0 [UP ✅]`
- Error messages formatted with clear borders — no raw stack traces
- Config tab: "Check Interface" + "Setup vcan0" buttons

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set up virtual CAN (for testing without hardware)
```bash
sudo bash setup_vcan.sh          # creates and brings up vcan0
# OR manually:
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

### 3. Run
```bash
python main.py
```

---

## Fuzzer Modes

| Mode        | Status  | Description |
|-------------|---------|-------------|
| `random`    | ✅ Fixed | Random CAN frames with configurable DLC, seed, delay |
| `bruteforce`| ✅ Fixed | Expands patterns with `..` wildcards across all 256 values |
| `mutate`    | ✅ Fixed | Non-blocking mutation loop — no hang, proper stop/timeout |
| `replay`    | ✅ OK   | Replays frames from log file (subprocess mode) |
| `identify`  | ✅ OK   | Identify mode (subprocess mode) |

---

## Interface Reference

| Interface | Type       | Notes |
|-----------|------------|-------|
| `vcan0`   | Virtual    | Linux simulation — needs `modprobe vcan` |
| `can0`    | Physical   | SocketCAN hardware (PCAN, Kvaser, etc.) |

---

## Log Structure

```
logs/
  fucyfuzz_app.log          ← global app log (all sessions)
  fuzzer/
    fuzzer_20260401_120000.csv   ← per-module CSV (rotated at 10 MB)
    fuzzer_20260401_120000.log   ← human-readable text
  uds/
    uds_20260401_120000.csv
  send/
    send_20260401_120000.csv
  session_20260401_120000/      ← session logger (legacy, kept for compat)
    session.log
    session.csv
    session.jsonl
```

---

## Files Changed in v2

| File | Change |
|------|--------|
| `utils/can_interface.py` | **NEW** — centralized CAN interface manager |
| `utils/fuzzer_engine.py` | **NEW** — RandomFuzzer, BruteforceFuzzer, MutateFuzzer |
| `utils/log_manager.py`   | **NEW** — per-module structured logging |
| `utils/runner.py`        | Updated — uses can_interface, better error display |
| `utils/isotp_handler.py` | Updated — validates interface before connecting |
| `utils/ecu_log_watcher.py` | Updated — no longer hardcodes `vcan0` |
| `modules/fuzzer_tab.py`  | **Rewritten** — integrates FuzzerEngine, non-blocking |
| `modules/base_tab.py`    | Updated — uses can_interface for pre-flight check |
| `modules/config_tab.py`  | Updated — Check Interface + Setup vcan0 buttons |
| `ui/main_window.py`      | Updated — shows CAN status in status bar |
| `main.py`                | Updated — logs to file, CAN pre-check on startup |
| `setup_vcan.sh`          | **NEW** — convenience script for vcan setup |
| `requirements.txt`       | Updated |
