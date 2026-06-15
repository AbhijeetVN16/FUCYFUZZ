# FucyFuzz — Automotive CAN Bus Security Framework

A graphical fuzzing and analysis tool for CAN bus / ECU security testing.  
Built with Python + PyQt5. Supports SocketCAN (Linux), virtual CAN (`vcan0`), PCAN USB hardware, and DoIP (Diagnostics over IP).

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup: Virtual CAN Interface](#setup-virtual-can-interface)
- [Running FucyFuzz](#running-fucyfuzz)
- [Navigation](#navigation)
- [Module Reference](#module-reference)
  - [Dashboard](#dashboard)
  - [UDS Analyser](#uds-analyser)
  - [Replay](#replay)
  - [Config](#config)
  - [Recon](#recon)
  - [Demo](#demo)
  - [UDS](#uds)
  - [UDS Fuzz](#uds-fuzz)
  - [DCM](#dcm)
  - [Fuzzer](#fuzzer)
  - [Len Attack](#len-attack)
  - [Send](#send)
  - [Dump](#dump)
  - [Listener](#listener)
  - [XCP](#xcp)
  - [DoIP](#doip)
  - [Advanced](#advanced)
  - [Help](#help)
  - [Logs](#logs)
- [Logging & Session Files](#logging--session-files)
- [Export Formats](#export-formats)
- [Project Structure](#project-structure)
- [Interface Reference](#interface-reference)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Overview

FucyFuzz is a desktop application for automotive security researchers and ECU testers. It provides a unified graphical interface for:

- Sending and fuzzing raw CAN frames (random, bruteforce, mutate modes)
- Executing UDS (ISO 14229) diagnostic commands against real or virtual ECUs
- Performing Diagnostics over IP (DoIP / ISO 13400) sessions over Ethernet
- Replaying captured CAN/UDS traffic from multiple log formats
- Monitoring live NRC responses and analysing security seeds for randomness weaknesses
- Exporting findings as PDF reports, ASC logs, MDF4 files, BLF captures, and PCAP files

---

## Requirements

- **Python** 3.10 or later (tested on 3.11 and 3.14)
- **OS**: Linux (recommended, for SocketCAN support) or Windows (virtual bus / PCAN USB)

### Python Dependencies

```
PyQt5>=5.15
python-can>=4.0.0
python-isotp>=1.3.0
```

Optional:
- `reportlab` — PDF report export
- `asammdf` — MDF4 (`.mf4`) export
- `python-can[pcan]` — PCAN USB hardware on Windows

Install all required packages:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/FucyFuzz.git
cd FucyFuzz

# 2. (Recommended) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate.bat       # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Optional — PDF export
pip install reportlab

# 5. Optional — MDF4 export
pip install asammdf
```

---

## Setup: Virtual CAN Interface

If you are testing without real hardware you need a virtual CAN interface. This is Linux-only.

### Using the included script (recommended)

```bash
sudo bash setup_vcan.sh
```

The script loads the `vcan` kernel module, creates `vcan0`, and brings it up. Pass a custom name as an argument:

```bash
sudo bash setup_vcan.sh vcan1
```

### Manual setup

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

Verify:

```bash
ip link show vcan0
candump vcan0   # optional sanity check
```

You can also click **Setup vcan0** inside the **Config** tab to run the equivalent setup from the GUI.

---

## Running FucyFuzz

```bash
python main.py
```

On startup FucyFuzz will:

1. Check the configured CAN interface and log its status.
2. Create a new timestamped session directory under `logs/`.
3. Start the background session logger (JSONL + CSV + plain text + pairs CSV).
4. Open the main window with the **Dashboard** tab active.

---

## Navigation

The left sidebar is organised into four sections:

**OVERVIEW** — Dashboard · Replay · Config  
**ANALYSIS** — Recon · Demo · Advanced  
**ATTACK MODULES** — UDS · UDS Fuzz · DCM · Fuzzer · Len Attack  
**TOOLS** — Send · Dump · Listener · XCP · DoIP  

Plus **Help** and **Logs** at the bottom of the sidebar.

The title bar shows a live **CAN Bus Idle / CAN Bus Active** indicator that updates whenever a command starts or stops.

The menu bar provides:
- **File** → Export Session Data · Export Failure Report · Quit
- **Tools** → Clear All Faults · Kill Running Process · Auto-Initialize CAN Interface · View Session Logs · View Failure Cases
- **Help** → Open Documentation · About

---

## Module Reference

Every attack/tool tab shares the same base layout: a left controls panel and a right embedded terminal showing real-time output. All commands run in background threads so the GUI never freezes.

---

### Dashboard

The real-time session overview. Contains five widgets:

**Stat cards (top row)**
- Total Faults — cumulative fault count across the session
- Critical — faults classified as CRITICAL severity
- Open — unresolved faults
- Sessions — number of unique sessions recorded

**LiveAlertStack** — animated pop-up banners that appear each time a new vulnerability is detected. Each banner shows the severity icon, timestamp, and fault description, and fades out after 8 seconds.

**LiveFuzzingStatusWidget** — a live session status panel showing:
- Session duration (live clock)
- Total TX / RX frame counts from the session logger
- Per-severity fault counters (Critical / High / Medium / Low)
- A "Recent Anomalies" mini-list — last 5 faults, always fresh

**SeverityDistributionWidget** — horizontal severity bars showing the proportion of each severity level.

**LiveVulnerabilityFeed** — a scrollable running list of every vulnerability event with zero-latency updates pushed from any module.

All widgets update via Qt signals from background worker threads (QueuedConnection) so updates always arrive on the main thread.

---

### UDS Analyser

Three-panel live NRC (Negative Response Code) tracker. All data is derived from real-time output line parsing — no simulator or special ECU firmware required.

**Panel A — Live NRC Tracker table**  
Columns: NRC Code | Description | Count | Last Seen | Severity  
Every unique NRC code seen is added as a row and its count increments on each recurrence.

**Panel B — Session Statistics Strip**  
Stat cards for: Total Requests | Total NRCs | Unique NRC Codes | NRC Diversity score.

**Panel C — Response Timeline sparkline**  
A 60-second rolling window chart showing response cadence over time.

NRC codes and their severity:

| Code | Name | Severity |
|---|---|---|
| 0x10 | generalReject | low |
| 0x11 | serviceNotSupported | low |
| 0x12 | subFunctionNotSupported | low |
| 0x13 | incorrectMessageLength | low |
| 0x22 | conditionsNotCorrect | medium |
| 0x24 | requestSequenceError | medium |
| 0x25 | noResponseFromSubnetComponent | high |
| 0x31 | requestOutOfRange | low |
| 0x33 | securityAccessDenied | high |
| 0x35 | invalidKey | high |
| 0x36 | exceededNumberOfAttempts | critical |
| 0x37 | requiredTimeDelayNotExpired | medium |
| 0x70 | uploadDownloadNotAccepted | medium |
| 0x72 | generalProgrammingFailure | high |
| 0x7E | subFunctionNotSupportedInSession | low |
| 0x7F | serviceNotSupportedInSession | low |

---

### Replay

Multi-format CAN log replay with timing control.

**Supported input formats:**
- `.jsonl` — FucyFuzz native session log
- `.log` — FucyFuzz text log or `candump` log (auto-detected)
- `.csv` — FucyFuzz CSV export
- `.asc` — Vector ASC (CANalyzer / CANdb++ captures)
- `.blf` — Vector BLF (requires `python-can`)
- `.pcap` — Wireshark / socketcan captures (DLT 227 CAN_SOCKETCAN)

**Timing modes:**

| Mode | Behaviour |
|---|---|
| Original Timing | Uses the real inter-frame delta from the captured log |
| Custom Delay | Fixed gap between all frames (configurable in ms) |
| Scaled Timing | Original delta multiplied by a scale factor (0.1× to 5.0×) |
| Burst Mode | No inter-frame delay — maximum throughput |

**Loop count options:** 1× / 2× / 3× / 5× / 10× / ∞

**UI layout (3-column splitter):**

Column 1 — File browser, CAN interface selector, timing mode, loop count, progress bar + frame counter, action buttons (Dry Run / ▶ Replay / ⏹ Stop).

Column 2 — Frame List table with columns: # | ✓ | Time | Δt (ms) | ID | DLC | Data | Decoded | Sev. Per-row checkboxes let you select exactly which frames to replay. Filter/search bar above the table. Right-click context menu: replay single frame / edit payload / toggle include.

Column 3 — Terminal output + live stats panel (elapsed / frames sent / errors / frames-per-sec).

**Dry Run** validates the frame list and timing without transmitting — useful for inspecting a capture before committing to live replay.

---

### Config

Central configuration panel. Settings are persisted to `~/.fucyfuzz_gui.json` and restored on next launch.

**Sections:**

- **FucyFuzz Binary** — path to the backend CLI binary. Browse button + platform hint (Windows: `.exe`, Linux: no extension, run `chmod +x` first).
- **CAN Interface** — interface name (e.g. `vcan0`, `can0`, `PCAN_USBBUS1`), driver (auto-derived from interface name), and bitrate.
- **CAN Interface Setup** (Linux only) — command buttons to modprobe, create, and bring up the interface from inside the GUI. On Windows this section is replaced with a note about PCAN USB setup.
- **Interface Status** — live check button that validates whether the configured interface is currently UP.
- **Logging** — log directory path.
- **Custom Output Rules** — keyword detection rules for the ECU Monitor (custom CRITICAL/HIGH/LOW patterns added on top of the built-in ones).
- **DBC File** (optional) — load a `.dbc` file to populate CAN ID dropdowns across the Fuzzer, Len Attack, Send, UDS, and DCM tabs with named message identifiers.
- **Save Configuration** button — writes all settings to `~/.fucyfuzz_gui.json`.

---

### Recon

Two distinct functions in one tab.

**Start Listener** — launches the passive CAN listener directly. All received frames are shown in the terminal in real-time. A separate STOP button terminates it.

**Master Demo** — queues and executes a full sweep of FucyFuzz commands automatically in sequence. Covers: fuzzer (random, bruteforce, mutate), lenattack, DCM (discovery, services, subfunc, dtc, testerpresent), and UDS (discovery, services, ecu_reset, testerpresent, security_seed, dump_dids, read_mem). A progress bar shows the current step (N / total commands) and the active command string. Useful for a rapid initial assessment of an unknown ECU.

---

### Demo

Three pre-configured vehicle fuzzing demonstrations. Each targets a specific instrument cluster CAN ID and can be toggled independently. Stopping any demo sends a reset frame to restore the ECU to a known state.

| Demo | CAN ID | Target | Reset frame |
|---|---|---|---|
| Speed Gauge Fuzz | 0x244 | Instrument cluster speed display | `0x244#00` (speed → 0) |
| Indicator Fuzz | 0x188 | Turn indicator signals | `0x188#00` (indicators OFF) |
| Door Lock Fuzz | 0x19B | Door lock state messages | `0x19B#00.00.00.00` (doors → closed) |

All three can run concurrently. Each runs its fuzzer as a background subprocess and streams output to the shared terminal.

---

### UDS

Execute Unified Diagnostic Services (ISO 14229) commands over CAN + ISO-TP.

**Sub-commands:**

| Sub-command | Description |
|---|---|
| `discovery` | Sweeps request IDs across a configurable range and records every ID that responds to a UDS probe. Supports auto-blacklist to skip high-traffic IDs. |
| `services` | Probes all UDS service IDs against a known ECU (request ID + response ID) and records which services return positive or negative responses. |
| `ecu_reset` | Sends an `0x11 ECUReset` request. Configurable reset type (1 = hard, 2 = key-off-on, 3 = soft). |
| `testerpresent` | Sends periodic `0x3E TesterPresent` frames to keep an extended diagnostic session alive. |
| `security_seed` | Requests SecurityAccess seeds (SID `0x27`/`0x67`) repeatedly. Configurable: security level, number of repetitions, delay between requests. |
| `dump_dids` | Enumerates DIDs by range using `0x22 ReadDataByIdentifier`. Configurable min/max DID. |
| `read_did` | Reads a single specific DID and displays the decoded response. |
| `read_mem` | Reads a memory region using `0x23 ReadMemoryByAddress`. |

Configuration inputs: Request CAN ID, Response CAN ID, discovery range, timeout per frame, inter-frame delay.

---

### UDS Fuzz

UDS-level protocol fuzzer targeting security-critical functions over ISO-TP.

**Sub-commands:**

| Sub-command | Description |
|---|---|
| `seed_randomness_fuzzer` | Sends rapid SecurityAccess seed requests and analyses responses for randomness weaknesses. Configurable: security level (Standard 0 / Extended 1), number of seeds to collect, delay, max iterations, timeout. |
| `delay_fuzzer` | Fuzzes timing-sensitive UDS interactions by varying inter-request delays to probe for race conditions and timing vulnerabilities. |

**Live seed analysis** runs on every collected seed during `seed_randomness_fuzzer`:

- Duplicate seed detection — flags any seed seen more than once as CRITICAL
- Low-entropy detection — seeds with too many repeated bytes
- Sequential/predictable pattern detection — seeds that increment predictably
- Shannon entropy scoring — normalised entropy score with severity rating

Findings are reported in the terminal and pushed to the Dashboard's live vulnerability feed in real time.

---

### DCM

Diagnostic Communication Manager module. Sends DCM-level commands over CAN + ISO-TP.

**Sub-commands:**

| Sub-command | Description |
|---|---|
| `discovery` | Scans for DCM-responding ECUs. Supports manual blacklist and auto-blacklist (skip IDs seen more than N times). |
| `services` | Enumerates supported DCM services on a known ECU (request ID + response ID). |
| `subfunc` | Enumerates sub-functions for a given service ID across a configurable index range (start index to end index). |
| `dtc` | Reads Diagnostic Trouble Codes from the ECU. |
| `testerpresent` | Sends TesterPresent keep-alive frames. |

Configuration: Request CAN ID, Response CAN ID, service ID (for subfunc), sub-function range.

---

### Fuzzer

Raw CAN frame fuzzer with three distinct modes.

**Sub-commands:**

| Mode | Description |
|---|---|
| `random` | Sends frames with randomised payload bytes. Options: Min DLC / Max DLC (1–8), seed for reproducibility (leave blank for random), delay between frames (ms precision), optional output log file. |
| `bruteforce` | Expands a byte-pattern template using `..` wildcard tokens across all 256 values. Example: `7f..` iterates every possible second byte. Options: pattern string, inter-frame delay. |
| `mutate` | Takes one or more space-separated base patterns (hex + `..` wildcards) and applies mutations. Options: mutation rate (0.01–1.0), max frames (0 = unlimited), timeout in seconds (10–3600 s, default 300 s). |
| `replay` | Replays frames from a previously captured log file. |
| `identify` | Sends an identify probe to discover active ECUs on the bus. |

All modes run in a background thread with a stop-event. The **KILL** button terminates the fuzzer thread immediately. CAN interface is validated before any fuzzer starts.

---

### Len Attack

DLC (Data Length Code) length attack — tests ECU robustness against malformed frame lengths.

Sends a series of CAN frames to a target CAN ID with incrementing DLC values (0 through 8, or a configured range). Tests ECU behaviour against:
- Frames shorter than expected
- Zero-length frames
- Over-length frames

Uses the built-in `LenAttackEngine` — no external binary required. Non-blocking, KILL button works immediately. Per-frame results logged to CSV and session logger.

Configuration: Target CAN ID, DLC range (min/max), payload byte pattern, inter-frame delay, max iterations, timeout.

---

### Send

Manually transmit one or more CAN frames.

**Modes:**
- `message` — Type frames directly in the text area, one per line. Format: `<ID>#<data>` (e.g. `0x7a0#c0.ff.ee.00`). Multiple frames are sent in sequence.
- `file` — Load a text file containing frames in the same format.

Configurable inter-frame delay and optional looping. Output captured in the embedded terminal.

---

### Dump

Samples CAN frames from the bus at a configurable rate and optionally writes them to a file.

Options:
- Sample rate (seconds between samples, decimal precision)
- Output file path (optional — if blank, output goes to terminal only)
- Count only mode (`-c`) — counts frames without displaying data
- Filter by IDs — space-separated list of CAN IDs to include (e.g. `0x7E0 0x7E8`)

---

### Listener

Passive CAN frame capture. Listens on the configured interface and displays every received frame in the terminal without transmitting anything.

Options:
- Raw mode (`-r`) — outputs raw bytes without any decoding

---

### XCP

XCP (ASAM AE XCP — Universal Measurement and Calibration Protocol) module for ECU measurement and calibration diagnostics.

**Sub-commands:**

| Sub-command | Description |
|---|---|
| `discovery` | Scans for XCP-capable ECUs. Supports manual blacklist and auto-blacklist (threshold configurable). |
| `commands` | Enumerates supported XCP commands on a known ECU (request ID + response ID). |
| `info` | Reads ECU identification and capability information. |
| `dump` | Reads a memory region from the ECU. Options: start address (hex), length (hex), output file path (`.hex`). |

Configuration: Request ID, Response ID (decimal or hex accepted).

---

### DoIP

Diagnostics over IP (ISO 13400) — communicates with ECUs over TCP/IP rather than CAN.

**Sub-commands:**

| Sub-command | Description |
|---|---|
| `discovery` | UDP broadcast scan to detect DoIP-capable ECUs on the local network. |
| `services` | Enumerates UDS services over the DoIP TCP transport. |
| `ecu_reset` | Sends ISO 14229 ECUReset (`0x11`) over DoIP. |
| `testerpresent` | Sends TesterPresent (`0x3E`) keep-alive over DoIP. |
| `security_seed` | Captures SecurityAccess seeds over DoIP. |
| `dump_dids` | DID range enumeration over DoIP. |
| `seed_randomness_fuzzer` | Rapid seed requests over DoIP with live randomness scoring. |

Configuration: DoIP logical address (tester), DoIP target address (ECU), TCP host IP, port (default 13400), routing activation type, timeout.

FucyFuzz includes a built-in pure-Python DoIP engine (`protocol_layer/doip_layer.py`) with no third-party `doipclient` dependency. If the backend CLI binary fails, the built-in engine is used as a transparent fallback.

---

### Advanced

Three sub-tabs combined in one panel. Left side is the sub-tab selector; right side is a split terminal (top) and a decoded DID response display (bottom).

**Sub-tab 1: DoIP**  
DoIP discovery — scans for DoIP-capable ECUs on the configured interface. Results appear in the terminal.

**Sub-tab 2: XCP**  
XCP protocol operations — discovery, commands, info, and memory dump. Same options as the standalone XCP tab but accessible here alongside the response display.

**Sub-tab 3: DID Reader**  
UDS DID read with a structured decoded response display.

Preset DID selector:
- `0xF190` — VIN
- `0xF180` — Boot Software
- `0xF181` — Application Software
- `0xF186` — Active Session
- `0xF187` — Part Number
- `0xF188` — ECU Software Version
- `0xF198` — Repair Shop Code
- `0xF18C` — ECU Serial Number
- Custom DID (4 hex digits, no `0x` prefix)
- DID Range scan (min/max configurable)

Decoded responses are shown in the right-side panel with full UDS service decoding.

---

### Help

Built-in reference documentation rendered as HTML inside the tab. Covers:

- Getting Started — configuring the binary, CAN interface setup (Linux vcan, Linux PCAN USB, Windows PCAN USB), standard CAN IDs, navigating the modules
- UDS Message Reference — frame structure, all UDS services (0x10 through 0x3E), negative response NRC codes
- Attack Modules — UDS, UDS Fuzz, DCM, Fuzzer, Length Attack
- Tools — Send, Dump, Listener, XCP, DoIP, Replay
- Advanced Features — RECON tab automated suite, DEMO tab vehicle fuzzing demos

Also includes an interactive **UDS Frame Decoder** — paste any hex string and get a full human-readable UDS decode with example one-click buttons (e.g. `7F221F`, `6710DEADBEEF`, `022700`).

---

### Logs

Wireshark-style live log viewer for all CAN and UDS traffic across the session.

Two sub-tabs:

**Live Log tab:**
- Live stats banner — TX / RX / CMD / VULN / ERROR chips updating in real-time
- Main table — columns: Time | Direction | Arb ID | DLC | Data | Decoded | Severity
- Detail pane — click any row to see full metadata, hex dump, and complete UDS service decode
- Auto-scroll toggle — pin/unpin with one click
- Filter bar — direction (All/TX/RX/ERROR/CMD/INFO/VULN), severity (All/CRITICAL/HIGH/MEDIUM/LOW/INFO), module (UDS/DoIP), and free-text search (ID, data, decoded string)
- Save Log button — save the current log as ASC / BLF / PCAP / JSONL with real timestamps
- Export Report button — triggers the main export dialog

**Post-Processing Analyzer tab:**  
Load any supported CAN log format from disk (JSONL / LOG / CSV / ASC / BLF / PCAP) and inspect it offline. Same table layout and detail pane as the live tab. No active CAN connection required.

---

## Logging & Session Files

A new timestamped session directory is created on each launch of FucyFuzz. No carry-over between runs. Files grow without size limit — no rotation, no auto-deletion.

### Session directory (`logs/session_<timestamp>/`)

| File | Format | Contents |
|---|---|---|
| `session.log` | Plain text | Human-readable timestamped entry for every frame event |
| `session.csv` | CSV | Fields: `timestamp, timestamp_tx, timestamp_rx, direction, arb_id, data_hex, decoded, module, raw_line, severity` |
| `session.jsonl` | JSONL | Full structured JSON — one object per event; re-loadable by the Replay and Logs tabs |
| `session_pairs.csv` | CSV | TX/RX matched round-trips. Fields: `seq, module, timestamp_tx, tx_arb_id, tx_data_hex, decoded_tx, timestamp_rx, rx_arb_id, rx_data_hex, decoded_rx, latency_ms, anomaly, session_id`. Anomaly field is set to `NO_RESPONSE`, `UNSOLICITED_RX`, `REPEATED_SEED`, or `LATENCY_SPIKE_<N>ms` when applicable. |
| `can_frames.jsonl` | JSONL | Raw CAN frames written directly by the protocol layer (`can_layer.py`) |

### Per-module files (`logs/<module>/`)

| File | Contents |
|---|---|
| `<module>_<timestamp>.csv` | Fields: `timestamp, module, direction, can_id, data_hex, status, raw` |
| `<module>_<timestamp>.log` | Human-readable text for that module |

### Global log

`logs/fucyfuzz.log` — persistent append log across all sessions and all launches.

### Full directory layout

```
logs/
  fucyfuzz.log                      ← global append log (all sessions, all time)
  fuzzer/
    fuzzer_20260613_120000.csv
    fuzzer_20260613_120000.log
  uds/
    uds_20260613_120000.csv
    uds_20260613_120000.log
  doip/
    doip_20260613_120000.csv
  ...
  session_20260613_120000/
    session.log
    session.csv
    session.jsonl
    session_pairs.csv
    can_frames.jsonl
```

### Environment variables set at startup

```
FUCYFUZZ_SESSION_LOG    absolute path to session.log
FUCYFUZZ_SESSION_JSONL  absolute path to session.jsonl
FUCYFUZZ_SESSION_CSV    absolute path to session.csv
FUCYFUZZ_SESSION_DIR    absolute path to the current session directory
```

### Other app directories (created automatically)

```
exports/           ← PDF, ASC, MDF4, BLF, PCAP, JSONL exported reports
failure_reports/   ← auto-saved failure report PDFs
failure_cases/     ← individual failure case records
ecu_sessions/      ← ECU session archives
```

### Config file

User preferences are stored at `~/.fucyfuzz_gui.json`.

---

## Export Formats

Accessible from **File → Export Session Data**, **File → Export Failure Report**, and the **Save Log** button in the Logs tab.

| Format | Extension | Notes |
|---|---|---|
| Full PDF Report | `.pdf` | Professional layout — findings table, severity summary, frame log. Requires `reportlab`. Auto-saved to `failure_reports/` on export. |
| Failure-only PDF | `.pdf` | Same as above but filtered to anomalies and faults only. |
| Vector ASC | `.asc` | Compatible with CANalyzer, CANdb++, and most automotive tools. |
| Vector BLF | `.blf` | Binary Log File format. Requires `python-can`. |
| ASAM MDF4 | `.mf4` | Industry-standard measurement data. Requires `asammdf`. |
| PCAP | `.pcap` | Wireshark-compatible capture file. |
| JSONL | `.jsonl` | FucyFuzz native format — re-loadable by Replay and Log Viewer. |
| JSON | `.jsonl` | Session data exported via DataManager. |

---

## Project Structure

```
FucyFuzz/
├── main.py                           Entry point — app bootstrap, logging setup, CAN pre-check
│
├── modules/                          One file per GUI tab
│   ├── base_tab.py                   BaseModuleTab — shared layout, terminal, start/stop/kill
│   ├── dashboard_tab.py              Dashboard — stat cards, alert stack, vuln feed, status widget
│   ├── uds_response_tab.py           UDS Analyser — NRC tracker, stats strip, timeline sparkline
│   ├── replay_tab.py                 Replay — multi-format loader, timing engine, frame table
│   ├── config_tab.py                 Config — binary, interface, logging, custom rules, DBC
│   ├── recon_tab.py                  Recon — passive listener + master demo sweep
│   ├── demo_tab.py                   Demo — Speed/Indicator/Door fuzz with reset on stop
│   ├── uds_tab.py                    UDS — discovery/services/reset/seed/DID commands
│   ├── uds_fuzz_tab.py               UDS Fuzz — seed randomness fuzzer + delay fuzzer
│   ├── dcm_tab.py                    DCM — discovery/services/subfunc/dtc/testerpresent
│   ├── fuzzer_tab.py                 Fuzzer — random/bruteforce/mutate/replay/identify
│   ├── lenattack_tab.py              Len Attack — DLC length attack engine
│   ├── send_tab.py                   Send — manual CAN frame transmission
│   ├── dump_listener_tab.py          Dump + Listener — two separate tabs in one file
│   ├── xcp_tab.py                    XCP — discovery/commands/info/dump
│   ├── doip_tab.py                   DoIP — ISO 13400 over TCP/IP with built-in engine
│   ├── advanced_tab.py               Advanced — DoIP/XCP/DID Reader sub-tabs
│   ├── help_tab.py                   Help — HTML reference docs + interactive UDS decoder
│   ├── log_tab.py                    Logs — live log viewer + post-processing analyzer
│   └── __init__.py
│
├── ui/                               GUI primitives
│   ├── main_window.py                MainWindow — sidebar, tab stack, menu bar, status bar
│   ├── theme.py                      COLORS dict + GLOBAL_STYLESHEET (dark theme)
│   ├── widgets.py                    Reusable widgets: StatCard, GlowButton, TerminalWidget, etc.
│   ├── DBC.py                        DBC file parser and signal decoder
│   ├── dbc_analyzer.py               DBC analysis and visualisation
│   └── export_dialog.py              Export format selection dialog
│
├── protocol_layer/                   Pure-Python protocol implementations (no third-party deps)
│   ├── can_layer.py                  Raw CAN send/receive wrapper + frame logger
│   ├── doip_layer.py                 Built-in DoIP client (ISO 13400)
│   ├── uds_layer.py                  UDS request builder and response parser
│   └── __init__.py
│
├── utils/                            Backend engines and helpers
│   ├── can_interface.py              CAN interface manager — validation, status, auto-setup
│   ├── config.py                     App config load/save, APP_DIRS, DoIP defaults
│   ├── data_manager.py               DataManager — central Qt signal bus between modules
│   ├── fuzzer_engine.py              RandomFuzzer, BruteforceFuzzer, MutateFuzzer
│   ├── lenattack_engine.py           DLC length attack engine
│   ├── isotp_handler.py              ISO-TP framing and reassembly
│   ├── log_manager.py                Per-module structured logger (CSV + text, no rotation)
│   ├── session_logger.py             Session-wide JSONL + CSV + text + pairs log writer
│   ├── replay_loader.py              Multi-format CAN log loader
│   ├── export_manager.py             PDF / ASC / BLF / PCAP / MDF4 / JSONL export
│   ├── seed_analyzer.py              Dual-mode seed randomness analyser (16-bit array / 32-bit hashmap)
│   ├── realtime_seed_engine.py       Real-time seed collection and scoring
│   ├── log_fault_parser.py           Pattern-based fault detector and VulnDB
│   ├── ecu_log_watcher.py            File-system watcher for ECU log updates
│   ├── ecu_response_monitor.py       Live ECU response monitor thread
│   ├── failure_cases_dialog.py       Failure cases management dialog
│   ├── report_generators.py          PDF / text report generation helpers
│   ├── runner.py                     CommandRunner — subprocess wrapper for CLI backend
│   └── __init__.py
│
├── requirements.txt                  Python dependencies
└── setup_vcan.sh                     Shell script to create and bring up vcan0
```

---

## Interface Reference

| Interface | Type | OS | Notes |
|---|---|---|---|
| `vcan0` | Virtual CAN | Linux | Requires `modprobe vcan`. Use `setup_vcan.sh`. |
| `can0`, `can1` | Physical SocketCAN | Linux | Any SocketCAN-compatible adapter. |
| `PCAN_USBBUS1` | Physical CAN | Windows | PEAK PCAN USB. Requires `pip install python-can[pcan]`. |
| Virtual bus | Virtual | Windows | `python-can` built-in. No extra packages needed. |

Default config:
- Linux → `interface=vcan0`, `driver=socketcan`
- Windows → `interface=PCAN_USBBUS1`, `driver=pcan`
- DoIP → `host=192.168.1.1`, `port=13400`, `logical_address=0x0E00`, `target_address=0x1001`
- Default bitrate: 500000

---

## Troubleshooting

**`Could not access SocketCAN device vcan0 ([Errno 19] No such device)`**

The virtual CAN interface has not been created. Run:

```bash
sudo bash setup_vcan.sh
```

Or use the **CAN Interface Setup** section inside the **Config** tab.

---

**The fuzzer or lenattack hangs**

All modules run in background threads with stop-events. Click **KILL**. If the KILL button is unresponsive, check that `python-can` is installed and the interface is up.

---

**PDF export fails silently**

```bash
pip install reportlab
```

---

**BLF files fail to load in Replay**

```bash
pip install python-can
```

---

**MDF4 export is unavailable**

```bash
pip install asammdf
```

---

**DoIP discovery returns nothing**

- Confirm the ECU's Ethernet port is on the same subnet.
- Check that UDP port 13400 is not blocked by a firewall.
- Set the host IP directly in the DoIP tab rather than relying on broadcast.

---

**DBC dropdown does not populate after loading a file**

Check that `cantools` is installed (optional dependency listed in `requirements.txt` as a comment). Without it the DBC loader falls back to a built-in parser that covers basic message/signal definitions.

---

## Disclaimer

**FucyFuzz is intended for authorised security research and testing only.**

Using this tool against vehicles, ECUs, or CAN networks without explicit written permission from the owner is illegal in most jurisdictions. Always test in an isolated lab environment on hardware you own and are authorised to test. The authors accept no liability for misuse.
