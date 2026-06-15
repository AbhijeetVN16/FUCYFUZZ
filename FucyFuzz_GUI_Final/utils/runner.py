"""
FucyFuzz Command Runner — v6 (Race-condition-free)

Key fix vs v5: Each _execute() call gets its OWN stop_event.
No shared state between old and new runs — impossible to cross-contaminate.
"""

import re
import signal
import subprocess
import os
import sys
import platform
import logging
import threading
import time

from PyQt5.QtCore import QObject, pyqtSignal

log = logging.getLogger(__name__)

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _clean_line(line: str) -> str:
    line = _ANSI_RE.sub('', line)
    line = line.replace('\r', '').replace('\x00', '')
    return line.strip()

_IS_WINDOWS = platform.system().lower() == "windows"
_IS_LINUX   = platform.system().lower() == "linux"

_SUPPRESS = (
    "uptime library not available",
    "timestamps are relative to boot time",
)

_INFO_PATTERNS = (
    'seed', 'security', 'captured', 'session', 'did', 'service',
    'discovery', 'reset', 'tester', 'routing', 'doip', 'ecu',
    'found', 'response', 'iteration', 'collecting', 'entropy',
    '0x', '[+]', '[*]', '[i]', '---', '===', 'loading', 'module',
    'scan', 'dump', 'completed', 'started', 'running', 'sent',
    'received', 'timeout', 'attempt', 'result', 'positive',
    'negative', 'nrc', 'sid', 'subfunction',
)


def _is_doip_command(args: list) -> bool:
    return any(str(a).lower() == 'doip' for a in args)


def _resolve_binary(binary_path: str) -> str:
    if os.path.isfile(binary_path):
        return binary_path
    if _IS_WINDOWS:
        win_path = binary_path if binary_path.endswith('.exe') else binary_path + '.exe'
        if os.path.isfile(win_path):
            return win_path
        here = os.path.dirname(os.path.abspath(sys.argv[0]))
        for candidate in (win_path, os.path.join(here, os.path.basename(win_path))):
            if os.path.isfile(candidate):
                return candidate
    else:
        for candidate in (binary_path, './fucyfuzz', '/usr/local/bin/fucyfuzz'):
            if os.path.isfile(candidate):
                return candidate
    return binary_path


def _check_can_interface(iface: str) -> tuple:
    try:
        from utils.can_interface import check_interface
        status = check_interface(iface)
        if status.ok:
            return True, "ok"
        return False, status.user_message()
    except Exception:
        sys_path = f"/sys/class/net/{iface}"
        if not os.path.exists(sys_path):
            return False, (
                f"CAN interface '{iface}' not found (Errno 19: No such device).\n"
                f"  • Virtual: sudo modprobe vcan && "
                f"sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0\n"
                f"  • Physical: sudo ip link set {iface} type can bitrate 500000 "
                f"&& sudo ip link set up {iface}\n"
                f"  • Then set the correct interface in Config tab."
            )
        return True, "ok"


# ─────────────────────────────────────────────────────────────────────────────
#  Chunk-based pipe reader
# ─────────────────────────────────────────────────────────────────────────────

def _drain_pipe(pipe, stop_event, on_line, on_progress, label=""):
    """
    Read from a binary pipe in 4KB chunks. Non-blocking on Linux via select().
    Each call to on_line/on_progress is guarded by stop_event check.
    """
    buf = b''
    fd = pipe.fileno()
    last_progress_time = 0.0

    if _IS_LINUX:
        import select as _sel

    try:
        while not stop_event.is_set():
            if _IS_LINUX:
                try:
                    ready, _, _ = _sel.select([fd], [], [], 0.1)
                except (ValueError, OSError):
                    break
                if not ready:
                    continue

            try:
                chunk = os.read(fd, 4096)
            except (OSError, ValueError):
                break
            if not chunk:
                break

            buf += chunk

            while buf:
                idx_n = buf.find(b'\n')
                idx_r = buf.find(b'\r')

                if idx_n == -1 and idx_r == -1:
                    break

                if idx_n == -1:
                    idx = idx_r
                elif idx_r == -1:
                    idx = idx_n
                else:
                    idx = min(idx_n, idx_r)

                terminator = buf[idx:idx+1]
                raw = buf[:idx]
                buf = buf[idx+1:]

                if terminator == b'\r' and buf.startswith(b'\n'):
                    buf = buf[1:]
                    terminator = b'\n'

                if stop_event.is_set():
                    return

                line_str = raw.decode('utf-8', errors='replace')
                line_str = _clean_line(line_str)

                if terminator == b'\r' and line_str:
                    now = time.time()
                    if now - last_progress_time >= 0.1:
                        last_progress_time = now
                        try:
                            on_progress(line_str)
                        except Exception:
                            pass
                else:
                    try:
                        on_line(line_str)
                    except Exception:
                        pass

        # Flush remaining
        if buf:
            line_str = buf.decode('utf-8', errors='replace')
            line_str = _clean_line(line_str)
            if line_str and not stop_event.is_set():
                try:
                    on_line(line_str)
                except Exception:
                    pass
    except Exception as exc:
        log.debug("_drain_pipe(%s) exception: %s", label, exc)


# Backward-compatible legacy reader
def _read_stream_by_char(pipe, is_running_cb):
    buf = bytearray()
    while is_running_cb():
        try:
            char = pipe.read(1)
            if not char:
                if buf:
                    yield buf, False
                break
            buf.extend(char)
            if char == b'\r' or char == b'\n':
                is_progress = (char == b'\r')
                yield buf, is_progress
                buf.clear()
        except (OSError, ValueError, AttributeError):
            break


# ─────────────────────────────────────────────────────────────────────────────
#  CommandRunner
# ─────────────────────────────────────────────────────────────────────────────

class CommandRunner(QObject):
    """
    Race-condition-free subprocess runner.

    CRITICAL FIX: Each _execute() call creates its OWN threading.Event.
    The old run's stop_event CANNOT affect the new run's pipe readers.
    A generation counter prevents the old run's finally block from
    clobbering the new run's state.
    """

    output_line   = pyqtSignal(str)
    error_line    = pyqtSignal(str)
    started       = pyqtSignal(str)
    finished      = pyqtSignal(int)
    progress_line = pyqtSignal(str)

    @property
    def cur_module(self) -> str:
        return getattr(self, '_cur_module', '')

    def __init__(self, binary_path: str, parent=None):
        super().__init__(parent)
        self.binary_path = binary_path
        self._process    = None
        self._running    = False
        self._lock       = threading.Lock()
        self._cur_module = ""
        self._generation = 0          # increments on each run()
        self._current_stop = None     # stop event for current run

    # ── Public API (GUI thread — MUST NOT BLOCK) ─────────────────────────

    def build_command(self, args: list) -> list:
        resolved = _resolve_binary(self.binary_path)
        return [resolved] + [str(a) for a in args]

    def run(self, args: list, interface: str = None, module: str = ""):
        with self._lock:
            if self._running:
                self.error_line.emit("A command is already running. Click KILL first.")
                return
            self._running = True
            self._generation += 1
            gen = self._generation

        self._cur_module = module or (args[0] if args else "")
        cmd = self.build_command(args)
        if interface:
            cmd = [c.replace('IFACE', interface) for c in cmd]

        # Each run gets its OWN stop event — no sharing with old runs
        stop = threading.Event()
        self._current_stop = stop

        def _launch():
            # CAN interface preflight (skip for DoIP)
            if not _is_doip_command(args):
                iface_to_check = interface
                if not iface_to_check:
                    try:
                        idx = [str(a) for a in args].index('-i')
                        iface_to_check = str(args[idx + 1])
                    except (ValueError, IndexError):
                        iface_to_check = None
                if iface_to_check:
                    ok, msg = _check_can_interface(iface_to_check)
                    if not ok:
                        self.error_line.emit("─" * 60)
                        self.error_line.emit("  CAN INTERFACE ERROR")
                        self.error_line.emit("─" * 60)
                        for line in msg.strip().splitlines():
                            self.error_line.emit(f"  {line}")
                        self.error_line.emit("─" * 60)
                        with self._lock:
                            if self._generation == gen:
                                self._running = False
                        self.finished.emit(-1)
                        return

            self._execute(cmd, stop, gen)

        threading.Thread(target=_launch, daemon=True).start()

    def kill(self):
        with self._lock:
            if not self._running:
                return
            self._running = False
            proc = self._process

        # Signal THIS run's drain threads to stop
        stop = self._current_stop
        if stop:
            stop.set()

        if not proc:
            return

        def _do_kill():
            try:
                if _IS_WINDOWS:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                            capture_output=True, timeout=3,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    except Exception:
                        try: proc.terminate()
                        except Exception: pass
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except Exception:
                        try: proc.terminate()
                        except Exception: pass
            except Exception as exc:
                log.debug("kill step1: %s", exc)

            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    if _IS_LINUX:
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=1)
                except Exception:
                    pass

            for pipe in (proc.stdout, proc.stderr):
                try:
                    if pipe and not pipe.closed:
                        pipe.close()
                except Exception:
                    pass

        threading.Thread(target=_do_kill, daemon=True).start()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    # ── Execution (worker thread) ────────────────────────────────────────

    def _execute(self, cmd, stop_event, generation):
        """
        Run the subprocess. Uses its OWN stop_event (not shared).
        Only modifies self._running if generation matches (no clobbering).
        """
        cmd_str = " ".join(str(c) for c in cmd)
        self.started.emit(cmd_str)

        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        env['CC_JSON_LOGS'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'

        rc = -99
        stdout_thread = None
        stderr_thread = None

        try:
            kwargs = {}
            if _IS_WINDOWS:
                kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            else:
                kwargs['preexec_fn'] = os.setsid

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=env,
                **kwargs,
            )
            self._process = proc

            def _stdout_line(line):
                if not line or stop_event.is_set():
                    return
                if any(s in line for s in _SUPPRESS):
                    return
                self.output_line.emit(line)
                self._session_log_output(line)

            def _stdout_progress(line):
                if stop_event.is_set():
                    return
                self.progress_line.emit(line)

            def _stderr_line(line):
                if not line or stop_event.is_set():
                    return
                if any(s in line for s in _SUPPRESS):
                    return
                line_lower = line.lower()
                if any(p in line_lower for p in _INFO_PATTERNS):
                    self.output_line.emit(line)
                    self._session_log_output(line)
                else:
                    self.error_line.emit(line)
                    self._session_log_error(line)

            def _stderr_progress(line):
                if stop_event.is_set():
                    return
                line_lower = line.lower()
                if any(p in line_lower for p in _INFO_PATTERNS):
                    self.progress_line.emit(line)

            stdout_thread = threading.Thread(
                target=_drain_pipe,
                args=(proc.stdout, stop_event,
                      _stdout_line, _stdout_progress, "stdout"),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=_drain_pipe,
                args=(proc.stderr, stop_event,
                      _stderr_line, _stderr_progress, "stderr"),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()

            # Poll for process completion — check stop_event each iteration
            while not stop_event.is_set():
                try:
                    rc_val = proc.wait(timeout=0.5)
                    rc = rc_val
                    break
                except subprocess.TimeoutExpired:
                    continue

            # Signal drain threads to stop and wait for them
            stop_event.set()
            if stdout_thread:
                stdout_thread.join(timeout=3.0)
            if stderr_thread:
                stderr_thread.join(timeout=3.0)

            if rc == -99:
                rc = proc.returncode if proc.returncode is not None else -1

        except FileNotFoundError:
            self.error_line.emit(
                f"Binary not found: {cmd[0]}\n"
                f"  Set the correct path in Config → FucyFuzz Binary."
            )
            rc = -2
        except PermissionError:
            self.error_line.emit(
                f"Permission denied: {cmd[0]}\n"
                f"  Linux: run  chmod +x {cmd[0]}  first."
            )
            rc = -3
        except Exception as exc:
            self.error_line.emit(f"Runner error: {exc}")
            rc = -99
        finally:
            # CRITICAL: only reset state if WE are still the current run.
            # If a new run() already started, don't clobber its state.
            with self._lock:
                if self._generation == generation:
                    self._running = False
                    self._process = None
            self.finished.emit(rc)

    # ── Session logger ───────────────────────────────────────────────────

    def _session_log_output(self, line: str):
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.log_output_line(line, module=self._cur_module)
        except Exception:
            pass

    def _session_log_error(self, line: str):
        try:
            from utils.session_logger import get_session_logger
            sl = get_session_logger()
            if sl:
                sl.log_error_line(line, module=self._cur_module)
        except Exception:
            pass
