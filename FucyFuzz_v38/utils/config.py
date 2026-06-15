"""
FucyFuzz Configuration Manager
Persists user preferences (binary path, interface, driver, DoIP, etc.)

Cross-platform defaults:
  Windows → interface=PCAN_USBBUS1, driver=pcan
  Linux   → interface=vcan0,        driver=socketcan

DoIP defaults (ISO 13400):
  host=192.168.1.1, port=13400, logical_address=0x0E00, target_address=0x1001
"""

import json
import os
import platform

_IS_WINDOWS = platform.system().lower() == "windows"

DEFAULT_CONFIG = {
    'binary_path':   'fucyfuzz.exe' if _IS_WINDOWS else './fucyfuzz',
    # CAN defaults
    'interface':     'PCAN_USBBUS1'  if _IS_WINDOWS else 'vcan0',
    'driver':        'virtual'       if _IS_WINDOWS else 'socketcan',
    'virtual_channel': 0,
    'bitrate':       500000,
    'log_dir':       './logs',
    'theme':         'dark',
    'auto_scroll':   True,
    'max_log_lines': 0,
    'req_id':        '0x7E0',
    'resp_id':       '0x7E8',
    # DoIP / Ethernet defaults (ISO 13400)
    'doip_host':           '192.168.1.1',
    'doip_port':           13400,
    'doip_logical_addr':   '0x0E00',   # tester logical address
    'doip_target_addr':    '0x1001',   # ECU logical address (AURIX TC397 default)
    'doip_activation_type': '0x00',   # routing activation type
    'doip_timeout':        5.0,        # TCP connect/response timeout (seconds)
}

CONFIG_FILE = os.path.expanduser('~/.fucyfuzz_gui.json')

# ── App-level directory constants ─────────────────────────────────────────────
_APP_ROOT = os.path.dirname(os.path.abspath(
    os.environ.get('FUCYFUZZ_ROOT', __file__)
))

APP_DIRS = {
    'failure_reports': os.path.join(_APP_ROOT, 'failure_reports'),
    'failure_cases':   os.path.join(_APP_ROOT, 'failure_cases'),
    'exports':         os.path.join(_APP_ROOT, 'exports'),
    'ecu_sessions':    os.path.join(_APP_ROOT, 'ecu_sessions'),
    'logs':            os.path.join(_APP_ROOT, 'logs'),
}


def ensure_app_dirs():
    for path in APP_DIRS.values():
        os.makedirs(path, exist_ok=True)
    return APP_DIRS


def _auto_driver_for_interface(iface: str) -> str:
    """
    Infer the correct python-can driver from an interface/channel string.
    Never returns None.
    """
    if not iface:
        return 'virtual' if _IS_WINDOWS else 'socketcan'
    ch = iface.strip().upper()
    if ch.startswith('PCAN') or 'PCAN' in ch:
        return 'pcan'
    if ch in ('VIRTUAL', ''):
        return 'virtual'
    if ch.startswith('VECTOR'):
        return 'vector'
    if ch.startswith('KVASER'):
        return 'kvaser'
    # Linux
    if ch.startswith('VCAN') or ch.startswith('CAN'):
        return 'socketcan'
    # Default by OS
    return 'pcan' if _IS_WINDOWS else 'socketcan'


class ConfigManager:
    def __init__(self):
        self._cfg = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    saved = json.load(f)
                    self._cfg.update(saved)
        except Exception:
            pass
        self._ensure_driver()

    def _ensure_driver(self):
        """
        If driver is missing, empty, or 'None', auto-derive it from interface.
        Fixes configs saved by older versions that stored driver=None.
        """
        driver = self._cfg.get('driver', '')
        if not driver or str(driver).lower() in ('none', 'null', ''):
            iface = self._cfg.get('interface', '')
            self._cfg['driver'] = _auto_driver_for_interface(iface)

    def save(self):
        self._ensure_driver()
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self._cfg, f, indent=2)
        except Exception:
            pass

    def get(self, key, default=None):
        return self._cfg.get(key, default)

    def set(self, key, value):
        self._cfg[key] = value
        if key == 'interface':
            self._ensure_driver()
        self.save()

    def update(self, d: dict):
        self._cfg.update(d)
        self._ensure_driver()
        self.save()

    def all(self) -> dict:
        return dict(self._cfg)

    def get_can_params(self) -> dict:
        """Return {'channel': ..., 'driver': ..., 'bitrate': ...} ready for python-can."""
        self._ensure_driver()
        return {
            'channel': self._cfg.get('interface', 'PCAN_USBBUS1' if _IS_WINDOWS else 'vcan0'),
            'driver':  self._cfg.get('driver',    'pcan'         if _IS_WINDOWS else 'socketcan'),
            'bitrate': self._cfg.get('bitrate',   500000),
        }

    def get_doip_params(self) -> dict:
        """Return DoIP connection parameters dict."""
        return {
            'host':            self._cfg.get('doip_host',           '192.168.1.1'),
            'port':            int(self._cfg.get('doip_port',        13400)),
            'logical_address': self._cfg.get('doip_logical_addr',   '0x0E00'),
            'target_address':  self._cfg.get('doip_target_addr',    '0x1001'),
            'activation_type': self._cfg.get('doip_activation_type','0x00'),
            'timeout':         float(self._cfg.get('doip_timeout',   5.0)),
        }


# Singleton
_config = None

def get_config() -> ConfigManager:
    global _config
    if _config is None:
        _config = ConfigManager()
    return _config
