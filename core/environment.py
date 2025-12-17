import os
import sys

class EnvironmentDetector:
    def __init__(self):
        self.info = {}

    def detect_all(self):
        self.info = {
            "os": self._detect_os(),
            "termux": self._is_termux(),
            "root": self._is_root()
        }
        return self.info

    def _detect_os(self):
        return sys.platform

    def _is_termux(self):
        return "com.termux" in os.environ.get("PREFIX", "")

    def _is_root(self):
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def get_scan_capabilities(self):
        return {
            "ping_scan": True,
            "port_scan": True,
            "arp_scan": self._is_root(),
            "lan_discovery": self._is_root(),
            "route_inspection": self._is_root(),
            "packet_capture": self._is_root()
        }

    def format_for_display(self):
        return (
            "Environment Information\n"
            "------------------------------\n"
            f"OS           : {self.info.get('os')}\n"
            f"Termux       : {'Yes' if self.info.get('termux') else 'No'}\n"
            f"Root Access  : {'Yes' if self.info.get('root') else 'No'}"
        )
