#!/usr/bin/env python3
"""
CEX-NetScan Professional
Main Entry Point

Author  : CyberEmpireX
Purpose : Real network scanning & analysis tool
License : MIT
"""

import os
import sys
import json
import traceback
from datetime import datetime

# ==============================
# INTERNAL IMPORTS
# ==============================

from core.environment import EnvironmentDetector
from core.network_detect import NetworkDetector

from ui.colors import colors
from ui.banner import display_main_banner
from ui.animations import LoadingAnimation
from ui.menus import MainMenu

from utils.logger import setup_logger
from utils.updater import UpdateChecker


# ==============================
# MAIN APPLICATION CLASS
# ==============================

class CEXNetScan:
    """
    Main application controller
    """

    def __init__(self):
        self.environment = None
        self.network = None
        self.menu = None
        self.logger = None
        self.config = self._load_config()

    # --------------------------
    # CONFIG
    # --------------------------

    def _load_config(self):
        config_path = os.path.join(
            os.path.dirname(__file__), "config.json"
        )

        default_config = {
            "auto_update_check": True,
            "verbose": False
        }

        if not os.path.exists(config_path):
            return default_config

        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                default_config.update(data)
        except Exception:
            pass

        return default_config

    # --------------------------
    # INITIALIZATION
    # --------------------------

    def initialize(self):
        """
        Initialize environment, network, UI
        """
        try:
            # Logger (file only by default)
            self.logger = setup_logger(
                verbose=self.config.get("verbose", False)
            )
            self.logger.info("CEX-NetScan starting")

            # Python version check
            if sys.version_info < (3, 8):
                print("Python 3.8+ required")
                sys.exit(1)

            # Banner
            display_main_banner()

            # Detection phase
            with LoadingAnimation("Initializing security scanner"):
                self.environment = EnvironmentDetector()
                env_info = self.environment.detect_all()
                self.logger.info(f"Environment: {env_info}")

                self.network = NetworkDetector()
                net_info = self.network.detect_all()
                self.logger.info(f"Network: {net_info}")

                if self.config.get("auto_update_check", True):
                    self._check_updates()

            # Show startup summary
            self._show_startup_info()

            # Menu system
            self.menu = MainMenu(
                environment=self.environment,
                network=self.network,
                config=self.config
            )

            return True

        except Exception as e:
            self._fatal_error(e)
            return False

    # --------------------------
    # UPDATE CHECK
    # --------------------------

    def _check_updates(self):
        try:
            updater = UpdateChecker()
            if updater.check_available():
                print(
                    colors.colorize(
                        "\n⚠ Update available. Use menu to update.\n",
                        "WARNING"
                    )
                )
        except Exception:
            pass

    # --------------------------
    # STARTUP INFO
    # --------------------------

    def _show_startup_info(self):
        print("\n" + "=" * 60)

        print(self.environment.format_for_display())
        print("-" * 60)
        print(self.network.format_for_display())

        print("=" * 60)

        self._show_capabilities()

    def _show_capabilities(self):
        caps = self.environment.get_scan_capabilities()

        # Adjust for network conditions
        if self.network.network_status == "offline":
            for k in caps:
                caps[k] = False
            caps["port_scan"] = True

        elif self.network.network_type == "mobile_cgnat":
            caps["arp_scan"] = False
            caps["lan_discovery"] = False

        available = [k for k, v in caps.items() if v]
        disabled = [k for k, v in caps.items() if not v]

        if available:
            print(colors.colorize("\n✅ AVAILABLE SCANS", "SUCCESS"))
            for item in available:
                print("  •", item.replace("_", " ").title())

        if disabled:
            print(colors.colorize("\n⚠ LIMITED / DISABLED", "WARNING"))
            for item in disabled:
                print("  •", item.replace("_", " ").title())

        print()

    # --------------------------
    # ERROR HANDLING
    # --------------------------

    def _fatal_error(self, error):
        print(colors.colorize("\nCRITICAL ERROR", "ERROR"))
        print(str(error))
        print()

        with open("cex_netscan_crash.log", "w") as f:
            f.write(
                f"{datetime.now()}\n{traceback.format_exc()}"
            )

        sys.exit(1)

    # --------------------------
    # RUN LOOP
    # --------------------------

    def run(self):
        if not self.initialize():
            return

        try:
            self.menu.run()
        except KeyboardInterrupt:
            print(colors.colorize("\nInterrupted by user", "WARNING"))
        finally:
            print(colors.colorize("\nCEX-NetScan terminated", "INFO"))
            print("Stay secure.\n")


# ==============================
# ENTRY POINT
# ==============================

def main():
    app = CEXNetScan()
    app.run()


if __name__ == "__main__":
    main()
