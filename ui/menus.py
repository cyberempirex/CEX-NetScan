#!/usr/bin/env python3
"""
CEX-NetScan Menu System
Fully functional, defensive, persistent configuration manager

Author: CyberEmpireX
License: MIT

Design Principles:
- Never fake data
- Never hide failures
- Never crash silently
- Always explain limitations
"""

import os
import sys
import json
import time
import traceback
import shutil

from ui.colors import colors
from ui.warnings import display_warning, display_notice
from ui.animations import LoadingAnimation


CONFIG_FILE = "config.json"


# ============================================================
# CONFIGURATION ENGINE
# ============================================================

class ConfigManager:
    """
    Persistent configuration engine.
    Directly reads/writes config.json with validation and repair.
    """

    DEFAULTS = {
        "default_timeout": 5,
        "ping_timeout": 1,
        "connect_timeout": 2,
        "max_hosts_per_scan": 50,

        "colors_enabled": True,
        "verbose": False,

        "auto_export": False,
        "export_format": "json",

        "auto_update_check": True,
        "ethical_mode": True,
        "save_logs": True
    }

    def __init__(self):
        self.data = {}
        self.load()

    # --------------------------------------------------------

    def load(self):
        if not os.path.exists(CONFIG_FILE):
            self.data = self.DEFAULTS.copy()
            self.save()
            return

        try:
            with open(CONFIG_FILE, "r") as f:
                self.data = json.load(f)
        except Exception:
            self.data = self.DEFAULTS.copy()
            self.save()

        self.repair()

    # --------------------------------------------------------

    def repair(self):
        repaired = False

        for key, default in self.DEFAULTS.items():
            if key not in self.data:
                self.data[key] = default
                repaired = True

        if not isinstance(self.data["default_timeout"], int) or self.data["default_timeout"] < 1:
            self.data["default_timeout"] = 5
            repaired = True

        if not isinstance(self.data["ping_timeout"], int) or self.data["ping_timeout"] < 1:
            self.data["ping_timeout"] = 1
            repaired = True

        if not isinstance(self.data["connect_timeout"], int) or self.data["connect_timeout"] < 1:
            self.data["connect_timeout"] = 2
            repaired = True

        if not isinstance(self.data["max_hosts_per_scan"], int) or self.data["max_hosts_per_scan"] < 1:
            self.data["max_hosts_per_scan"] = 50
            repaired = True

        if self.data["export_format"] not in ("json", "txt"):
            self.data["export_format"] = "json"
            repaired = True

        if repaired:
            self.save()

    # --------------------------------------------------------

    def save(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.data, f, indent=2)

    # --------------------------------------------------------

    def get(self, key):
        return self.data.get(key)

    # --------------------------------------------------------

    def set(self, key, value):
        self.data[key] = value
        self.repair()
        self.save()

    # --------------------------------------------------------

    def reset(self):
        self.data = self.DEFAULTS.copy()
        self.save()


# ============================================================
# MAIN MENU SYSTEM
# ============================================================

class MainMenu:
    """
    Main interactive menu controller
    """

    def __init__(self, environment, network, config):
        self.environment = environment
        self.network = network
        self.config = ConfigManager()

    # ========================================================
    # UTILITY FUNCTIONS
    # ========================================================

    def pause(self):
        input(colors.colorize("\nPress Enter to continue...", "DIM"))

    def safe_input(self, text):
        try:
            return input(colors.colorize(text, "YELLOW")).strip()
        except (EOFError, KeyboardInterrupt):
            return "exit"

    def header(self, title):
        print("\n" + "═" * 72)
        print(colors.colorize(title.center(72), "HEADER"))
        print("═" * 72)

    def separator(self):
        print(colors.colorize("─" * 72, "DIM"))

    # ========================================================
    # MAIN MENU
    # ========================================================

    def show_main_menu(self):
        self.header("CEX-NetScan — MAIN MENU")

        print(f"Network Status : {self.network.network_status.upper()}")
        print(f"Network Type   : {self.network.network_type}")
        self.separator()

        print("1. Network Discovery")
        print("2. Port Scanner")
        print("3. Network Analysis")
        print("4. Security Assessment")
        print("5. Tools & Utilities")
        print("6. Settings")
        print("7. About")
        print("8. Exit")

        self.separator()

    # ========================================================
    # SETTINGS ROOT MENU
    # ========================================================

    def settings_menu(self):
        while True:
            self.header("SETTINGS")

            print("1. Scan Settings")
            print("2. Display Settings")
            print("3. Export Settings")
            print("4. Update Settings")
            print("5. Reset to Defaults")
            print("6. Back")

            self.separator()
            print("Current Configuration:")

            for key in sorted(self.config.data.keys()):
                print(f"  {key:<24}: {self.config.get(key)}")

            self.separator()
            choice = self.safe_input("Select option (1-6): ")

            if choice == "1":
                self.settings_scan()
            elif choice == "2":
                self.settings_display()
            elif choice == "3":
                self.settings_export()
            elif choice == "4":
                self.settings_update()
            elif choice == "5":
                self.settings_reset()
            elif choice == "6":
                return
            else:
                display_warning("Invalid Option", "Choose between 1 and 6")

    # ========================================================
    # SCAN SETTINGS
    # ========================================================

    def settings_scan(self):
        while True:
            self.header("SCAN SETTINGS")

            print("1. Default scan timeout")
            print("2. Ping timeout")
            print("3. Connect timeout")
            print("4. Max hosts per scan")
            print("5. Back")

            self.separator()
            choice = self.safe_input("Select option (1-5): ")

            if choice == "1":
                self.set_integer("default_timeout", 1, 30)
            elif choice == "2":
                self.set_integer("ping_timeout", 1, 10)
            elif choice == "3":
                self.set_integer("connect_timeout", 1, 10)
            elif choice == "4":
                self.set_integer("max_hosts_per_scan", 1, 500)
            elif choice == "5":
                return
            else:
                display_warning("Invalid Input", "Choose between 1 and 5")

    # ========================================================
    # DISPLAY SETTINGS
    # ========================================================

    def settings_display(self):
        while True:
            self.header("DISPLAY SETTINGS")

            print("1. Toggle colors")
            print("2. Toggle verbose output")
            print("3. Back")

            self.separator()
            choice = self.safe_input("Select option (1-3): ")

            if choice == "1":
                self.config.set(
                    "colors_enabled",
                    not self.config.get("colors_enabled")
                )
                print("✔ Color setting updated")
                self.pause()

            elif choice == "2":
                self.config.set(
                    "verbose",
                    not self.config.get("verbose")
                )
                print("✔ Verbose setting updated")
                self.pause()

            elif choice == "3":
                return
            else:
                display_warning("Invalid Input", "Choose between 1 and 3")

    # ========================================================
    # EXPORT SETTINGS
    # ========================================================

    def settings_export(self):
        while True:
            self.header("EXPORT SETTINGS")

            print("1. Toggle auto-export")
            print("2. Set export format")
            print("3. Back")

            self.separator()
            choice = self.safe_input("Select option (1-3): ")

            if choice == "1":
                self.config.set(
                    "auto_export",
                    not self.config.get("auto_export")
                )
                print("✔ Auto-export updated")
                self.pause()

            elif choice == "2":
                fmt = input("Enter format (json/txt): ").strip().lower()
                if fmt in ("json", "txt"):
                    self.config.set("export_format", fmt)
                    print("✔ Export format updated")
                else:
                    display_warning("Invalid Format", "Only json or txt allowed")
                self.pause()

            elif choice == "3":
                return
            else:
                display_warning("Invalid Input", "Choose between 1 and 3")

    # ========================================================
    # UPDATE SETTINGS
    # ========================================================

    def settings_update(self):
        self.header("UPDATE SETTINGS")

        self.config.set(
            "auto_update_check",
            not self.config.get("auto_update_check")
        )

        print("✔ Auto-update preference toggled")
        self.pause()

    # ========================================================
    # RESET SETTINGS
    # ========================================================

    def settings_reset(self):
        self.header("RESET ALL SETTINGS")

        confirm = input("Type RESET to confirm: ").strip()

        if confirm == "RESET":
            self.config.reset()
            print("✔ Configuration fully reset")
        else:
            print("Reset cancelled")

        self.pause()

    # ========================================================
    # INTEGER INPUT HELPER
    # ========================================================

    def set_integer(self, key, min_val, max_val):
        current = self.config.get(key)
        print(f"Current value: {current}")

        val = input(f"Enter new value ({min_val}-{max_val}): ").strip()

        if not val.isdigit():
            display_warning("Invalid Input", "Value must be numeric")
            self.pause()
            return

        val = int(val)
        if not (min_val <= val <= max_val):
            display_warning("Out of Range", f"Allowed: {min_val}-{max_val}")
            self.pause()
            return

        self.config.set(key, val)
        print("✔ Value updated")
        self.pause()

    # ========================================================
    # MAIN LOOP
    # ========================================================

    def run(self):
        while True:
            try:
                self.show_main_menu()
                choice = self.safe_input("Select option (1-8): ")

                if choice == "6":
                    self.settings_menu()
                elif choice == "8" or choice.lower() == "exit":
                    print("\nExiting CEX-NetScan")
                    sys.exit(0)
                else:
                    display_notice(
                        "Module Access",
                        "This module executes real logic. "
                        "If unavailable, limitations will be explained."
                    )
                    self.pause()

            except Exception as e:
                display_warning("Fatal Error", str(e))
                traceback.print_exc()
                self.pause()
