#!/usr/bin/env python3
"""
CEX-NetScan Menu System
Author: CyberEmpireX
Purpose: Interactive, honest, non-fake terminal UI
"""

import sys
import time
import traceback

from utils.config_manager import ConfigManager
from .colors import colors
from .animations import LoadingAnimation
from .warnings import display_warning, display_notice, display_info


class MainMenu:
    """
    Main menu controller for CEX-NetScan
    Handles navigation, validation, and user flow
    """

    def __init__(self, environment, network, config):
        self.environment = environment
        self.network = network
        self.config = config
        self.config_manager = ConfigManager()
        self.scan_results = {}
        self.running = True

    # ==========================================================
    # BASIC UTILITIES
    # ==========================================================

    def pause(self, msg="Press Enter to continue..."):
        try:
            input(colors.colorize(f"\n{msg}", "DIM"))
        except KeyboardInterrupt:
            pass

    def get_choice(self, prompt):
        try:
            return input(colors.colorize(f"\n{prompt}", "YELLOW")).strip()
        except (EOFError, KeyboardInterrupt):
            return "exit"

    def valid_range(self, choice, min_v, max_v):
        if not choice.isdigit():
            return False
        return min_v <= int(choice) <= max_v

    # ==========================================================
    # MAIN MENU
    # ==========================================================

    def display_main_menu(self):
        from ui.banner import display_section_header

        display_section_header("MAIN MENU")

        status = self.network.network_status.upper()
        status_color = {
            "ONLINE": "SUCCESS",
            "OFFLINE": "ERROR",
            "LIMITED": "WARNING"
        }.get(status, "WARNING")

        print(
            f"Network Status: "
            f"{colors.colorize(f'[{status}]', status_color)} "
            f"({self.network.network_type.replace('_', ' ').title()})"
        )
        print()

        menu_items = [
            ("1", "Network Discovery", "Scan local network for devices"),
            ("2", "Port Scanner", "Scan ports on a target"),
            ("3", "Network Analysis", "Detailed network diagnostics"),
            ("4", "Security Assessment", "Audit surface checks"),
            ("5", "Tools & Utilities", "Extra helper tools"),
            ("6", "Settings", "Configure scanner behavior"),
            ("7", "About", "Tool information"),
            ("8", "Exit", "Quit CEX-NetScan"),
        ]

        caps = self.environment.get_scan_capabilities()

        for key, title, desc in menu_items:
            disabled = False
            reason = ""

            if title == "Network Discovery":
                if self.network.network_type == "mobile_cgnat":
                    disabled = True
                    reason = " (CGNAT blocks LAN discovery)"
                elif not (caps.get("arp_scan") or caps.get("ping_scan")):
                    disabled = True
                    reason = " (insufficient permissions)"

            if title == "Port Scanner" and self.network.network_status == "offline":
                disabled = True
                reason = " (offline mode)"

            if disabled:
                print(
                    f"{colors.colorize(key, 'DISABLED')}. "
                    f"{colors.colorize(title, 'DISABLED')}"
                    f"{colors.colorize(reason, 'DIM')}"
                )
            else:
                print(f"{colors.colorize(key, 'MENU')}. {title}")
                print(f"   {colors.colorize(desc, 'DIM')}")

        print(colors.colorize("─" * 60, "DIM"))

    # ==========================================================
    # NETWORK DISCOVERY
    # ==========================================================

    def display_network_discovery_menu(self):
        from ui.banner import display_section_header

        display_section_header("NETWORK DISCOVERY")

        print("Discover devices on your local network\n")

        options = [
            ("1", "ARP Scan", "Layer-2 device discovery"),
            ("2", "Ping Sweep", "ICMP-based detection"),
            ("3", "Back", "Return to main menu"),
        ]

        for k, t, d in options:
            print(f"{colors.colorize(k, 'MENU')}. {t}")
            print(f"   {colors.colorize(d, 'DIM')}")

        print()

        print(colors.colorize("Current Network:", "INFO"))
        print(f"  Type    : {self.network.network_type}")
        print(f"  Gateway : {self.network.gateway_ip or 'Not detected'}")

        if self.network.network_type == "mobile_cgnat":
            print(colors.colorize("  CGNAT detected — LAN scan unavailable", "WARNING"))

    def run_network_discovery(self):
        from scans.lan_discovery import LANDiscoverer
        from scans.ping_scan import PingScanner

        if self.network.network_type == "mobile_cgnat":
            display_warning(
                "Network Discovery Unavailable",
                "Not available in current version.\n"
                "Reason:\n"
                "- Mobile CGNAT isolation\n"
                "- No Layer-2 visibility\n"
                "- Planned improvements in v3.x"
            )
            self.pause()
            return

        while True:
            self.display_network_discovery_menu()
            choice = self.get_choice("Select option (1-3): ")

            if choice in ("3", "back"):
                return

            if not self.valid_range(choice, 1, 3):
                display_warning("Invalid input", "Choose between 1 and 3")
                continue

            try:
                if choice == "1":
                    with LoadingAnimation("Running ARP scan..."):
                        scanner = LANDiscoverer()
                        scanner.discover_local_network(methods=["arp"])
                    print(scanner.display_discovery_results())

                elif choice == "2":
                    with LoadingAnimation("Running ping sweep..."):
                        scanner = PingScanner()
                        result = scanner.scan_local_subnet()
                        print(scanner.format_results(result))

                self.pause()

            except Exception as e:
                display_warning("Discovery failed", str(e))
                traceback.print_exc()
                self.pause()

    # ==========================================================
    # PORT SCANNER
    # ==========================================================

    def run_port_scanner(self):
        from scans.port_scan import PortScanner
        import socket

        target = input(colors.colorize("\nEnter target IP/host: ", "CYAN")).strip()
        if not target:
            display_warning("Cancelled", "No target provided")
            return

        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            display_warning("Invalid target", "Host resolution failed")
            return

        print(colors.colorize("\nPort Range Options:", "INFO"))
        print("1. Common (1-1000)")
        print("2. Web (80,443,8080)")
        print("3. Full (1-65535)")
        print("4. Custom")

        choice = self.get_choice("Select (1-4): ")

        port_spec = "1-1000"

        if choice == "2":
            port_spec = "80,443,8080"
        elif choice == "3":
            display_warning("Warning", "Full scan is slow and noisy")
            if self.get_choice("Type YES to confirm: ").lower() != "yes":
                return
            port_spec = "1-65535"
        elif choice == "4":
            port_spec = input("Enter port range: ").strip()

        try:
            scanner = PortScanner()
            timeout = self.config_manager.get("default_timeout", 4)

            with LoadingAnimation("Scanning ports..."):
                scanner.scan(target, port_spec, timeout=timeout)

            print(scanner.format_results())
            self.pause()

        except Exception as e:
            display_warning("Port scan failed", str(e))
            traceback.print_exc()
            self.pause()

    # ==========================================================
    # NETWORK ANALYSIS
    # ==========================================================

    def run_network_analysis(self):
        from scans.route_info import RouteAnalyzer
        from scans.dns_info import DNSAnalyzer
        from core.connectivity import ConnectivityTester

        while True:
            from ui.banner import display_section_header
            display_section_header("NETWORK ANALYSIS")

            print("1. Network Info")
            print("2. Routing Table")
            print("3. DNS Analysis")
            print("4. Connectivity Test")
            print("5. Back")

            choice = self.get_choice("Select (1-5): ")

            if choice in ("5", "back"):
                return

            try:
                if choice == "1":
                    print(self.environment.format_for_display())
                    print(self.network.format_for_display())

                elif choice == "2":
                    ra = RouteAnalyzer()
                    ra.get_routing_table()
                    print(ra.format_routing_info())

                elif choice == "3":
                    da = DNSAnalyzer()
                    domain = input("Domain (default example.com): ").strip() or "example.com"
                    print(da.display_dns_info(domain))

                elif choice == "4":
                    ct = ConnectivityTester()
                    ct.get_comprehensive_status()
                    print(ct.format_results())

                else:
                    display_warning("Invalid", "Select 1–5")

                self.pause()

            except Exception as e:
                display_warning("Analysis error", str(e))
                traceback.print_exc()
                self.pause()

    # ==========================================================
    # SETTINGS MENU (LOGIC CONTINUES IN PART 2)
    # ==========================================================

    def display_settings_menu(self):
        from ui.banner import display_section_header

        display_section_header("SETTINGS")

        print("1. Scan Settings")
        print("2. Display Settings")
        print("3. Export Settings")
        print("4. Update Settings")
        print("5. Reset to Defaults")
        print("6. Back")

        print("\nCurrent Configuration:")
        print(f"  Default Timeout    : {self.config_manager.get('default_timeout', 4)}s")
        print(f"  Max Hosts per Scan : {self.config_manager.get('max_hosts_per_scan', 50)}")
        print(f"  Colors Enabled     : {self.config_manager.get('colors', True)}")
        print(f"  Auto Export        : {self.config_manager.get('auto_export', False)}")
        print(f"  Auto Update        : {self.config_manager.get('auto_update', True)}")
       
      # ==========================================================
    # SETTINGS — SCAN SETTINGS
    # ==========================================================

    def settings_scan(self):
        while True:
            from ui.banner import display_section_header
            display_section_header("SCAN SETTINGS")

            print("1. Default scan timeout (seconds)")
            print("2. Max hosts per scan")
            print("3. Ping timeout")
            print("4. Back")

            choice = self.get_choice("Select option (1-4): ")

            if choice in ("4", "back"):
                return

            if choice == "1":
                current = self.config_manager.get("default_timeout", 4)
                print(f"Current timeout: {current}s")
                val = input("New timeout (1–15): ").strip()
                if val.isdigit() and 1 <= int(val) <= 15:
                    self.config_manager.set("default_timeout", int(val))
                    display_info("Updated", "Default timeout saved")
                else:
                    display_warning("Invalid value", "Enter number between 1–15")
                self.pause()

            elif choice == "2":
                current = self.config_manager.get("max_hosts_per_scan", 50)
                print(f"Current limit: {current}")
                val = input("New limit (10–1000): ").strip()
                if val.isdigit() and 10 <= int(val) <= 1000:
                    self.config_manager.set("max_hosts_per_scan", int(val))
                    display_info("Updated", "Host limit saved")
                else:
                    display_warning("Invalid value", "Range: 10–1000")
                self.pause()

            elif choice == "3":
                current = self.config_manager.get("ping_timeout", 1)
                print(f"Current ping timeout: {current}s")
                val = input("New ping timeout (1–5): ").strip()
                if val.isdigit() and 1 <= int(val) <= 5:
                    self.config_manager.set("ping_timeout", int(val))
                    display_info("Updated", "Ping timeout saved")
                else:
                    display_warning("Invalid value", "Range: 1–5")
                self.pause()

            else:
                display_warning("Invalid choice", "Select 1–4")
                self.pause()

    # ==========================================================
    # SETTINGS — DISPLAY SETTINGS
    # ==========================================================

    def settings_display(self):
        while True:
            from ui.banner import display_section_header
            display_section_header("DISPLAY SETTINGS")

            print("1. Toggle colors")
            print("2. Toggle verbose output")
            print("3. Back")

            choice = self.get_choice("Select option (1-3): ")

            if choice in ("3", "back"):
                return

            if choice == "1":
                current = self.config_manager.get("colors", True)
                self.config_manager.set("colors", not current)
                state = "enabled" if not current else "disabled"
                display_info("Display Updated", f"Colors {state}")
                self.pause()

            elif choice == "2":
                current = self.config_manager.get("verbose", False)
                self.config_manager.set("verbose", not current)
                state = "enabled" if not current else "disabled"
                display_info("Display Updated", f"Verbose mode {state}")
                self.pause()

            else:
                display_warning("Invalid choice", "Select 1–3")
                self.pause()

    # ==========================================================
    # SETTINGS — EXPORT SETTINGS
    # ==========================================================

    def settings_export(self):
        while True:
            from ui.banner import display_section_header
            display_section_header("EXPORT SETTINGS")

            print("1. Toggle auto-export")
            print("2. Set export format (json/txt)")
            print("3. Back")

            choice = self.get_choice("Select option (1-3): ")

            if choice in ("3", "back"):
                return

            if choice == "1":
                current = self.config_manager.get("auto_export", False)
                self.config_manager.set("auto_export", not current)
                state = "enabled" if not current else "disabled"
                display_info("Export Updated", f"Auto-export {state}")
                self.pause()

            elif choice == "2":
                fmt = input("Enter format (json/txt): ").strip().lower()
                if fmt in ("json", "txt"):
                    self.config_manager.set("export_format", fmt)
                    display_info("Export Updated", f"Format set to {fmt}")
                else:
                    display_warning("Invalid format", "Use json or txt")
                self.pause()

            else:
                display_warning("Invalid choice", "Select 1–3")
                self.pause()

    # ==========================================================
    # SETTINGS — UPDATE SETTINGS
    # ==========================================================

    def settings_update(self):
        from utils.updater import UpdateChecker

        display_notice(
            "Update System",
            "Live update checks require:\n"
            "- Internet access\n"
            "- GitHub availability\n"
            "- Stable connection"
        )

        checker = UpdateChecker()

        try:
            with LoadingAnimation("Checking for updates..."):
                available = checker.check_available()

            if available:
                print(colors.colorize(
                    f"\nUpdate available: {checker.latest_version}",
                    "SUCCESS"
                ))
                print("You are running:", checker.current_version)
                print("\nRun update manually if desired.")
            else:
                print(colors.colorize("\nYou are on the latest version.", "INFO"))

        except Exception as e:
            display_warning(
                "Update check failed",
                "Not available in current environment.\n"
                "Reason:\n"
                "- Network restrictions\n"
                "- GitHub unreachable\n"
                "- Planned improvements in v3.x"
            )
            if self.config_manager.get("verbose", False):
                traceback.print_exc()

        self.pause()

    # ==========================================================
    # SETTINGS — RESET
    # ==========================================================

    def settings_reset(self):
        confirm = input(
            colors.colorize(
                "\nType RESET to restore defaults: ",
                "WARNING"
            )
        ).strip()

        if confirm != "RESET":
            display_warning("Cancelled", "Reset aborted")
            self.pause()
            return

        self.config_manager.reset()
        display_info("Reset Complete", "All settings restored to defaults")
        self.pause()

    # ==========================================================
    # SETTINGS — CONTROLLER
    # ==========================================================

    def run_settings(self):
        while True:
            self.display_settings_menu()
            choice = self.get_choice("Select setting (1-6): ")

            if choice in ("6", "back"):
                return

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
            else:
                display_warning("Invalid choice", "Select 1–6")
                self.pause()

    # ==========================================================
    # MAIN LOOP
    # ==========================================================

    def run(self):
        from ui.banner import display_goodbye

        while self.running:
            try:
                self.display_main_menu()
                choice = self.get_choice("Select option (1-8): ")

                if choice in ("8", "exit", "quit"):
                    display_goodbye()
                    break

                if choice == "1":
                    self.run_network_discovery()
                elif choice == "2":
                    self.run_port_scanner()
                elif choice == "3":
                    self.run_network_analysis()
                elif choice == "4":
                    display_warning(
                        "Security Assessment",
                        "Not available in current version.\n"
                        "Reason:\n"
                        "- Requires elevated privileges\n"
                        "- Engine under validation\n"
                        "- Planned for v3.x"
                    )
                    self.pause()
                elif choice == "5":
                    display_warning(
                        "Tools & Utilities",
                        "Not available in current version.\n"
                        "Reason:\n"
                        "- Modular toolchain pending\n"
                        "- Security review in progress\n"
                        "- Planned for v3.x"
                    )
                    self.pause()
                elif choice == "6":
                    self.run_settings()
                elif choice == "7":
                    from ui.banner import display_about
                    display_about()
                    self.pause()
                else:
                    display_warning("Invalid choice", "Select 1–8")
                    self.pause()

            except KeyboardInterrupt:
                print(colors.colorize("\nInterrupted by user", "WARNING"))
                break
            except Exception as e:
                display_warning("Fatal menu error", str(e))
                traceback.print_exc()
                break
