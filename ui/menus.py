#!/usr/bin/env python3
"""
Menu System Module
Interactive menu interface for CEX-NetScan
"""

import sys
import time
from .colors import colors
from .animations import LoadingAnimation
from .warnings import display_warning, display_notice

class MainMenu:
    """Main menu system for CEX-NetScan"""
    
    def __init__(self, environment, network, config):
        self.environment = environment
        self.network = network
        self.config = config
        self.scan_results = {}
        self.current_view = "main"
        
    def display_main_menu(self):
        """Display main menu"""
        from ui.banner import display_section_header
        
        display_section_header("MAIN MENU")
        
        # Network status indicator
        status_color = {
            "online": "SUCCESS",
            "offline": "ERROR",
            "limited": "WARNING"
        }.get(self.network.network_status, "WARNING")
        
        status_text = colors.colorize(f"[{self.network.network_status.upper()}]", status_color)
        print(f"Network Status: {status_text} ({self.network.network_type.replace('_', ' ').title()})")
        print()
        
        # Available options based on network status
        if self.network.network_status == "offline":
            print(colors.colorize("⚠ OFFLINE MODE - Limited options available", "WARNING"))
            print()
        
        # Menu options
        options = [
            ("1", "Network Discovery", "Scan local network for devices"),
            ("2", "Port Scanner", "Scan ports on a target"),
            ("3", "Network Analysis", "Detailed network information"),
            ("4", "Security Assessment", "Basic security checks"),
            ("5", "Tools & Utilities", "Additional network tools"),
            ("6", "Settings", "Configure scanner options"),
            ("7", "About", "Tool information and credits"),
            ("8", "Exit", "Exit CEX-NetScan")
        ]
        
        # Adjust options based on capabilities
        caps = self.environment.get_scan_capabilities()
        
        for key, title, description in options:
            # Disable options based on network/capabilities
            disabled = False
            disabled_reason = ""
            
            if title == "Network Discovery" and self.network.network_type == "mobile_cgnat":
                disabled = True
                disabled_reason = " (CGNAT prevents LAN discovery)"
            elif title == "Network Discovery" and not caps.get("arp_scan", False) and not caps.get("ping_scan", False):
                disabled = True
                disabled_reason = " (requires network permissions)"
            elif title == "Port Scanner" and self.network.network_status == "offline":
                disabled = True
                disabled_reason = " (offline mode)"
            
            if disabled:
                print(f"{colors.colorize(key, 'DISABLED')}. {colors.colorize(title, 'DISABLED')}{colors.colorize(disabled_reason, 'DIM')}")
            else:
                print(f"{colors.colorize(key, 'MENU')}. {title}")
                print(f"   {colors.colorize(description, 'DIM')}")
        
        print()
        print(colors.colorize("─" * 60, "DIM"))
        
    def display_network_discovery_menu(self):
        """Display network discovery menu"""
        from ui.banner import display_section_header
        
        display_section_header("NETWORK DISCOVERY")
        
        print("Discover devices on your local network")
        print()
        
        options = [
            ("1", "Quick ARP Scan", "Fast device discovery using ARP"),
            ("2", "Comprehensive Scan", "ARP + Ping for maximum coverage"),
            ("3", "Ping Sweep", "ICMP-based network scanning"),
            ("4", "Custom Range Scan", "Scan specific IP range"),
            ("5", "View Previous Results", "Show last scan results"),
            ("6", "Export Results", "Save results to file"),
            ("7", "Back to Main Menu", "Return to main menu")
        ]
        
        for key, title, description in options:
            print(f"{colors.colorize(key, 'MENU')}. {title}")
            print(f"   {colors.colorize(description, 'DIM')}")
        
        print()
        
        # Show current network info
        print(colors.colorize("Current Network:", "INFO"))
        print(f"  Type: {self.network.network_type.replace('_', ' ').title()}")
        print(f"  Gateway: {self.network.gateway_ip or 'Not detected'}")
        
        if self.network.network_type == "mobile_cgnat":
            print(colors.colorize("  ⚠ CGNAT detected - LAN discovery limited", "WARNING"))
        
        print()
    
    def display_port_scanner_menu(self):
        """Display port scanner menu"""
        from ui.banner import display_section_header
        
        display_section_header("PORT SCANNER")
        
        print("Scan ports on network targets")
        print()
        
        options = [
            ("1", "Quick Common Ports", "Scan common services (1-1000)"),
            ("2", "Full Port Scan", "Scan all ports (1-65535)"),
            ("3", "Custom Port Range", "Specify exact ports to scan"),
            ("4", "Service Detection", "Identify services on open ports"),
            ("5", "Multiple Targets", "Scan multiple IP addresses"),
            ("6", "View Previous Results", "Show last scan results"),
            ("7", "Back to Main Menu", "Return to main menu")
        ]
        
        for key, title, description in options:
            print(f"{colors.colorize(key, 'MENU')}. {title}")
            print(f"   {colors.colorize(description, 'DIM')}")
        
        print()
        
        # Quick target suggestions
        print(colors.colorize("Target Suggestions:", "INFO"))
        print("  • Localhost: 127.0.0.1")
        
        if self.network.gateway_ip:
            print(f"  • Gateway: {self.network.gateway_ip}")
        
        print("  • Common servers: 192.168.1.1, 192.168.0.1")
        print()
    
    def display_network_analysis_menu(self):
        """Display network analysis menu"""
        from ui.banner import display_section_header
        
        display_section_header("NETWORK ANALYSIS")
        
        print("Detailed network information and diagnostics")
        print()
        
        options = [
            ("1", "Network Information", "IP, gateway, DNS, interfaces"),
            ("2", "Routing Table", "View system routing information"),
            ("3", "DNS Analysis", "DNS server and resolution tests"),
            ("4", "Connectivity Tests", "Test internet connectivity"),
            ("5", "Interface Details", "Detailed network interface info"),
            ("6", "Back to Main Menu", "Return to main menu")
        ]
        
        for key, title, description in options:
            print(f"{colors.colorize(key, 'MENU')}. {title}")
            print(f"   {colors.colorize(description, 'DIM')}")
        
        print()
    
    def display_settings_menu(self):
        """Display settings menu"""
        from ui.banner import display_section_header
        
        display_section_header("SETTINGS")
        
        print("Configure CEX-NetScan behavior")
        print()
        
        options = [
            ("1", "Scan Settings", "Timeout, limits, behavior"),
            ("2", "Display Settings", "Colors, output format"),
            ("3", "Export Settings", "Auto-export, formats"),
            ("4", "Update Settings", "Auto-update checks"),
            ("5", "Reset to Defaults", "Restore default settings"),
            ("6", "Back to Main Menu", "Return to main menu")
        ]
        
        for key, title, description in options:
            print(f"{colors.colorize(key, 'MENU')}. {title}")
            print(f"   {colors.colorize(description, 'DIM')}")
        
        print()
        
        # Show current settings summary
        print(colors.colorize("Current Settings:", "INFO"))
        print(f"  Auto-update: {'Enabled' if self.config.get('auto_update_check', True) else 'Disabled'}")
        print(f"  Save logs: {'Enabled' if self.config.get('save_logs', True) else 'Disabled'}")
        print(f"  Default timeout: {self.config.get('default_timeout', 5)}s")
        print(f"  Ethical mode: {'Enabled' if self.config.get('ethical_mode', True) else 'Disabled'}")
        print()
    
    def get_user_choice(self, prompt="Select an option: "):
        """Get user choice with validation"""
        try:
            choice = input(f"\n{colors.colorize(prompt, 'YELLOW')}").strip()
            return choice
        except (EOFError, KeyboardInterrupt):
            return "exit"
        except:
            return ""
    
    def validate_choice(self, choice, min_val, max_val):
        """Validate menu choice"""
        try:
            choice_num = int(choice)
            return min_val <= choice_num <= max_val
        except:
            return False
    
    def run_network_discovery(self):
        """Run network discovery scan"""
        from scans.lan_discovery import LANDiscoverer
        
        display_notice("Network Discovery", "Only scan networks you own or have permission to test.")
        
        # Get scan type
        while True:
            self.display_network_discovery_menu()
            choice = self.get_user_choice("Select scan type (1-7): ")
            
            if choice == "7" or choice.lower() == "back":
                return
            
            if not self.validate_choice(choice, 1, 7):
                display_warning("Invalid choice", "Please select 1-7")
                continue
            
            # Execute scan
            try:
                scanner = LANDiscoverer()
                
                with LoadingAnimation("Scanning network..."):
                    if choice == "1":
                        # Quick ARP scan
                        devices = scanner.discover_local_network(methods=['arp'])
                    elif choice == "2":
                        # Comprehensive scan
                        devices = scanner.discover_local_network(methods=['arp', 'ping'])
                    elif choice == "3":
                        # Ping sweep
                        from scans.ping_scan import PingScanner
                        ping_scanner = PingScanner()
                        
                        # Get network range
                        import socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                        
                        network_prefix = ".".join(local_ip.split(".")[:3])
                        network_range = f"{network_prefix}.0/24"
                        
                        results = ping_scanner.scan_range(network_range)
                        devices = [{'ip': ip, 'vendor': 'Unknown', 'source': 'ping'} for ip in results['alive_hosts']]
                    else:
                        continue
                
                # Display results
                print("\n" + "="*70)
                print(scanner.display_discovery_results())
                print("="*70)
                
                # Save results
                self.scan_results['network_discovery'] = {
                    'devices': scanner.discovered_devices,
                    'stats': scanner.get_network_info(),
                    'timestamp': time.time()
                }
                
                input(f"\n{colors.colorize('Press Enter to continue...', 'DIM')}")
                
            except Exception as e:
                display_warning("Scan failed", str(e))
    
    def run_port_scanner(self):
        """Run port scanner"""
        from scans.port_scan import PortScanner
        
        display_notice("Port Scanning", "Only scan systems you own or have permission to test.")
        
        # Get target
        target = input(f"\n{colors.colorize('Enter target IP/hostname: ', 'CYAN')}").strip()
        if not target:
            display_warning("No target specified", "Scan cancelled")
            return
        
        # Validate target
        import socket
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            display_warning("Invalid target", f"Cannot resolve {target}")
            return
        
        # Get port range
        print(f"\n{colors.colorize('Port range options:', 'INFO')}")
        print("  1. Common ports (1-1000)")
        print("  2. Web servers (80,443,8080,8443)")
        print("  3. All ports (1-65535) - WARNING: Very slow")
        print("  4. Custom range (e.g., 20-100)")
        print("  5. Specific ports (e.g., 22,80,443)")
        
        port_choice = self.get_user_choice("Select port range (1-5): ")
        
        port_spec = "1-1000"  # Default
        
        if port_choice == "1":
            port_spec = "1-1000"
        elif port_choice == "2":
            port_spec = "80,443,8080,8443"
        elif port_choice == "3":
            display_warning("Full Port Scan", "This will scan 65535 ports and may take hours!")
            confirm = input(f"{colors.colorize('Are you sure? (yes/no): ', 'YELLOW')}").lower()
            if confirm != "yes":
                return
            port_spec = "1-65535"
        elif port_choice == "4":
            custom_range = input(f"{colors.colorize('Enter port range (e.g., 20-100): ', 'CYAN')}").strip()
            port_spec = custom_range
        elif port_choice == "5":
            specific_ports = input(f"{colors.colorize('Enter ports (comma-separated): ', 'CYAN')}").strip()
            port_spec = specific_ports
        
        # Perform scan
        try:
            scanner = PortScanner()
            
            print(f"\n{colors.colorize('Starting port scan...', 'INFO')}")
            print(f"Target: {target}")
            print(f"Ports: {port_spec}")
            print()
            
            results = scanner.scan(target, port_spec, timeout=2)
            
            # Display results
            print("\n" + "="*70)
            print(scanner.format_results())
            print("="*70)
            
            # Save results
            self.scan_results['port_scan'] = {
                'target': target,
                'ports': port_spec,
                'results': results,
                'timestamp': time.time()
            }
            
            input(f"\n{colors.colorize('Press Enter to continue...', 'DIM')}")
            
        except Exception as e:
            display_warning("Port scan failed", str(e))
    
    def run_network_analysis(self):
        """Run network analysis"""
        from scans.route_info import RouteAnalyzer
        from scans.dns_info import DNSAnalyzer
        from core.connectivity import ConnectivityTester
        
        while True:
            self.display_network_analysis_menu()
            choice = self.get_user_choice("Select analysis (1-6): ")
            
            if choice == "6" or choice.lower() == "back":
                return
            
            if not self.validate_choice(choice, 1, 6):
                display_warning("Invalid choice", "Please select 1-6")
                continue
            
            try:
                if choice == "1":
                    # Network information
                    print("\n" + "="*70)
                    print(self.environment.format_for_display())
                    print()
                    print(self.network.format_for_display())
                    print("="*70)
                
                elif choice == "2":
                    # Routing table
                    analyzer = RouteAnalyzer()
                    with LoadingAnimation("Analyzing routing table..."):
                        analyzer.get_routing_table()
                    print("\n" + "="*70)
                    print(analyzer.format_routing_info())
                    print("="*70)
                
                elif choice == "3":
                    # DNS analysis
                    analyzer = DNSAnalyzer()
                    domain = input(f"{colors.colorize('Enter domain to analyze: ', 'CYAN')}").strip() or "example.com"
                    print("\n" + "="*70)
                    print(analyzer.display_dns_info(domain))
                    print("="*70)
                
                elif choice == "4":
                    # Connectivity tests
                    tester = ConnectivityTester()
                    with LoadingAnimation("Testing connectivity..."):
                        tester.get_comprehensive_status()
                    print("\n" + "="*70)
                    print(tester.format_results())
                    print("="*70)
                
                elif choice == "5":
                    # Interface details
                    analyzer = RouteAnalyzer()
                    interfaces = analyzer.get_network_interfaces()
                    print("\n" + "="*70)
                    print(colors.colorize("Network Interfaces", "HEADER"))
                    print(colors.colorize("─" * 60, "DIM"))
                    
                    for iface in interfaces:
                        status_color = "SUCCESS" if iface["status"] == "up" else "ERROR"
                        status = colors.colorize(iface["status"].upper(), status_color)
                        
                        print(f"\nInterface: {iface['name']} ({status})")
                        
                        if iface.get("mac_address"):
                            print(f"  MAC: {iface['mac_address']}")
                        
                        if iface.get("ip_addresses"):
                            print("  IP Addresses:")
                            for ip in iface["ip_addresses"]:
                                print(f"    • {ip}")
                    
                    print("\n" + "="*70)
                
                input(f"\n{colors.colorize('Press Enter to continue...', 'DIM')}")
                
            except Exception as e:
                display_warning("Analysis failed", str(e))
    
    def run(self):
        """Main menu loop"""
        from ui.banner import display_goodbye
        
        while True:
            try:
                self.display_main_menu()
                choice = self.get_user_choice("Select option (1-8): ")
                
                if choice == "8" or choice.lower() in ["exit", "quit"]:
                    display_goodbye()
                    break
                
                if not self.validate_choice(choice, 1, 8):
                    display_warning("Invalid choice", "Please select 1-8")
                    continue
                
                if choice == "1":
                    self.run_network_discovery()
                elif choice == "2":
                    self.run_port_scanner()
                elif choice == "3":
                    self.run_network_analysis()
                elif choice == "4":
                    # Security assessment
                    display_notice("Coming Soon", "Security assessment module is under development.")
                elif choice == "5":
                    # Tools & utilities
                    display_notice("Coming Soon", "Additional tools module is under development.")
                elif choice == "6":
                    self.display_settings_menu()
                    settings_choice = self.get_user_choice("Select setting (1-6): ")
                    if settings_choice == "6":
                        continue
                    display_notice("Coming Soon", "Settings configuration is under development.")
                elif choice == "7":
                    from ui.banner import display_about
                    display_about()
                    input(f"\n{colors.colorize('Press Enter to continue...', 'DIM')}")
                
            except KeyboardInterrupt:
                print(f"\n{colors.colorize('Interrupted by user', 'WARNING')}")
                break
            except Exception as e:
                display_warning("Unexpected error", str(e))
                import traceback
                traceback.print_exc()
                break
