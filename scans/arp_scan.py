#!/usr/bin/env python3
"""
ARP Scanning Module
Real ARP-based device discovery
"""

import os
import re
import subprocess
import time
from queue import Queue
from threading import Thread
from collections import defaultdict

class ARPScanner:
    """ARP-based network device discovery"""
    
    def __init__(self):
        self.devices = []
        self.mac_vendor_db = self._load_mac_vendors()
        self.scan_timeout = 5
    
    def _load_mac_vendors(self):
        """Load MAC address vendor database"""
        # In-memory database of common OUI prefixes
        vendors = {
            "00:14:22": "Dell",
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:15:5D": "Microsoft",
            "00:05:69": "Apple",
            "00:0A:95": "Apple",
            "00:1A:11": "Google",
            "00:1B:63": "HP",
            "00:1E:68": "HP",
            "00:25:BC": "Intel",
            "00:26:B0": "Cisco",
            "00:30:48": "Samsung",
            "00:50:F2": "Microsoft",
            "08:00:27": "VirtualBox",
            "3C:5A:B4": "Google",
            "A4:1F:72": "Microsoft",
            "B8:27:EB": "Raspberry Pi",
            "D8:96:95": "Apple",
            "F0:18:98": "Apple",
            "FC:15:B4": "Samsung",
            "14:CC:20": "Samsung",
            "28:16:AD": "Samsung",
            "34:23:BA": "Samsung",
            "44:80:EB": "Samsung",
            "60:F4:45": "Apple",
            "64:B8:53": "Apple",
            "68:96:7B": "Apple",
            "6C:3E:6D": "Apple",
            "70:56:81": "Apple",
            "84:38:35": "Apple",
            "88:66:A5": "Apple",
            "98:01:A7": "Apple",
            "AC:BC:32": "Apple",
            "BC:67:78": "Apple",
            "D0:25:44": "Apple",
            "DC:2B:2A": "Apple",
            "EC:35:86": "Apple",
            "F0:98:9D": "Apple",
            "F0:DC:E2": "Apple",
            "F4:0F:24": "Google",
            "F8:0F:41": "Google",
            "FC:F1:36": "Samsung",
        }
        return vendors
    
    def get_vendor_from_mac(self, mac):
        """Get vendor name from MAC address"""
        if not mac or mac == "00:00:00:00:00:00":
            return "Unknown"
        
        mac_upper = mac.upper().replace("-", ":").strip()
        
        # Extract OUI (first 6 characters without colons)
        oui = mac_upper.replace(":", "")[:6].upper()
        
        # Check against database
        for vendor_prefix, vendor_name in self.mac_vendor_db.items():
            vendor_oui = vendor_prefix.replace(":", "")[:6]
            if oui.startswith(vendor_oui):
                return vendor_name
        
        return "Unknown"
    
    def scan_via_arp_cache(self):
        """Scan using existing ARP cache"""
        devices = []
        
        if os.name == "posix":
            # Linux/Unix systems
            arp_files = [
                "/proc/net/arp",
                "/usr/sbin/arp -a 2>/dev/null",
                "ip neighbor show 2>/dev/null"
            ]
            
            for arp_source in arp_files:
                try:
                    if arp_source.startswith("/proc/"):
                        if os.path.exists(arp_source):
                            with open(arp_source, "r") as f:
                                content = f.read()
                            devices = self._parse_proc_net_arp(content)
                            if devices:
                                break
                    else:
                        result = subprocess.run(
                            arp_source.split(),
                            capture_output=True,
                            text=True,
                            timeout=2
                        )
                        if result.returncode == 0:
                            devices = self._parse_arp_output(result.stdout)
                            if devices:
                                break
                except:
                    continue
        
        elif os.name == "nt":
            # Windows systems
            try:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if result.returncode == 0:
                    devices = self._parse_windows_arp(result.stdout)
            except:
                pass
        
        return devices
    
    def _parse_proc_net_arp(self, content):
        """Parse /proc/net/arp format"""
        devices = []
        
        # Skip header line
        lines = content.strip().split("\n")[1:]
        
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3]
                
                if mac != "00:00:00:00:00:00":
                    vendor = self.get_vendor_from_mac(mac)
                    
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "source": "arp_cache",
                        "status": "cached"
                    })
        
        return devices
    
    def _parse_arp_output(self, output):
        """Parse standard arp command output"""
        devices = []
        
        # Pattern for arp -a output
        patterns = [
            r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)',
            r'(\d+\.\d+\.\d+\.\d+)\s+ether\s+([0-9a-fA-F:]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                if len(match) == 2:
                    ip, mac = match
                    if mac != "00:00:00:00:00:00":
                        vendor = self.get_vendor_from_mac(mac)
                        
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "source": "arp_command",
                            "status": "cached"
                        })
        
        return devices
    
    def _parse_windows_arp(self, output):
        """Parse Windows arp -a output"""
        devices = []
        
        # Windows ARP format
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            
            # Match: 192.168.1.1           00-11-22-33-44-55     dynamic
            if "dynamic" in line.lower() or "static" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].replace("-", ":")
                    
                    if self._is_valid_mac(mac):
                        vendor = self.get_vendor_from_mac(mac)
                        
                        devices.append({
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor,
                            "source": "windows_arp",
                            "status": "cached"
                        })
        
        return devices
    
    def scan_via_netdiscover(self, network_range=None):
        """Scan using netdiscover (if available)"""
        devices = []
        
        # Check if netdiscover exists
        try:
            result = subprocess.run(
                ["which", "netdiscover"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return devices
        except:
            return devices
        
        # Build command
        if not network_range:
            # Get local network
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                network_prefix = ".".join(local_ip.split(".")[:3])
                network_range = f"{network_prefix}.0/24"
            except:
                network_range = "192.168.1.0/24"
        
        try:
            cmd = [
                "netdiscover",
                "-r", network_range,
                "-P",  # Print only, no interactive
                "-s", "1"  # Sleep 1ms between packets
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            
            if result.returncode == 0:
                devices = self._parse_netdiscover_output(result.stdout)
        
        except subprocess.TimeoutExpired:
            # Netdiscover was killed due to timeout
            pass
        except:
            pass
        
        return devices
    
    def _parse_netdiscover_output(self, output):
        """Parse netdiscover output"""
        devices = []
        
        # Netdiscover format example:
        # 192.168.1.1   00:11:22:33:44:55     Vendor Name
        
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            
            # Skip header lines
            if not line or "IP" in line and "MAC" in line:
                continue
            
            # Split by whitespace
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                
                if self._is_valid_ip(ip) and self._is_valid_mac(mac):
                    # Vendor is everything after MAC
                    vendor = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                    
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "source": "netdiscover",
                        "status": "discovered"
                    })
        
        return devices
    
    def _is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_mac(self, mac):
        """Validate MAC address"""
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
            r'^([0-9A-Fa-f]{12})$'
        ]
        
        for pattern in mac_patterns:
            if re.match(pattern, mac):
                return True
        return False
    
    def scan(self, method="auto", network_range=None):
        """Perform ARP scan"""
        devices = []
        
        if method == "auto":
            # Try netdiscover first (most accurate)
            devices = self.scan_via_netdiscover(network_range)
            
            # Fall back to ARP cache
            if not devices:
                devices = self.scan_via_arp_cache()
        
        elif method == "netdiscover":
            devices = self.scan_via_netdiscover(network_range)
        
        elif method == "arp_cache":
            devices = self.scan_via_arp_cache()
        
        # Remove duplicates by IP
        unique_devices = {}
        for device in devices:
            ip = device["ip"]
            if ip not in unique_devices:
                unique_devices[ip] = device
        
        self.devices = list(unique_devices.values())
        return self.devices
    
    def get_scan_stats(self):
        """Get scan statistics"""
        stats = {
            "total_devices": len(self.devices),
            "vendors": defaultdict(int),
            "sources": defaultdict(int)
        }
        
        for device in self.devices:
            stats["vendors"][device["vendor"]] += 1
            stats["sources"][device["source"]] += 1
        
        return stats
    
    def format_results(self):
        """Format scan results for display"""
        from ui.colors import colors
        
        if not self.devices:
            return colors.colorize("No devices found in ARP cache", "WARNING")
        
        lines = []
        lines.append(colors.colorize("ARP Scan Results", "HEADER"))
        lines.append(colors.colorize(f"Devices Found: {len(self.devices)}", "INFO"))
        lines.append(colors.colorize("─" * 60, "DIM"))
        
        # Table header
        header = f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<20} {'Source':<10}"
        lines.append(colors.colorize(header, "HEADER"))
        lines.append(colors.colorize("─" * 60, "DIM"))
        
        # Device rows
        for device in sorted(self.devices, key=lambda x: x["ip"]):
            ip = device["ip"][:15].ljust(16)
            mac = device["mac"][:17].ljust(18)
            vendor = (device["vendor"][:18] + ".." if len(device["vendor"]) > 18 else device["vendor"].ljust(20))
            source = device["source"][:9].ljust(10)
            
            line = f"{colors.colorize(ip, 'INFO')} {mac} {vendor} {source}"
            lines.append(line)
        
        # Statistics
        stats = self.get_scan_stats()
        if stats["vendors"]:
            lines.append("")
            lines.append(colors.colorize("Vendor Summary:", "INFO"))
            for vendor, count in sorted(stats["vendors"].items(), key=lambda x: x[1], reverse=True)[:5]:
                if vendor != "Unknown":
                    lines.append(f"  • {vendor}: {count}")
        
        return "\n".join(lines)
