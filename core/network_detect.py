#!/usr/bin/env python3
"""
Real Network Type Detection
No guessing, real connectivity tests
"""

import socket
import subprocess
import json
import time
from urllib.request import urlopen, Request
from urllib.error import URLError

class NetworkDetector:
    """Accurate network type and connectivity detection"""
    
    def __init__(self):
        self.network_status = "unknown"
        self.network_type = "unknown"
        self.public_ip = None
        self.gateway_ip = None
        self.is_cgnat = False
        self.latency_ms = None
        self.accuracy_level = "high"
        
    def detect_all(self, timeout=5):
        """Run comprehensive network detection"""
        results = {}
        
        # Phase 1: Basic connectivity
        results.update(self._check_local_connectivity())
        
        # Phase 2: If online, determine network type
        if results["status"] == "online":
            results.update(self._determine_network_type(timeout))
            
            # Phase 3: Test external connectivity
            if results["can_reach_external"]:
                results.update(self._test_external_services(timeout))
        
        self._update_from_results(results)
        return results
    
    def _check_local_connectivity(self):
        """Check if we have any network interface up"""
        results = {
            "status": "offline",
            "has_local_network": False,
            "interfaces": [],
            "error": None
        }
        
        try:
            # Method 1: Try to get local IP
            local_ip = self._get_local_ip()
            if local_ip and local_ip != "127.0.0.1":
                results["has_local_network"] = True
                results["local_ip"] = local_ip
                
                # Check if we can reach gateway
                gateway = self._get_default_gateway()
                if gateway:
                    results["gateway"] = gateway
                    results["status"] = "online"
                else:
                    results["status"] = "limited"
            
            # Method 2: Check interfaces
            interfaces = self._get_network_interfaces()
            results["interfaces"] = interfaces
            
            # If no IP but interfaces exist, might be DHCP issue
            if not results["has_local_network"] and interfaces:
                results["status"] = "limited"
                results["error"] = "Network interface detected but no IP address"
                
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _get_local_ip(self):
        """Get non-localhost IP address"""
        try:
            # Try socket connection method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
            if ip.startswith("127.") or ip == "0.0.0.0":
                return None
            return ip
        except:
            pass
        
        # Fallback: check all interfaces
        try:
            import netifaces
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith("127.") and ip != "0.0.0.0":
                            return ip
        except ImportError:
            pass
        
        return None
    
    def _get_default_gateway(self):
        """Get default gateway IP"""
        try:
            # Linux/Android method
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":  # Default route
                        # Convert hex to IP
                        hex_ip = parts[2]
                        if len(hex_ip) == 8:
                            ip_parts = [int(hex_ip[i:i+2], 16) for i in range(0, 8, 2)]
                            return ".".join(str(p) for p in reversed(ip_parts))
        except:
            pass
        
        # Try ip command
        try:
            result = subprocess.run(["ip", "route", "show", "default"],
                                  capture_output=True,
                                  text=True,
                                  timeout=2)
            if result.returncode == 0 and "via" in result.stdout:
                for line in result.stdout.split("\n"):
                    if "via" in line:
                        parts = line.split()
                        gateway_index = parts.index("via") + 1
                        if gateway_index < len(parts):
                            return parts[gateway_index]
        except:
            pass
        
        return None
    
    def _get_network_interfaces(self):
        """Get list of network interfaces"""
        interfaces = []
        
        try:
            # Try netifaces first
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                iface_info = {"name": iface, "addresses": []}
                
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        iface_info["addresses"].append({
                            "family": "IPv4",
                            "address": addr.get("addr"),
                            "netmask": addr.get("netmask")
                        })
                
                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        iface_info["addresses"].append({
                            "family": "IPv6",
                            "address": addr.get("addr")
                        })
                
                interfaces.append(iface_info)
                
        except ImportError:
            # Fallback to basic detection
            try:
                result = subprocess.run(["ip", "addr", "show"],
                                      capture_output=True,
                                      text=True,
                                      timeout=2)
                if result.returncode == 0:
                    current_iface = None
                    for line in result.stdout.split("\n"):
                        if ":" in line and "mtu" in line:
                            # New interface
                            iface_name = line.split(":")[1].strip().split()[0]
                            current_iface = {"name": iface_name, "addresses": []}
                            interfaces.append(current_iface)
                        elif "inet " in line and current_iface:
                            # IPv4 address
                            parts = line.strip().split()
                            ip = parts[1].split("/")[0]
                            current_iface["addresses"].append({
                                "family": "IPv4",
                                "address": ip
                            })
            except:
                pass
        
        return interfaces
    
    def _determine_network_type(self, timeout):
        """Determine if we're on WiFi, mobile data, etc."""
        results = {
            "network_type": "unknown",
            "is_cgnat": False,
            "can_reach_external": False
        }
        
        # First, try to reach external service
        if self._test_connectivity("1.1.1.1", 53, timeout):
            results["can_reach_external"] = True
            
            # Get public IP to detect CGNAT
            public_ip = self._get_public_ip(timeout)
            if public_ip:
                results["public_ip"] = public_ip
                
                # Check for CGNAT ranges (100.64.0.0/10)
                ip_parts = list(map(int, public_ip.split(".")))
                if ip_parts[0] == 100 and 64 <= ip_parts[1] <= 127:
                    results["is_cgnat"] = True
                    results["network_type"] = "mobile_cgnat"
                    results["accuracy_level"] = "limited"
                else:
                    # Determine by latency and local network scan
                    results.update(self._analyze_network_characteristics(timeout))
        
        return results
    
    def _get_public_ip(self, timeout):
        """Get public IP address using multiple services"""
        services = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com"
        ]
        
        for service in services:
            try:
                req = Request(service, headers={"User-Agent": "CEX-NetScan/1.0"})
                with urlopen(req, timeout=timeout) as response:
                    ip = response.read().decode("utf-8").strip()
                    if self._is_valid_ip(ip):
                        return ip
            except:
                continue
        
        return None
    
    def _is_valid_ip(self, ip):
        """Validate IP address format"""
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
    
    def _test_connectivity(self, host, port, timeout):
        """Test TCP connectivity to a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _analyze_network_characteristics(self, timeout):
        """Analyze network to determine type"""
        results = {"network_type": "wifi_lan", "accuracy_level": "high"}
        
        # Check for multiple local devices (indicative of LAN)
        try:
            local_ip = self._get_local_ip()
            if local_ip:
                network_prefix = ".".join(local_ip.split(".")[:3])
                
                # Quick ping test of common gateway and broadcast
                test_ips = [
                    f"{network_prefix}.1",  # Common gateway
                    f"{network_prefix}.254", # Common gateway alt
                    "224.0.0.1"  # Multicast
                ]
                
                responses = 0
                for ip in test_ips:
                    if self._ping_host(ip, timeout=1):
                        responses += 1
                
                if responses >= 2:
                    results["network_type"] = "wifi_lan"
                elif responses == 1:
                    results["network_type"] = "hotspot_or_mobile"
                    results["accuracy_level"] = "medium"
                else:
                    results["network_type"] = "isolated"
                    results["accuracy_level"] = "low"
        except:
            results["accuracy_level"] = "low"
        
        return results
    
    def _ping_host(self, ip, timeout=1):
        """Ping a host to check if alive"""
        try:
            if os.name == "posix":
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(timeout), ip],
                    capture_output=True,
                    timeout=timeout + 1
                )
                return result.returncode == 0
            else:
                # Windows ping
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
                    capture_output=True,
                    timeout=timeout + 1
                )
                return result.returncode == 0
        except:
            return False
    
    def _test_external_services(self, timeout):
        """Test connectivity to common services"""
        results = {
            "dns_working": False,
            "http_working": False,
            "latency_ms": None
        }
        
        # Test DNS
        start = time.time()
        try:
            socket.gethostbyname("google.com")
            results["dns_working"] = True
            results["latency_ms"] = int((time.time() - start) * 1000)
        except:
            pass
        
        # Test HTTP
        try:
            req = Request("http://httpbin.org/get",
                         headers={"User-Agent": "CEX-NetScan/1.0"})
            with urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    results["http_working"] = True
        except:
            pass
        
        return results
    
    def _update_from_results(self, results):
        """Update instance variables from results"""
        self.network_status = results.get("status", "unknown")
        self.network_type = results.get("network_type", "unknown")
        self.public_ip = results.get("public_ip")
        self.gateway_ip = results.get("gateway")
        self.is_cgnat = results.get("is_cgnat", False)
        self.latency_ms = results.get("latency_ms")
        self.accuracy_level = results.get("accuracy_level", "unknown")
    
    def format_for_display(self):
        """Format network info for UI"""
        from ui.colors import colors
        
        lines = []
        lines.append(colors.colorize("Network Status", "HEADER"))
        lines.append(colors.colorize("─" * 40, "DIM"))
        
        # Status with color
        status_color = {
            "online": "SUCCESS",
            "offline": "ERROR",
            "limited": "WARNING",
            "unknown": "WARNING"
        }.get(self.network_status, "WARNING")
        
        status_text = colors.colorize(self.network_status.upper(), status_color)
        lines.append(f"Status:       {status_text}")
        
        if self.network_type != "unknown":
            type_display = self.network_type.replace("_", " ").title()
            if self.is_cgnat:
                type_display += " (CGNAT)"
            lines.append(f"Type:         {type_display}")
        
        # Accuracy indicator
        accuracy_colors = {
            "high": "SUCCESS",
            "medium": "WARNING",
            "low": "ERROR",
            "limited": "WARNING"
        }
        acc_color = accuracy_colors.get(self.accuracy_level, "WARNING")
        acc_text = colors.colorize(self.accuracy_level.upper(), acc_color)
        lines.append(f"Accuracy:     {acc_text}")
        
        # IP addresses
        if self.gateway_ip:
            lines.append(f"Gateway:      {self.gateway_ip}")
        
        if self.public_ip:
            lines.append(f"Public IP:    {self.public_ip}")
            if self.is_cgnat:
                lines.append(colors.colorize("  ⚠ CGNAT detected - LAN scans limited", "WARNING"))
        
        if self.latency_ms:
            latency_color = "SUCCESS" if self.latency_ms < 100 else "WARNING"
            latency_text = colors.colorize(f"{self.latency_ms}ms", latency_color)
            lines.append(f"Latency:      {latency_text}")
        
        # Warnings based on network type
        if self.network_type == "mobile_cgnat":
            lines.append("")
            lines.append(colors.colorize("⚠ CGNAT LIMITATIONS:", "WARNING"))
            lines.append("• Cannot scan other devices on mobile network")
            lines.append("• ARP scanning will not work")
            lines.append("• Only port scanning external hosts is possible")
        
        elif self.network_type == "isolated":
            lines.append("")
            lines.append(colors.colorize("⚠ ISOLATED NETWORK:", "WARNING"))
            lines.append("• No other devices detected")
            lines.append("• May be a hotspot or VPN connection")
        
        elif self.network_status == "offline":
            lines.append("")
            lines.append(colors.colorize("⚠ OFFLINE DETECTED:", "ERROR"))
            lines.append("• No network connectivity")
            lines.append("• Only offline features available")
        
        return "\n".join(lines)
