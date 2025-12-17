#!/usr/bin/env python3
"""
Routing Information Module
Network routing table analysis
"""

import os
import subprocess
import socket
import re

class RouteAnalyzer:
    """Network routing table analyzer"""
    
    def __init__(self):
        self.routes = []
        self.gateway = None
        self.interface = None
        
    def get_routing_table(self):
        """Get system routing table"""
        routes = []
        
        if os.name == "posix":
            # Linux/Unix/Android systems
            routes = self._get_unix_routes()
        elif os.name == "nt":
            # Windows systems
            routes = self._get_windows_routes()
        
        self.routes = routes
        
        # Extract default gateway
        for route in routes:
            if route.get("destination") == "0.0.0.0" or route.get("destination") == "default":
                self.gateway = route.get("gateway")
                self.interface = route.get("interface")
                break
        
        return routes
    
    def _get_unix_routes(self):
        """Get routing table on Unix-like systems"""
        routes = []
        
        # Try 'ip route' command first
        try:
            result = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                return self._parse_ip_route(result.stdout)
        except:
            pass
        
        # Try 'netstat' as fallback
        try:
            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                return self._parse_netstat_rn(result.stdout)
        except:
            pass
        
        # Try reading /proc/net/route
        try:
            if os.path.exists("/proc/net/route"):
                with open("/proc/net/route", "r") as f:
                    content = f.read()
                return self._parse_proc_net_route(content)
        except:
            pass
        
        return routes
    
    def _parse_ip_route(self, output):
        """Parse 'ip route' output"""
        routes = []
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            route = {
                "destination": "",
                "gateway": "",
                "interface": "",
                "flags": []
            }
            
            # Parse line
            parts = line.split()
            
            # Destination
            if parts[0] == "default":
                route["destination"] = "0.0.0.0"
            else:
                route["destination"] = parts[0]
            
            # Look for gateway and interface
            for i, part in enumerate(parts):
                if part == "via":
                    if i + 1 < len(parts):
                        route["gateway"] = parts[i + 1]
                elif part == "dev":
                    if i + 1 < len(parts):
                        route["interface"] = parts[i + 1]
                elif part in ["src", "metric", "mtu"]:
                    if i + 1 < len(parts):
                        route[part] = parts[i + 1]
            
            routes.append(route)
        
        return routes
    
    def _parse_netstat_rn(self, output):
        """Parse 'netstat -rn' output"""
        routes = []
        
        lines = output.strip().split("\n")
        start_parsing = False
        
        for line in lines:
            line = line.strip()
            
            # Skip until we see the routing table
            if "Destination" in line and "Gateway" in line:
                start_parsing = True
                continue
            
            if not start_parsing or not line:
                continue
            
            # Parse route line
            parts = line.split()
            if len(parts) >= 4:
                route = {
                    "destination": parts[0],
                    "gateway": parts[1],
                    "interface": parts[3] if len(parts) > 3 else "",
                    "flags": parts[2] if len(parts) > 2 else ""
                }
                routes.append(route)
        
        return routes
    
    def _parse_proc_net_route(self, content):
        """Parse /proc/net/route"""
        routes = []
        
        lines = content.strip().split("\n")
        
        # Skip header
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 3:
                # Convert hex IPs to decimal
                dest_hex = parts[1]
                gateway_hex = parts[2]
                
                dest_ip = self._hex_to_ip(dest_hex)
                gateway_ip = self._hex_to_ip(gateway_hex)
                
                route = {
                    "destination": dest_ip,
                    "gateway": gateway_ip,
                    "interface": parts[0],
                    "flags": parts[3] if len(parts) > 3 else ""
                }
                routes.append(route)
        
        return routes
    
    def _hex_to_ip(self, hex_str):
        """Convert hex string to IP address"""
        if len(hex_str) != 8:
            return "0.0.0.0"
        
        # Little-endian conversion
        parts = [
            str(int(hex_str[6:8], 16)),
            str(int(hex_str[4:6], 16)),
            str(int(hex_str[2:4], 16)),
            str(int(hex_str[0:2], 16))
        ]
        
        return ".".join(parts)
    
    def _get_windows_routes(self):
        """Get routing table on Windows"""
        routes = []
        
        try:
            result = subprocess.run(
                ["route", "print"],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0:
                routes = self._parse_windows_route(result.stdout)
        except:
            pass
        
        return routes
    
    def _parse_windows_route(self, output):
        """Parse Windows 'route print' output"""
        routes = []
        
        lines = output.split("\n")
        in_ipv4_table = False
        
        for line in lines:
            line = line.strip()
            
            # Find IPv4 Route Table
            if "IPv4 Route Table" in line:
                in_ipv4_table = True
                continue
            
            if not in_ipv4_table:
                continue
            
            # Skip header lines
            if "Network Destination" in line or "Active Routes:" in line or line.startswith("="):
                continue
            
            # Empty line ends the table
            if not line:
                break
            
            # Parse route line
            parts = re.split(r'\s+', line)
            if len(parts) >= 5:
                route = {
                    "destination": parts[0],
                    "netmask": parts[1],
                    "gateway": parts[2],
                    "interface": parts[3],
                    "metric": parts[4] if len(parts) > 4 else ""
                }
                routes.append(route)
        
        return routes
    
    def get_network_interfaces(self):
        """Get network interface information"""
        interfaces = []
        
        if os.name == "posix":
            # Unix-like systems
            try:
                result = subprocess.run(
                    ["ip", "addr", "show"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    return self._parse_ip_addr(result.stdout)
            except:
                pass
        
        # Fallback using socket
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            interfaces.append({
                "name": "primary",
                "ip_address": ip_address,
                "status": "active"
            })
        except:
            pass
        
        return interfaces
    
    def _parse_ip_addr(self, output):
        """Parse 'ip addr show' output"""
        interfaces = []
        current_iface = None
        
        for line in output.strip().split("\n"):
            line = line.strip()
            
            # New interface
            if line[0].isdigit():
                if current_iface:
                    interfaces.append(current_iface)
                
                # Parse interface number and name
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    current_iface = {
                        "index": parts[0].strip(),
                        "name": parts[1].strip(),
                        "mac_address": "",
                        "ip_addresses": [],
                        "status": "down"
                    }
                    
                    # Check status
                    if "UP" in line.upper():
                        current_iface["status"] = "up"
            
            elif current_iface:
                # MAC address
                if "link/ether" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        current_iface["mac_address"] = parts[1]
                
                # IP address
                elif "inet " in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_with_prefix = parts[1]
                        ip = ip_with_prefix.split("/")[0]
                        current_iface["ip_addresses"].append(ip)
        
        # Add last interface
        if current_iface:
            interfaces.append(current_iface)
        
        return interfaces
    
    def analyze_routing(self):
        """Analyze routing table for security insights"""
        analysis = {
            "default_gateway": self.gateway,
            "total_routes": len(self.routes),
            "default_route_exists": False,
            "local_routes": 0,
            "remote_routes": 0,
            "security_issues": []
        }
        
        for route in self.routes:
            dest = route.get("destination", "")
            
            # Check for default route
            if dest == "0.0.0.0" or dest == "default":
                analysis["default_route_exists"] = True
            
            # Count local vs remote routes
            if dest.startswith("127.") or dest.startswith("192.168.") or dest.startswith("10."):
                analysis["local_routes"] += 1
            elif dest != "0.0.0.0" and dest != "default":
                analysis["remote_routes"] += 1
        
        # Security checks
        if not analysis["default_route_exists"]:
            analysis["security_issues"].append("No default gateway configured")
        
        if analysis["remote_routes"] > 5:
            analysis["security_issues"].append("Many remote routes - possible routing table manipulation")
        
        return analysis
    
    def format_routing_info(self):
        """Format routing information for display"""
        from ui.colors import colors
        
        if not self.routes:
            self.get_routing_table()
        
        lines = []
        lines.append(colors.colorize("Routing Information", "HEADER"))
        lines.append(colors.colorize("─" * 60, "DIM"))
        
        # Default gateway
        if self.gateway:
            lines.append(f"Default Gateway: {colors.colorize(self.gateway, 'INFO')}")
            if self.interface:
                lines.append(f"Interface:      {self.interface}")
        else:
            lines.append(colors.colorize("No default gateway found", "WARNING"))
        
        # Interfaces
        interfaces = self.get_network_interfaces()
        if interfaces:
            lines.append("")
            lines.append(colors.colorize("Network Interfaces:", "INFO"))
            
            for iface in interfaces[:3]:  # Show first 3
                status_color = "SUCCESS" if iface["status"] == "up" else "ERROR"
                status = colors.colorize(iface["status"].upper(), status_color)
                
                lines.append(f"  {iface['name']}: {status}")
                
                if iface.get("ip_addresses"):
                    for ip in iface["ip_addresses"][:2]:  # Show first 2 IPs
                        lines.append(f"    IP: {ip}")
                
                if iface.get("mac_address"):
                    lines.append(f"    MAC: {iface['mac_address']}")
        
        # Routing table (simplified)
        if self.routes:
            lines.append("")
            lines.append(colors.colorize("Routing Table (simplified):", "INFO"))
            lines.append(colors.colorize("─" * 60, "DIM"))
            
            # Show only important routes
            important_routes = []
            for route in self.routes[:10]:  # Limit to 10 routes
                dest = route.get("destination", "")
                gateway = route.get("gateway", "")
                
                if dest == "0.0.0.0" or dest.startswith("192.168.") or dest.startswith("10."):
                    important_routes.append(route)
            
            for route in important_routes[:5]:  # Show top 5
                dest = route.get("destination", "").ljust(20)
                gateway = route.get("gateway", "").ljust(20)
                iface = route.get("interface", "").ljust(15)
                
                line = f"{dest} → {gateway} via {iface}"
                lines.append(line)
            
            if len(self.routes) > 5:
                lines.append(f"... and {len(self.routes) - 5} more routes")
        
        # Security analysis
        analysis = self.analyze_routing()
        if analysis["security_issues"]:
            lines.append("")
            lines.append(colors.colorize("Security Analysis:", "WARNING"))
            
            for issue in analysis["security_issues"]:
                lines.append(f"  • {issue}")
        
        return "\n".join(lines)
