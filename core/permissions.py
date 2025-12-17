#!/usr/bin/env python3
"""
Permissions Detection Module
Real privilege and capability checking
"""

import os
import sys
import subprocess
import ctypes
from pathlib import Path

class PermissionChecker:
    """Check system permissions and capabilities"""
    
    def __init__(self):
        self.is_root = False
        self.is_admin = False
        self.has_sudo = False
        self.has_net_raw = False
        self.has_net_admin = False
        self.capabilities = []
    
    def check_all(self):
        """Check all permissions"""
        self._check_root_admin()
        self._check_sudo()
        self._check_linux_capabilities()
        self._check_termux_permissions()
        return self.get_summary()
    
    def _check_root_admin(self):
        """Check for root/admin privileges"""
        if os.name == "posix":
            # Unix-like systems
            self.is_root = os.geteuid() == 0
        elif os.name == "nt":
            # Windows
            try:
                self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                self.is_admin = False
        else:
            self.is_root = False
            self.is_admin = False
    
    def _check_sudo(self):
        """Check if sudo is available and usable"""
        if os.name != "posix":
            self.has_sudo = False
            return
        
        try:
            # Try to run sudo -n true (non-interactive)
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=2
            )
            self.has_sudo = result.returncode == 0
        except:
            self.has_sudo = False
    
    def _check_linux_capabilities(self):
        """Check Linux capabilities (if available)"""
        if os.name != "posix":
            return
        
        # Check for capsh utility
        try:
            result = subprocess.run(
                ["which", "capsh"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return
        except:
            return
        
        # Get current capabilities
        try:
            result = subprocess.run(
                ["capsh", "--print"],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                # Check for network-related capabilities
                if "cap_net_raw" in output or "cap_net_raw+eip" in output:
                    self.has_net_raw = True
                    self.capabilities.append("CAP_NET_RAW")
                
                if "cap_net_admin" in output or "cap_net_admin+eip" in output:
                    self.has_net_admin = True
                    self.capabilities.append("CAP_NET_ADMIN")
                
                if "cap_net_bind_service" in output:
                    self.capabilities.append("CAP_NET_BIND_SERVICE")
                
                if "cap_sys_admin" in output:
                    self.capabilities.append("CAP_SYS_ADMIN")
        except:
            pass
    
    def _check_termux_permissions(self):
        """Check Termux-specific permissions"""
        if not self._is_termux():
            return
        
        # Check for Termux storage permission
        try:
            storage_path = Path.home() / "storage"
            if storage_path.exists():
                self.capabilities.append("TERMUX_STORAGE")
        except:
            pass
        
        # Check for Termux API permissions
        try:
            result = subprocess.run(
                ["termux-battery-status"],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                self.capabilities.append("TERMUX_API")
        except:
            pass
    
    def _is_termux(self):
        """Check if running in Termux"""
        termux_paths = [
            "/data/data/com.termux/files/usr",
            Path.home() / ".termux"
        ]
        return any(os.path.exists(p) for p in termux_paths)
    
    def check_arp_permission(self):
        """Check if ARP scanning is possible"""
        if os.name == "nt":
            # Windows requires admin for ARP
            return self.is_admin
        
        # Linux/Unix systems
        if self.is_root:
            return True
        
        if self.has_net_raw:
            return True
        
        # Check if we can read /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                f.read(1)
            return True
        except PermissionError:
            return False
        except FileNotFoundError:
            return False
    
    def check_ping_permission(self):
        """Check if ping is possible"""
        if os.name == "nt":
            # Windows ping usually works for users
            return True
        
        # Unix-like systems
        if self.is_root:
            return True
        
        # Check if ping binary is available and executable
        try:
            result = subprocess.run(
                ["which", "ping"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return False
            
            # Check if we can create raw sockets (ping requires)
            # This is approximated by checking capabilities
            return self.has_net_raw
        except:
            return False
    
    def check_port_scan_permission(self):
        """Check if port scanning is possible"""
        # TCP connect scanning works for everyone
        return True
    
    def check_packet_capture_permission(self):
        """Check if packet capture is possible"""
        if os.name == "nt":
            # Windows requires admin/Npcap
            return self.is_admin
        
        # Unix-like systems
        if self.is_root:
            return True
        
        return self.has_net_raw and self.has_net_admin
    
    def get_scan_capabilities(self):
        """Get list of available scan capabilities"""
        capabilities = {
            "arp_scan": self.check_arp_permission(),
            "ping_scan": self.check_ping_permission(),
            "port_scan": self.check_port_scan_permission(),
            "packet_capture": self.check_packet_capture_permission(),
            "service_detection": True,  # Always possible
            "dns_query": True,  # Always possible
            "route_inspection": self.is_root or self.has_sudo,
        }
        
        return capabilities
    
    def get_summary(self):
        """Get permission summary"""
        summary = {
            "is_root": self.is_root,
            "is_admin": self.is_admin,
            "has_sudo": self.has_sudo,
            "has_net_raw": self.has_net_raw,
            "has_net_admin": self.has_net_admin,
            "capabilities": self.capabilities,
            "scan_capabilities": self.get_scan_capabilities()
        }
        
        return summary
    
    def format_for_display(self):
        """Format permission info for display"""
        from ui.colors import colors
        
        lines = []
        lines.append(colors.colorize("Permission Analysis", "HEADER"))
        lines.append(colors.colorize("─" * 40, "DIM"))
        
        # Privilege status
        if self.is_root:
            lines.append(f"User:       {colors.colorize('ROOT', 'ERROR')}")
        elif self.is_admin:
            lines.append(f"User:       {colors.colorize('ADMINISTRATOR', 'ERROR')}")
        else:
            lines.append("User:       Standard User")
        
        if self.has_sudo:
            lines.append(f"Sudo:       {colors.colorize('AVAILABLE', 'SUCCESS')}")
        
        # Capabilities
        if self.capabilities:
            lines.append("")
            lines.append(colors.colorize("Capabilities:", "INFO"))
            for cap in self.capabilities:
                lines.append(f"  • {cap}")
        
        # Scan permissions
        caps = self.get_scan_capabilities()
        lines.append("")
        lines.append(colors.colorize("Scan Permissions:", "INFO"))
        
        for scan, allowed in caps.items():
            scan_name = scan.replace("_", " ").title()
            if allowed:
                lines.append(f"  • {scan_name}: {colors.colorize('✓', 'SUCCESS')}")
            else:
                lines.append(f"  • {scan_name}: {colors.colorize('✗', 'ERROR')}")
        
        # Recommendations
        lines.append("")
        lines.append(colors.colorize("Recommendations:", "WARNING"))
        
        if not caps["arp_scan"]:
            lines.append("• Run as root/sudo for ARP scanning")
        
        if not caps["ping_scan"] and os.name == "posix":
            lines.append("• Set CAP_NET_RAW capability for ping")
        
        if not caps["packet_capture"]:
            lines.append("• Admin/root required for packet capture")
        
        return "\n".join(lines)
