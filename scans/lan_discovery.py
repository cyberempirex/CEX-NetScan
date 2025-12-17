#!/usr/bin/env python3
"""
LAN Discovery Module
Comprehensive local network device discovery
"""

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from .arp_scan import ARPScanner
from .ping_scan import PingScanner

class LANDiscoverer:
    """High-level LAN discovery combining multiple methods"""
    
    def __init__(self):
        self.arp_scanner = ARPScanner()
        self.ping_scanner = PingScanner()
        self.discovered_devices = []
        self.scan_methods_used = []
    
    def discover_local_network(self, methods=None, timeout=2):
        """
        Discover devices on local network
        
        Args:
            methods: List of methods to use ['arp', 'ping', 'mdns', 'upnp']
            timeout: Timeout per method in seconds
        """
        if methods is None:
            methods = ['arp', 'ping']
        
        all_devices = []
        self.scan_methods_used = []
        
        # Get local network range
        network_range = self._get_local_network_range()
        if not network_range:
            return []
        
        # ARP Scanning
        if 'arp' in methods:
            try:
                self.scan_methods_used.append('arp')
                arp_devices = self.arp_scanner.scan()
                all_devices.extend(arp_devices)
            except Exception as e:
                pass
        
        # Ping Scanning (if ARP found few or no devices)
        if 'ping' in methods and len(all_devices) < 5:
            try:
                self.scan_methods_used.append('ping')
                
                # Convert network range for ping scan
                if network_range:
                    network = ipaddress.ip_network(network_range, strict=False)
                    targets = [str(ip) for ip in network.hosts()][:50]  # Limit to 50
                    
                    ping_results = self.ping_scanner.scan(targets, timeout=timeout)
                    
                    # Convert ping results to device format
                    for ip in ping_results['alive_hosts']:
                        # Check if already found via ARP
                        if not any(d['ip'] == ip for d in all_devices):
                            all_devices.append({
                                'ip': ip,
                                'mac': '00:00:00:00:00:00',
                                'vendor': 'Unknown',
                                'source': 'ping_scan',
                                'status': 'alive'
                            })
            except:
                pass
        
        # Remove duplicates by IP
        unique_devices = {}
        for device in all_devices:
            ip = device['ip']
            if ip not in unique_devices:
                unique_devices[ip] = device
            else:
                # Prefer device with MAC address
                if device['mac'] != '00:00:00:00:00:00':
                    unique_devices[ip] = device
        
        self.discovered_devices = list(unique_devices.values())
        return self.discovered_devices
    
    def _get_local_network_range(self):
        """Get local network range from IP address"""
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Determine network range based on IP class
            ip_parts = list(map(int, local_ip.split('.')))
            
            if ip_parts[0] == 10:
                # Class A: 10.0.0.0/8
                return "10.0.0.0/8"
            elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
                # Class B: 172.16.0.0/12
                return f"172.{ip_parts[1]}.0.0/16"
            elif ip_parts[0] == 192 and ip_parts[1] == 168:
                # Class C: 192.168.x.0/24
                return f"192.168.{ip_parts[2]}.0/24"
            else:
                # Default to /24 of local IP
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        except:
            # Default fallback
            return "192.168.1.0/24"
    
    def get_network_info(self):
        """Get comprehensive network information"""
        info = {
            'total_devices': len(self.discovered_devices),
            'methods_used': self.scan_methods_used,
            'device_types': {},
            'ip_ranges': set(),
            'vendors': {}
        }
        
        for device in self.discovered_devices:
            # Count by vendor
            vendor = device['vendor']
            if vendor not in info['vendors']:
                info['vendors'][vendor] = 0
            info['vendors'][vendor] += 1
            
            # Track IP ranges
            ip_parts = device['ip'].split('.')
            if len(ip_parts) >= 3:
                ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.x"
                info['ip_ranges'].add(ip_range)
            
            # Infer device type from vendor
            vendor_lower = vendor.lower()
            if any(word in vendor_lower for word in ['router', 'gateway', 'cisco']):
                device_type = 'router'
            elif any(word in vendor_lower for word in ['printer', 'hp', 'epson']):
                device_type = 'printer'
            elif any(word in vendor_lower for word in ['tv', 'samsung', 'lg', 'sony']):
                device_type = 'tv'
            elif any(word in vendor_lower for word in ['phone', 'mobile', 'apple', 'android']):
                device_type = 'phone'
            elif any(word in vendor_lower for word in ['computer', 'pc', 'laptop', 'dell']):
                device_type = 'computer'
            elif 'raspberry' in vendor_lower:
                device_type = 'raspberry_pi'
            else:
                device_type = 'other'
            
            if device_type not in info['device_types']:
                info['device_types'][device_type] = 0
            info['device_types'][device_type] += 1
        
        info['ip_ranges'] = list(info['ip_ranges'])
        
        return info
    
    def identify_gateway(self):
        """Try to identify network gateway"""
        gateways = []
        
        for device in self.discovered_devices:
            ip = device['ip']
            
            # Common gateway IPs
            if ip.endswith('.1') or ip.endswith('.254') or ip.endswith('.100'):
                # Check for router vendors
                vendor_lower = device['vendor'].lower()
                if any(word in vendor_lower for word in ['cisco', 'netgear', 'tp-link', 'd-link', 'asus']):
                    gateways.append(device)
            
            # Also check for common router hostnames
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                hostname_lower = hostname.lower()
                if any(word in hostname_lower for word in ['router', 'gateway', 'modem', 'fritz']):
                    gateways.append(device)
            except:
                pass
        
        return gateways
    
    def display_discovery_results(self):
        """Display LAN discovery results"""
        from ui.colors import colors
        
        if not self.discovered_devices:
            return colors.colorize("No devices discovered on local network", "WARNING")
        
        lines = []
        lines.append(colors.colorize("LAN Discovery Results", "HEADER"))
        lines.append(colors.colorize("─" * 70, "DIM"))
        
        # Summary
        info = self.get_network_info()
        lines.append(f"Total Devices: {colors.colorize(str(info['total_devices']), 'INFO')}")
        lines.append(f"Methods Used: {', '.join(info['methods_used'])}")
        
        # Gateway detection
        gateways = self.identify_gateway()
        if gateways:
            lines.append("")
            lines.append(colors.colorize("⚠ Possible Gateways:", "WARNING"))
            for gw in gateways[:2]:  # Show first 2
                lines.append(f"  • {gw['ip']} ({gw['vendor']})")
        
        # Device types
        if info['device_types']:
            lines.append("")
            lines.append(colors.colorize("Device Types:", "INFO"))
            for dev_type, count in sorted(info['device_types'].items(), key=lambda x: x[1], reverse=True):
                dev_type_name = dev_type.replace('_', ' ').title()
                lines.append(f"  • {dev_type_name}: {count}")
        
        # Top vendors
        if info['vendors'] and len(info['vendors']) > 1:
            lines.append("")
            lines.append(colors.colorize("Top Vendors:", "INFO"))
            for vendor, count in sorted(info['vendors'].items(), key=lambda x: x[1], reverse=True)[:5]:
                if vendor != 'Unknown':
                    lines.append(f"  • {vendor}: {count}")
        
        # Detailed device list
        lines.append("")
        lines.append(colors.colorize("Discovered Devices:", "INFO"))
        lines.append(colors.colorize("─" * 70, "DIM"))
        
        # Table header
        header = f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<25} {'Source':<10}"
        lines.append(colors.colorize(header, "HEADER"))
        lines.append(colors.colorize("─" * 70, "DIM"))
        
        # Show devices (limit to 20 for display)
        display_limit = min(20, len(self.discovered_devices))
        for device in sorted(self.discovered_devices[:display_limit], key=lambda x: x['ip']):
            ip = device['ip'][:15].ljust(16)
            mac = device['mac'][:17].ljust(18)
            
            vendor = device['vendor']
            if len(vendor) > 23:
                vendor = vendor[:21] + ".."
            vendor = vendor.ljust(25)
            
            source = device['source'][:9].ljust(10)
            
            # Color code by device type
            vendor_lower = vendor.lower()
            if 'router' in vendor_lower or 'cisco' in vendor_lower:
                ip_color = 'WARNING'
            elif 'printer' in vendor_lower:
                ip_color = 'MAGENTA'
            elif any(word in vendor_lower for word in ['apple', 'samsung', 'phone']):
                ip_color = 'CYAN'
            else:
                ip_color = 'INFO'
            
            line = f"{colors.colorize(ip, ip_color)} {mac} {vendor} {source}"
            lines.append(line)
        
        if len(self.discovered_devices) > display_limit:
            lines.append(f"... and {len(self.discovered_devices) - display_limit} more devices")
        
        return "\n".join(lines)
