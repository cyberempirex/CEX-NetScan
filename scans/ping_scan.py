#!/usr/bin/env python3
"""
Ping Scanning Module
ICMP-based host discovery
"""

import os
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from threading import Thread

class PingScanner:
    """ICMP ping scanner for host discovery"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.results = {
            'alive_hosts': [],
            'dead_hosts': [],
            'timeout_hosts': [],
            'errors': []
        }
    
    def ping_host(self, host, timeout=1, count=1):
        """
        Ping a single host
        
        Returns:
            bool: True if host responds to ping
        """
        try:
            if self.system == "windows":
                # Windows ping command
                cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), host]
            else:
                # Unix-like systems (Linux, macOS, Android)
                cmd = ['ping', '-c', str(count), '-W', str(timeout), host]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 1
            )
            
            # Check output for success indicators
            output = result.stdout.lower()
            
            if self.system == "windows":
                return "reply from" in output and "bytes=" in output
            else:
                return result.returncode == 0 and "1 received" in output
        
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            return False
    
    def scan(self, hosts, timeout=1, max_workers=20):
        """
        Scan multiple hosts using ping
        
        Args:
            hosts: List of IP addresses or hostnames
            timeout: Ping timeout per host
            max_workers: Maximum concurrent pings
        
        Returns:
            dict: Scan results
        """
        self.results = {
            'alive_hosts': [],
            'dead_hosts': [],
            'timeout_hosts': [],
            'errors': []
        }
        
        total_hosts = len(hosts)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all ping tasks
            future_to_host = {
                executor.submit(self.ping_host, host, timeout): host 
                for host in hosts
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                completed += 1
                
                try:
                    is_alive = future.result(timeout=timeout + 1)
                    if is_alive:
                        self.results['alive_hosts'].append(host)
                    else:
                        self.results['dead_hosts'].append(host)
                except Exception as e:
                    self.results['errors'].append(f"{host}: {str(e)}")
                    self.results['timeout_hosts'].append(host)
        
        # Calculate statistics
        self.results['total_scanned'] = total_hosts
        self.results['alive_percentage'] = (len(self.results['alive_hosts']) / total_hosts * 100) if total_hosts > 0 else 0
        
        return self.results
    
    def scan_range(self, start_ip, end_ip=None, timeout=1):
        """
        Scan a range of IP addresses
        
        Args:
            start_ip: Starting IP or CIDR notation (e.g., "192.168.1.0/24")
            end_ip: Ending IP (if start_ip is not CIDR)
            timeout: Ping timeout
        
        Returns:
            dict: Scan results
        """
        try:
            import ipaddress
            
            if '/' in start_ip:
                # CIDR notation
                network = ipaddress.ip_network(start_ip, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            elif end_ip:
                # IP range
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                hosts = [str(ipaddress.ip_address(ip)) for ip in range(int(start), int(end) + 1)]
            else:
                # Single IP
                hosts = [start_ip]
            
            # Limit scan size for safety
            if len(hosts) > 255:
                hosts = hosts[:255]
            
            return self.scan(hosts, timeout)
        
        except Exception as e:
            self.results['errors'].append(f"Invalid IP range: {str(e)}")
            return self.results
    
    def get_statistics(self):
        """Get scan statistics"""
        stats = {
            'total_scanned': self.results.get('total_scanned', 0),
            'alive': len(self.results.get('alive_hosts', [])),
            'dead': len(self.results.get('dead_hosts', [])),
            'timeout': len(self.results.get('timeout_hosts', [])),
            'alive_percentage': self.results.get('alive_percentage', 0),
            'errors': len(self.results.get('errors', []))
        }
        return stats
    
    def format_results(self, show_details=False):
        """Format ping scan results for display"""
        from ui.colors import colors
        
        lines = []
        lines.append(colors.colorize("Ping Scan Results", "HEADER"))
        lines.append(colors.colorize("─" * 50, "DIM"))
        
        # Statistics
        stats = self.get_statistics()
        lines.append(f"Hosts Scanned: {stats['total_scanned']}")
        lines.append(f"Alive Hosts: {colors.colorize(str(stats['alive']), 'SUCCESS')}")
        lines.append(f"Dead Hosts: {colors.colorize(str(stats['dead']), 'ERROR')}")
        
        if stats['timeout'] > 0:
            lines.append(f"Timeout: {colors.colorize(str(stats['timeout']), 'WARNING')}")
        
        if stats['alive_percentage'] > 0:
            percentage_color = 'SUCCESS' if stats['alive_percentage'] > 50 else 'WARNING'
            lines.append(f"Alive Percentage: {colors.colorize(f'{stats['alive_percentage']:.1f}%', percentage_color)}")
        
        # Alive hosts list
        alive_hosts = self.results.get('alive_hosts', [])
        if alive_hosts and show_details:
            lines.append("")
            lines.append(colors.colorize("Alive Hosts:", "INFO"))
            
            # Group by IP ranges
            ip_ranges = {}
            for ip in sorted(alive_hosts):
                parts = ip.split('.')
                if len(parts) >= 3:
                    range_key = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
                    if range_key not in ip_ranges:
                        ip_ranges[range_key] = []
                    ip_ranges[range_key].append(ip)
            
            # Display grouped IPs
            for ip_range, ips in sorted(ip_ranges.items()):
                lines.append(f"  {ip_range}:")
                # Show IPs in compact format
                ip_display = []
                for ip in sorted(ips):
                    last_octet = ip.split('.')[-1]
                    ip_display.append(last_octet)
                
                # Group last octets
                if len(ip_display) <= 10:
                    lines.append(f"    {', '.join(ip_display)}")
                else:
                    lines.append(f"    {', '.join(ip_display[:5])} ... {len(ip_display)-5} more")
        
        # Errors
        errors = self.results.get('errors', [])
        if errors and show_details:
            lines.append("")
            lines.append(colors.colorize("Errors:", "ERROR"))
            for error in errors[:3]:  # Show first 3 errors
                lines.append(f"  • {error}")
        
        return "\n".join(lines)
