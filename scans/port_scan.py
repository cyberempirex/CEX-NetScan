#!/usr/bin/env python3
"""
Port Scanning Module
TCP-based port scanning with service detection
"""

import socket
import concurrent.futures
import time
from .service_fingerprint import ServiceFingerprinter

class PortScanner:
    """TCP port scanner with service detection"""
    
    def __init__(self):
        self.open_ports = []
        self.filtered_ports = []
        self.closed_ports = []
        self.scan_stats = {}
        self.fingerprinter = ServiceFingerprinter()
        
    def parse_port_range(self, port_spec):
        """
        Parse port range specification
        
        Args:
            port_spec: String like "80", "1-1000", "22,80,443", "1-100,1000-1100"
        
        Returns:
            list: List of port numbers
        """
        ports = []
        
        try:
            # Handle comma-separated lists
            parts = port_spec.split(',')
            
            for part in parts:
                part = part.strip()
                
                if '-' in part:
                    # Range like "1-100"
                    start_str, end_str = part.split('-')
                    start = int(start_str.strip())
                    end = int(end_str.strip())
                    
                    if 1 <= start <= 65535 and 1 <= end <= 65535:
                        if start <= end:
                            ports.extend(range(start, end + 1))
                        else:
                            ports.extend(range(end, start + 1))
                
                elif part.isdigit():
                    # Single port
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
                
                elif part.lower() == 'common':
                    # Common ports
                    ports.extend(self._get_common_ports())
                
                elif part.lower() == 'all':
                    # All ports (limited to first 1000 for safety)
                    ports.extend(range(1, 1001))
        
        except:
            # Fallback to common ports
            ports = self._get_common_ports()
        
        # Remove duplicates and sort
        return sorted(list(set(ports)))
    
    def _get_common_ports(self):
        """Get list of commonly used ports"""
        return [
            # Web
            80,    # HTTP
            443,   # HTTPS
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            
            # Security/Admin
            22,    # SSH
            23,    # Telnet
            21,    # FTP
            25,    # SMTP
            110,   # POP3
            143,   # IMAP
            993,   # IMAPS
            995,   # POP3S
            
            # Databases
            3306,  # MySQL
            5432,  # PostgreSQL
            27017, # MongoDB
            6379,  # Redis
            
            # Windows
            135,   # RPC
            139,   # NetBIOS
            445,   # SMB
            3389,  # RDP
            
            # Misc
            53,    # DNS
            123,   # NTP
            161,   # SNMP
            389,   # LDAP
            636,   # LDAPS
        ]
    
    def scan_port(self, target, port, timeout=2):
        """
        Scan a single port
        
        Returns:
            dict: Port scan result
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': 'unknown',
            'banner': None,
            'error': None,
            'scan_time': None
        }
        
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Try to connect
            conn_result = sock.connect_ex((target, port))
            
            if conn_result == 0:
                # Port is open
                result['state'] = 'open'
                
                # Try to get banner
                try:
                    banner = self._get_banner(sock, timeout=1)
                    if banner:
                        result['banner'] = banner
                except:
                    pass
                
                # Try to identify service
                service_info = self.fingerprinter.identify_service(target, port, timeout=1)
                if service_info:
                    result['service'] = service_info.get('name', 'unknown')
                    if 'version' in service_info:
                        result['version'] = service_info['version']
            
            elif conn_result == 111:  # Connection refused
                result['state'] = 'closed'
            else:
                # Other errors (filtered, no route, etc.)
                result['state'] = 'filtered'
                result['error'] = f"Error code: {conn_result}"
        
        except socket.timeout:
            result['state'] = 'filtered'
            result['error'] = 'Timeout'
        except ConnectionRefusedError:
            result['state'] = 'closed'
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
        finally:
            try:
                sock.close()
            except:
                pass
        
        result['scan_time'] = time.time() - start_time
        return result
    
    def _get_banner(self, sock, timeout=1):
        """Try to get banner from open port"""
        try:
            sock.settimeout(timeout)
            
            # Send basic probes based on common ports
            data = sock.recv(1024)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                return banner[:500]  # Limit length
            
            # If no banner received, try sending a probe
            port = sock.getpeername()[1]
            
            if port == 80 or port == 8080:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                sock.send(b"SSH-2.0-CEX-NetScan\r\n")
            elif port == 21:
                sock.send(b"USER anonymous\r\n")
            
            data = sock.recv(1024)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                return banner[:500]
        
        except:
            pass
        
        return None
    
    def scan(self, target, ports="common", timeout=2, max_workers=50):
        """
        Scan multiple ports on a target
        
        Args:
            target: IP address or hostname
            ports: Port specification string
            timeout: Connection timeout per port
            max_workers: Maximum concurrent scans
        
        Returns:
            dict: Scan results
        """
        # Parse port range
        port_list = self.parse_port_range(ports)
        
        # Limit scan size for safety
        if len(port_list) > 1000:
            port_list = port_list[:1000]
        
        # Reset results
        self.open_ports = []
        self.filtered_ports = []
        self.closed_ports = []
        
        # Scan statistics
        self.scan_stats = {
            'target': target,
            'total_ports': len(port_list),
            'scanned_ports': 0,
            'start_time': time.time(),
            'open_ports': 0,
            'filtered_ports': 0,
            'closed_ports': 0
        }
        
        # Perform scan with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit scan jobs
            future_to_port = {
                executor.submit(self.scan_port, target, port, timeout): port 
                for port in port_list
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                self.scan_stats['scanned_ports'] += 1
                
                try:
                    result = future.result()
                    
                    if result['state'] == 'open':
                        self.open_ports.append(result)
                        self.scan_stats['open_ports'] += 1
                    elif result['state'] == 'filtered':
                        self.filtered_ports.append(result)
                        self.scan_stats['filtered_ports'] += 1
                    else:
                        self.closed_ports.append(result)
                        self.scan_stats['closed_ports'] += 1
                
                except Exception as e:
                    # Log error but continue
                    error_result = {
                        'port': port,
                        'state': 'error',
                        'error': str(e)
                    }
                    self.filtered_ports.append(error_result)
        
        # Finalize statistics
        self.scan_stats['end_time'] = time.time()
        self.scan_stats['duration'] = self.scan_stats['end_time'] - self.scan_stats['start_time']
        
        # Sort results
        self.open_ports.sort(key=lambda x: x['port'])
        self.filtered_ports.sort(key=lambda x: x['port'])
        self.closed_ports.sort(key=lambda x: x['port'])
        
        return self.get_results()
    
    def get_results(self):
        """Get comprehensive scan results"""
        results = {
            'stats': self.scan_stats,
            'open_ports': self.open_ports,
            'filtered_ports': self.filtered_ports[:100],  # Limit filtered ports
            'closed_ports': self.closed_ports[:100],      # Limit closed ports
            'summary': self.get_summary()
        }
        return results
    
    def get_summary(self):
        """Get scan summary"""
        if not self.scan_stats:
            return {}
        
        summary = {
            'target': self.scan_stats.get('target', 'unknown'),
            'total_ports': self.scan_stats.get('total_ports', 0),
            'open_ports': len(self.open_ports),
            'filtered_ports': len(self.filtered_ports),
            'closed_ports': len(self.closed_ports),
            'duration': self.scan_stats.get('duration', 0),
            'ports_per_second': self.scan_stats.get('total_ports', 1) / max(self.scan_stats.get('duration', 1), 0.1)
        }
        
        # Risk assessment
        risky_ports = [p for p in self.open_ports if p['port'] in [21, 23, 135, 139, 445]]
        summary['risky_ports_found'] = len(risky_ports)
        
        if summary['open_ports'] == 0:
            summary['security_status'] = 'secure'
        elif summary['risky_ports_found'] > 0:
            summary['security_status'] = 'risky'
        else:
            summary['security_status'] = 'moderate'
        
        return summary
    
    def format_results(self, show_banners=False):
        """Format port scan results for display"""
        from ui.colors import colors
        
        if not self.scan_stats:
            return colors.colorize("No scan performed", "WARNING")
        
        lines = []
        lines.append(colors.colorize(f"Port Scan: {self.scan_stats['target']}", "HEADER"))
        lines.append(colors.colorize("─" * 70, "DIM"))
        
        # Statistics
        summary = self.get_summary()
        lines.append(f"Ports Scanned: {summary['total_ports']}")
        lines.append(f"Scan Duration: {summary['duration']:.2f}s")
        lines.append(f"Scan Speed: {summary['ports_per_second']:.1f} ports/sec")
        lines.append("")
        
        # Port counts with colors
        open_color = 'SUCCESS' if summary['open_ports'] == 0 else 'WARNING'
        lines.append(f"Open Ports:     {colors.colorize(str(summary['open_ports']), open_color)}")
        
        filtered_color = 'WARNING' if summary['filtered_ports'] > 0 else 'INFO'
        lines.append(f"Filtered Ports: {colors.colorize(str(summary['filtered_ports']), filtered_color)}")
        
        lines.append(f"Closed Ports:   {summary['closed_ports']}")
        
        # Security status
        lines.append("")
        status_color = {
            'secure': 'SUCCESS',
            'moderate': 'WARNING',
            'risky': 'ERROR'
        }.get(summary['security_status'], 'WARNING')
        
        lines.append(f"Security Status: {colors.colorize(summary['security_status'].upper(), status_color)}")
        
        if summary['risky_ports_found'] > 0:
            lines.append(colors.colorize(f"⚠ {summary['risky_ports_found']} risky ports found", "ERROR"))
        
        # Open ports details
        if self.open_ports:
            lines.append("")
            lines.append(colors.colorize("Open Ports:", "INFO"))
            lines.append(colors.colorize("─" * 70, "DIM"))
            
            # Table header
            header = f"{'Port':<8} {'Service':<20} {'Version/Banner':<30} {'State':<10}"
            lines.append(colors.colorize(header, "HEADER"))
            lines.append(colors.colorize("─" * 70, "DIM"))
            
            for result in self.open_ports:
                port = str(result['port']).ljust(8)
                
                service = result.get('service', 'unknown')
                if len(service) > 18:
                    service = service[:16] + ".."
                service = service.ljust(20)
                
                # Banner/version
                banner = result.get('banner', '') or result.get('version', '')
                if banner:
                    if len(banner) > 28:
                        banner = banner[:26] + ".."
                banner = banner.ljust(30)
                
                state = result.get('state', 'open').ljust(10)
                
                # Color code by service
                service_lower = service.lower()
                if any(word in service_lower for word in ['http', 'web', 'www']):
                    service_color = 'CYAN'
                elif any(word in service_lower for word in ['ssh', 'telnet', 'ftp']):
                    service_color = 'YELLOW'
                elif any(word in service_lower for word in ['sql', 'db', 'database']):
                    service_color = 'MAGENTA'
                elif any(word in service_lower for word in ['rdp', 'smb', 'netbios']):
                    service_color = 'ERROR'
                else:
                    service_color = 'INFO'
                
                line = f"{port} {colors.colorize(service, service_color)} {banner} {state}"
                lines.append(line)
        
        # Filtered ports (if any)
        if self.filtered_ports and len(self.filtered_ports) < 20:
            lines.append("")
            lines.append(colors.colorize("Filtered Ports (may be firewalled):", "WARNING"))
            filtered_ports = [str(r['port']) for r in self.filtered_ports[:10]]
            lines.append(f"  {', '.join(filtered_ports)}")
            if len(self.filtered_ports) > 10:
                lines.append(f"  ... and {len(self.filtered_ports) - 10} more")
        
        # Recommendations
        lines.append("")
        lines.append(colors.colorize("Recommendations:", "INFO"))
        
        if summary['open_ports'] == 0:
            lines.append("  • No open ports found - good security posture")
        elif summary['risky_ports_found'] > 0:
            lines.append("  • Close or secure risky ports (FTP, Telnet, SMB)")
            lines.append("  • Use SSH instead of Telnet")
            lines.append("  • Consider a firewall")
        else:
            lines.append("  • Ensure services are updated and secured")
            lines.append("  • Use strong authentication")
        
        return "\n".join(lines)
