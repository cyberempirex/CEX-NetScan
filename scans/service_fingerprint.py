#!/usr/bin/env python3
"""
Service Fingerprinting Module
Identify services running on open ports
"""

import socket
import re
import time

class ServiceFingerprinter:
    """Service detection and fingerprinting"""
    
    def __init__(self):
        self.service_db = self._load_service_database()
        self.banner_db = self._load_banner_patterns()
    
    def _load_service_database(self):
        """Load service port to name mapping"""
        # IANA well-known ports + common services
        services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1723: "pptp",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
            6379: "redis"
        }
        return services
    
    def _load_banner_patterns(self):
        """Load banner patterns for service identification"""
        patterns = {
            "ssh": [
                r"SSH-[0-9\.]+",
                r"OpenSSH_[0-9\.]+"
            ],
            "http": [
                r"HTTP/[0-9\.]+",
                r"Server: .+",
                r"Apache/[0-9\.]+",
                r"nginx/[0-9\.]+",
                r"IIS/[0-9\.]+"
            ],
            "ftp": [
                r"220 .*FTP",
                r"220 .*FileZilla",
                r"220 .*vsFTPd"
            ],
            "smtp": [
                r"220 .*SMTP",
                r"220 .*ESMTP",
                r"220 .*Postfix",
                r"220 .*Sendmail"
            ],
            "telnet": [
                r"Welcome",
                r"login:",
                r"Password:"
            ]
        }
        return patterns
    
    def identify_service(self, host, port, timeout=2):
        """
        Identify service running on a port
        
        Args:
            host: Target hostname or IP
            port: Port number
            timeout: Connection timeout
        
        Returns:
            dict: Service information
        """
        result = {
            "port": port,
            "name": "unknown",
            "version": "",
            "banner": "",
            "confidence": "low"
        }
        
        # First, check our port-based database
        if port in self.service_db:
            result["name"] = self.service_db[port]
            result["confidence"] = "medium"
        
        # Try to get banner for better identification
        banner = self._get_service_banner(host, port, timeout)
        if banner:
            result["banner"] = banner
            result["confidence"] = "high"
            
            # Try to extract service name from banner
            detected_service = self._analyze_banner(banner, port)
            if detected_service:
                result.update(detected_service)
        
        return result
    
    def _get_service_banner(self, host, port, timeout):
        """Get banner from service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect
            sock.connect((host, port))
            
            # Try to receive initial banner
            sock.settimeout(1)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # If no banner received, send probe based on port
            if not banner or len(banner.strip()) < 5:
                banner = self._send_service_probe(sock, port)
            
            sock.close()
            return banner.strip() if banner else None
            
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def _send_service_probe(self, sock, port):
        """Send appropriate probe based on port"""
        probes = {
            80: b"GET / HTTP/1.0\r\n\r\n",
            443: b"GET / HTTP/1.0\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\n\r\n",
            22: b"SSH-2.0-CEX-NetScan\r\n",
            21: b"USER anonymous\r\n",
            25: b"EHLO localhost\r\n",
            110: b"USER test\r\n",
            143: b"A001 LOGIN test test\r\n"
        }
        
        if port in probes:
            try:
                sock.send(probes[port])
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                return response
            except:
                pass
        
        return None
    
    def _analyze_banner(self, banner, port):
        """Analyze banner to identify service"""
        banner_lower = banner.lower()
        result = {}
        
        # HTTP servers
        if "http/" in banner_lower or "server:" in banner:
            result["name"] = "http"
            
            # Extract server version
            server_match = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if server_match:
                result["version"] = server_match.group(1).strip()
            
            # Detect specific servers
            if "apache" in banner_lower:
                result["name"] = "apache"
                apache_match = re.search(r"Apache/([0-9\.]+)", banner, re.IGNORECASE)
                if apache_match:
                    result["version"] = f"Apache {apache_match.group(1)}"
            
            elif "nginx" in banner_lower:
                result["name"] = "nginx"
                nginx_match = re.search(r"nginx/([0-9\.]+)", banner, re.IGNORECASE)
                if nginx_match:
                    result["version"] = f"nginx {nginx_match.group(1)}"
            
            elif "iis" in banner_lower:
                result["name"] = "iis"
                iis_match = re.search(r"IIS/([0-9\.]+)", banner, re.IGNORECASE)
                if iis_match:
                    result["version"] = f"IIS {iis_match.group(1)}"
        
        # SSH servers
        elif "ssh-" in banner_lower:
            result["name"] = "ssh"
            ssh_match = re.search(r"(SSH-[0-9\.]+-[0-9\.]+)", banner, re.IGNORECASE)
            if ssh_match:
                result["version"] = ssh_match.group(1)
        
        # FTP servers
        elif "220" in banner and ("ftp" in banner_lower or "filezilla" in banner_lower):
            result["name"] = "ftp"
            # Extract FTP server info
            ftp_match = re.search(r"220[^-]*-([^\r\n]+)", banner, re.IGNORECASE)
            if ftp_match:
                result["version"] = ftp_match.group(1).strip()
        
        # SMTP servers
        elif "220" in banner and ("smtp" in banner_lower or "esmtp" in banner_lower):
            result["name"] = "smtp"
            # Extract SMTP server info
            smtp_match = re.search(r"220[^-]*-([^\r\n]+)", banner, re.IGNORECASE)
            if smtp_match:
                result["version"] = smtp_match.group(1).strip()
        
        # Generic patterns
        elif port == 3389 and "mstshash" in banner_lower:
            result["name"] = "rdp"
            result["version"] = "Remote Desktop Protocol"
        
        elif "mysql" in banner_lower:
            result["name"] = "mysql"
            mysql_match = re.search(r"([0-9\.]+)", banner)
            if mysql_match:
                result["version"] = f"MySQL {mysql_match.group(1)}"
        
        return result if result else None
    
    def get_service_info(self, service_name):
        """Get information about a service"""
        service_info = {
            "name": service_name,
            "description": "",
            "default_port": "",
            "security_risk": "unknown",
            "recommendations": []
        }
        
        # Service descriptions
        descriptions = {
            "ssh": "Secure Shell - encrypted remote access",
            "telnet": "Telnet - unencrypted remote access (insecure)",
            "ftp": "File Transfer Protocol - file transfer",
            "http": "HTTP Web Server",
            "https": "HTTPS Web Server (encrypted)",
            "rdp": "Remote Desktop Protocol - Windows remote access",
            "smb": "Server Message Block - Windows file sharing",
            "mysql": "MySQL Database",
            "postgresql": "PostgreSQL Database",
            "vnc": "Virtual Network Computing - remote desktop",
            "redis": "Redis in-memory database"
        }
        
        # Default ports
        default_ports = {
            "ssh": 22,
            "telnet": 23,
            "ftp": 21,
            "http": 80,
            "https": 443,
            "rdp": 3389,
            "smb": 445,
            "mysql": 3306,
            "postgresql": 5432,
            "vnc": 5900,
            "redis": 6379
        }
        
        # Security risks
        security_risks = {
            "telnet": "high",
            "ftp": "high",
            "rdp": "medium",
            "smb": "high",
            "vnc": "medium",
            "ssh": "low",
            "https": "low",
            "mysql": "medium",
            "postgresql": "medium",
            "redis": "high"
        }
        
        # Recommendations
        recommendations = {
            "telnet": ["Replace with SSH", "Disable if not needed"],
            "ftp": ["Use SFTP or FTPS", "Disable anonymous login"],
            "rdp": ["Use VPN", "Enable Network Level Authentication"],
            "smb": ["Use SMB3 with encryption", "Disable SMB1"],
            "vnc": ["Use VNC over SSH tunnel", "Enable authentication"],
            "ssh": ["Use key-based authentication", "Disable root login"],
            "mysql": ["Use strong passwords", "Enable SSL", "Restrict network access"],
            "redis": ["Enable authentication", "Bind to localhost only", "Use SSL"]
        }
        
        if service_name in descriptions:
            service_info["description"] = descriptions[service_name]
        
        if service_name in default_ports:
            service_info["default_port"] = default_ports[service_name]
        
        if service_name in security_risks:
            service_info["security_risk"] = security_risks[service_name]
        
        if service_name in recommendations:
            service_info["recommendations"] = recommendations[service_name]
        
        return service_info
    
    def format_service_info(self, service_name):
        """Format service information for display"""
        from ui.colors import colors
        
        info = self.get_service_info(service_name)
        
        lines = []
        lines.append(colors.colorize(f"Service: {service_name.upper()}", "HEADER"))
        lines.append(colors.colorize("─" * 50, "DIM"))
        
        # Basic info
        if info["description"]:
            lines.append(f"Description: {info['description']}")
        
        if info["default_port"]:
            lines.append(f"Default Port: {info['default_port']}")
        
        # Security risk with color
        risk = info["security_risk"]
        risk_color = {
            "high": "ERROR",
            "medium": "WARNING",
            "low": "SUCCESS",
            "unknown": "WARNING"
        }.get(risk, "WARNING")
        
        lines.append(f"Security Risk: {colors.colorize(risk.upper(), risk_color)}")
        
        # Recommendations
        if info["recommendations"]:
            lines.append("")
            lines.append(colors.colorize("Recommendations:", "INFO"))
            for rec in info["recommendations"]:
                lines.append(f"  • {rec}")
        
        return "\n".join(lines)
