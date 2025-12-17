#!/usr/bin/env python3
"""
Validation Module
Input validation and sanitization
"""

import re
import socket
import ipaddress

class InputValidator:
    """Validate user inputs for security and correctness"""
    
    @staticmethod
    def validate_ip(ip_str):
        """Validate IP address format"""
        try:
            # Check if it's a valid IPv4 or IPv6 address
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    @staticmethod
    def validate_port_range(port_range):
        """Validate port range specification"""
        patterns = [
            r'^\d+$',                      # Single port: 80
            r'^\d+-\d+$',                  # Range: 1-1000
            r'^\d+(,\d+)*$',               # List: 80,443,8080
            r'^(common|all)$',             # Keywords
        ]
        
        for pattern in patterns:
            if re.match(pattern, port_range):
                return True
        
        return False
    
    @staticmethod
    def parse_port_range(port_spec):
        """Parse port range specification to list of ports"""
        ports = []
        
        try:
            # Single port
            if re.match(r'^\d+$', port_spec):
                port = int(port_spec)
                if 1 <= port <= 65535:
                    return [port]
            
            # Range
            elif '-' in port_spec:
                start_str, end_str = port_spec.split('-')
                start = int(start_str.strip())
                end = int(end_str.strip())
                
                if 1 <= start <= 65535 and 1 <= end <= 65535:
                    if start <= end:
                        return list(range(start, end + 1))
                    else:
                        return list(range(end, start + 1))
            
            # List
            elif ',' in port_spec:
                parts = port_spec.split(',')
                for part in parts:
                    port = part.strip()
                    if port.isdigit():
                        port_num = int(port)
                        if 1 <= port_num <= 65535:
                            ports.append(port_num)
                return ports
            
            # Keywords
            elif port_spec.lower() == 'common':
                return [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389, 8080]
            elif port_spec.lower() == 'all':
                return list(range(1, 1001))  # Limit to first 1000 ports
        
        except:
            pass
        
        return []
    
    @staticmethod
    def validate_hostname(hostname):
        """Validate hostname format"""
        if len(hostname) > 255:
            return False
        
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        
        allowed = re.compile(r"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)
        
        return all(allowed.match(x) for x in hostname.split("."))
    
    @staticmethod
    def validate_mac_address(mac):
        """Validate MAC address format"""
        patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
            r'^([0-9A-Fa-f]{12})$'
        ]
        
        for pattern in patterns:
            if re.match(pattern, mac):
                return True
        
        return False
    
    @staticmethod
    def validate_cidr(cidr):
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to prevent path traversal"""
        # Remove directory components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        dangerous = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250 - len(ext)] + ext
        
        return filename
    
    @staticmethod
    def validate_email(email):
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
        return re.match(pattern, url, re.IGNORECASE) is not None

def validate_scan_target(target):
    """Comprehensive target validation for scanning"""
    results = {
        "valid": False,
        "type": "unknown",
        "resolved_ip": None,
        "warnings": [],
        "errors": []
    }
    
    # Check if it's an IP address
    if InputValidator.validate_ip(target):
        results["type"] = "ip_address"
        results["resolved_ip"] = target
        
        # Check if it's a private IP
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private:
                results["valid"] = True
            elif ip.is_loopback:
                results["valid"] = True
                results["warnings"].append("Loopback address (localhost)")
            elif ip.is_multicast:
                results["errors"].append("Multicast addresses cannot be scanned")
            elif ip.is_reserved:
                results["warnings"].append("Reserved IP address")
            else:
                # Public IP - warn user
                results["valid"] = True
                results["warnings"].append("Public IP address - ensure you have permission")
        
        except:
            results["errors"].append("Invalid IP address")
    
    # Check if it's a hostname
    elif InputValidator.validate_hostname(target):
        results["type"] = "hostname"
        
        try:
            # Try to resolve
            ip = socket.gethostbyname(target)
            results["resolved_ip"] = ip
            results["valid"] = True
            
            # Check if resolved IP is private
            if InputValidator.validate_ip(ip):
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    results["warnings"].append(f"Resolves to public IP: {ip}")
        
        except socket.gaierror:
            results["errors"].append("Cannot resolve hostname")
    
    # Check if it's a CIDR range
    elif InputValidator.validate_cidr(target):
        results["type"] = "cidr_range"
        
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 256:
                results["warnings"].append(f"Large network range: {network.num_addresses} hosts")
            
            results["valid"] = True
        
        except:
            results["errors"].append("Invalid CIDR notation")
    
    else:
        results["errors"].append("Invalid target format")
    
    return results

def validate_scan_parameters(target, ports, timeout):
    """Validate all scan parameters"""
    validation_results = {
        "target": validate_scan_target(target),
        "ports_valid": InputValidator.validate_port_range(ports),
        "timeout_valid": isinstance(timeout, (int, float)) and 0.1 <= timeout <= 30,
        "overall_valid": True,
        "warnings": [],
        "errors": []
    }
    
    # Target validation
    if not validation_results["target"]["valid"]:
        validation_results["overall_valid"] = False
        validation_results["errors"].extend(validation_results["target"]["errors"])
    
    validation_results["warnings"].extend(validation_results["target"]["warnings"])
    
    # Port validation
    if not validation_results["ports_valid"]:
        validation_results["overall_valid"] = False
        validation_results["errors"].append("Invalid port specification")
    
    # Timeout validation
    if not validation_results["timeout_valid"]:
        validation_results["overall_valid"] = False
        validation_results["errors"].append("Timeout must be between 0.1 and 30 seconds")
    
    return validation_results

# Import os for filename sanitization
import os

# Export convenience functions
validate_ip = InputValidator.validate_ip
validate_port = InputValidator.validate_port
validate_port_range = InputValidator.validate_port_range
parse_port_range = InputValidator.parse_port_range
sanitize_filename = InputValidator.sanitize_filename
