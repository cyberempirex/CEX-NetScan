#!/usr/bin/env python3
"""
DNS Information Module
Real DNS resolution and analysis
"""

import socket
import dns.resolver
import dns.reversename
from urllib.parse import urlparse

class DNSAnalyzer:
    """DNS resolution and analysis"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def get_dns_servers(self):
        """Get current DNS servers"""
        servers = []
        try:
            for server in self.resolver.nameservers:
                servers.append(str(server))
        except:
            # Fallback to system DNS
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            server = line.split()[1]
                            servers.append(server)
            except:
                pass
        
        return servers
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP addresses"""
        results = {
            "hostname": hostname,
            "ipv4": [],
            "ipv6": [],
            "error": None
        }
        
        try:
            # Try A records (IPv4)
            try:
                answers = self.resolver.resolve(hostname, 'A')
                for rdata in answers:
                    results["ipv4"].append(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # Try AAAA records (IPv6)
            try:
                answers = self.resolver.resolve(hostname, 'AAAA')
                for rdata in answers:
                    results["ipv6"].append(str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            if not results["ipv4"] and not results["ipv6"]:
                results["error"] = "No DNS records found"
        
        except dns.resolver.NXDOMAIN:
            results["error"] = "Domain does not exist"
        except dns.resolver.Timeout:
            results["error"] = "DNS resolution timeout"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def reverse_dns(self, ip_address):
        """Perform reverse DNS lookup"""
        results = {
            "ip": ip_address,
            "hostnames": [],
            "error": None
        }
        
        try:
            addr = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(addr, 'PTR')
            
            for rdata in answers:
                results["hostnames"].append(str(rdata))
        
        except dns.resolver.NXDOMAIN:
            results["error"] = "No reverse DNS record"
        except dns.resolver.Timeout:
            results["error"] = "Reverse DNS timeout"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def get_mx_records(self, domain):
        """Get MX records for a domain"""
        results = {
            "domain": domain,
            "mx_records": [],
            "error": None
        }
        
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                results["mx_records"].append({
                    "preference": rdata.preference,
                    "exchange": str(rdata.exchange)
                })
        
        except dns.resolver.NoAnswer:
            results["error"] = "No MX records found"
        except dns.resolver.NXDOMAIN:
            results["error"] = "Domain does not exist"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def get_txt_records(self, domain):
        """Get TXT records for a domain"""
        results = {
            "domain": domain,
            "txt_records": [],
            "error": None
        }
        
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    results["txt_records"].append(txt_string.decode('utf-8'))
        
        except dns.resolver.NoAnswer:
            results["error"] = "No TXT records found"
        except:
            results["error"] = "Failed to get TXT records"
        
        return results
    
    def test_dns_resolution(self, test_domains=None):
        """Test DNS resolution for common domains"""
        if test_domains is None:
            test_domains = [
                "google.com",
                "github.com",
                "cloudflare.com",
                "example.com",
                "localhost"
            ]
        
        results = {
            "working": False,
            "domains_tested": len(test_domains),
            "domains_resolved": 0,
            "detailed_results": []
        }
        
        for domain in test_domains:
            domain_result = {
                "domain": domain,
                "resolved": False,
                "ipv4": [],
                "ipv6": [],
                "error": None
            }
            
            try:
                # Try IPv4
                socket.getaddrinfo(domain, 80, socket.AF_INET)
                domain_result["resolved"] = True
                domain_result["ipv4"] = ["Resolved"]
                
                # Count successful resolution
                results["domains_resolved"] += 1
            
            except socket.gaierror as e:
                domain_result["error"] = str(e)
            
            results["detailed_results"].append(domain_result)
        
        results["working"] = results["domains_resolved"] > 0
        results["success_rate"] = (results["domains_resolved"] / results["domains_tested"]) * 100
        
        return results
    
    def format_dns_info(self, hostname):
        """Get comprehensive DNS information for a hostname"""
        results = {
            "hostname": hostname,
            "dns_servers": self.get_dns_servers(),
            "resolution": self.resolve_hostname(hostname),
            "mx_records": self.get_mx_records(hostname),
            "txt_records": self.get_txt_records(hostname),
            "test_results": self.test_dns_resolution()
        }
        
        # Add reverse DNS for each IP
        if results["resolution"]["ipv4"]:
            results["reverse_dns"] = []
            for ip in results["resolution"]["ipv4"][:3]:  # Limit to 3
                reverse = self.reverse_dns(ip)
                results["reverse_dns"].append(reverse)
        
        return results
    
    def display_dns_info(self, hostname):
        """Display DNS information in formatted output"""
        from ui.colors import colors
        
        info = self.format_dns_info(hostname)
        
        lines = []
        lines.append(colors.colorize(f"DNS Analysis: {hostname}", "HEADER"))
        lines.append(colors.colorize("─" * 60, "DIM"))
        
        # DNS Servers
        lines.append(colors.colorize("DNS Servers:", "INFO"))
        for server in info["dns_servers"][:5]:  # Show first 5
            lines.append(f"  • {server}")
        
        # Resolution results
        resolution = info["resolution"]
        lines.append("")
        lines.append(colors.colorize("Resolution:", "INFO"))
        
        if resolution["error"]:
            lines.append(f"  Error: {colors.colorize(resolution['error'], 'ERROR')}")
        else:
            if resolution["ipv4"]:
                lines.append("  IPv4 Addresses:")
                for ip in resolution["ipv4"][:3]:  # Show first 3
                    lines.append(f"    • {ip}")
            
            if resolution["ipv6"]:
                lines.append("  IPv6 Addresses:")
                for ip in resolution["ipv6"][:3]:  # Show first 3
                    lines.append(f"    • {ip}")
        
        # MX Records
        mx = info["mx_records"]
        if not mx["error"] and mx["mx_records"]:
            lines.append("")
            lines.append(colors.colorize("Mail Servers (MX):", "INFO"))
            for record in sorted(mx["mx_records"], key=lambda x: x["preference"])[:5]:
                lines.append(f"  • {record['exchange']} (Priority: {record['preference']})")
        
        # Reverse DNS
        if "reverse_dns" in info:
            lines.append("")
            lines.append(colors.colorize("Reverse DNS:", "INFO"))
            for reverse in info["reverse_dns"]:
                if not reverse["error"] and reverse["hostnames"]:
                    for hostname in reverse["hostnames"][:2]:  # Show first 2
                        lines.append(f"  • {reverse['ip']} → {hostname}")
        
        # TXT Records
        txt = info["txt_records"]
        if not txt["error"] and txt["txt_records"]:
            lines.append("")
            lines.append(colors.colorize("TXT Records:", "INFO"))
            for record in txt["txt_records"][:3]:  # Show first 3
                if len(record) > 50:
                    record = record[:47] + "..."
                lines.append(f"  • {record}")
        
        # DNS Test Results
        test = info["test_results"]
        lines.append("")
        lines.append(colors.colorize("DNS Health Test:", "INFO"))
        
        if test["working"]:
            success_color = "SUCCESS" if test["success_rate"] > 75 else "WARNING"
            lines.append(f"  Status: {colors.colorize('WORKING', success_color)}")
            lines.append(f"  Success Rate: {colors.colorize(f'{test['success_rate']:.1f}%', success_color)}")
            lines.append(f"  Resolved: {test['domains_resolved']}/{test['domains_tested']}")
        else:
            lines.append(f"  Status: {colors.colorize('NOT WORKING', 'ERROR')}")
        
        return "\n".join(lines)
