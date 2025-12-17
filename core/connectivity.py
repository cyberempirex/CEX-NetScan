#!/usr/bin/env python3
"""
Connectivity Detection Module
Real online/offline status detection
"""

import socket
import time
import threading
from queue import Queue
from urllib.request import urlopen, Request
from urllib.error import URLError

class ConnectivityTester:
    """Test and verify network connectivity"""
    
    def __init__(self):
        self.test_servers = [
            {"name": "Cloudflare DNS", "host": "1.1.1.1", "port": 53},
            {"name": "Google DNS", "host": "8.8.8.8", "port": 53},
            {"name": "OpenDNS", "host": "208.67.222.222", "port": 53},
            {"name": "Quad9", "host": "9.9.9.9", "port": 53}
        ]
        
        self.http_test_urls = [
            "http://httpbin.org/get",
            "http://checkip.amazonaws.com",
            "http://icanhazip.com"
        ]
        
        self.results = {}
    
    def test_basic_connectivity(self, timeout=3):
        """Test basic TCP connectivity to common services"""
        results = {
            "status": "offline",
            "reachable_servers": [],
            "latency": None,
            "errors": []
        }
        
        reachable = []
        latencies = []
        
        def test_server(server):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((server["host"], server["port"]))
                elapsed = (time.time() - start) * 1000  # ms
                sock.close()
                
                if result == 0:
                    reachable.append(server["name"])
                    latencies.append(elapsed)
                    return True
            except Exception as e:
                pass
            return False
        
        # Test multiple servers in parallel
        threads = []
        for server in self.test_servers:
            thread = threading.Thread(target=test_server, args=(server,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join(timeout=timeout + 1)
        
        if reachable:
            results["status"] = "online"
            results["reachable_servers"] = reachable
            if latencies:
                results["latency"] = sum(latencies) / len(latencies)
        
        return results
    
    def test_dns_resolution(self, timeout=3):
        """Test DNS resolution capability"""
        test_domains = [
            "google.com",
            "github.com",
            "cloudflare.com",
            "example.com"
        ]
        
        results = {
            "working": False,
            "resolved_domains": [],
            "failed_domains": [],
            "dns_servers": []
        }
        
        # Get current DNS servers
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            results["dns_servers"] = [str(server) for server in resolver.nameservers]
        except:
            pass
        
        # Test resolution
        for domain in test_domains:
            try:
                socket.gethostbyname(domain)
                results["resolved_domains"].append(domain)
            except socket.gaierror:
                results["failed_domains"].append(domain)
        
        results["working"] = len(results["resolved_domains"]) > 0
        return results
    
    def test_http_connectivity(self, timeout=3):
        """Test HTTP/HTTPS connectivity"""
        results = {
            "http_working": False,
            "https_working": False,
            "public_ip": None,
            "user_agent": "CEX-NetScan/2.0.0"
        }
        
        # Test HTTP
        for url in self.http_test_urls[:2]:
            try:
                req = Request(url, headers={"User-Agent": results["user_agent"]})
                with urlopen(req, timeout=timeout) as response:
                    if response.status == 200:
                        results["http_working"] = True
                        # Try to get public IP
                        if "ip" in url:
                            ip = response.read().decode('utf-8').strip()
                            if self._validate_ip(ip):
                                results["public_ip"] = ip
                        break
            except:
                continue
        
        # Test HTTPS
        https_urls = [
            "https://1.1.1.1/",
            "https://www.google.com/"
        ]
        
        for url in https_urls:
            try:
                req = Request(url, headers={"User-Agent": results["user_agent"]})
                with urlopen(req, timeout=timeout) as response:
                    if response.status in [200, 301, 302]:
                        results["https_working"] = True
                        break
            except:
                continue
        
        return results
    
    def _validate_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def get_comprehensive_status(self, timeout=3):
        """Get comprehensive connectivity status"""
        results = {}
        
        # Basic TCP connectivity
        basic = self.test_basic_connectivity(timeout)
        results.update(basic)
        
        if basic["status"] == "online":
            # DNS resolution
            dns = self.test_dns_resolution(timeout)
            results.update({"dns": dns})
            
            # HTTP/HTTPS
            http = self.test_http_connectivity(timeout)
            results.update(http)
        
        # Determine overall status
        if basic["status"] == "offline":
            results["overall_status"] = "offline"
            results["status_description"] = "No network connectivity detected"
        elif not results.get("dns", {}).get("working", False):
            results["overall_status"] = "limited"
            results["status_description"] = "Connected but DNS not working"
        elif not results.get("http_working", False):
            results["overall_status"] = "partial"
            results["status_description"] = "Connected but HTTP limited"
        else:
            results["overall_status"] = "full"
            results["status_description"] = "Full internet connectivity"
        
        self.results = results
        return results
    
    def format_results(self):
        """Format connectivity results for display"""
        from ui.colors import colors
        
        if not self.results:
            self.get_comprehensive_status()
        
        lines = []
        lines.append(colors.colorize("Connectivity Status", "HEADER"))
        lines.append(colors.colorize("─" * 40, "DIM"))
        
        # Overall status
        status = self.results.get("overall_status", "unknown")
        status_color = {
            "full": "SUCCESS",
            "partial": "WARNING",
            "limited": "WARNING",
            "offline": "ERROR"
        }.get(status, "WARNING")
        
        lines.append(f"Status:     {colors.colorize(status.upper(), status_color)}")
        lines.append(f"Description: {self.results.get('status_description', 'Unknown')}")
        
        # Details
        if self.results["status"] == "online":
            lines.append("")
            lines.append(colors.colorize("Details:", "INFO"))
            
            # Reachable servers
            servers = self.results.get("reachable_servers", [])
            if servers:
                lines.append(f"Reachable:  {', '.join(servers[:3])}")
            
            # Latency
            latency = self.results.get("latency")
            if latency:
                latency_color = "SUCCESS" if latency < 100 else "WARNING"
                lines.append(f"Latency:    {colors.colorize(f'{latency:.0f}ms', latency_color)}")
            
            # DNS
            dns = self.results.get("dns", {})
            if dns.get("working"):
                resolved = len(dns.get("resolved_domains", []))
                lines.append(f"DNS:        {colors.colorize(f'Working ({resolved}/4)', 'SUCCESS')}")
            else:
                lines.append(f"DNS:        {colors.colorize('Not working', 'ERROR')}")
            
            # HTTP/HTTPS
            if self.results.get("http_working"):
                lines.append(f"HTTP:       {colors.colorize('Working', 'SUCCESS')}")
            if self.results.get("https_working"):
                lines.append(f"HTTPS:      {colors.colorize('Working', 'SUCCESS')}")
            
            # Public IP
            public_ip = self.results.get("public_ip")
            if public_ip:
                lines.append(f"Public IP:  {public_ip}")
        
        return "\n".join(lines)
