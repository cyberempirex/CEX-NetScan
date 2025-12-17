#!/usr/bin/env python3
"""
Update Module
GitHub-based update checking and self-update
"""

import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

class UpdateChecker:
    """Check for updates and perform self-update"""
    
    def __init__(self):
        self.current_version = "2.0.0"
        self.github_repo = "cyberempirex/cex-netscan"
        self.latest_version = None
        self.update_available = False
        self.update_info = {}
    
    def check_available(self):
        """Check if updates are available"""
        try:
            # Get latest release info from GitHub API
            api_url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
            headers = {
                "User-Agent": "CEX-NetScan-Updater/2.0.0",
                "Accept": "application/vnd.github.v3+json"
            }
            
            req = Request(api_url, headers=headers)
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            self.latest_version = data.get("tag_name", "").lstrip("v")
            self.update_info = {
                "version": self.latest_version,
                "name": data.get("name", ""),
                "body": data.get("body", ""),
                "published_at": data.get("published_at", ""),
                "html_url": data.get("html_url", "")
            }
            
            # Compare versions
            if self._compare_versions(self.current_version, self.latest_version) < 0:
                self.update_available = True
                return True
            else:
                return False
        
        except URLError:
            # No internet or GitHub blocked
            return False
        except Exception as e:
            # Any other error
            return False
    
    def _compare_versions(self, v1, v2):
        """Compare version strings"""
        def parse_version(v):
            parts = []
            for part in v.split("."):
                try:
                    parts.append(int(part))
                except ValueError:
                    parts.append(0)
            return parts
        
        v1_parts = parse_version(v1)
        v2_parts = parse_version(v2)
        
        # Pad with zeros if needed
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        # Compare
        for i in range(max_len):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
        
        return 0
    
    def get_update_info(self):
        """Get detailed update information"""
        if not self.update_available:
            self.check_available()
        
        return self.update_info
    
    def perform_update(self):
        """Perform self-update"""
        if not self.update_available:
            return {"success": False, "message": "No update available"}
        
        try:
            # Get download URL for the latest release
            api_url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
            headers = {"User-Agent": "CEX-NetScan-Updater/2.0.0"}
            
            req = Request(api_url, headers=headers)
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            # Find source code download
            download_url = None
            for asset in data.get("assets", []):
                if asset.get("name", "").endswith(".zip"):
                    download_url = asset.get("browser_download_url")
                    break
            
            if not download_url:
                # Fallback to source code zip
                download_url = data.get("zipball_url")
            
            if not download_url:
                return {"success": False, "message": "No download URL found"}
            
            # Download update
            with tempfile.TemporaryDirectory() as tmpdir:
                # Download zip
                zip_path = os.path.join(tmpdir, "update.zip")
                self._download_file(download_url, zip_path)
                
                # Extract
                extract_path = os.path.join(tmpdir, "extracted")
                self._extract_zip(zip_path, extract_path)
                
                # Find extracted directory
                extracted_dirs = [d for d in os.listdir(extract_path) 
                                if os.path.isdir(os.path.join(extract_path, d))]
                
                if not extracted_dirs:
                    return {"success": False, "message": "No files in update"}
                
                update_dir = os.path.join(extract_path, extracted_dirs[0])
                
                # Backup current installation
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(os.path.dirname(current_dir))
                backup_dir = os.path.join(os.path.dirname(project_root), 
                                        f"cex_netscan_backup_{self.current_version}")
                
                # Create backup
                self._copy_directory(project_root, backup_dir)
                
                # Apply update
                self._copy_directory(update_dir, project_root)
                
                # Clean up backup if update successful
                # (Keep backup for safety)
                
                return {
                    "success": True,
                    "message": f"Updated to version {self.latest_version}",
                    "backup_location": backup_dir
                }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Update failed: {str(e)}"
            }
    
    def _download_file(self, url, destination):
        """Download file from URL"""
        headers = {"User-Agent": "CEX-NetScan-Updater/2.0.0"}
        req = Request(url, headers=headers)
        
        with urlopen(req, timeout=30) as response:
            with open(destination, 'wb') as f:
                f.write(response.read())
    
    def _extract_zip(self, zip_path, extract_path):
        """Extract zip file"""
        import zipfile
        os.makedirs(extract_path, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
    
    def _copy_directory(self, src, dst):
        """Copy directory recursively"""
        import shutil
        shutil.copytree(src, dst, dirs_exist_ok=True)
    
    def check_dependencies(self):
        """Check if all dependencies are available"""
        dependencies = [
            ("python", "3.6.0", "Python interpreter"),
            ("requests", "2.25.0", "HTTP library"),
            ("netifaces", "0.10.0", "Network interface info"),
        ]
        
        results = []
        
        for dep, min_version, description in dependencies:
            if dep == "python":
                current = sys.version_info
                required = tuple(map(int, min_version.split(".")))
                satisfied = current >= required
                version_str = f"{current.major}.{current.minor}.{current.micro}"
            else:
                try:
                    module = __import__(dep)
                    version_str = getattr(module, "__version__", "unknown")
                    
                    # Simple version comparison
                    satisfied = self._compare_versions(version_str, min_version) >= 0
                except ImportError:
                    satisfied = False
                    version_str = "not installed"
            
            results.append({
                "dependency": dep,
                "required": min_version,
                "installed": version_str,
                "satisfied": satisfied,
                "description": description
            })
        
        return results
    
    def format_update_info(self):
        """Format update information for display"""
        from ui.colors import colors
        
        if not self.update_available:
            return colors.colorize("You have the latest version", "SUCCESS")
        
        lines = []
        lines.append(colors.colorize("Update Available!", "INFO"))
        lines.append(colors.colorize("─" * 50, "DIM"))
        
        lines.append(f"Current Version: {colors.colorize(self.current_version, 'WARNING')}")
        lines.append(f"Latest Version:  {colors.colorize(self.latest_version, 'SUCCESS')}")
        
        if "name" in self.update_info:
            lines.append(f"Release: {self.update_info['name']}")
        
        if "body" in self.update_info and self.update_info["body"]:
            # Show first few lines of release notes
            lines.append("")
            lines.append(colors.colorize("Release Notes:", "HEADER"))
            notes = self.update_info["body"].split("\n")
            for note in notes[:5]:  # Show first 5 lines
                if note.strip():
                    lines.append(f"  • {note[:60]}{'...' if len(note) > 60 else ''}")
        
        lines.append("")
        lines.append(colors.colorize("To update:", "INFO"))
        lines.append("  1. Run: python cex_netscan.py --update")
        lines.append("  2. Or use the update option in settings")
        
        return "\n".join(lines)

def check_self_integrity():
    """Check if all required files are present"""
    required_files = [
        "cex_netscan.py",
        "core/__init__.py",
        "core/environment.py",
        "core/network_detect.py",
        "scans/port_scan.py",
        "ui/colors.py",
        "utils/logger.py"
    ]
    
    missing = []
    corrupted = []
    
    for filepath in required_files:
        if not os.path.exists(filepath):
            missing.append(filepath)
        else:
            # Check if file is readable and has content
            try:
                with open(filepath, 'r') as f:
                    content = f.read(100)  # Read first 100 chars
                    if len(content.strip()) == 0:
                        corrupted.append(filepath)
            except:
                corrupted.append(filepath)
    
    return {
        "missing": missing,
        "corrupted": corrupted,
        "valid": len(missing) == 0 and len(corrupted) == 0
    }
