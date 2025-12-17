#!/usr/bin/env python3
"""
Export Module
Save scan results to files
"""

import json
import csv
import os
import time
from datetime import datetime

class ExportManager:
    """Manage export of scan results"""
    
    def __init__(self, base_dir="exports"):
        self.base_dir = base_dir
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Ensure export directory exists"""
        os.makedirs(self.base_dir, exist_ok=True)
    
    def generate_filename(self, scan_type, format="json"):
        """Generate timestamped filename"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cex_netscan_{scan_type}_{timestamp}.{format}"
        return os.path.join(self.base_dir, filename)
    
    def export_json(self, data, filename=None):
        """Export data to JSON file"""
        if filename is None:
            filename = self.generate_filename("scan", "json")
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            return {
                "success": True,
                "filename": filename,
                "size": os.path.getsize(filename)
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def export_txt(self, data, filename=None):
        """Export data to text file"""
        if filename is None:
            filename = self.generate_filename("scan", "txt")
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                self._write_text_data(f, data)
            
            return {
                "success": True,
                "filename": filename,
                "size": os.path.getsize(filename)
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _write_text_data(self, file, data, indent=0):
        """Recursively write data as text"""
        indent_str = "  " * indent
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    file.write(f"{indent_str}{key}:\n")
                    self._write_text_data(file, value, indent + 1)
                else:
                    file.write(f"{indent_str}{key}: {value}\n")
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    file.write(f"{indent_str}[{i}]:\n")
                    self._write_text_data(file, item, indent + 1)
                else:
                    file.write(f"{indent_str}• {item}\n")
        
        else:
            file.write(f"{indent_str}{data}\n")
    
    def export_csv(self, data, filename=None):
        """Export data to CSV file"""
        if filename is None:
            filename = self.generate_filename("scan", "csv")
        
        try:
            # Flatten data for CSV
            flattened = self._flatten_for_csv(data)
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if flattened:
                    writer = csv.DictWriter(f, fieldnames=flattened[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened)
            
            return {
                "success": True,
                "filename": filename,
                "size": os.path.getsize(filename)
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _flatten_for_csv(self, data):
        """Flatten data structure for CSV export"""
        results = []
        
        if isinstance(data, dict):
            # Handle network discovery data
            if 'devices' in data:
                for device in data['devices']:
                    row = {
                        'type': 'device',
                        'ip': device.get('ip', ''),
                        'mac': device.get('mac', ''),
                        'vendor': device.get('vendor', ''),
                        'source': device.get('source', '')
                    }
                    results.append(row)
            
            # Handle port scan data
            elif 'open_ports' in data:
                for port in data['open_ports']:
                    row = {
                        'type': 'open_port',
                        'port': port.get('port', ''),
                        'service': port.get('service', ''),
                        'state': port.get('state', ''),
                        'banner': port.get('banner', '')[:100]  # Limit banner length
                    }
                    results.append(row)
            
            # Generic flattening
            else:
                row = {}
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        row[key] = str(value)[:100]  # Limit length
                    else:
                        row[key] = value
                results.append(row)
        
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    row = {}
                    for key, value in item.items():
                        if isinstance(value, (dict, list)):
                            row[key] = str(value)[:100]
                        else:
                            row[key] = value
                    results.append(row)
        
        return results
    
    def export_scan_results(self, scan_data, format="auto"):
        """Export scan results in specified format"""
        if format == "auto":
            format = "json"
        
        if format == "json":
            return self.export_json(scan_data)
        elif format == "txt":
            return self.export_txt(scan_data)
        elif format == "csv":
            return self.export_csv(scan_data)
        else:
            return {
                "success": False,
                "error": f"Unsupported format: {format}"
            }
    
    def list_exports(self):
        """List all exported files"""
        try:
            files = []
            for filename in os.listdir(self.base_dir):
                if filename.startswith("cex_netscan_"):
                    filepath = os.path.join(self.base_dir, filename)
                    stat = os.stat(filepath)
                    
                    files.append({
                        "name": filename,
                        "path": filepath,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime)
                    })
            
            return sorted(files, key=lambda x: x["modified"], reverse=True)
        
        except Exception as e:
            return []
    
    def cleanup_old_exports(self, max_age_days=30):
        """Clean up old export files"""
        cutoff = time.time() - (max_age_days * 24 * 60 * 60)
        deleted = []
        
        try:
            for filename in os.listdir(self.base_dir):
                if filename.startswith("cex_netscan_"):
                    filepath = os.path.join(self.base_dir, filename)
                    
                    if os.stat(filepath).st_mtime < cutoff:
                        os.remove(filepath)
                        deleted.append(filename)
            
            return deleted
        
        except Exception as e:
            return []
