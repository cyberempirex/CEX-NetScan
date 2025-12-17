#!/usr/bin/env python3
"""
CEX-NetScan - Professional Color Scheme
Author: CyberEmpireX
"""

import sys
import os

class ColorSystem:
    """Professional color system with auto-detection for terminal support"""
    
    # ANSI color codes
    COLORS = {
        # Status colors
        'INFO': '\033[96m',      # Cyan for information
        'SUCCESS': '\033[92m',   # Green for success (used sparingly)
        'WARNING': '\033[93m',   # Yellow for warnings
        'ERROR': '\033[91m',     # Red for critical errors only
        'DANGER': '\033[31;1m',  # Bright red for immediate danger
        
        # UI colors
        'TITLE': '\033[94;1m',   # Bright blue for titles
        'HEADER': '\033[95m',    # Magenta for headers
        'MENU': '\033[97m',      # White for menu items
        'DISABLED': '\033[90m',  # Grey for disabled options
        'HIGHLIGHT': '\033[97;1m', # Bright white for highlights
        'DIM': '\033[2m',        # Dimmed text
        
        # Scan result colors
        'OPEN_PORT': '\033[92;1m',  # Bright green for open ports
        'FILTERED_PORT': '\033[93m', # Yellow for filtered
        'CLOSED_PORT': '\033[90m',  # Grey for closed
        'HOST_UP': '\033[92m',      # Green for live hosts
        'HOST_DOWN': '\033[90m',    # Grey for dead hosts
        'SERVICE': '\033[96m',      # Cyan for service names
        
        # Reset
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
    }
    
    def __init__(self):
        """Initialize color system with terminal detection"""
        self.supports_color = self._detect_color_support()
        self.is_dark_bg = self._detect_background()
    
    def _detect_color_support(self):
        """Detect if terminal supports colors"""
        # Check for NO_COLOR environment variable
        if os.environ.get('NO_COLOR'):
            return False
        
        # Check if we're in a terminal
        if not sys.stdout.isatty():
            return False
        
        # Check platform-specific color support
        if sys.platform.startswith('win'):
            # Windows color support check
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # Enable virtual terminal processing on Windows 10+
                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                mode = ctypes.c_ulong()
                if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                    kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
                    return True
                return False
            except:
                return False
        else:
            # Unix-like systems
            try:
                import curses
                curses.setupterm()
                return curses.tigetnum('colors') > 0
            except:
                # Assume color support
                return True
    
    def _detect_background(self):
        """Try to detect terminal background color (dark/light)"""
        # Default to dark for security tools
        return True  # Dark background
    
    def colorize(self, text, color_name):
        """Apply color if supported, return plain text otherwise"""
        if not self.supports_color:
            return text
        
        color_code = self.COLORS.get(color_name.upper(), '')
        reset_code = self.COLORS['RESET']
        
        return f"{color_code}{text}{reset_code}"
    
    def print_status(self, status, message):
        """Print with appropriate status color"""
        status_colors = {
            'online': 'SUCCESS',
            'offline': 'ERROR',
            'limited': 'WARNING',
            'protected': 'INFO',
            'vulnerable': 'DANGER',
            'scanning': 'INFO',
            'complete': 'SUCCESS',
            'failed': 'ERROR',
        }
        
        color = status_colors.get(status.lower(), 'INFO')
        status_text = self.colorize(f"[{status.upper()}]", color)
        print(f"{status_text} {message}")
    
    def format_table(self, headers, rows, align=None):
        """Format data as a table with colors"""
        if not rows:
            return ""
        
        # Calculate column widths
        col_widths = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build table
        result = []
        
        # Header
        header_line = "  ".join(
            self.colorize(str(h).ljust(w), 'HEADER') 
            for h, w in zip(headers, col_widths)
        )
        result.append(header_line)
        
        # Separator
        sep = self.colorize("─" * (sum(col_widths) + len(headers) * 2), 'DIM')
        result.append(sep)
        
        # Rows
        for row in rows:
            row_line = "  ".join(
                str(cell).ljust(w) for cell, w in zip(row, col_widths)
            )
            result.append(row_line)
        
        return "\n".join(result)
    
    def progress_bar(self, current, total, width=40, label=""):
        """Create a progress bar with colors"""
        if not self.supports_color:
            return f"{label} [{current}/{total}]"
        
        percent = current / total
        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)
        
        # Color based on progress
        if percent < 0.3:
            color = 'ERROR'
        elif percent < 0.7:
            color = 'WARNING'
        else:
            color = 'SUCCESS'
        
        bar_colored = self.colorize(bar, color)
        percent_text = self.colorize(f"{percent:.1%}", color)
        
        return f"{label} [{bar_colored}] {percent_text}"
    
    def create_warning_box(self, title, message, level="warning"):
        """Create a colored warning/notice box"""
        if not self.supports_color:
            border = "*" * 60
            return f"\n{border}\n{title}\n{message}\n{border}\n"
        
        color_map = {
            "info": "INFO",
            "warning": "WARNING", 
            "error": "ERROR",
            "danger": "DANGER"
        }
        color = color_map.get(level.lower(), "WARNING")
        
        # Create box
        width = 60
        border_char = "═"
        top_border = self.colorize(border_char * width, color)
        bottom_border = self.colorize(border_char * width, color)
        
        title_line = self.colorize(f"⚠ {title.upper()}", color)
        
        # Wrap message
        import textwrap
        wrapped = textwrap.fill(message, width=width-4)
        message_lines = wrapped.split('\n')
        
        box = f"\n{top_border}"
        box += f"\n{title_line}"
        box += f"\n{self.colorize('─' * width, 'DIM')}"
        for line in message_lines:
            box += f"\n  {line}"
        box += f"\n{bottom_border}"
        
        return box

# Global instance
colors = ColorSystem()
