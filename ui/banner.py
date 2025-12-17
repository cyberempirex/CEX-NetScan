#!/usr/bin/env python3
"""
Banner Display Module
Professional banners for CEX-NetScan
"""

from .colors import colors

def display_main_banner():
    """Display main application banner"""
    banner = f"""
{colors.colorize('╔══════════════════════════════════════════════════════════════╗', 'CYAN')}
{colors.colorize('║', 'CYAN')}                                                              {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize(' ██████╗███████╗██╗  ██╗    ███╗   ██╗███████╗████████╗', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize('██╔════╝██╔════╝╚██╗██╔╝    ████╗  ██║██╔════╝╚══██╔══╝', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize('██║     █████╗   ╚███╔╝     ██╔██╗ ██║█████╗     ██║   ', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize('██║     ██╔══╝   ██╔██╗     ██║╚██╗██║██╔══╝     ██║   ', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize('╚██████╗███████╗██╔╝ ██╗    ██║ ╚████║███████╗   ██║   ', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}  {colors.colorize(' ╚═════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ', 'TITLE')}  {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}                                                              {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}     {colors.colorize('PROFESSIONAL NETWORK SECURITY SCANNER', 'HEADER')}             {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}     {colors.colorize('Version 2.0.0 | Created by CyberEmpireX', 'INFO')}             {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}     {colors.colorize('https://cyberempirex.com', 'DIM')}                              {colors.colorize('║', 'CYAN')}
{colors.colorize('║', 'CYAN')}                                                              {colors.colorize('║', 'CYAN')}
{colors.colorize('╚══════════════════════════════════════════════════════════════╝', 'CYAN')}
"""
    
    print(banner)

def display_scan_banner(scan_type):
    """Display scan-specific banner"""
    banners = {
        "network": f"""
{colors.colorize('╔══════════════════════════════════════════════════════════════╗', 'BLUE')}
{colors.colorize('║', 'BLUE')}                    {colors.colorize('NETWORK DISCOVERY SCAN', 'TITLE')}                   {colors.colorize('║', 'BLUE')}
{colors.colorize('╚══════════════════════════════════════════════════════════════╝', 'BLUE')}
""",
        "port": f"""
{colors.colorize('╔══════════════════════════════════════════════════════════════╗', 'CYAN')}
{colors.colorize('║', 'CYAN')}                      {colors.colorize('PORT SCANNING', 'TITLE')}                         {colors.colorize('║', 'CYAN')}
{colors.colorize('╚══════════════════════════════════════════════════════════════╝', 'CYAN')}
""",
        "security": f"""
{colors.colorize('╔══════════════════════════════════════════════════════════════╗', 'MAGENTA')}
{colors.colorize('║', 'MAGENTA')}                    {colors.colorize('SECURITY ASSESSMENT', 'TITLE')}                   {colors.colorize('║', 'MAGENTA')}
{colors.colorize('╚══════════════════════════════════════════════════════════════╝', 'MAGENTA')}
""",
        "analysis": f"""
{colors.colorize('╔══════════════════════════════════════════════════════════════╗', 'GREEN')}
{colors.colorize('║', 'GREEN')}                     {colors.colorize('NETWORK ANALYSIS', 'TITLE')}                      {colors.colorize('║', 'GREEN')}
{colors.colorize('╚══════════════════════════════════════════════════════════════╝', 'GREEN')}
"""
    }
    
    banner = banners.get(scan_type.lower(), banners["network"])
    print(banner)

def display_section_header(title, width=60):
    """Display a section header"""
    padding = (width - len(title) - 4) // 2
    left_pad = " " * padding
    right_pad = " " * (width - len(title) - padding - 4)
    
    border = colors.colorize("═" * width, "CYAN")
    header = colors.colorize(f"{left_pad}{title}{right_pad}", "HEADER")
    
    print(f"\n{border}")
    print(f"{colors.colorize('║', 'CYAN')}{header}{colors.colorize('║', 'CYAN')}")
    print(f"{border}")

def display_welcome():
    """Display welcome message"""
    message = f"""
{colors.colorize('Welcome to CEX-NetScan Professional', 'TITLE')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('This tool provides:', 'INFO')}
  • Real network discovery and analysis
  • Professional security scanning
  • Accurate results with no fake data
  • Educational insights and recommendations

{colors.colorize('Principles:', 'INFO')}
  • {colors.colorize('No Fake Data', 'SUCCESS')}: Every result is verified and real
  • {colors.colorize('Adaptive Scanning', 'SUCCESS')}: Automatically adjusts to your network
  • {colors.colorize('Educational', 'SUCCESS')}: Teaches as it scans
  • {colors.colorize('Ethical', 'SUCCESS')}: Designed for legitimate security testing

{colors.colorize('⚠ Warning:', 'WARNING')}
Only scan networks you own or have permission to test.
Unauthorized scanning may be illegal.
"""
    print(message)

def display_goodbye():
    """Display goodbye message"""
    message = f"""
{colors.colorize('Thank you for using CEX-NetScan!', 'HEADER')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('Remember:', 'INFO')}
  • Stay curious, keep learning
  • Practice ethical security testing
  • Verify before you trust
  • Security is a journey, not a destination

{colors.colorize('Resources:', 'INFO')}
  • Website: https://cyberempirex.com
  • GitHub: https://github.com/cyberempirex
  • Community: https://t.me/CyberEmpireXChat

{colors.colorize('Stay secure! 🔒', 'TITLE')}
"""
    print(message)

def display_about():
    """Display about information"""
    about = f"""
{colors.colorize('About CEX-NetScan Professional', 'TITLE')}
{colors.colorize('─' * 60, 'DIM')}

{colors.colorize('Tool Identity', 'HEADER')}
  Tool:        CEX-NetScan Professional
  Version:     2.0.0
  Purpose:     Professional network security scanning
  Platform:    Termux, Linux, Windows
  License:     MIT

{colors.colorize('Creator Identity', 'HEADER')}
  Created by:  CyberEmpireX
  Focus:       Practical cybersecurity & research tools
  Approach:    Simple, offline-first, ethical

{colors.colorize('Project Links', 'HEADER')}
  Website:     https://cyberempirex.com
  GitHub:      https://github.com/cyberempirex
  Community:   https://t.me/CyberEmpireXChat

{colors.colorize('Ethics Notice', 'HEADER')}
  This tool is for educational and defensive use only.
  Use only on networks you own or have permission to test.
  The author is not responsible for misuse.

{colors.colorize('Build Info', 'HEADER')}
  Built With:  Python 3
  Framework:   CEX Professional Toolkit
  Database:    500+ MAC vendors, 100+ service patterns
"""
    print(about)
