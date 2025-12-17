#!/usr/bin/env python3
"""
Warnings and Notices Module
Display security warnings and educational messages
"""

from .colors import colors

def display_warning(title, message, level="warning"):
    """
    Display a warning box
    
    Args:
        title: Warning title
        message: Warning message
        level: warning level (info, warning, error, danger)
    """
    color_map = {
        "info": "INFO",
        "warning": "WARNING",
        "error": "ERROR",
        "danger": "DANGER"
    }
    
    color_name = color_map.get(level.lower(), "WARNING")
    color = colors.COLORS[color_name]
    reset = colors.COLORS["RESET"]
    
    # Create box
    width = 60
    border = "═" * width
    
    # Title with icon
    icons = {
        "info": "ℹ",
        "warning": "⚠",
        "error": "✗",
        "danger": "☠"
    }
    icon = icons.get(level.lower(), "⚠")
    
    title_line = f"{icon} {title.upper()}"
    
    # Wrap message
    import textwrap
    wrapped_lines = textwrap.wrap(message, width=width-4)
    
    # Build warning box
    box = []
    box.append(f"{color}{border}{reset}")
    box.append(f"{color}{title_line.center(width)}{reset}")
    box.append(f"{colors.COLORS['DIM']}{'─' * width}{reset}")
    
    for line in wrapped_lines:
        box.append(f"{color}  {line}{reset}")
    
    box.append(f"{color}{border}{reset}")
    
    print("\n" + "\n".join(box) + "\n")

def display_notice(title, message):
    """Display an informational notice"""
    display_warning(title, message, level="info")

def display_error(title, message):
    """Display an error message"""
    display_warning(title, message, level="error")

def display_danger(title, message):
    """Display a danger warning"""
    display_warning(title, message, level="danger")

def display_ethical_warning():
    """Display ethical usage warning"""
    warning = f"""
{colors.colorize('⚠ ETHICAL USAGE WARNING', 'DANGER')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('This tool is for:', 'INFO')}
  • Security education and research
  • Testing your own networks and systems
  • Authorized penetration testing
  • Network troubleshooting and analysis

{colors.colorize('This tool is NOT for:', 'ERROR')}
  • Scanning networks without permission
  • Attempting to breach security systems
  • Any illegal or unauthorized activities

{colors.colorize('Legal Notice:', 'WARNING')}
Unauthorized scanning may violate:
  • Computer Fraud and Abuse Act (CFAA)
  • Local computer crime laws
  • Terms of Service agreements

{colors.colorize('By using this tool, you agree:', 'INFO')}
  • To use it only for legal purposes
  • To only scan systems you own or have permission to test
  • That the author is not responsible for misuse

{colors.colorize('Press Enter to acknowledge and continue...', 'YELLOW')}
"""
    print(warning)
    input()

def display_cgnat_warning():
    """Display CGNAT limitation warning"""
    warning = f"""
{colors.colorize('⚠ CGNAT DETECTED', 'WARNING')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('What is CGNAT?', 'INFO')}
CGNAT (Carrier-Grade NAT) is used by mobile carriers and some ISPs
to share public IP addresses among multiple customers.

{colors.colorize('Limitations:', 'WARNING')}
  • Cannot scan other devices on the mobile network
  • ARP scanning will not work
  • Device discovery is impossible
  • Only external port scanning is possible

{colors.colorize('Available Actions:', 'INFO')}
  • Port scanning external hosts
  • DNS and connectivity tests
  • Local network analysis (if on WiFi)

{colors.colorize('Recommendation:', 'SUCCESS')}
Switch to a WiFi network for full LAN scanning capabilities.
"""
    display_warning("CGNAT Limitations", warning)

def display_root_warning():
    """Display root permission warning"""
    warning = f"""
{colors.colorize('⚠ PERMISSION LIMITATIONS', 'WARNING')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('Running as standard user limits:', 'INFO')}
  • ARP scanning (device discovery)
  • Ping scanning (ICMP discovery)
  • Packet capture
  • Routing table inspection

{colors.colorize('Available without root:', 'SUCCESS')}
  • TCP port scanning
  • DNS analysis
  • Basic network information
  • Service detection

{colors.colorize('Recommendations:', 'INFO')}
  • Run with sudo/root for full features
  • On Termux: Some features may work without root
  • On Windows: Run as Administrator
"""
    display_warning("Permission Warning", warning)

def display_scan_warning(target, scan_type):
    """Display scan confirmation warning"""
    import socket
    
    # Check if target is external
    is_external = True
    try:
        target_ip = socket.gethostbyname(target)
        
        # Check if target is in private ranges
        private_ranges = [
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
        ]
        
        is_external = not any(target_ip.startswith(prefix) for prefix in private_ranges)
    
    except:
        pass
    
    if is_external and scan_type == "port_scan":
        warning = f"""
{colors.colorize('⚠ EXTERNAL TARGET WARNING', 'DANGER')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('Target:', 'INFO')} {target}
{colors.colorize('Type:', 'INFO')} External/Public IP

{colors.colorize('WARNING:', 'ERROR')}
Scanning external systems without permission:
  • May be illegal in your jurisdiction
  • May violate the Computer Fraud and Abuse Act
  • Could result in legal action
  • May get your IP address blocked

{colors.colorize('Are you sure you want to continue?', 'WARNING')}
Type 'YES' to confirm: """
        
        print(warning)
        confirmation = input().strip().upper()
        return confirmation == "YES"
    
    return True

def display_export_warning(filename, data_type):
    """Display export confirmation"""
    warning = f"""
{colors.colorize('⚠ DATA EXPORT', 'WARNING')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('Exporting:', 'INFO')}
  File: {filename}
  Type: {data_type}
  Size: {len(str(data_type))} bytes (approximate)

{colors.colorize('Security Considerations:', 'INFO')}
  • Scan results may contain sensitive information
  • Files should be stored securely
  • Consider encrypting sensitive data
  • Delete files when no longer needed

{colors.colorize('Continue with export?', 'WARNING')}
Type 'YES' to confirm: """
    
    print(warning)
    confirmation = input().strip().upper()
    return confirmation == "YES"

def display_update_warning(current_version, new_version):
    """Display update warning"""
    warning = f"""
{colors.colorize('⚠ UPDATE AVAILABLE', 'INFO')}
{colors.colorize('─' * 50, 'DIM')}

{colors.colorize('Current Version:', 'INFO')} {current_version}
{colors.colorize('New Version:', 'SUCCESS')} {new_version}

{colors.colorize('Update includes:', 'INFO')}
  • Security improvements
  • New features
  • Bug fixes
  • Performance enhancements

{colors.colorize('Update now?', 'WARNING')}
Type 'YES' to update: """
    
    print(warning)
    confirmation = input().strip().upper()
    return confirmation == "YES"
