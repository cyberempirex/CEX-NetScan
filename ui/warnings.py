#!/usr/bin/env python3
"""
Warnings and Notices Module
Display security warnings and educational messages
"""

from .colors import colors
import textwrap
import socket


def display_warning(title, message, level="warning"):
    """
    Display a styled warning box
    """
    color_map = {
        "info": "INFO",
        "warning": "WARNING",
        "error": "ERROR",
        "danger": "DANGER"
    }

    icons = {
        "info": "ℹ",
        "warning": "⚠",
        "error": "✗",
        "danger": "☠"
    }

    level = level.lower()
    color_name = color_map.get(level, "WARNING")
    icon = icons.get(level, "⚠")

    color = colors.COLORS[color_name]
    reset = colors.COLORS["RESET"]

    width = 60
    border = "═" * width
    title_line = f"{icon} {title.upper()}"

    wrapped_lines = textwrap.wrap(message, width=width - 4)

    box = []
    box.append(f"{color}{border}{reset}")
    box.append(f"{color}{title_line.center(width)}{reset}")
    box.append(f"{colors.COLORS['DIM']}{'─' * width}{reset}")

    for line in wrapped_lines:
        box.append(f"{color}  {line}{reset}")

    box.append(f"{color}{border}{reset}")

    print("\n" + "\n".join(box) + "\n")


def display_notice(title, message):
    """Display informational notice"""
    display_warning(title, message, level="info")


def display_error(title, message):
    """Display error message"""
    display_warning(title, message, level="error")


def display_danger(title, message):
    """Display danger message"""
    display_warning(title, message, level="danger")


def display_ethical_warning():
    """Display ethical usage warning"""
    message = (
        "This tool is intended for security education, authorized testing, "
        "and troubleshooting only.\n\n"
        "Unauthorized scanning may violate local laws including the "
        "Computer Fraud and Abuse Act (CFAA).\n\n"
        "You are responsible for ensuring you have permission to scan "
        "any target."
    )
    display_warning("Ethical Usage Warning", message, level="danger")
    input("Press Enter to continue...")


def display_cgnat_warning():
    """Display CGNAT limitation warning"""
    message = (
        "CGNAT (Carrier-Grade NAT) prevents local network discovery.\n\n"
        "Limitations:\n"
        "• ARP scanning unavailable\n"
        "• LAN discovery impossible\n"
        "• Only external scans possible\n\n"
        "Recommendation:\n"
        "Switch to WiFi for full LAN scanning."
    )
    display_warning("CGNAT Detected", message, level="warning")


def display_root_warning():
    """Display root permission warning"""
    message = (
        "Running without root limits some features.\n\n"
        "Unavailable:\n"
        "• ARP scanning\n"
        "• Packet capture\n"
        "• Routing inspection\n\n"
        "Available:\n"
        "• Port scanning\n"
        "• DNS analysis\n"
        "• Basic network info"
    )
    display_warning("Permission Limitations", message, level="warning")


def display_scan_warning(target, scan_type):
    """
    Warn before scanning external targets
    """
    is_external = True
    try:
        target_ip = socket.gethostbyname(target)
        private_prefixes = (
            "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
        )
        is_external = not target_ip.startswith(private_prefixes)
    except Exception:
        pass

    if is_external and scan_type == "port_scan":
        message = (
            f"Target: {target}\n\n"
            "You are about to scan an external/public IP.\n\n"
            "Unauthorized scanning may be illegal.\n\n"
            "Type YES to continue."
        )
        display_warning("External Target Warning", message, level="danger")
        return input("> ").strip().upper() == "YES"

    return True


def display_export_warning(filename, data_type):
    """Confirm export of sensitive data"""
    message = (
        f"File: {filename}\n"
        f"Type: {data_type}\n\n"
        "Scan results may contain sensitive information.\n"
        "Store securely and delete when no longer needed.\n\n"
        "Type YES to confirm export."
    )
    display_warning("Data Export", message, level="warning")
    return input("> ").strip().upper() == "YES"


def display_update_warning(current_version, new_version):
    """Display update confirmation"""
    message = (
        f"Current version: {current_version}\n"
        f"New version: {new_version}\n\n"
        "Includes:\n"
        "• Security fixes\n"
        "• New features\n"
        "• Performance improvements\n\n"
        "Type YES to update."
    )
    display_warning("Update Available", message, level="info")
    return input("> ").strip().upper() == "YES"


def display_info(title, message):
    """Display informational message"""
    print("\n" + "=" * 60)
    print(f"ℹ {title}")
    print("-" * 60)
    print(message)
    print("=" * 60)
