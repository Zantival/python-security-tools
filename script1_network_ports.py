#!/usr/bin/env python3
"""
Script 1 - Network Ports Monitor
=================================
Validates which network ports are currently active and displays
the process (PID and name) occupying each port.

Dependencies:
    pip install psutil

Usage:
    python script1_network_ports.py
    python script1_network_ports.py --port 80
    python script1_network_ports.py --protocol tcp
"""

import argparse
import socket
import sys

try:
    import psutil
except ImportError:
    print("[ERROR] psutil is not installed. Run: pip install psutil")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
COLUMN_WIDTH = {
    "protocol": 10,
    "local_address": 25,
    "remote_address": 25,
    "status": 15,
    "pid": 8,
    "process": 20,
}

STATUS_COLORS = {
    "LISTEN": "\033[92m",      # Green
    "ESTABLISHED": "\033[94m", # Blue
    "TIME_WAIT": "\033[93m",   # Yellow
    "CLOSE_WAIT": "\033[91m",  # Red
    "default": "\033[0m",      # Reset
}

RESET = "\033[0m"
BOLD  = "\033[1m"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def colorize(text: str, color_code: str) -> str:
    """
    Wraps a string with ANSI color codes for terminal output.

    Args:
        text: The string to colorize.
        color_code: ANSI escape code (e.g. '\\033[92m').

    Returns:
        Colorized string with reset suffix.
    """
    return f"{color_code}{text}{RESET}"


def get_status_color(status: str) -> str:
    """
    Returns the ANSI color code associated with a connection status.

    Args:
        status: Connection status string (e.g. 'LISTEN', 'ESTABLISHED').

    Returns:
        ANSI color escape string.
    """
    return STATUS_COLORS.get(status, STATUS_COLORS["default"])


def resolve_process(pid: int) -> str:
    """
    Attempts to resolve the process name from a given PID.

    Args:
        pid: Process identifier (integer).

    Returns:
        Process name string or a descriptive fallback string if unavailable.
    """
    if pid is None:
        return "N/A"
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "<access denied>"


def format_address(addr) -> str:
    """
    Formats a (host, port) address tuple into a readable string.

    Args:
        addr: A psutil address named-tuple with 'ip' and 'port' attributes,
              or None if no remote address exists.

    Returns:
        Formatted address string such as '0.0.0.0:80' or '*' if empty.
    """
    if not addr:
        return "*"
    host = addr.ip if addr.ip else "*"
    port = addr.port if addr.port else "*"
    return f"{host}:{port}"


def print_header() -> None:
    """Prints the formatted table header to stdout."""
    header = (
        f"{'PROTO':<{COLUMN_WIDTH['protocol']}}"
        f"{'LOCAL ADDRESS':<{COLUMN_WIDTH['local_address']}}"
        f"{'REMOTE ADDRESS':<{COLUMN_WIDTH['remote_address']}}"
        f"{'STATUS':<{COLUMN_WIDTH['status']}}"
        f"{'PID':<{COLUMN_WIDTH['pid']}}"
        f"{'PROCESS':<{COLUMN_WIDTH['process']}}"
    )
    separator = "-" * sum(COLUMN_WIDTH.values())
    print(colorize(BOLD + header, "\033[97m"))
    print(separator)


def collect_connections(
    protocol_filter: str = "all",
    port_filter: int = None,
) -> list[dict]:
    """
    Collects active network connections from the system.

    Filters connections by protocol and/or specific port number when
    the respective arguments are provided.

    Args:
        protocol_filter: One of 'tcp', 'udp', or 'all'. Defaults to 'all'.
        port_filter: Integer port number to filter results. Defaults to None
                     (no port filtering applied).

    Returns:
        List of dictionaries, each representing one active connection with
        keys: protocol, local_address, remote_address, status, pid, process.
    """
    results = []

    # Determine which kinds of connections to retrieve
    kind_map = {
        "tcp": "tcp",
        "udp": "udp",
        "all": "inet",  # Both TCP and UDP over IPv4/IPv6
    }
    kind = kind_map.get(protocol_filter.lower(), "inet")

    try:
        connections = psutil.net_connections(kind=kind)
    except PermissionError:
        print("[WARNING] Some connections require root/administrator privileges.")
        connections = psutil.net_connections(kind=kind)

    for conn in connections:
        local_addr  = format_address(conn.laddr)
        remote_addr = format_address(conn.raddr)
        status      = conn.status if conn.status else "N/A"
        pid         = conn.pid
        process     = resolve_process(pid)

        # Determine protocol label (tcp / udp)
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        # Apply port filter when specified
        if port_filter is not None:
            local_port = conn.laddr.port if conn.laddr else None
            if local_port != port_filter:
                continue

        results.append({
            "protocol":       proto,
            "local_address":  local_addr,
            "remote_address": remote_addr,
            "status":         status,
            "pid":            str(pid) if pid else "N/A",
            "process":        process,
        })

    # Sort: LISTEN first, then alphabetically by status
    results.sort(key=lambda x: (x["status"] != "LISTEN", x["status"]))
    return results


def display_connections(connections: list[dict]) -> None:
    """
    Renders connection records as a formatted table to stdout.

    Args:
        connections: List of connection dictionaries as returned by
                     collect_connections().
    """
    if not connections:
        print("[INFO] No active connections found matching the given filters.")
        return

    print_header()
    for conn in connections:
        status_color = get_status_color(conn["status"])
        colored_status = colorize(conn["status"], status_color)

        # Pad the status manually since colorize adds invisible ANSI codes
        # that misalign standard ljust()
        status_padding = COLUMN_WIDTH["status"] - len(conn["status"])
        status_field = colored_status + (" " * status_padding)

        row = (
            f"{conn['protocol']:<{COLUMN_WIDTH['protocol']}}"
            f"{conn['local_address']:<{COLUMN_WIDTH['local_address']}}"
            f"{conn['remote_address']:<{COLUMN_WIDTH['remote_address']}}"
            f"{status_field}"
            f"{conn['pid']:<{COLUMN_WIDTH['pid']}}"
            f"{conn['process']:<{COLUMN_WIDTH['process']}}"
        )
        print(row)

    print(f"\n[INFO] Total connections displayed: {len(connections)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        Parsed argument namespace with attributes: port, protocol.
    """
    parser = argparse.ArgumentParser(
        description="Network Ports Monitor – list active ports and their owning processes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python script1_network_ports.py\n"
            "  python script1_network_ports.py --port 443\n"
            "  python script1_network_ports.py --protocol tcp\n"
            "  python script1_network_ports.py --port 22 --protocol tcp\n"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help="Filter output to a specific port number (e.g. --port 8080).",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        default="all",
        choices=["tcp", "udp", "all"],
        metavar="PROTOCOL",
        help="Filter by protocol: tcp, udp, or all (default: all).",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the Network Ports Monitor script.

    Parses CLI arguments, collects active network connections, and
    displays them in a formatted, color-coded table.
    """
    args = parse_arguments()

    print(colorize(BOLD + "\n=== Network Ports Monitor ===\n", "\033[96m"))

    if args.port:
        print(f"[FILTER] Port     : {args.port}")
    if args.protocol != "all":
        print(f"[FILTER] Protocol : {args.protocol.upper()}")

    print()

    connections = collect_connections(
        protocol_filter=args.protocol,
        port_filter=args.port,
    )
    display_connections(connections)
    print()


if __name__ == "__main__":
    main()
