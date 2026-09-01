#!/usr/bin/env python3
"""
Script 4 - Real-Time Memory Monitor
======================================
Lists running system processes sorted by RAM consumption in real time,
from highest to lowest memory percentage.

Features:
    - Configurable refresh interval and number of top processes to display.
    - Color-coded memory usage bars.
    - Displays: rank, PID, name, memory %, memory (MB), CPU %, status.
    - Graceful exit on Ctrl+C.

Dependencies:
    pip install psutil

Usage:
    python script4_memory_monitor.py
    python script4_memory_monitor.py --top 20 --interval 2
    python script4_memory_monitor.py --once          # single snapshot, no loop
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List

try:
    import psutil
except ImportError:
    print("[ERROR] psutil is not installed. Run: pip install psutil")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants & ANSI colors
# ---------------------------------------------------------------------------
DEFAULT_TOP_N:    int = 15    # Number of processes to display by default
DEFAULT_INTERVAL: int = 3     # Refresh interval in seconds

BOLD    = "\033[1m"
RESET   = "\033[0m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
WHITE   = "\033[97m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
DIM     = "\033[2m"

# Memory thresholds for color coding (percentage of total RAM)
MEM_HIGH:   float = 10.0  # Red   above this %
MEM_MEDIUM: float = 3.0   # Yellow above this %
# Below MEM_MEDIUM → Green

# Column widths for the table layout
COL = {
    "rank":   5,
    "pid":    8,
    "name":   25,
    "mem_pct": 10,
    "bar":    20,
    "mem_mb": 12,
    "cpu_pct": 9,
    "status": 12,
}


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def get_process_list(top_n: int) -> List[dict]:
    """
    Collects and sorts all running processes by memory usage (descending).

    For each process the following attributes are captured:
        - pid:      Process identifier.
        - name:     Executable name (truncated to 24 chars for display).
        - mem_pct:  Resident Set Size as a percentage of total physical RAM.
        - mem_mb:   RSS memory consumed in megabytes.
        - cpu_pct:  CPU usage percentage (sampled over a 0.1 s interval).
        - status:   Process status string (e.g. 'running', 'sleeping').

    Processes that raise psutil exceptions (terminated, zombie, no access)
    are silently skipped to avoid crashing the monitor.

    Args:
        top_n: Maximum number of processes to return after sorting.

    Returns:
        List of process-info dicts sorted by mem_pct descending,
        limited to top_n entries.
    """
    processes: List[dict] = []

    for proc in psutil.process_iter(
        attrs=["pid", "name", "memory_percent", "memory_info", "cpu_percent", "status"]
    ):
        try:
            info     = proc.info
            mem_pct  = info.get("memory_percent") or 0.0
            mem_info = info.get("memory_info")
            mem_mb   = (mem_info.rss / (1024 ** 2)) if mem_info else 0.0
            cpu_pct  = info.get("cpu_percent") or 0.0
            status   = info.get("status", "unknown")
            name     = (info.get("name") or "unknown")[:24]
            pid      = info.get("pid", 0)

            processes.append({
                "pid":      pid,
                "name":     name,
                "mem_pct":  round(mem_pct, 2),
                "mem_mb":   round(mem_mb, 1),
                "cpu_pct":  round(cpu_pct, 1),
                "status":   status,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process vanished or inaccessible – skip gracefully
            continue

    # Sort by memory percentage (highest first) and return the top N
    processes.sort(key=lambda p: p["mem_pct"], reverse=True)
    return processes[:top_n]


def mem_color(mem_pct: float) -> str:
    """
    Returns the ANSI color code appropriate for a given memory percentage.

    Args:
        mem_pct: Process memory usage as a percentage of total physical RAM.

    Returns:
        ANSI escape string for RED, YELLOW, or GREEN based on thresholds.
    """
    if mem_pct >= MEM_HIGH:
        return RED
    if mem_pct >= MEM_MEDIUM:
        return YELLOW
    return GREEN


def build_bar(mem_pct: float, bar_width: int = 20) -> str:
    """
    Builds a mini ASCII progress bar proportional to the memory percentage.

    The bar is scaled relative to MEM_HIGH (10 %) as the upper bound,
    clamped at 100 % fill so that extremely high-memory processes do not
    overflow the column.

    Args:
        mem_pct:   Memory percentage value to represent.
        bar_width: Total character width of the bar (default: 20).

    Returns:
        Color-coded filled bar string.
    """
    # Scale: MEM_HIGH% → full bar
    ratio  = min(mem_pct / MEM_HIGH, 1.0)
    filled = int(ratio * bar_width)
    empty  = bar_width - filled
    color  = mem_color(mem_pct)
    return f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    """Clears the terminal screen using the appropriate OS command."""
    os.system("cls" if os.name == "nt" else "clear")


def print_system_summary() -> None:
    """
    Prints a one-line system memory summary (total, used, available, swap).
    """
    vm   = psutil.virtual_memory()
    swap = psutil.swap_memory()

    total_gb = vm.total   / (1024 ** 3)
    used_gb  = vm.used    / (1024 ** 3)
    avail_gb = vm.available / (1024 ** 3)
    swap_gb  = swap.used  / (1024 ** 3)

    bar  = build_bar(vm.percent, bar_width=30)
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{CYAN}{BOLD}  Real-Time Memory Monitor{RESET}  {DIM}{now}{RESET}")
    print(
        f"  RAM : {bar}  "
        f"{BOLD}{vm.percent:5.1f}%{RESET}  "
        f"Used {used_gb:.1f} GB / Total {total_gb:.1f} GB  "
        f"(Available: {avail_gb:.1f} GB)"
    )
    print(
        f"  Swap: {MAGENTA}{swap.percent:5.1f}%{RESET}  "
        f"Used {swap_gb:.1f} GB"
    )


def print_table_header() -> None:
    """Prints the column header row for the process table."""
    header = (
        f"  {'#':<{COL['rank']}}"
        f"{'PID':<{COL['pid']}}"
        f"{'PROCESS NAME':<{COL['name']}}"
        f"{'MEM %':>{COL['mem_pct']}}"
        f"  {'USAGE BAR':<{COL['bar']}}"
        f"{'MEM (MB)':>{COL['mem_mb']}}"
        f"{'CPU %':>{COL['cpu_pct']}}"
        f"  {'STATUS':<{COL['status']}}"
    )
    sep = "  " + "─" * (sum(COL.values()) + 8)
    print(f"\n{WHITE}{BOLD}{header}{RESET}")
    print(sep)


def display_processes(processes: List[dict]) -> None:
    """
    Renders the sorted process list as a formatted, color-coded table.

    Args:
        processes: List of process dicts as returned by get_process_list().
    """
    if not processes:
        print(f"  {YELLOW}[INFO]{RESET} No process data available.")
        return

    print_table_header()

    for rank, proc in enumerate(processes, start=1):
        color  = mem_color(proc["mem_pct"])
        bar    = build_bar(proc["mem_pct"])
        status = proc["status"]

        # Color-code the status label
        status_color = {
            "running":  GREEN,
            "sleeping": DIM,
            "zombie":   RED,
            "stopped":  YELLOW,
        }.get(status, RESET)

        row = (
            f"  {rank:<{COL['rank']}}"
            f"{proc['pid']:<{COL['pid']}}"
            f"{proc['name']:<{COL['name']}}"
            f"{color}{proc['mem_pct']:>{COL['mem_pct'] - 1}.2f}%{RESET}"
            f"  {bar:<{COL['bar']}}"
            f"{proc['mem_mb']:>{COL['mem_mb'] - 1}.1f} MB"
            f"{proc['cpu_pct']:>{COL['cpu_pct'] - 1}.1f}%"
            f"  {status_color}{status:<{COL['status']}}{RESET}"
        )
        print(row)


def render_snapshot(top_n: int) -> None:
    """
    Captures one snapshot of process memory usage and renders it.

    Args:
        top_n: How many top processes to display.
    """
    processes = get_process_list(top_n)
    print_system_summary()
    display_processes(processes)
    print(f"\n  {DIM}Showing top {top_n} processes by memory usage.{RESET}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        Namespace with attributes: top (int), interval (int), once (bool).
    """
    parser = argparse.ArgumentParser(
        description="Real-Time Memory Monitor – shows top RAM-consuming processes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python script4_memory_monitor.py\n"
            "  python script4_memory_monitor.py --top 20 --interval 2\n"
            "  python script4_memory_monitor.py --once\n"
        ),
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP_N,
        metavar="N",
        help=f"Number of processes to display (default: {DEFAULT_TOP_N}).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        metavar="SECONDS",
        help=f"Refresh interval in seconds (default: {DEFAULT_INTERVAL}).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Take a single snapshot and exit (no live refresh loop).",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the Real-Time Memory Monitor.

    In default mode: clears the screen and refreshes the process table
    every --interval seconds until Ctrl+C is pressed.

    In --once mode: prints a single snapshot and exits.
    """
    args = parse_arguments()

    if args.once:
        # Single snapshot – useful for scripting or piping output
        render_snapshot(args.top)
        return

    # Live refresh loop
    print(f"{CYAN}Starting Memory Monitor (Ctrl+C to exit)…{RESET}")
    time.sleep(0.5)

    try:
        while True:
            clear_screen()
            render_snapshot(args.top)
            print(
                f"  {DIM}Refreshing every {args.interval}s  –  "
                f"Press Ctrl+C to exit{RESET}\n"
            )
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n{CYAN}Memory Monitor stopped. Goodbye!{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
