#!/usr/bin/env python3
"""
PortHunter - A lightweight, multi-threaded network reconnaissance tool.

Scans a target host for open TCP ports using concurrent worker threads,
then hands any open ports off to Nmap for service/version detection.

Usage:
    python3 porthunter.py <target> [-p START-END] [-t THREADS] [--no-nmap]

Examples:
    python3 porthunter.py scanme.nmap.org
    python3 porthunter.py 192.168.1.1 -p 1-1024 -t 200
    python3 porthunter.py 192.168.1.1 --no-nmap

Note:
    Only scan hosts you own or have explicit permission to test.
"""

import argparse
import socket
import sys
import threading
from datetime import datetime
from queue import Queue

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class PortHunter:
    """Encapsulates a single scan run: port discovery + optional service detection."""

    def __init__(self, target, start_port=1, end_port=1024, max_threads=100, timeout=0.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.max_threads = max_threads
        self.timeout = timeout

        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def resolve_target(self):
        """Resolve hostname to an IP address, raising a clear error if it fails."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve host '{self.target}'") from exc

    def _worker(self):
        """Pull ports off the queue and test each one until the queue is empty."""
        while not self.queue.empty():
            port = self.queue.get()
            self._scan_port(port)
            self.queue.task_done()

    def _scan_port(self, port):
        """Attempt a TCP connection to a single port; record it if open."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
        except socket.error:
            pass
        finally:
            sock.close()

    def scan(self):
        """Run the multi-threaded port sweep across the configured range."""
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)

        thread_count = min(self.max_threads, self.queue.qsize())
        threads = [threading.Thread(target=self._worker, daemon=True) for _ in range(thread_count)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.open_ports.sort()
        return self.open_ports

    def detect_services(self):
        """Run Nmap service/version detection against discovered open ports only.

        Scanning only the ports we already know are open keeps this fast -
        Nmap doesn't need to re-probe the full range, just fingerprint it.
        """
        if not self.open_ports:
            return {}
        if not NMAP_AVAILABLE:
            raise RuntimeError(
                "python-nmap is not installed. Run: pip install python-nmap"
            )

        scanner = nmap.PortScanner()
        port_list = ",".join(str(p) for p in self.open_ports)
        scanner.scan(self.target, port_list, arguments="-sV")

        services = {}
        if self.target in scanner.all_hosts():
            for proto in scanner[self.target].all_protocols():
                for port, info in scanner[self.target][proto].items():
                    services[port] = {
                        "name": info.get("name", "unknown"),
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                    }
        return services


def write_log(target, open_ports, services, log_path="port_scan_log.txt"):
    """Append a timestamped summary of the scan to a log file."""
    with open(log_path, "a") as log_file:
        log_file.write(f"Scan on {target} at {datetime.now()}\n")
        log_file.write(f"Open ports: {open_ports}\n")
        if services:
            for port, info in services.items():
                label = f"{info['product']} {info['version']}".strip()
                log_file.write(f"  Port {port}: {info['name']} ({label or 'version unknown'})\n")
        log_file.write("\n")


def print_report(target, open_ports, services):
    """Print a human-readable scan summary to the console."""
    print(f"\nScan complete for {target}")
    print("-" * 50)
    if not open_ports:
        print("No open ports found in the given range.")
        return

    for port in open_ports:
        if port in services:
            info = services[port]
            label = f"{info['product']} {info['version']}".strip()
            print(f"  {port:>6}  open   {info['name']:<10} {label}")
        else:
            print(f"  {port:>6}  open")


def parse_args():
    parser = argparse.ArgumentParser(
        description="PortHunter - lightweight multi-threaded port scanner with Nmap service detection."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan, e.g. 1-1024 (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent worker threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Per-port connection timeout in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--no-nmap", action="store_true",
        help="Skip Nmap service detection and only report open ports"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        start_port, end_port = (int(x) for x in args.ports.split("-"))
    except ValueError:
        sys.exit("Invalid port range. Use the format START-END, e.g. 1-1024")

    hunter = PortHunter(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        max_threads=args.threads,
        timeout=args.timeout,
    )

    try:
        resolved_ip = hunter.resolve_target()
    except ValueError as exc:
        sys.exit(str(exc))

    print(f"Starting PortHunter scan on {args.target} ({resolved_ip})")
    print(f"Port range: {start_port}-{end_port} | Threads: {args.threads}\n")

    open_ports = hunter.scan()

    services = {}
    if open_ports and not args.no_nmap:
        print(f"Found {len(open_ports)} open port(s). Running Nmap service detection...")
        try:
            services = hunter.detect_services()
        except RuntimeError as exc:
            print(f"Warning: {exc}")

    print_report(args.target, open_ports, services)
    write_log(args.target, open_ports, services)
    print("\nResults appended to port_scan_log.txt")


if __name__ == "__main__":
    main()
