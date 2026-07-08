# RapidScan

A lightweight, multi-threaded network reconnaissance tool for identifying open ports and active services on a target host — built for vulnerability assessment and attack-surface evaluation.

## What it does

RapidScan scans a target for open TCP ports using a pool of concurrent worker threads, then hands any open ports it finds to **Nmap** for service and version detection. Instead of guessing what's listening on a port, you get the actual service name, product, and version Nmap can fingerprint.

```
Starting RapidScan scan on scanme.nmap.org (45.33.32.156)
Port range: 1-1024 | Threads: 100

Found 3 open port(s). Running Nmap service detection...

Scan complete for scanme.nmap.org
--------------------------------------------------
      22  open   ssh        OpenSSH 6.6.1p1
      80  open   http       Apache httpd 2.4.7
    9929  open   nping-echo
```

## Why it's built this way

- **Multi-threading** — Sequentially checking 1,000+ ports over a raw TCP connection is slow, since most of the time is spent waiting on the network, not the CPU. A thread pool (via a shared `Queue`) lets many connection attempts happen concurrently, cutting scan time dramatically compared to a single-threaded loop.
- **Nmap integration for service detection** — A raw connect scan only tells you a port is open, not what's running on it. Once RapidScan finds open ports, it passes *just those ports* to Nmap's `-sV` service/version scan — this is much faster than asking Nmap to sweep the whole range itself.
- **Modular design** — Port discovery (`RapidScan.scan`), service detection (`RapidScan.detect_services`), reporting, and logging are separated into distinct functions/methods, so any piece (e.g. swapping in a different detection backend, or a different reporting format) can be changed independently.

## Requirements

- Python 3.8+
- [Nmap](https://nmap.org/download.html) installed and on your `PATH` (required for service detection; the tool still works for port discovery without it via `--no-nmap`)

## Installation

```bash
git clone https://github.com/Samriddhi806/RapidScan.git
cd RapidScan
pip install -r requirements.txt
```

## Usage

```bash
python3 rapidscan.py <target> [-p START-END] [-t THREADS] [--timeout SECONDS] [--no-nmap]
```

| Flag | Description | Default |
|---|---|---|
| `target` | Hostname or IP address to scan | required |
| `-p, --ports` | Port range, e.g. `1-1024` | `1-1024` |
| `-t, --threads` | Number of concurrent worker threads | `100` |
| `--timeout` | Per-port connection timeout (seconds) | `0.5` |
| `--no-nmap` | Skip service detection, report open ports only | off |

**Examples:**

```bash
# Full range scan with service detection
python3 rapidscan.py 192.168.1.1 -p 1-1024

# Faster port-only sweep, no Nmap needed
python3 rapidscan.py 192.168.1.1 --no-nmap

# More threads for a large range
python3 rapidscan.py 192.168.1.1 -p 1-65535 -t 300
```

Results are printed to the console and appended to `port_scan_log.txt` with a timestamp for later reference.

## Testing

Tested against local VMs and hosts on an isolated lab network, plus [scanme.nmap.org](https://scanme.nmap.org) (a host Nmap's maintainers provide specifically for scan testing), to validate accuracy against known open ports and services.

## Responsible use

Only scan hosts and networks you own or have explicit authorization to test. Unauthorized port scanning may violate computer misuse laws depending on your jurisdiction.

## Possible extensions

- UDP scan support
- JSON/CSV export of results
- Basic web dashboard for visualizing scan history
