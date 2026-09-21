# Port Scanner

A simple port scanner that performs threaded port scanning with additional features like service identification and banner grabbing.



## Features

- **Threading support** for fast scanning of multiple ports
- **Service identification** for common ports (HTTP, HTTPS, SSH, FTP, etc.)
- **Banner grabbing** to retrieve service version information and detailed service data
- **Version detection** from banners for services like SSH and HTTP
- **Basic OS fingerprinting** guess based on which ports are open
- **Ping sweep** using real threaded ICMP pings across an entire CIDR range to discover active hosts
- **Host discovery** combining ping sweep with a port scan of each active host
- **Top-ports presets** to scan a curated list of the most common ports instead of a range
- **Randomized scan order** to avoid always hitting ports lowest-to-highest
- **Quiet/verbose output modes** for scripting or live per-port detail
- **Multiple targets** in one run, via a comma-separated list and/or a targets file
- **Retry on timeout** to avoid false negatives from a dropped packet or transient network blip
- **Rate limiting** (`--delay`) to pace out connection attempts and go easier on the target
- **Custom port lists** via a `--port-file`, and a **config file** (`--config`) for your usual default settings
- **UDP scanning** (`--udp`) alongside the default TCP scanning
- **IPv6 support** for direct scans (TCP/UDP), alongside IPv4
- **Port exclusion** (`--exclude-ports`) to skip specific ports regardless of how the port list was built
- **Result diffing** (`--diff`) to compare two saved scans and see what changed
- **Audit logging** (`--log-file`) for a timestamped record of what was scanned and found
- **Multiple output formats** (JSON, CSV, and a self-contained HTML report)
- **Command-line interface** with flexible options
- **Color-coded output** for improved readability
- **Progress bar** with a live open-port count, using tqdm library for visual feedback during scanning
- **Scan duration** reported per target and for the whole batch on multi-target runs

## Banner Grabbing Feature

The banner grabbing feature retrieves initial response data (service banners) from open ports, which often contain version information about the running services.

When a port is found to be open, the scanner will:
1. Connect to the port using a socket
2. Read the service banner (initial response data)
3. Extract version information where possible
4. Display detailed information in the scan results

Example output with banner information:
```
  22 (SSH)
    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    Version: 8.9
```

Version detection understands SSH banners (`SSH-<version>`) and HTTP/HTTPS `Server:` response headers specifically; for any other service it falls back to pulling the first version-looking number (e.g. `3.0.3`) out of the raw banner.

## Prerequisites

- Python 3.6 or higher installed on your system
- The `colorama` and `tqdm` packages (see Installation)

## Installation

1. Clone or download this repository
2. Install dependencies: `pip install -r requirements.txt`

## Usage

```bash
# Scan default port range (1-1024) on a target IP
python portscanner.py 192.168.1.1

# Scan specific ports
python portscanner.py example.com -p 80,443,22

# Scan a port range with custom thread count
python portscanner.py target.com -p 1-1000 -t 200

# Scan with custom timeout and save results
python portscanner.py 10.0.0.1 --timeout 2.0 --save scan_results.json

# Discover active hosts on a network range
python portscanner.py 192.168.1.0/24 --ping-sweep

# Discover hosts and scan each one's open ports
python portscanner.py 192.168.1.0/24 --host-discovery

# Scan the 100 most common ports in random order
python portscanner.py target.com --top-ports 100 --randomize

# Quiet mode for scripting (no progress bar or setup messages)
python portscanner.py target.com -p 1-1000 -q

# Verbose mode: print each open port as it's found
python portscanner.py target.com -p 1-1000 -v

# Scan multiple targets in one run
python portscanner.py host1.com,host2.com,192.168.1.5 -p 80,443

# Scan targets listed in a file (one per line, # comments allowed)
python portscanner.py --targets-file hosts.txt -p 1-1000

# Retry twice (3 attempts total) on a timeout before giving up on a port
python portscanner.py target.com -p 1-1000 --retries 2

# Scan a custom list of ports from a file (one port or range per line)
python portscanner.py target.com --port-file myports.txt

# Use a config file for your usual defaults; any CLI flag still overrides it
python portscanner.py target.com --config myconfig.json

# Scan UDP ports instead of TCP
python portscanner.py target.com -p 53,123,161 --udp

# Scan an IPv6 target directly
python portscanner.py 2001:db8::1 -p 1-1000

# Scan a range but skip a few noisy ports
python portscanner.py target.com -p 1-1000 --exclude-ports 135,445

# Compare two saved scans to see what changed
python portscanner.py --diff old_scan.json new_scan.json

# Pace out connections instead of firing as fast as possible
python portscanner.py target.com -p 1-1000 --delay 0.2 -t 10

# Keep a timestamped audit trail of the scan
python portscanner.py target.com -p 1-1000 --log-file scan.log
```

A `--port-file` looks like this (blank lines and `#` comments are ignored):
```
# web ports
80
443
8080-8090
```

A `--config` file is JSON, and any of its keys can be overridden by the matching CLI flag:
```json
{
  "threads": 200,
  "timeout": 2.0,
  "retries": 2,
  "top_ports": 100
}
```
Valid config keys: `ports`, `top_ports`, `port_file` (only one of these three), `exclude_ports`, `threads`, `timeout`, `retries`, `delay`, `save`, `log_file`, `randomize`, `quiet`, `verbose`, `udp`. It does not set the target itself — that's still given on the command line or via `--targets-file`.

## UDP Scanning

TCP scanning gets a clean yes/no answer (connection succeeds, or is refused). UDP is connectionless, so there's no equivalent — with `--udp`, each port gets one of three outcomes:

- **`open`** — the target actually sent a response back. Confirmed.
- **`open|filtered`** — no response came back at all within the timeout. This is the most common outcome and is genuinely ambiguous: it could be an open service that simply doesn't respond to an empty probe, or a firewall silently dropping the packet. It's shown with a `[open|filtered]` marker in the output rather than being reported as a plain open port.
- Closed (not shown in results at all) — the OS received an ICMP "port unreachable" back, a definitive answer.

Two honest limitations worth knowing: the probe sent is an empty UDP datagram, not a protocol-specific payload (real DNS/SNMP/etc. queries), so services that only respond to well-formed requests will show as `open|filtered` rather than `open`. And UDP scans are typically slower than TCP ones — most non-responding ports have to wait out the full `--timeout` instead of getting an instant refusal.

## Result Diffing

`--diff OLD.json NEW.json` compares two previously saved (`--save foo.json`) scans and reports what changed — it doesn't perform a live scan itself. Typical workflow: scan and save now, scan and save again later (e.g. after some time, or after a change to the target), then diff the two files.

```
Comparing old_scan.json -> new_scan.json
  Old target: 192.168.1.1
  New target: 192.168.1.1

Newly open (1):
  + 8080 (HTTP)

No longer open (1):
  - 21 (FTP)

Changed (1):
  ~ 22: open/SSH/7.4 -> open/SSH/8.9
```

Only JSON is supported (it's the only saved format with full structured per-port data); CSV/HTML aren't diffable inputs.

## Audit Logging

`--log-file FILE` appends a timestamped record to the given file, independent of `--quiet`/`--verbose` (i.e. it keeps a full log even when the terminal is quiet). It captures the exact command run, when each scan started/finished, every open port found (with its status), and any targets that had to be skipped:

```
2026-09-21 11:21:49,468 INFO Command: portscanner.py 192.168.1.1 -p 1-1000 --log-file scan.log
2026-09-21 11:21:49,469 INFO Scan started: 192.168.1.1 (1000 ports, protocol=tcp)
2026-09-21 11:21:49,472 INFO Open port: 192.168.1.1:22 (SSH) status=open
2026-09-21 11:21:49,495 INFO Scan completed: 192.168.1.1 - 1 open port(s) in 11.09s
```

The file is appended to, not overwritten, so pointing repeated scans at the same `--log-file` builds up a running history over time — a lighter-weight alternative to a full scan-history database.

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `target` | Target IP address or hostname to scan; comma-separate for multiple. IPv4 and IPv6 both work. Required unless `--targets-file` is given | `192.168.1.1`, `2001:db8::1`, or `host1.com,host2.com` |
| `--targets-file` | File with one target per line (blank lines and `#` comments ignored); combines with `target` and de-duplicates. Not supported with `--ping-sweep`/`--host-discovery` | `--targets-file hosts.txt` |
| `-p`, `--ports` | Port range or specific ports (e.g., 80,443,22 or 1-1000); scans exactly the ports given, not the range spanning them | `-p 80,443,22` |
| `--top-ports` | Scan the N most common ports (a hand-curated list, not `-p`/range-based); mutually exclusive with `-p`/`--port-file` | `--top-ports 100` |
| `--port-file` | File with one port or port range per line (blank lines and `#` comments ignored); mutually exclusive with `-p`/`--top-ports` | `--port-file myports.txt` |
| `--exclude-ports` | Ports to skip, same format as `-p`; applied after `-p`/`--top-ports`/`--port-file`, regardless of which was used | `--exclude-ports 135,445` |
| `--config` | JSON file of default settings (see below); any matching CLI flag overrides its value | `--config myconfig.json` |
| `--diff` | Compare two saved JSON scans and report what changed; performs no live scan (see [Result Diffing](#result-diffing) above) | `--diff old.json new.json` |
| `-t`, `--threads` | Maximum number of concurrent threads (default: 100) | `-t 200` |
| `--timeout` | Connection timeout in seconds (default: 1.0) | `--timeout 2.0` |
| `--retries` | Extra attempts on a connection *timeout* before marking a port closed (default: 1). A clean "connection refused" is never retried — only an actual timeout, since that's the ambiguous case | `--retries 2` |
| `--delay` | Seconds to pause before each connection attempt, to avoid flooding the target (default: 0) | `--delay 0.2` |
| `--save` | Save results to a file; format is inferred from the extension (`.json`, `.csv`, or `.html`/`.htm`). With multiple targets, each host's results are saved to their own file (target name inserted before the extension, e.g. `results_192.168.1.1.json`) | `--save results.json` |
| `--log-file` | Append a timestamped audit trail (command, scan start/end, open ports, skipped targets) to this file; independent of `--quiet`/`--verbose` (see [Audit Logging](#audit-logging) above) | `--log-file scan.log` |
| `--randomize` | Scan ports in random order instead of sequential | `--randomize` |
| `-q`, `--quiet` | Suppress the progress bar and setup messages; the final summary still prints. Mutually exclusive with `-v` | `-q` |
| `-v`, `--verbose` | Print each open port as soon as it's found, not just in the final summary. Mutually exclusive with `-q` | `-v` |
| `--udp` | Scan using UDP instead of TCP (see [UDP Scanning](#udp-scanning) above for what the results mean) | `--udp` |
| `--ping-sweep` | Discover active hosts across a CIDR network range (e.g. `192.168.1.0/24`) using real ICMP pings, instead of scanning ports. IPv4 only | `--ping-sweep` |
| `--host-discovery` | Discover active hosts and scan each one's open ports. IPv4 only | `--host-discovery` |

### Examples

```bash
# Quick scan of common ports on localhost
python portscanner.py 127.0.0.1

# Scan specific web ports
python portscanner.py example.com -p 80,443,8080

# Scan a large port range with more threads
python portscanner.py target.com -p 1-5000 -t 500

# Save results to CSV file
python portscanner.py 192.168.1.1 --save scan_results.csv

# Save a self-contained HTML report
python portscanner.py 192.168.1.1 --save scan_report.html
```

## Expected Output

```bash
Starting scan of 192.168.1.1 on 1024 ports
Using 100 threads with 1.0s timeout
Scanning Ports: 100%|##########| 1024/1024 [00:11<00:00, 92.14port/s, open=2]

==================================================
SCAN RESULTS FOR: 192.168.1.1
PORTS SCANNED: 1024
SCAN DURATION: 11.09s
OPEN PORTS FOUND: 2

Open ports:
  22 (SSH)
    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    Version: 8.9
  80 (HTTP)
==================================================
```

Banner and version lines are only shown when a banner could be grabbed for that service; unrecognized services show just the port number.

## Color Coding

The output now features color-coded services for improved readability:
- **SSH** - Cyan
- **HTTP/HTTPS** - Green  
- **FTP** - Magenta
- **RDP** - Blue
- Other services - White

## Legal Disclaimer

⚠️ This tool is intended for educational purposes and authorized security testing only. Always ensure you have proper authorization before scanning any network or system.

## Author

Port Scanner