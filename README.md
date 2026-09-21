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
- **Multiple output formats** (JSON and CSV)
- **Command-line interface** with flexible options
- **Color-coded output** for improved readability
- **Progress bar** using tqdm library for visual feedback during scanning

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

## Installation

1. Clone or download this repository
2. Make sure you have Python installed on your system

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
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `target` | Target IP address or hostname to scan; comma-separate for multiple. Required unless `--targets-file` is given | `192.168.1.1` or `host1.com,host2.com` |
| `--targets-file` | File with one target per line (blank lines and `#` comments ignored); combines with `target` and de-duplicates. Not supported with `--ping-sweep`/`--host-discovery` | `--targets-file hosts.txt` |
| `-p`, `--ports` | Port range or specific ports (e.g., 80,443,22 or 1-1000); scans exactly the ports given, not the range spanning them | `-p 80,443,22` |
| `--top-ports` | Scan the N most common ports (a hand-curated list, not `-p`/range-based); mutually exclusive with `-p` | `--top-ports 100` |
| `-t`, `--threads` | Maximum number of concurrent threads (default: 100) | `-t 200` |
| `--timeout` | Connection timeout in seconds (default: 1.0) | `--timeout 2.0` |
| `--save` | Save results to a file; format is inferred from the extension (`.json` or `.csv`). With multiple targets, each host's results are saved to their own file (target name inserted before the extension, e.g. `results_192.168.1.1.json`) | `--save results.json` |
| `--randomize` | Scan ports in random order instead of sequential | `--randomize` |
| `-q`, `--quiet` | Suppress the progress bar and setup messages; the final summary still prints. Mutually exclusive with `-v` | `-q` |
| `-v`, `--verbose` | Print each open port as soon as it's found, not just in the final summary. Mutually exclusive with `-q` | `-v` |
| `--ping-sweep` | Discover active hosts across a CIDR network range (e.g. `192.168.1.0/24`) using real ICMP pings, instead of scanning ports | `--ping-sweep` |
| `--host-discovery` | Discover active hosts and scan each one's open ports | `--host-discovery` |

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
```

## Expected Output

```bash
Starting scan of 192.168.1.1 on 1024 ports
Using 100 threads with 1.0s timeout
Scanning Ports: 100%|##########| 1024/1024 [00:11<00:00, 92.14port/s]

==================================================
SCAN RESULTS FOR: 192.168.1.1
PORTS SCANNED: 1024
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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Port Scanner