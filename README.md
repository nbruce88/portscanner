# Advanced Port Scanner

An advanced port scanner that performs threaded port scanning with additional features like service identification and banner grabbing.

## Features

- **Threading support** for fast scanning of multiple ports
- **Service identification** for common ports (HTTP, HTTPS, SSH, FTP, etc.)
- **Banner grabbing** to retrieve service version information
- **Multiple output formats** (JSON and CSV)
- **Command-line interface** with flexible options

## Prerequisites

- Python 3.6 or higher installed on your system

## Installation

1. Clone or download this repository
2. Make sure you have Python installed on your system

## Usage

```bash
# Scan default port range (1-1024) on a target IP
python advanced_scanner.py 192.168.1.1

# Scan specific ports
python advanced_scanner.py example.com -p 80,443,22

# Scan a port range with custom thread count
python advanced_scanner.py target.com -p 1-1000 -t 200

# Scan with custom timeout and save results
python advanced_scanner.py 10.0.0.1 --timeout 2.0 --save scan_results.json
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `target` | Target IP address or hostname to scan | `192.168.1.1` |
| `-p`, `--ports` | Port range or specific ports (e.g., 80,443,22 or 1-1000) | `-p 80,443,22` |
| `-t`, `--threads` | Number of concurrent threads | `-t 200` |
| `--timeout` | Connection timeout in seconds | `--timeout 2.0` |
| `--save` | Save results to file | `--save results.json` |

### Examples

```bash
# Quick scan of common ports on localhost
python advanced_scanner.py 127.0.0.1

# Scan specific web ports
python advanced_scanner.py example.com -p 80,443,8080

# Scan a large port range with more threads
python advanced_scanner.py target.com -p 1-5000 -t 500

# Save results to CSV file
python advanced_scanner.py 192.168.1.1 --save scan_results.csv
```

## Expected Output

```
Starting scan of 192.168.1.1 on ports 1-1024
Using 100 threads with 1.0s timeout
Port 22 (SSH)
Port 80 (HTTP)
Port 443 (HTTPS)

==================================================
SCAN RESULTS FOR: 192.168.1.1
PORT RANGE: 1-1024
OPEN PORTS FOUND: 3

Open ports:
  22 (SSH)
  80 (HTTP)
  443 (HTTPS)
==================================================
```

## Legal Disclaimer

⚠️ This tool is intended for educational purposes and authorized security testing only. Always ensure you have proper authorization before scanning any network or system.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Advanced Port Scanner