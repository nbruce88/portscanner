# Port Scanner

A simple port scanner that performs threaded port scanning with additional features like service identification and banner grabbing.

\\\\\\
              /\\/\\
 ___--~^~~--_(-  -)_--~~^~--___
 ^\\        Port Scanner        /^
    \\   /\\   /\\    /\\   /\\   /
      \\/   \\/  \\  /   \\/  \\/
             ^\\/^

## Features

- **Threading support** for fast scanning of multiple ports
- **Service identification** for common ports (HTTP, HTTPS, SSH, FTP, etc.)
- **Banner grabbing** to retrieve service version information and detailed service data
- **Version detection** from banners for services like SSH and HTTP
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
    Version: 8.9p1
  80 (HTTP)
    Banner: HTTP/1.1 200 OK
    Server: Apache/2.4.52 (Ubuntu)
    Version: 2.4.52
```

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