import socket
import threading
import sys
import time
import platform
import subprocess
import re
import ipaddress
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import csv
from typing import List, Dict, Optional
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm  # Added tqdm for progress bar

# Hand-curated list of commonly-scanned ports, roughly ordered by how likely
# they are to be interesting. Not derived from nmap's statistical frequency data.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080,
    20, 69, 88, 123, 161, 162, 389, 465, 514, 587,
    636, 902, 989, 990, 1025, 1433, 1521, 2049, 2082, 2083,
    3268, 3269, 5060, 5061, 5432, 6379, 8000, 8443, 8888, 9200,
]

class PortScanner:
    """
    A port scanner that performs threaded port scanning with additional features.

    This class provides functionality to scan ports on a target host using multiple threads,
    identify services running on open ports, perform ping sweeps for network discovery,
    and identify operating systems based on service ports.
    """

    def __init__(self, target: str, ports: List[int]):
        """
        Initialize the port scanner with target and the ports to scan.

        Args:
            target (str): Target IP address or hostname to scan
            ports (List[int]): Port numbers to scan
        """
        self.target = target
        self.ports = list(ports)
        self.open_ports = []
        self.port_info = {}  # Store detailed port information
        self.lock = threading.Lock()  # Thread synchronization lock
        self.timeout = 1.0  # Connection timeout in seconds
        self.retries = 1  # Extra attempts on a timeout before giving up on a port
        self.protocol = 'tcp'
        self.verbose = False
        self.quiet = False

    def get_service_name(self, port: int) -> str:
        """
        Map port numbers to service names for common ports.

        Args:
            port (int): Port number to identify

        Returns:
            str: Service name or "Unknown" if not recognized
        """
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server",
            1521: "Oracle DB", 3389: "RDP", 5900: "VNC"
        }
        return services.get(port, "Unknown")

    def get_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        """
        Grab service banners from open ports for detailed identification.

        Args:
            host (str): Host to connect to
            port (int): Port number to connect to
            timeout (float): Connection timeout in seconds

        Returns:
            str: Service banner or "No banner" if connection fails
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip() if banner.strip() else "No banner"
        except Exception as e:
            # Log the exception for debugging
            print(f"Error getting banner from {host}:{port} - {e}")
            return "No banner"

    def detect_version(self, service_name: str, banner: str) -> str:
        """
        Detect service versions from banners.

        Args:
            service_name (str): Name of the service
            banner (str): Service banner text

        Returns:
            str: Detected version or "Unknown"
        """
        if not banner:
            return "Unknown"

        # Simple version detection based on banner content
        if service_name == "SSH":
            # Look for SSH version in banner
            match = re.search(r'SSH-(\d+\.\d+)', banner)
            return match.group(1) if match else "Unknown"
        elif service_name == "HTTP" or service_name == "HTTPS":
            # Look for server information in banner
            match = re.search(r'Server: (.+)', banner, re.IGNORECASE)
            return match.group(1).strip() if match else "Unknown"
        else:
            # Generic best-effort: look for a version-like number in the banner
            match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
            return match.group(1) if match else "Unknown"

    def host_discovery(self, network_range: str) -> Dict[str, Dict]:
        """
        Perform comprehensive host discovery on a network range.
        
        This method performs both ping sweep and service detection to identify
        active hosts and their services. It returns detailed information about
        each discovered host including OS fingerprinting.
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            Dict[str, Dict]: Dictionary mapping IP addresses to host information
        """
        active_hosts = self.ping_sweep(network_range)
        host_info = {}
        
        for host in active_hosts:
            # For each active host, scan common ports to identify services
            scanner = PortScanner(host, list(range(1, 1025)))  # Scan first 1024 ports
            scanner.timeout = self.timeout
            
            try:
                open_ports = scanner.scan_ports_threaded(50)  # Use fewer threads for discovery
                
                # Get detailed port information including OS fingerprinting
                ports_info = {}
                for port in open_ports:
                    service = scanner.get_service_name(port)
                    os_fingerprint = scanner.get_os_fingerprint(port)
                    ports_info[port] = {
                        'service': service,
                        'os_fingerprint': os_fingerprint
                    }
                
                host_info[host] = {
                    'active': True,
                    'open_ports': ports_info
                }
            except Exception as e:
                # Even if scanning fails, we know the host is active
                host_info[host] = {
                    'active': True,
                    'error': str(e)
                }
        
        return host_info

    def scan_single_port(self, port: int) -> Optional[Dict]:
        """
        Scan a single port and collect detailed information about it.

        This method attempts to connect to a specific port and determines if it's open,
        then gathers service information and banner data.

        Args:
            port (int): Port number to scan

        Returns:
            dict or None: Port information dictionary if open, None otherwise
        """
        attempts = self.retries + 1
        for attempt in range(attempts):
            try:
                # Create socket for connection attempt
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)  # Set timeout for connection

                # Attempt to connect to the port
                result = sock.connect_ex((self.target, port))

                if result == 0:  # Port is open (connect_ex returns 0 on success)
                    # Get service name for the port
                    service = self.get_service_name(port)

                    # Get banner information
                    banner = self.get_banner(self.target, port, self.timeout) if service != "Unknown" else None

                    # Detect version from banner
                    version = self.detect_version(service, banner) if banner and banner != "No banner" else "Unknown"

                    # Create detailed port information
                    port_info = {
                        'port': port,
                        'status': 'open',
                        'service': service,
                        'banner': banner,
                        'version': version,
                        'os_fingerprint': self.get_os_fingerprint(port)
                    }

                    # Thread-safe update of results
                    with self.lock:
                        self.open_ports.append(port)
                        self.port_info[port] = port_info

                    if self.verbose:
                        tqdm.write(f"[+] Port {port} open - {service}")

                    # Return the port info for the progress bar to handle display
                    return port_info

                # Definitive refusal (e.g. ECONNREFUSED) - no point retrying
                sock.close()
                return None

            except socket.timeout:
                # No response at all - could be packet loss, worth a retry
                if attempt < attempts - 1:
                    continue
                return None

            except Exception:
                # Any other error is not retry-worthy
                return None

        return None

    def scan_single_port_udp(self, port: int) -> Optional[Dict]:
        """
        Scan a single UDP port and collect detailed information about it.

        UDP is connectionless, so unlike TCP there's no clean "port is open"
        signal. Three outcomes are possible: the target sends a real response
        (definitively open), the OS delivers an ICMP "port unreachable" back
        to us on this connected socket (definitively closed, no retry needed),
        or nothing comes back at all within the timeout (ambiguous - could be
        an open service that ignores empty probes, or a firewall dropping the
        packet silently - reported as 'open|filtered', matching nmap's own
        terminology for this exact ambiguity).

        Args:
            port (int): Port number to scan

        Returns:
            dict or None: Port information dictionary if open or open|filtered,
                None if a definitive ICMP refusal was received
        """
        attempts = self.retries + 1
        for attempt in range(attempts):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            status, banner = None, None
            try:
                sock.connect((self.target, port))
                sock.send(b'')
                data, _ = sock.recvfrom(1024)
                status = 'open'
                banner = data.decode('utf-8', errors='ignore').strip() or None
            except socket.timeout:
                if attempt < attempts - 1:
                    continue
                status = 'open|filtered'
            except (ConnectionRefusedError, ConnectionResetError, OSError):
                # ICMP port unreachable (or similar) - definitively closed
                return None
            finally:
                sock.close()

            service = self.get_service_name(port)
            version = self.detect_version(service, banner) if banner else "Unknown"

            port_info = {
                'port': port,
                'status': status,
                'service': service,
                'banner': banner,
                'version': version,
                'os_fingerprint': self.get_os_fingerprint(port)
            }

            with self.lock:
                self.open_ports.append(port)
                self.port_info[port] = port_info

            if self.verbose:
                tqdm.write(f"[+] Port {port} {status} - {service}")

            return port_info

        return None

    def scan_ports(self) -> List[int]:
        """
        Scan all ports in the specified range.

        Returns:
            List[int]: List of open port numbers
        """
        return self.open_ports

    def get_os_fingerprint(self, port: int) -> str:
        """
        Provide a rough OS fingerprint guess based on the open port.

        Args:
            port (int): Port number to base the guess on

        Returns:
            str: A simple OS guess derived from common service ports
        """
        windows_ports = {135, 139, 445, 3389}
        unix_ports = {22, 111, 2049}
        if port in windows_ports:
            return "Likely Windows"
        elif port in unix_ports:
            return "Likely Unix/Linux"
        else:
            return "Unknown"

    def scan_ports_threaded(self, max_threads: int = 100) -> List[int]:
        """
        Scan ports using multiple threads for improved performance.

        Args:
            max_threads (int): Maximum number of concurrent threads to use

        Returns:
            List[int]: List of open port numbers
        """
        ports = self.ports
        scan_fn = self.scan_single_port_udp if self.protocol == 'udp' else self.scan_single_port

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(scan_fn, port): port for port in ports}

            with tqdm(total=len(ports), desc="Scanning Ports", unit="port", disable=self.quiet) as pbar:
                for future in as_completed(future_to_port):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Error scanning port {future_to_port[future]}: {e}")

                    pbar.update(1)

        return self.open_ports

    def save_results(self, filename: str, file_format: str = 'json'):
        """
        Save scan results to a file in JSON or CSV format.

        Args:
            filename (str): Path to the output file
            file_format (str): Output format, either 'json' or 'csv'
        """
        if file_format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['port', 'status', 'service', 'banner', 'version', 'os_fingerprint'])
                for port in sorted(self.open_ports):
                    info = self.port_info[port]
                    writer.writerow([
                        info['port'], info['status'], info['service'],
                        info['banner'], info['version'], info['os_fingerprint']
                    ])
        else:
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.target,
                    'ports_scanned': len(self.ports),
                    'open_ports': [self.port_info[port] for port in sorted(self.open_ports)]
                }, f, indent=2)

    def print_summary(self):
        """
        Print a summary of the scan results.
        """
        print("\n" + "="*50)
        print(f"SCAN RESULTS FOR: {self.target}")
        print(f"PORTS SCANNED: {len(self.ports)}")
        print(f"OPEN PORTS FOUND: {len(self.open_ports)}")

        if self.open_ports:
            print("\nOpen ports:")
            for port in sorted(self.open_ports):
                info = self.port_info[port]
                service = info['service']
                banner = info['banner']
                version = info['version']
                status = info.get('status', 'open')

                # Color code different services
                if service == "SSH":
                    service_color = Fore.CYAN
                elif service in ["HTTP", "HTTPS"]:
                    service_color = Fore.GREEN
                elif service == "FTP":
                    service_color = Fore.MAGENTA
                elif service == "RDP":
                    service_color = Fore.BLUE
                else:
                    service_color = Fore.WHITE

                # Ambiguous UDP results (no confirmed response) get a visible marker
                status_label = f" {Fore.MAGENTA}[{status}]{Style.RESET_ALL}" if status != 'open' else ""

                # Print port information with banner and version
                print(f"  {Fore.YELLOW}{port} ({service_color}{service}{Style.RESET_ALL}){status_label}")
                if banner and banner != "No banner":
                    print(f"    Banner: {banner}")
                if version and version != "Unknown":
                    print(f"    Version: {version}")
        else:
            print("\nNo open ports found.")

        print("="*50)

    def ping_sweep(self, network_range: str) -> List[str]:
        """
        Perform a ping sweep to discover active hosts in a network range.

        This method performs a network discovery by pinging hosts in the specified 
        network range to identify which ones are active. It supports both Windows 
        and Unix/Linux/Mac platforms using appropriate ping commands.

        Args:
            network_range (str): Network range in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            List[str]: List of active IP addresses found in the network range
        """
        active_hosts = []

        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError as e:
            print(f"Invalid network range: {e}")
            return active_hosts

        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]

        print(f"Performing ping sweep on {network_range} ({len(hosts)} hosts)...")

        def ping_host(ip: str) -> Optional[str]:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(self.timeout))), str(ip)]

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 2)
                return str(ip) if result.returncode == 0 else None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=min(100, len(hosts))) as executor:
            future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}

            with tqdm(total=len(hosts), desc="Ping sweep", unit="host") as pbar:
                for future in as_completed(future_to_ip):
                    ip = future.result()
                    if ip:
                        active_hosts.append(ip)
                        tqdm.write(f"Active: {Fore.GREEN}{ip}{Style.RESET_ALL}")
                    pbar.update(1)

        return sorted(active_hosts, key=lambda ip: ipaddress.ip_address(ip))

def main():
    """
    Main function to parse command line arguments and execute the port scan.

    This function handles user input, validates parameters, and orchestrates
    the scanning process with appropriate error handling.
    """
    # Initialize colorama for cross-platform colored output
    colorama.init()

    # Pre-parse just --config so its values can become argparse defaults
    # below, before the real command-line parsing happens
    conf_parser = argparse.ArgumentParser(add_help=False)
    conf_parser.add_argument("--config")
    conf_args, _ = conf_parser.parse_known_args()

    config_overrides = {}
    if conf_args.config:
        try:
            with open(conf_args.config) as f:
                config_overrides = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error: could not load config file '{conf_args.config}': {e}")
            sys.exit(1)

        allowed_keys = {"ports", "top_ports", "port_file", "threads", "timeout",
                         "retries", "save", "randomize", "quiet", "verbose", "udp"}
        unknown = set(config_overrides) - allowed_keys
        if unknown:
            print(f"Error: unknown config option(s): {', '.join(sorted(unknown))}")
            sys.exit(1)
        if sum(k in config_overrides for k in ("ports", "top_ports", "port_file")) > 1:
            print("Error: config can only set one of ports / top_ports / port_file")
            sys.exit(1)
        if config_overrides.get("quiet") and config_overrides.get("verbose"):
            print("Error: config cannot set both quiet and verbose")
            sys.exit(1)

    # Create argument parser for command line interface
    parser = argparse.ArgumentParser(
        description="Port Scanner - Scan ports on a target host with threading",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python portscanner.py 192.168.1.1
  python portscanner.py example.com -p 80,443,22
  python portscanner.py target.com -p 1-1000 -t 200 --timeout 2.0
  python portscanner.py 10.0.0.1 --save scan_results.json
  python portscanner.py 192.168.1.0/24 --ping-sweep
  python portscanner.py 192.168.1.0/24 --host-discovery
  python portscanner.py target.com --top-ports 100 --randomize
  python portscanner.py target.com -p 1-1000 -q
  python portscanner.py target.com -p 1-1000 -v
  python portscanner.py host1.com,host2.com,192.168.1.5 -p 80,443
  python portscanner.py --targets-file hosts.txt -p 1-1000
  python portscanner.py target.com --port-file myports.txt
  python portscanner.py target.com --config myconfig.json
  python portscanner.py target.com -p 53,123,161 --udp

To run this script:
1. Save it as 'portscanner.py'
2. Open terminal/command prompt in the same directory
3. Run with: python portscanner.py [arguments]

Required arguments:
  target              Target IP address or hostname(s) to scan (comma-separated for
                       multiple), required unless --targets-file is given

Optional arguments:
  -p, --ports         Port range or specific ports (e.g., 80,443,22 or 1-1000)
  --top-ports         Scan the N most common ports instead of a range
  --port-file         File with one port or port range per line (blank lines
                       and lines starting with # are ignored)
  -t, --threads       Maximum number of concurrent threads (default: 100)
  --timeout           Connection timeout in seconds (default: 1.0)
  --retries           Extra attempts on a connection timeout before marking a
                       port closed (default: 1)
  --save              Save results to file (JSON or CSV format)
  --targets-file      File with one target per line (blank lines and lines
                       starting with # are ignored)
  --config            JSON file of default settings; any CLI flag overrides
                       its values
  --randomize         Scan ports in random order instead of sequential
  -q, --quiet         Suppress progress bar and setup messages
  -v, --verbose       Print each open port as it's found during the scan
  --udp               Scan using UDP instead of TCP. UDP is connectionless, so
                       a non-response is ambiguous ("open|filtered") rather
                       than a confirmed open port, and scans are typically
                       slower since most non-responding ports wait out the
                       full timeout instead of returning instantly
  --ping-sweep        Perform ping sweep on network range

Note: This tool is intended for educational purposes and authorized security testing only.
        """
    )

    # Add command line arguments
    parser.add_argument("target", nargs="?",
                       help="Target IP address or hostname(s) to scan (comma-separated for multiple)")
    parser.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("--config", help="JSON file of default settings; any CLI flag overrides its values")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports",
                       help="Port range or specific ports (e.g., 80,443,22 or 1-1000)")
    port_group.add_argument("--top-ports", type=int, metavar="N",
                       help="Scan the N most common ports instead of a range")
    port_group.add_argument("--port-file",
                       help="File with one port or port range per line")
    parser.add_argument("-t", "--threads", type=int, default=100,
                       help="Maximum number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                       help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--retries", type=int, default=1,
                       help="Extra attempts on a connection timeout before marking a port closed (default: 1)")
    parser.add_argument("--save", help="Save results to file (JSON or CSV format)")
    parser.add_argument("--randomize", action="store_true", help="Scan ports in random order instead of sequential")
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress progress bar and setup messages")
    verbosity_group.add_argument("-v", "--verbose", action="store_true",
                       help="Print each open port as it's found during the scan")
    parser.add_argument("--udp", action="store_true",
                       help="Scan using UDP instead of TCP (non-responses are ambiguous, see --help epilog)")
    parser.add_argument("--ping-sweep", action="store_true", help="Perform ping sweep on network range")
    parser.add_argument("--host-discovery", action="store_true", help="Perform comprehensive host discovery")

    # Config file values become the new defaults; explicit CLI flags still win
    parser.set_defaults(**config_overrides)

    # Parse command line arguments
    args = parser.parse_args()

    try:
        if args.targets_file and (args.ping_sweep or args.host_discovery):
            raise ValueError("--targets-file is not supported with --ping-sweep/--host-discovery; "
                              "those take a single CIDR range as the target")

        # Check if ping sweep is requested
        if args.ping_sweep:
            if not args.target:
                raise ValueError("target (a CIDR range) is required for --ping-sweep")
            print(f"Performing ping sweep on {args.target}")
            scanner = PortScanner(args.target, [])
            active_hosts = scanner.ping_sweep(args.target)
            print(f"Found {len(active_hosts)} active hosts:")
            for host in active_hosts:
                print(f"  {host}")
            return

        # Check if host discovery is requested
        if args.host_discovery:
            if not args.target:
                raise ValueError("target (a CIDR range) is required for --host-discovery")
            print(f"Performing comprehensive host discovery on {args.target}")
            scanner = PortScanner(args.target, [])
            host_info = scanner.host_discovery(args.target)
            print(f"Discovered {len(host_info)} hosts:")
            
            for host, info in host_info.items():
                print(f"  {Fore.YELLOW}{host}{Style.RESET_ALL}:")
                if 'error' in info:
                    print(f"    {Fore.RED}Error: {info['error']}{Style.RESET_ALL}")
                elif 'open_ports' in info:
                    if info['open_ports']:
                        for port, port_info in info['open_ports'].items():
                            service = port_info['service']
                            os_fingerprint = port_info['os_fingerprint']
                            
                            # Color code different services
                            if service == "SSH":
                                service_color = Fore.CYAN
                            elif service in ["HTTP", "HTTPS"]:
                                service_color = Fore.GREEN
                            elif service == "FTP":
                                service_color = Fore.MAGENTA
                            elif service == "RDP":
                                service_color = Fore.BLUE
                            else:
                                service_color = Fore.WHITE
                                
                            print(f"    Port {Fore.YELLOW}{port} ({service_color}{service}{Style.RESET_ALL}): {os_fingerprint}")
                    else:
                        print("    No open ports found")
            return

        # Build the list of ports to scan
        if args.top_ports:
            if args.top_ports <= 0:
                raise ValueError("--top-ports must be a positive integer")
            ports = TOP_PORTS[:args.top_ports]
            if args.top_ports > len(TOP_PORTS):
                print(f"Only {len(TOP_PORTS)} curated top ports available; scanning all of them")
        elif args.ports:
            if ',' in args.ports:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            elif '-' in args.ports:
                start_port, end_port = map(int, args.ports.split('-'))
                ports = list(range(start_port, end_port + 1))
            else:
                ports = [int(args.ports)]
        elif args.port_file:
            ports = []
            with open(args.port_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '-' in line:
                        start, end = map(int, line.split('-'))
                        ports.extend(range(start, end + 1))
                    else:
                        ports.append(int(line))
            ports = list(dict.fromkeys(ports))  # de-dup, preserve order
        else:
            ports = list(range(1, 1025))

        if not all(1 <= p <= 65535 for p in ports):
            raise ValueError("Port numbers must be between 1 and 65535")

        if args.threads <= 0:
            raise ValueError("Thread count must be a positive integer")

        if args.retries < 0:
            raise ValueError("Retries must be zero or a positive integer")

        if args.randomize:
            random.shuffle(ports)

        # Build the list of targets to scan
        targets = []
        if args.target:
            targets.extend(t.strip() for t in args.target.split(',') if t.strip())
        if args.targets_file:
            with open(args.targets_file) as f:
                targets.extend(
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith('#')
                )
        targets = list(dict.fromkeys(targets))  # de-dup, preserve order

        if not targets:
            raise ValueError("A target (or --targets-file) is required")

        resolved_targets = []
        for target in targets:
            try:
                socket.gethostbyname(target)
                resolved_targets.append(target)
            except socket.gaierror:
                print(f"Skipping {target}: could not resolve")

        if not resolved_targets:
            raise ValueError("No targets could be resolved")

        total_open = 0
        for target in resolved_targets:
            scanner = PortScanner(target, ports)
            scanner.timeout = args.timeout
            scanner.retries = args.retries
            scanner.protocol = 'udp' if args.udp else 'tcp'
            scanner.verbose = args.verbose
            scanner.quiet = args.quiet

            if not args.quiet:
                protocol_label = " (UDP)" if args.udp else ""
                print(f"Starting scan of {target} on {len(ports)} ports{protocol_label}")
                print(f"Using {args.threads} threads with {args.timeout}s timeout")

            # Perform the scan
            scanner.scan_ports_threaded(args.threads)
            total_open += len(scanner.open_ports)

            # Print summary of results
            scanner.print_summary()

            # Save results if requested
            if args.save:
                if len(resolved_targets) > 1:
                    safe_target = re.sub(r'[<>:"/\\|?*]', '_', target)
                    base, ext = args.save.rsplit('.', 1) if '.' in args.save else (args.save, '')
                    save_path = f"{base}_{safe_target}.{ext}" if ext else f"{base}_{safe_target}"
                else:
                    save_path = args.save

                # Determine format from filename extension
                if save_path.endswith('.csv'):
                    scanner.save_results(save_path, 'csv')
                else:
                    scanner.save_results(save_path, 'json')
                print(f"Results saved to {save_path}")

        if len(targets) > 1:
            print(f"\nScanned {len(resolved_targets)}/{len(targets)} target(s), {total_open} open port(s) total")

    except Exception as e:
        # Handle any errors during execution
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    """
    Entry point of the script.

    This block ensures that the main function is called when the script is executed directly,
    rather than when it's imported as a module.
    """
    main()