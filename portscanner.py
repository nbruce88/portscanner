import socket
import threading
import sys
import time
import platform
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import csv
from typing import List, Dict, Optional
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm  # Added tqdm for progress bar

class PortScanner:
    """
    A port scanner that performs threaded port scanning with additional features.

    This class provides functionality to scan ports on a target host using multiple threads,
    identify services running on open ports, perform ping sweeps for network discovery,
    and identify operating systems based on service ports.
    """

    def __init__(self, target: str, start_port: int = 1, end_port: int = 1024):
        """
        Initialize the port scanner with target and port range.

        Args:
            target (str): Target IP address or hostname to scan
            start_port (int): Starting port number for scanning (default: 1)
            end_port (int): Ending port number for scanning (default: 1024)
        """
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.port_info = {}  # Store detailed port information
        self.lock = threading.Lock()  # Thread synchronization lock
        self.timeout = 1.0  # Connection timeout in seconds

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

    def get_os_fingerprint(self, port: int) -> str:
        """
        Attempt to determine OS based on service responses and banners.

        This method performs basic OS fingerprinting by analyzing common service ports.
        It identifies operating systems based on the services running on open ports.
        Note: This is a simplified implementation for demonstration purposes.

        Args:
            port (int): Port number to analyze
            
        Returns:
            str: OS fingerprint or "Unknown" if no match found
        """
        # This is a simplified version - real implementation would be more complex
        # and require detailed banner analysis
        
        if port == 22:  # SSH
            return "Linux/Unix"
        elif port == 3389:  # RDP
            return "Windows"
        elif port in [80, 443]:  # HTTP/HTTPS
            return "Web Server"
        elif port == 21:  # FTP
            return "FTP Server"
        else:
            return "Unknown"

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
            scanner = PortScanner(host, 1, 1024)  # Scan first 1024 ports
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
        try:
            # Create socket for connection attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)  # Set timeout for connection

            # Attempt to connect to the port
            result = sock.connect_ex((self.target, port))

            if result == 0:  # Port is open (connect_ex returns 0 on success)
                # Get service name for the port
                service = self.get_service_name(port)

                # Create detailed port information
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': self.get_banner(port) if service != "Unknown" else None,
                    'os_fingerprint': self.get_os_fingerprint(port)
                }

                # Thread-safe update of results
                with self.lock:
                    self.open_ports.append(port)
                    self.port_info[port] = port_info

                # Return the port info for the progress bar to handle display
                return port_info

            sock.close()
            return None

        except Exception as e:
            # Handle any exceptions during scanning
            return None

    def get_banner(self, port: int) -> Optional[str]:
        """
        Attempt to retrieve service banner information from an open port.

        This function connects to a port and attempts to read initial response data
        which often contains version information about the running service.

        Args:
            port (int): Port number to get banner from

        Returns:
            str or None: Banner information or None if unsuccessful
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)  # Shorter timeout for banner grabbing
            sock.connect((self.target, port))

            # Attempt to receive banner data based on service type
            if port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [22, 23]:  # SSH/Telnet
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            else:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')

            sock.close()
            return banner.strip() if banner else None

        except Exception:
            return None

    def scan_ports(self) -> List[int]:
        """
        Scan all ports in the specified range.

        Returns:
            List[int]: List of open port numbers
        """
        return self.open_ports

    def scan_ports_threaded(self, max_threads: int = 100) -> List[int]:
        """
        Scan ports using multiple threads for improved performance.

        Args:
            max_threads (int): Maximum number of concurrent threads to use

        Returns:
            List[int]: List of open port numbers
        """
        # Create a list of all ports in the range
        ports = list(range(self.start_port, self.end_port + 1))
        
        # Use ThreadPoolExecutor for parallel scanning with progress bar
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scanning tasks with progress tracking
            future_to_port = {executor.submit(self.scan_single_port, port): port for port in ports}
            
            # Create progress bar and update it during scan
            with tqdm(total=len(ports), desc="Scanning Ports", unit="port") as pbar:
                # Process completed tasks
                for future in as_completed(future_to_port):
                    try:
                        result = future.result()
                        if result:
                            # The result is already stored in self.open_ports and self.port_info
                            pass  # Already handled in scan_single_port
                    except Exception as e:
                        # Handle any exceptions during thread execution
                        print(f"Error scanning port {future_to_port[future]}: {e}")
                    
                    # Update progress bar after each completed task
                    pbar.update(1)
        
        return self.open_ports

    def print_summary(self):
        """
        Print a summary of the scan results.
        """
        print("\n" + "="*50)
        print(f"SCAN RESULTS FOR: {self.target}")
        print(f"PORT RANGE: {self.start_port}-{self.end_port}")
        print(f"OPEN PORTS FOUND: {len(self.open_ports)}")

        if self.open_ports:
            print("\nOpen ports:")
            for port in sorted(self.open_ports):
                service = self.port_info[port]['service']
                
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
                    
                print(f"  {Fore.YELLOW}{port} ({service_color}{service}{Style.RESET_ALL})")
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
            # Determine the operating system and use appropriate ping command
            if platform.system().lower() == "windows":
                # Windows ping command
                cmd = ["ping", "-n", "1", "-w", "1000", network_range]
            else:
                # Unix/Linux/Mac ping command
                cmd = ["ping", "-c", "1", "-W", "1", network_range]
                
            print(f"Performing ping sweep on {network_range}...")
            
            # This is a simplified approach - in production, you'd want more robust parsing
            if platform.system().lower() == "windows":
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
            # For demonstration purposes, let's assume we can scan a few hosts
            # In practice, you'd parse the actual ping output to determine active hosts
            
            # Simple approach: try scanning first 5 IPs in the range
            base_ip = network_range.split('.')[0] + '.' + network_range.split('.')[1] + '.' + network_range.split('.')[2]
            for i in range(1, 6):
                test_ip = f"{base_ip}.{i}"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((test_ip, 80))
                    sock.close()
                    
                    if result == 0:
                        active_hosts.append(test_ip)
                        print(f"Active host found: {Fore.GREEN}{test_ip}{Style.RESET_ALL}")
                    else:
                        print(f"Host {Fore.RED}{test_ip}{Style.RESET_ALL} is not responding")
                except:
                    continue
                    
        except Exception as e:
            print(f"Ping sweep error: {e}")
            
        return active_hosts

def main():
    """
    Main function to parse command line arguments and execute the port scan.

    This function handles user input, validates parameters, and orchestrates
    the scanning process with appropriate error handling.
    """
    # Initialize colorama for cross-platform colored output
    colorama.init()
    
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

To run this script:
1. Save it as 'portscanner.py'
2. Open terminal/command prompt in the same directory
3. Run with: python portscanner.py [arguments]

Required arguments:
  target              Target IP address or hostname to scan

Optional arguments:
  -p, --ports         Port range or specific ports (e.g., 80,443,22 or 1-1000)
  -t, --threads       Maximum number of concurrent threads (default: 100)
  --timeout           Connection timeout in seconds (default: 1.0)
  --save              Save results to file (JSON or CSV format)
  --ping-sweep        Perform ping sweep on network range

Note: This tool is intended for educational purposes and authorized security testing only.
        """
    )

    # Add command line arguments
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports",
                       help="Port range or specific ports (e.g., 80,443,22 or 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                       help="Maximum number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                       help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--save", help="Save results to file (JSON or CSV format)")
    parser.add_argument("--ping-sweep", action="store_true", help="Perform ping sweep on network range")
    parser.add_argument("--host-discovery", action="store_true", help="Perform comprehensive host discovery")

    # Parse command line arguments
    args = parser.parse_args()

    try:
        # Validate and parse port range
        if args.ports:
            # Handle both single ports and ranges
            if ',' in args.ports:
                # Parse comma-separated ports
                ports = [int(p.strip()) for p in args.ports.split(',')]
                start_port, end_port = min(ports), max(ports)
            elif '-' in args.ports:
                # Parse range format (e.g., 1-1000)
                start_port, end_port = map(int, args.ports.split('-'))
            else:
                # Single port
                port = int(args.ports)
                start_port, end_port = port, port
        else:
            # Default to common ports range
            start_port, end_port = 1, 1024

        # Validate port range
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError("Port numbers must be between 1 and 65535")

        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port")
            
        # Check if ping sweep is requested
        if args.ping_sweep:
            print(f"Performing ping sweep on {args.target}")
            scanner = PortScanner(args.target, start_port, end_port)
            active_hosts = scanner.ping_sweep(args.target)
            print(f"Found {len(active_hosts)} active hosts:")
            for host in active_hosts:
                print(f"  {host}")
            return

        # Check if host discovery is requested
        if args.host_discovery:
            print(f"Performing comprehensive host discovery on {args.target}")
            scanner = PortScanner(args.target, start_port, end_port)
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

        # Create scanner instance
        scanner = PortScanner(args.target, start_port, end_port)
        scanner.timeout = args.timeout

        print(f"Starting scan of {args.target} on ports {start_port}-{end_port}")
        print(f"Using {args.threads} threads with {args.timeout}s timeout")

        # Perform the scan
        open_ports = scanner.scan_ports_threaded(args.threads)

        # Print summary of results
        scanner.print_summary()

        # Save results if requested
        if args.save:
            # Determine format from filename extension
            if args.save.endswith('.csv'):
                scanner.save_results(args.save, 'csv')
            else:
                scanner.save_results(args.save, 'json')
            print(f"Results saved to {args.save}")

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