import socket
import threading
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import csv
from typing import List, Dict, Optional

class AdvancedPortScanner:
    """
    An advanced port scanner that performs threaded port scanning with additional features.

    This class provides functionality to scan ports on a target host using multiple threads,
    identify services running on open ports, and save results in various formats.
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
                    'banner': self.get_banner(port) if service != "Unknown" else None
                }

                # Thread-safe update of results
                with self.lock:
                    self.open_ports.append(port)
                    self.port_info[port] = port_info

                # Print result to console
                print(f"Port {port}: Open ({service})")
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
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scanning tasks
            future_to_port = {executor.submit(self.scan_single_port, port): port for port in ports}
            
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
                print(f"  {port} ({service})")
        else:
            print("\nNo open ports found.")

        print("="*50)

def main():
    """
    Main function to parse command line arguments and execute the port scan.

    This function handles user input, validates parameters, and orchestrates
    the scanning process with appropriate error handling.
    """
    # Create argument parser for command line interface
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner - Scan ports on a target host with threading",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_scanner.py 192.168.1.1
  python advanced_scanner.py example.com -p 80,443,22
  python advanced_scanner.py target.com -p 1-1000 -t 200 --timeout 2.0
  python advanced_scanner.py 10.0.0.1 --save scan_results.json

To run this script:
1. Save it as 'advanced_scanner.py'
2. Open terminal/command prompt in the same directory
3. Run with: python advanced_scanner.py [arguments]

Required arguments:
  target              Target IP address or hostname to scan

Optional arguments:
  -p, --ports         Port range or specific ports (e.g., 80,443,22 or 1-1000)
  -t, --threads       Maximum number of concurrent threads (default: 100)
  --timeout           Connection timeout in seconds (default: 1.0)
  --save              Save results to file (JSON or CSV format)

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

        # Create scanner instance
        scanner = AdvancedPortScanner(args.target, start_port, end_port)
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