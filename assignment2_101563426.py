"""
Author: <Ashkan Pazaj>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime


# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")


# Dictionary mapping common port numbers to their associated service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    """Parent class representing a generic network tool with a target host."""

    def __init__(self, target):
        self.__target = None
        self.target = target  # Use the setter for validation

# Q3: What is the benefit of using @property and @target.setter?
# Using @property and @target.setter provides controlled access to the private
# __target. The getter allows clean reading, while the setter validates input
# (e.g., no empty values), preventing invalid state and centralizing validation logic.

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it reuses the target property,
# its getter/setter validation, and the destructor. By calling super().__init__(target),
# it delegates target handling to the parent instead of duplicating code,
# following DRY and improving reusability.

class PortScanner(NetworkTool):
    """Child class that extends NetworkTool with port scanning capabilities."""

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Q4: What would happen without try-except here?
# Without try-except, network errors would cause unhandled exceptions,
# crashing threads or the program. In multithreading, errors may be silent
# and leave results incomplete. try-except handles errors gracefully
# and allows scanning to continue.

        try:
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            with self.lock:
                self.scan_results.append((port, status, service_name))

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [entry for entry in self.scan_results if entry[1] == "Open"]

# Q2: Why do we use threading instead of scanning one port at a time?
# Sequential scanning waits for each timeout, making it very slow.
# Threading runs scans concurrently, reducing total time to about one timeout
# instead of the sum, making it faster and practical.

    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    """Save scan results to the scan_history SQLite database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            target  TEXT,
            port    INTEGER,
            status  TEXT,
            service TEXT,
            scan_date TEXT
        )""")

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    """Load and display all past scan results from the database."""
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                # row: (id, target, port, status, service, scan_date)
                _, target, port, status, service, scan_date = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.OperationalError:
        print("No past scans found.")

# MAIN PROGRAM

if __name__ == "__main__":

    # --- Get target IP ---
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    # --- Get start port ---
    start_port = None
    while start_port is None:
        try:
            start_port = int(input("Enter starting port (1–1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                start_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # --- Get end port ---
    end_port = None
    while end_port is None:
        try:
            end_port = int(input("Enter ending port (1–1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                end_port = None
            elif end_port < start_port:
                print(f"End port must be greater than or equal to start port ({start_port}).")
                end_port = None
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # --- Scan ---
    scanner = PortScanner(target)
    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")
    if open_ports:
        for port, status, service in sorted(open_ports):
            print(f"Port {port}: {status} ({service})")
    else:
        print("No open ports found.")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, open_ports)

    history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if history == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# Add banner-grabbing: after finding an open port, send a probe and read
# the response to identify the service/version (e.g., OpenSSH).
# Implement grab_banner(port), call it when port is open, and store the
# banner with results (e.g., in a database column). A nested if-statement
# would check if a response was received, and if so, whether it contains
# a recognizable service signature before storing it.
# Diagram: See diagram_studentID.png in the repository root