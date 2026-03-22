"""
Author: Kamran Omar
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# This dictionary stores common port numbers and their service names.
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
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets the program control access to the private target value
    # while still allowing it to be used like a normal attribute. This makes the code safer because
    # validation can happen before changing the value. In this program, the setter prevents the target
    # from being changed to an empty string.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code from NetworkTool by inheriting its target attribute and its getter and setter
# methods instead of rewriting them. For example, when PortScanner calls super().__init__(target),
# it uses the parent constructor to store the target as a private attribute. This saves code and keeps
# shared behavior in one place.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

        # Q4: What would happen without try-except here?
        # Without try-except, a socket error such as a timeout or unreachable target could cause the
        # program to crash while scanning. That would stop the rest of the ports from being checked and
        # make the scanner less reliable. Exception handling allows the program to report the error and
        # continue running.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            try:
                self.scan_results.append((port, status, service_name))
            finally:
                self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock is not None:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading so that multiple ports can be scanned at the same time, which makes the scan
    # much faster. If 1024 ports were scanned one by one, the program could take a long time because
    # each closed or slow port might wait for the timeout before moving on. Threading improves speed
    # by letting many connection attempts happen concurrently.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()

    except sqlite3.Error as e:
        print(f"Database error: {e}")

    finally:
        if conn is not None:
            conn.close()


def load_past_scans():
    conn = None
    try:
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return

        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
            return

        for target, port, status, service, scan_date in rows:
            print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    while True:
        try:
            start_port = int(input("Enter starting port number (1-1024): "))
            end_port = int(input("Enter ending port number (1-1024): "))

            if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
                continue

            if end_port < start_port:
                print("End port must be greater than or equal to start port.")
                continue

            break

        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"--- Scan Results for {target} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target, scanner.scan_results)

    history_choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if history_choice == "yes":
        load_past_scans()

# Q5: New Feature Proposal
# One additional feature I would add is a filter that shows only ports that match a certain status or service name,
# such as only Open ports or only web-related services. I would use a list comprehension to quickly build a filtered
# list from self.scan_results based on the user's choice. Diagram: See diagram_studentID.png in the repository root