"""
Unit tests for assignment2_studentID.py
"""

import unittest
from assignment2_101563426 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """PortScanner should store the target and start with an empty results list."""
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """get_open_ports() should return only tuples whose status is 'Open'."""
        scanner = PortScanner("127.0.0.1")
        scanner.scan_results.append((22,  "Open",   "SSH"))
        scanner.scan_results.append((80,  "Open",   "HTTP"))
        scanner.scan_results.append((443, "Closed", "HTTPS"))

        open_ports = scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)
        for entry in open_ports:
            self.assertEqual(entry[1], "Open")

    def test_common_ports_dict(self):
        """common_ports dictionary should map well-known ports to correct service names."""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """Setting target to an empty string should leave the original value unchanged."""
        scanner = PortScanner("127.0.0.1")
        scanner.target = ""
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()