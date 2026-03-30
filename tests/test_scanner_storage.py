"""Unit tests for settings and scan comparison helpers."""

from __future__ import annotations

import unittest

from scanner_storage import build_scan_snapshot, compare_scans


class ScannerStorageTests(unittest.TestCase):
    """Exercise deterministic history and comparison helpers."""

    def test_build_scan_snapshot_summarizes_open_ports_and_findings(self) -> None:
        """Snapshots should count open ports and expose the highest severity."""
        scan_results = {
            "ports": [
                {"port": 22, "status": "open", "service": "SSH", "severity": "low", "banner": ""},
                {"port": 445, "status": "open", "service": "SMB", "severity": "high", "banner": ""},
            ],
            "web": {"findings": []},
            "tls": {"findings": [], "grade": "B"},
        }
        snapshot = build_scan_snapshot(scan_results)
        self.assertEqual(snapshot["open_ports_count"], 2)
        self.assertEqual(snapshot["highest_severity"], "high")
        self.assertEqual(snapshot["tls_grade"], "B")

    def test_compare_scans_returns_port_and_finding_deltas(self) -> None:
        """Comparison output should show newly opened and closed ports."""
        current = {
            "ports": [
                {"port": 22, "status": "open", "service": "SSH", "severity": "low", "banner": ""},
                {"port": 443, "status": "open", "service": "HTTPS", "severity": "low", "banner": ""},
            ],
            "web": {"findings": [{"name": "Missing CSP", "severity": "medium", "evidence": ""}]},
            "tls": {"findings": []},
        }
        previous = {
            "ports": [
                {"port": 22, "status": "open", "service": "SSH", "severity": "low", "banner": ""},
                {"port": 80, "status": "open", "service": "HTTP", "severity": "low", "banner": ""},
            ],
            "web": {"findings": []},
            "tls": {"findings": []},
        }
        delta = compare_scans(current, previous)
        self.assertEqual(delta["new_open_ports"], [443])
        self.assertEqual(delta["closed_ports"], [80])
        self.assertIn("Missing CSP", delta["new_findings"])


if __name__ == "__main__":
    unittest.main()
