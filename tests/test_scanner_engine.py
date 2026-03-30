"""Unit tests for the scanner engine helpers."""

from __future__ import annotations

import unittest

from scanner_engine import ScannerEngine


class ScannerEngineTests(unittest.TestCase):
    """Exercise the deterministic utility paths in ScannerEngine."""

    def test_parse_ports_accepts_preset_and_ranges(self) -> None:
        """Mixed presets and explicit ranges should resolve into sorted ports."""
        ports = ScannerEngine.parse_ports("web,21,8000-8001")
        self.assertIn(21, ports)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8000, ports)
        self.assertIn(8001, ports)

    def test_prepare_target_normalizes_plain_hostnames(self) -> None:
        """Plain hostnames should be normalized into HTTP URLs."""
        prepared = ScannerEngine.prepare_target("example.com")
        self.assertEqual(prepared["hostname"], "example.com")
        self.assertEqual(prepared["url"], "http://example.com/")

    def test_prepare_target_rejects_invalid_ports(self) -> None:
        """Malformed target ports should raise a friendly ValueError."""
        with self.assertRaises(ValueError):
            ScannerEngine.prepare_target("https://example.com:70000")

    def test_inject_payload_targets_named_parameter(self) -> None:
        """Payload injection should update the requested query parameter."""
        engine = ScannerEngine()
        injected = engine._inject_payload("https://example.com/?id=1&view=full", "'", "view")
        self.assertIn("view=%27", injected)
        self.assertIn("id=1", injected)


if __name__ == "__main__":
    unittest.main()
