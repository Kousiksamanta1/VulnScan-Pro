"""Unit tests for the scanner engine helpers."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

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

    def test_run_xss_checks_detects_attribute_reflection(self) -> None:
        """Reflected payloads inside attributes should be flagged as XSS candidates."""
        engine = ScannerEngine()
        payload = engine.XSS_PAYLOADS[0]["payload"]
        response = SimpleNamespace(
            text=f'<input name="q" value="{payload}">',
            url="https://example.com/?q=probe",
            status_code=200,
        )
        engine._issue_probe = Mock(return_value=(response, 0.05, None))

        result = engine._run_xss_checks(
            Mock(),
            [{"url": "https://example.com/", "parameter": "q"}],
            "",
        )

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["parameter"], "q")
        self.assertEqual(result["context"], "attribute")

    def test_run_sqli_checks_detects_boolean_based_split(self) -> None:
        """A true/false response split should be treated as a boolean-based SQLi signal."""
        engine = ScannerEngine()
        baseline_text = "<html><body><h1>Inventory</h1><p>3 results returned.</p></body></html>"
        baseline_response = SimpleNamespace(
            text=baseline_text,
            url="https://example.com/items?id=1",
            status_code=200,
        )
        denied_response = SimpleNamespace(
            text="<html><body><h1>Access denied</h1></body></html>",
            url="https://example.com/items?id=1",
            status_code=403,
        )
        clean_response = SimpleNamespace(
            text=baseline_text,
            url="https://example.com/items?id=1",
            status_code=200,
        )
        engine._issue_probe = Mock(
            side_effect=[
                (clean_response, 0.06, None),
                (clean_response, 0.07, None),
                (clean_response, 0.05, None),
                (clean_response, 0.06, None),
                (clean_response, 0.07, None),
                (denied_response, 0.07, None),
                (clean_response, 0.07, None),
                (denied_response, 0.07, None),
            ]
        )

        result = engine._run_sqli_checks(
            Mock(),
            [{"url": "https://example.com/items", "parameter": "id"}],
            baseline_response,
            baseline_text,
            0.05,
        )

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["technique"], "boolean-based")
        self.assertEqual(result["parameter"], "id")

    def test_run_sqli_checks_detects_time_based_delay(self) -> None:
        """A large response delay over fast control probes should flag time-based SQLi."""
        engine = ScannerEngine()
        baseline_text = "<html><body><h1>Products</h1><p>Ready.</p></body></html>"
        baseline_response = SimpleNamespace(
            text=baseline_text,
            url="https://example.com/products?id=1",
            status_code=200,
        )
        clean_response = SimpleNamespace(
            text=baseline_text,
            url="https://example.com/products?id=1",
            status_code=200,
        )
        engine._issue_probe = Mock(
            side_effect=[
                (clean_response, 0.05, None),
                (clean_response, 0.05, None),
                (clean_response, 0.06, None),
                (clean_response, 0.06, None),
                (clean_response, 0.07, None),
                (clean_response, 0.06, None),
                (clean_response, 0.06, None),
                (clean_response, 0.07, None),
                (clean_response, 5.25, None),
            ]
        )

        result = engine._run_sqli_checks(
            Mock(),
            [{"url": "https://example.com/products", "parameter": "id"}],
            baseline_response,
            baseline_text,
            0.05,
        )

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["technique"], "time-based")
        self.assertEqual(result["parameter"], "id")

    def test_run_sqli_checks_detects_error_based(self) -> None:
        """A new database error should be flagged as an error-based SQLi signal."""
        engine = ScannerEngine()
        baseline_text = "<html><body><p>No results.</p></body></html>"
        baseline_response = SimpleNamespace(
            text=baseline_text,
            url="https://example.com/items?id=1",
            status_code=200,
        )
        error_response = SimpleNamespace(
            text="<html><body><p>SQL syntax error near '1''</p></body></html>",
            url="https://example.com/items?id=1%27",
            status_code=500,
        )
        engine._issue_probe = Mock(
            side_effect=[
                (error_response, 0.06, None),
            ]
        )

        result = engine._run_sqli_checks(
            Mock(),
            [{"url": "https://example.com/items", "parameter": "id"}],
            baseline_response,
            baseline_text,
            0.05,
        )

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["technique"], "error-based")
        self.assertEqual(result["parameter"], "id")


if __name__ == "__main__":
    unittest.main()
