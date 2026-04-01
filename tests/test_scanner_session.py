"""Unit tests for shared scan session helpers."""

from __future__ import annotations

import time
import unittest

from scanner_engine import ScannerEngine
from scanner_session import (
    append_scan_error,
    build_blank_scan_results,
    finalize_scan_results,
    seed_scan_results,
)


class ScannerSessionTests(unittest.TestCase):
    """Verify the shared scan result lifecycle used by GUI and CLI entry points."""

    def test_seed_scan_results_attaches_metadata_and_profile(self) -> None:
        """Seeded scan payloads should include runtime metadata and scan profile fields."""
        prepared_target = ScannerEngine.prepare_target("example.com")

        scan_results = seed_scan_results(
            mode="cli",
            target_input="example.com",
            prepared_target=prepared_target,
            ports=[80, 443],
            timeout=3.5,
            max_workers=12,
            port_spec="web",
            export_format="html",
        )

        self.assertEqual(scan_results["status"], "running")
        self.assertEqual(scan_results["metadata"]["app"]["name"], "VulnScan Pro")
        self.assertEqual(scan_results["metadata"]["execution"]["mode"], "cli")
        self.assertEqual(scan_results["scan_profile"]["port_spec"], "web")
        self.assertEqual(scan_results["scan_profile"]["port_count"], 2)
        self.assertEqual(scan_results["scan_profile"]["timeout_seconds"], 3.5)
        self.assertEqual(scan_results["scan_profile"]["export_format"], "HTML")

    def test_append_scan_error_deduplicates_messages(self) -> None:
        """Identical errors should only be stored once in scan results."""
        scan_results = build_blank_scan_results(mode="gui")

        append_scan_error(scan_results, "Network timeout")
        append_scan_error(scan_results, "Network timeout")

        self.assertEqual(scan_results["errors"], ["Network timeout"])

    def test_finalize_scan_results_records_status_and_duration(self) -> None:
        """Finalized scan payloads should capture end time and duration."""
        scan_results = build_blank_scan_results(mode="cli")

        finalize_scan_results(
            scan_results,
            status="completed",
            scan_started_monotonic=time.perf_counter() - 0.01,
        )

        self.assertEqual(scan_results["status"], "completed")
        self.assertTrue(scan_results["finished_at"])
        self.assertGreater(scan_results["duration_seconds"], 0.0)


if __name__ == "__main__":
    unittest.main()
