"""Unit tests for report exports with reproducibility metadata."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner_engine import ScannerEngine
from scanner_reporting import export_csv, export_html
from scanner_session import append_scan_error, finalize_scan_results, seed_scan_results


class ScannerReportingTests(unittest.TestCase):
    """Exercise report output for metadata-rich dissertation exports."""

    def _sample_scan_results(self) -> dict[str, object]:
        prepared_target = ScannerEngine.prepare_target("https://example.com")
        scan_results = seed_scan_results(
            mode="cli",
            target_input="https://example.com",
            prepared_target=prepared_target,
            ports=[80, 443],
            timeout=2.0,
            max_workers=8,
            port_spec="web",
            export_format="json",
        )
        scan_results["ports"] = [
            {
                "port": 443,
                "service": "HTTPS",
                "status": "open",
                "severity": "low",
                "latency_ms": 21.2,
                "banner": "nginx",
            }
        ]
        scan_results["web"] = {
            "findings": [
                {
                    "name": "Potential reflected XSS in 'q'",
                    "severity": "high",
                    "evidence": "<script>alert(1)</script>",
                }
            ]
        }
        scan_results["tls"] = {"findings": [], "grade": "A"}
        append_scan_error(scan_results, "Example web warning")
        finalize_scan_results(scan_results, status="completed")
        return scan_results

    def test_export_csv_includes_run_metadata(self) -> None:
        """CSV exports should carry metadata and dependency sections."""
        scan_results = self._sample_scan_results()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.csv"
            export_csv(scan_results, output_path)

            content = output_path.read_text(encoding="utf-8")

        self.assertIn("Run Metadata", content)
        self.assertIn("Port Spec,web", content)
        self.assertIn("Dependencies", content)
        self.assertIn("requests", content)
        self.assertIn("Recorded Errors", content)

    def test_export_html_includes_metadata_panels(self) -> None:
        """HTML exports should render metadata, dependencies, and escaped evidence."""
        scan_results = self._sample_scan_results()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.html"
            export_html(scan_results, output_path)

            content = output_path.read_text(encoding="utf-8")

        self.assertIn("Run Metadata", content)
        self.assertIn("Dependencies", content)
        self.assertIn("Recorded Errors", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)


if __name__ == "__main__":
    unittest.main()
