"""Unit tests for benchmark parsing and evaluation helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmark_metrics import (
    calculate_metrics,
    evaluate_run_directory,
    extract_nmap_tags,
    extract_vulnscan_tags,
    extract_zap_tags,
)


class BenchmarkMetricsTests(unittest.TestCase):
    """Verify canonical tag extraction and metric calculation."""

    def test_extract_vulnscan_tags_maps_findings_and_open_ports(self) -> None:
        """VulnScan results should normalize to canonical benchmark tags."""
        scan_results = {
            "ports": [
                {"port": 8081, "status": "open", "service": "HTTP", "severity": "low", "banner": ""},
                {"port": 22, "status": "closed", "service": "SSH", "severity": "info", "banner": ""},
            ],
            "web": {
                "findings": [
                    {"name": "Potential reflected XSS in 'q'", "severity": "high", "evidence": ""},
                    {"name": "Missing Content-Security-Policy", "severity": "medium", "evidence": ""},
                ]
            },
            "tls": {"findings": []},
        }

        tags = extract_vulnscan_tags(scan_results)

        self.assertIn("port:8081", tags)
        self.assertIn("web:xss", tags)
        self.assertIn("web:missing-content-security-policy", tags)
        self.assertNotIn("port:22", tags)

    def test_extract_nmap_tags_parses_open_ports_from_xml(self) -> None:
        """Nmap XML should map open ports to canonical tags."""
        xml_text = """
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80"><state state="open" /></port>
              <port protocol="tcp" portid="22"><state state="closed" /></port>
            </ports>
          </host>
        </nmaprun>
        """
        tags = extract_nmap_tags(xml_text)
        self.assertEqual(tags, {"port:80"})

    def test_extract_zap_tags_maps_common_alerts(self) -> None:
        """ZAP passive alerts should map to canonical web posture tags."""
        payload = {
            "site": [
                {
                    "alerts": [
                        {"alert": "Content Security Policy (CSP) Header Not Set"},
                        {"alert": "Cookie No HttpOnly Flag"},
                    ]
                }
            ]
        }
        tags = extract_zap_tags(payload)
        self.assertEqual(
            tags,
            {
                "web:missing-content-security-policy",
                "web:cookie-missing-httponly",
            },
        )

    def test_calculate_metrics_filters_categories(self) -> None:
        """Metrics should respect supported category filters."""
        metrics = calculate_metrics(
            {"port:8081", "web:xss"},
            {"port:8081", "web:missing-content-security-policy"},
            categories={"port"},
        )
        self.assertEqual(metrics["true_positive_count"], 1)
        self.assertEqual(metrics["false_positive_count"], 0)
        self.assertEqual(metrics["false_negative_count"], 0)

    def test_evaluate_run_directory_aggregates_tool_metrics(self) -> None:
        """A benchmark run directory should produce a per-tool evaluation summary."""
        targets_payload = {
            "metadata": {"tool_capabilities": {"vulnscan": ["port", "web"]}},
            "targets": [
                {
                    "id": "xss-lab",
                    "name": "XSS Lab",
                    "expected_findings": ["port:8081", "web:xss"],
                }
            ],
        }
        scan_results = {
            "ports": [{"port": 8081, "status": "open", "service": "HTTP", "severity": "low", "banner": ""}],
            "web": {"findings": [{"name": "Potential reflected XSS in 'q'", "severity": "high", "evidence": ""}]},
            "tls": {"findings": []},
        }
        run_metadata = {
            "targets": [
                {
                    "id": "xss-lab",
                    "tool_runs": {
                        "vulnscan": {
                            "status": "completed",
                            "duration_seconds": 1.25,
                        }
                    },
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            targets_path = root / "targets.json"
            results_dir = root / "run_1"
            vulnscan_dir = results_dir / "vulnscan"
            vulnscan_dir.mkdir(parents=True)
            targets_path.write_text(json.dumps(targets_payload), encoding="utf-8")
            (results_dir / "run-metadata.json").write_text(json.dumps(run_metadata), encoding="utf-8")
            (vulnscan_dir / "xss-lab.json").write_text(json.dumps(scan_results), encoding="utf-8")

            summary = evaluate_run_directory(results_dir, targets_path)

        self.assertIn("vulnscan", summary["tools"])
        self.assertEqual(summary["tools"]["vulnscan"]["true_positive_count"], 2)
        self.assertEqual(summary["tools"]["vulnscan"]["average_duration_seconds"], 1.25)


if __name__ == "__main__":
    unittest.main()
