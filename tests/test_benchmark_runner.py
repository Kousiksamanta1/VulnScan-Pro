"""Unit tests for benchmark runner helpers."""

from __future__ import annotations

import unittest
from pathlib import Path

from benchmark_runner import build_nmap_command, parse_requested_tools


class BenchmarkRunnerTests(unittest.TestCase):
    """Exercise deterministic benchmark runner helpers."""

    def test_parse_requested_tools_normalizes_tool_names(self) -> None:
        """Requested tools should be parsed and normalized cleanly."""
        tools = parse_requested_tools(" VulnScan , nmap ")
        self.assertEqual(tools, ["vulnscan", "nmap"])

    def test_build_nmap_command_uses_resolved_ports(self) -> None:
        """Nmap command generation should expand the configured port list."""
        command = build_nmap_command(
            {
                "id": "demo",
                "host": "localhost",
                "port_spec": "8081,8082",
            },
            Path("results/demo.xml"),
        )
        self.assertEqual(command[:5], ["nmap", "-Pn", "-sV", "-p", "8081,8082"])
        self.assertEqual(command[-1], "localhost")


if __name__ == "__main__":
    unittest.main()
