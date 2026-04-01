"""Unit tests for CLI helper behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner_cli import _resolve_export_format, _resolve_output_path


class ScannerCliTests(unittest.TestCase):
    """Exercise deterministic CLI helper behavior."""

    def test_resolve_export_format_prefers_explicit_flag(self) -> None:
        """Explicit export formats should override path inference."""
        resolved = _resolve_export_format(Path("report.csv"), "json")
        self.assertEqual(resolved, "JSON")

    def test_resolve_output_path_adds_missing_suffix(self) -> None:
        """Output paths without an extension should inherit the chosen export format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = _resolve_output_path(Path(temp_dir) / "scan-report", "HTML")

        self.assertEqual(output_path.suffix, ".html")


if __name__ == "__main__":
    unittest.main()
