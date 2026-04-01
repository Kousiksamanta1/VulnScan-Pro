"""Project metadata and reproducibility helpers."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any

APP_NAME = "VulnScan Pro"
APP_VERSION = "2.1.0"
SCAN_SCHEMA_VERSION = "2026.1"
RUNTIME_DEPENDENCIES = ("customtkinter", "dnspython", "requests", "reportlab")


def build_runtime_metadata(mode: str) -> dict[str, Any]:
    """Return stable runtime metadata for saved scans and exported reports."""
    return {
        "app": {
            "name": APP_NAME,
            "version": APP_VERSION,
            "scan_schema_version": SCAN_SCHEMA_VERSION,
        },
        "execution": {
            "mode": mode,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "runtime": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "dependencies": _dependency_versions(),
    }


def _dependency_versions() -> dict[str, str]:
    """Capture dependency versions without failing when optional packages are absent."""
    versions: dict[str, str] = {}
    for package_name in RUNTIME_DEPENDENCIES:
        try:
            versions[package_name] = version(package_name)
        except PackageNotFoundError:
            versions[package_name] = "not-installed"
    return versions
