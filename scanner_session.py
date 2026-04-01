"""Shared scan session helpers used by the GUI and CLI entry points."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any
from uuid import uuid4

from scanner_metadata import build_runtime_metadata


def build_blank_scan_results(mode: str = "gui") -> dict[str, Any]:
    """Return a fresh scan result payload with reproducibility metadata."""
    return {
        "scan_id": "",
        "target_input": "",
        "target": "",
        "url": "",
        "status": "idle",
        "started_at": "",
        "finished_at": "",
        "duration_seconds": 0.0,
        "ports_requested": [],
        "ports": [],
        "dns": {},
        "web": {},
        "tls": {},
        "errors": [],
        "metadata": build_runtime_metadata(mode),
        "scan_profile": {},
    }


def seed_scan_results(
    *,
    mode: str,
    target_input: str,
    prepared_target: dict[str, Any],
    ports: list[int],
    timeout: float,
    max_workers: int,
    port_spec: str,
    export_format: str = "",
) -> dict[str, Any]:
    """Create a ready-to-run scan result structure with run configuration attached."""
    scan_results = build_blank_scan_results(mode=mode)
    scan_results.update(
        {
            "scan_id": uuid4().hex[:10],
            "target_input": target_input,
            "target": prepared_target["hostname"],
            "url": prepared_target["url"],
            "status": "running",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "ports_requested": list(ports),
            "scan_profile": {
                "port_spec": port_spec,
                "port_count": len(ports),
                "timeout_seconds": timeout,
                "max_workers": max_workers,
                "export_format": export_format.strip().upper(),
                "target_scheme": prepared_target.get("scheme", ""),
                "target_port": prepared_target.get("port"),
                "target_type": "ip" if prepared_target.get("is_ip") else "hostname",
            },
        }
    )
    return scan_results


def append_scan_error(scan_results: dict[str, Any], message: str) -> None:
    """Record a scan error message once so it survives export and later review."""
    normalized_message = message.strip()
    if not normalized_message:
        return

    errors = scan_results.setdefault("errors", [])
    if normalized_message not in errors:
        errors.append(normalized_message)


def finalize_scan_results(
    scan_results: dict[str, Any],
    *,
    status: str,
    scan_started_monotonic: float | None = None,
) -> dict[str, Any]:
    """Finalize scan timings and status in a shared format."""
    scan_results["status"] = status
    scan_results["finished_at"] = datetime.now().isoformat(timespec="seconds")
    if scan_started_monotonic is not None:
        scan_results["duration_seconds"] = round(
            time.perf_counter() - scan_started_monotonic,
            2,
        )
    return scan_results
