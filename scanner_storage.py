"""Persistence helpers for scan history, comparison, and user settings."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4


def get_data_directory() -> Path:
    """Return the application data directory, creating it when needed."""
    data_directory = Path.home() / ".vulnscan_pro"
    data_directory.mkdir(parents=True, exist_ok=True)
    return data_directory


def get_settings_path() -> Path:
    """Return the JSON path used for persistent user settings."""
    return get_data_directory() / "settings.json"


def get_history_path() -> Path:
    """Return the JSON path used for persisted scan history."""
    return get_data_directory() / "scan_history.json"


def default_settings() -> dict[str, Any]:
    """Return default user settings for the scanner GUI."""
    return {
        "timeout": 2.0,
        "max_workers": 32,
        "port_profile": "common",
        "custom_ports": "",
        "export_format": "JSON",
        "history_limit": 30,
        "show_closed_ports": True,
        "sort_ports_by": "Port",
        "port_filter": "All",
        "last_target": "",
    }


def load_settings() -> dict[str, Any]:
    """Load settings from disk and merge them with defaults."""
    settings = default_settings()
    path = get_settings_path()
    if not path.exists():
        return settings

    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return settings

    if isinstance(stored, dict):
        settings.update(stored)
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    """Persist settings to disk in JSON format."""
    merged = default_settings()
    merged.update(settings)
    get_settings_path().write_text(
        json.dumps(merged, indent=2),
        encoding="utf-8",
    )


def load_history() -> list[dict[str, Any]]:
    """Load scan history entries from disk."""
    path = get_history_path()
    if not path.exists():
        return []

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(payload, list):
        return []

    return payload


def append_history(scan_results: dict[str, Any], limit: int = 30) -> list[dict[str, Any]]:
    """Append a scan result to history and enforce the configured retention limit."""
    entry = make_history_entry(scan_results)
    history = load_history()
    history.insert(0, entry)
    trimmed = history[: max(1, int(limit))]
    get_history_path().write_text(
        json.dumps(trimmed, indent=2),
        encoding="utf-8",
    )
    return trimmed


def make_history_entry(scan_results: dict[str, Any]) -> dict[str, Any]:
    """Create a lightweight history entry with a snapshot summary."""
    snapshot = build_scan_snapshot(scan_results)
    return {
        "scan_id": scan_results.get("scan_id") or uuid4().hex[:10],
        "target": scan_results.get("target", ""),
        "status": scan_results.get("status", "unknown"),
        "started_at": scan_results.get("started_at", ""),
        "finished_at": scan_results.get("finished_at", ""),
        "snapshot": snapshot,
        "results": deepcopy(scan_results),
    }


def collect_findings(scan_results: dict[str, Any]) -> list[dict[str, str]]:
    """Collect normalized findings from web, TLS, and risky port exposure."""
    findings: list[dict[str, str]] = []
    web_result = scan_results.get("web", {})
    tls_result = scan_results.get("tls", {})

    for finding in web_result.get("findings", []):
        findings.append(
            {
                "name": finding.get("name", "Web finding"),
                "severity": finding.get("severity", "info"),
                "evidence": finding.get("evidence", ""),
                "source": "web",
            }
        )

    for finding in tls_result.get("findings", []):
        findings.append(
            {
                "name": finding.get("name", "TLS finding"),
                "severity": finding.get("severity", "info"),
                "evidence": finding.get("evidence", ""),
                "source": "tls",
            }
        )

    for port_result in scan_results.get("ports", []):
        if port_result.get("status") == "open" and port_result.get("severity") in {"high", "medium"}:
            findings.append(
                {
                    "name": f"Exposed {port_result.get('service', 'service')} on port {port_result.get('port')}",
                    "severity": port_result.get("severity", "info"),
                    "evidence": port_result.get("banner", ""),
                    "source": "port",
                }
            )

    return findings


def build_scan_snapshot(scan_results: dict[str, Any]) -> dict[str, Any]:
    """Build a concise summary snapshot from a scan result structure."""
    open_port_results = [
        port_result
        for port_result in scan_results.get("ports", [])
        if port_result.get("status") == "open"
    ]
    findings = collect_findings(scan_results)
    services = sorted(
        {
            port_result.get("service", "Unknown")
            for port_result in open_port_results
            if port_result.get("service")
        }
    )

    return {
        "open_ports_count": len(open_port_results),
        "open_ports": [port_result.get("port") for port_result in open_port_results],
        "services": services,
        "findings_count": len(findings),
        "highest_severity": highest_severity(findings),
        "tls_grade": scan_results.get("tls", {}).get("grade", "Unavailable"),
    }


def compare_scans(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Compare two scan results and return a delta summary."""
    current_open_ports = {
        int(result["port"])
        for result in current.get("ports", [])
        if result.get("status") == "open"
    }
    previous_open_ports = {
        int(result["port"])
        for result in previous.get("ports", [])
        if result.get("status") == "open"
    }
    current_findings = {finding["name"] for finding in collect_findings(current)}
    previous_findings = {finding["name"] for finding in collect_findings(previous)}

    return {
        "new_open_ports": sorted(current_open_ports - previous_open_ports),
        "closed_ports": sorted(previous_open_ports - current_open_ports),
        "persistent_ports": sorted(current_open_ports & previous_open_ports),
        "new_findings": sorted(current_findings - previous_findings),
        "resolved_findings": sorted(previous_findings - current_findings),
    }


def highest_severity(findings: list[dict[str, str]]) -> str:
    """Return the highest severity represented in a findings collection."""
    ranking = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not findings:
        return "info"
    return max(
        (finding.get("severity", "info") for finding in findings),
        key=lambda severity: ranking.get(severity, 0),
    )

