"""Benchmark result parsing and evaluation helpers."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from scanner_storage import collect_findings

DEFAULT_TOOL_CAPABILITIES = {
    "vulnscan": ["port", "web", "tls"],
    "nmap": ["port"],
    "zap": ["web"],
}


def load_targets(targets_path: Path) -> dict[str, Any]:
    """Load benchmark target definitions from JSON."""
    return json.loads(targets_path.read_text(encoding="utf-8"))


def slugify(value: str) -> str:
    """Convert finding names into stable comparison slugs."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    return slug.strip("-")


def tag_category(tag: str) -> str:
    """Return the category prefix for a canonical benchmark tag."""
    return tag.split(":", maxsplit=1)[0]


def normalize_vulnscan_finding(name: str) -> str | None:
    """Map VulnScan findings into canonical benchmark tags."""
    lowered = name.strip().lower()
    if not lowered:
        return None
    if "potential reflected xss" in lowered:
        return "web:xss"
    if "potential sql injection" in lowered:
        return "web:sqli"
    if lowered.startswith("missing "):
        header_name = lowered.removeprefix("missing ").strip()
        return f"web:missing-{slugify(header_name)}"
    if lowered == "server header exposed":
        return "web:server-header-exposed"
    if lowered == "technology disclosure header":
        return "web:technology-disclosure"
    if "missing secure flag" in lowered:
        return "web:cookie-missing-secure"
    if "missing httponly flag" in lowered:
        return "web:cookie-missing-httponly"
    if "missing samesite flag" in lowered:
        return "web:cookie-missing-samesite"
    if "weak tls protocol support" in lowered:
        return "tls:weak-protocol"
    if "certificate expiring soon" in lowered:
        return "tls:certificate-expiring-soon"
    if "certificate renewal approaching" in lowered:
        return "tls:certificate-renewal-approaching"
    return None


def extract_vulnscan_tags(scan_results: dict[str, Any]) -> set[str]:
    """Extract canonical benchmark tags from a VulnScan result payload."""
    tags = {
        f"port:{port_result['port']}"
        for port_result in scan_results.get("ports", [])
        if port_result.get("status") == "open"
    }
    for finding in collect_findings(scan_results):
        normalized = normalize_vulnscan_finding(finding.get("name", ""))
        if normalized is not None:
            tags.add(normalized)
    return tags


def extract_nmap_tags(xml_text: str) -> set[str]:
    """Extract open-port tags from an Nmap XML report."""
    tags: set[str] = set()
    root = ET.fromstring(xml_text)
    for port in root.findall(".//port"):
        state = port.find("./state")
        if state is not None and state.attrib.get("state") == "open":
            port_id = port.attrib.get("portid", "")
            if port_id:
                tags.add(f"port:{port_id}")
    return tags


def normalize_zap_alert(alert_name: str) -> str | None:
    """Map common ZAP passive alerts into canonical benchmark tags."""
    lowered = alert_name.strip().lower()
    if not lowered:
        return None
    if "content security policy" in lowered and "not set" in lowered:
        return "web:missing-content-security-policy"
    if "anti-clickjacking" in lowered or "x-frame-options" in lowered:
        return "web:missing-x-frame-options"
    if "x-content-type-options" in lowered and ("missing" in lowered or "not set" in lowered):
        return "web:missing-x-content-type-options"
    if "strict-transport-security" in lowered and ("missing" in lowered or "not set" in lowered):
        return "web:missing-strict-transport-security"
    if "referrer-policy" in lowered and ("missing" in lowered or "not set" in lowered):
        return "web:missing-referrer-policy"
    if "permissions-policy" in lowered and ("missing" in lowered or "not set" in lowered):
        return "web:missing-permissions-policy"
    if "cookie no secure flag" in lowered:
        return "web:cookie-missing-secure"
    if "cookie no httponly flag" in lowered:
        return "web:cookie-missing-httponly"
    if "cookie without samesite attribute" in lowered:
        return "web:cookie-missing-samesite"
    return None


def extract_zap_tags(payload: dict[str, Any]) -> set[str]:
    """Extract canonical benchmark tags from a ZAP JSON report."""
    tags: set[str] = set()
    sites = payload.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        alerts = site.get("alerts", [])
        for alert in alerts:
            normalized = normalize_zap_alert(str(alert.get("alert", "")))
            if normalized is not None:
                tags.add(normalized)
    return tags


def calculate_metrics(
    expected_tags: Iterable[str],
    actual_tags: Iterable[str],
    categories: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Calculate precision/recall/F1 over canonical benchmark tags."""
    expected = set(expected_tags)
    actual = set(actual_tags)
    if categories is not None:
        allowed = set(categories)
        expected = {tag for tag in expected if tag_category(tag) in allowed}
        actual = {tag for tag in actual if tag_category(tag) in allowed}

    true_positives = sorted(expected & actual)
    false_positives = sorted(actual - expected)
    false_negatives = sorted(expected - actual)
    tp_count = len(true_positives)
    fp_count = len(false_positives)
    fn_count = len(false_negatives)
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) else 1.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) else 1.0
    f1_score = (
        2.0 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return {
        "expected_tags": sorted(expected),
        "actual_tags": sorted(actual),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_positive_count": tp_count,
        "false_positive_count": fp_count,
        "false_negative_count": fn_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
    }


def load_tool_tags(tool_name: str, output_path: Path) -> set[str]:
    """Load a tool output file and return canonical benchmark tags."""
    if tool_name == "vulnscan":
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        return extract_vulnscan_tags(payload)
    if tool_name == "nmap":
        return extract_nmap_tags(output_path.read_text(encoding="utf-8"))
    if tool_name == "zap":
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        return extract_zap_tags(payload)
    raise ValueError(f"Unsupported benchmark tool '{tool_name}'.")


def evaluate_run_directory(results_dir: Path, targets_path: Path) -> dict[str, Any]:
    """Evaluate one benchmark results directory against expected target findings."""
    targets_payload = load_targets(targets_path)
    metadata = targets_payload.get("metadata", {})
    tool_capabilities = dict(DEFAULT_TOOL_CAPABILITIES)
    tool_capabilities.update(metadata.get("tool_capabilities", {}))

    run_metadata_path = results_dir / "run-metadata.json"
    run_metadata = {}
    if run_metadata_path.exists():
        run_metadata = json.loads(run_metadata_path.read_text(encoding="utf-8"))

    aggregated: dict[str, dict[str, Any]] = {}
    targets = targets_payload.get("targets", [])

    for target in targets:
        tool_expectations = target.get("expected_findings_by_tool", {})
        target_id = str(target["id"])
        for tool_name in _iter_tools(results_dir, run_metadata):
            output_path = _tool_output_path(results_dir, tool_name, target_id)
            run_info = _lookup_run_info(run_metadata, target_id, tool_name)
            if not output_path.exists():
                continue

            actual_tags = load_tool_tags(tool_name, output_path)
            if tool_name in tool_expectations:
                expected_tags = tool_expectations.get(tool_name, [])
                categories = None
            else:
                expected_tags = target.get("expected_findings", [])
                categories = tool_capabilities.get(tool_name)

            metrics = calculate_metrics(expected_tags, actual_tags, categories=categories)
            metrics.update(
                {
                    "target_id": target_id,
                    "target_name": target.get("name", target_id),
                    "tool": tool_name,
                    "duration_seconds": run_info.get("duration_seconds"),
                    "status": run_info.get("status", "completed"),
                }
            )
            aggregated.setdefault(tool_name, {"targets": []})["targets"].append(metrics)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results_dir": str(results_dir),
        "targets_file": str(targets_path),
        "tools": {},
    }
    for tool_name, tool_summary in aggregated.items():
        summary["tools"][tool_name] = _aggregate_tool_metrics(tool_summary["targets"])
    return summary


def write_evaluation_summary(results_dir: Path, targets_path: Path) -> Path:
    """Evaluate a results directory and write `evaluation.json` beside it."""
    summary = evaluate_run_directory(results_dir, targets_path)
    output_path = results_dir / "evaluation.json"
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return output_path


def _aggregate_tool_metrics(target_metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-target metrics into a per-tool summary."""
    true_positive_count = sum(item["true_positive_count"] for item in target_metrics)
    false_positive_count = sum(item["false_positive_count"] for item in target_metrics)
    false_negative_count = sum(item["false_negative_count"] for item in target_metrics)
    precision = (
        true_positive_count / (true_positive_count + false_positive_count)
        if (true_positive_count + false_positive_count)
        else 1.0
    )
    recall = (
        true_positive_count / (true_positive_count + false_negative_count)
        if (true_positive_count + false_negative_count)
        else 1.0
    )
    f1_score = (
        2.0 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    durations = [item["duration_seconds"] for item in target_metrics if item["duration_seconds"] is not None]
    return {
        "target_count": len(target_metrics),
        "true_positive_count": true_positive_count,
        "false_positive_count": false_positive_count,
        "false_negative_count": false_negative_count,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "average_duration_seconds": round(sum(durations) / len(durations), 4) if durations else None,
        "targets": target_metrics,
    }


def _iter_tools(results_dir: Path, run_metadata: dict[str, Any]) -> list[str]:
    """Return the tools represented in a benchmark run."""
    tools = {
        path.name
        for path in results_dir.iterdir()
        if path.is_dir() and path.name in {"vulnscan", "nmap", "zap"}
    }
    for target in run_metadata.get("targets", []):
        tools.update(target.get("tool_runs", {}).keys())
    return sorted(tools)


def _tool_output_path(results_dir: Path, tool_name: str, target_id: str) -> Path:
    """Return the expected benchmark output path for a given tool and target."""
    suffix = {"vulnscan": ".json", "nmap": ".xml", "zap": ".json"}[tool_name]
    return results_dir / tool_name / f"{target_id}{suffix}"


def _lookup_run_info(run_metadata: dict[str, Any], target_id: str, tool_name: str) -> dict[str, Any]:
    """Look up tool execution metadata for one benchmark target."""
    for target in run_metadata.get("targets", []):
        if target.get("id") == target_id:
            return target.get("tool_runs", {}).get(tool_name, {})
    return {}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for benchmark evaluation."""
    parser = argparse.ArgumentParser(
        prog="vulnscan-benchmark-eval",
        description="Evaluate benchmark outputs against canonical expected findings.",
    )
    parser.add_argument("results_dir", type=Path, help="Benchmark results directory to evaluate.")
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path("benchmarks/targets.json"),
        help="Benchmark target definition file.",
    )
    args = parser.parse_args(argv)

    summary_path = write_evaluation_summary(args.results_dir.resolve(), args.targets.resolve())
    print(f"Wrote evaluation summary to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
