"""Headless CLI entry point for repeatable dissertation scans."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from scanner_engine import ScannerEngine
from scanner_reporting import export_scan_results
from scanner_session import append_scan_error, finalize_scan_results, seed_scan_results
from scanner_storage import build_scan_snapshot, collect_findings


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vulnscan-pro-scan",
        description="Run VulnScan Pro without the desktop UI for repeatable experiments.",
    )
    parser.add_argument("target", help="Target IP, hostname, or URL to scan.")
    parser.add_argument(
        "--ports",
        default="common",
        help="Port preset or explicit list/range such as common, web, 22,80,443, or 1-1024.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Socket and HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Maximum worker threads used for the scan.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv", "html", "pdf"),
        help="Optional export format for a saved report.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output file path. The format is inferred from the extension unless --format is set.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the final structured scan result to stdout.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress live progress output and print only the final summary.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI scan workflow."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] == "scan":
        args_list = args_list[1:]

    parser = build_parser()
    args = parser.parse_args(args_list)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")
    if args.workers <= 0:
        parser.error("--workers must be greater than zero.")

    export_format = _resolve_export_format(args.output, args.format)
    output_path = _resolve_output_path(args.output, export_format)
    if args.format and args.output is None:
        parser.error("--output is required when --format is provided.")
    if args.output is not None and export_format is None:
        parser.error(
            "Could not determine the export format. Use --format or an output path ending in "
            ".json, .csv, .html, or .pdf."
        )

    try:
        scan_results = run_scan(
            args.target,
            port_spec=args.ports,
            timeout=args.timeout,
            max_workers=args.workers,
            mode="cli",
            export_format=export_format or "",
            event_handler=None if args.quiet else _print_event,
        )
    except ValueError as exc:
        parser.error(str(exc))

    if output_path is not None and export_format is not None:
        export_scan_results(scan_results, output_path, export_format)
        if not args.quiet:
            print(f"Saved {export_format} report to {output_path}")

    if args.print_json:
        print(json.dumps(scan_results, indent=2))
    else:
        _print_summary(scan_results)

    return 0


def run_scan(
    target: str,
    *,
    port_spec: str = "common",
    timeout: float = 2.0,
    max_workers: int = 32,
    mode: str = "cli",
    export_format: str = "",
    event_handler: Any | None = None,
) -> dict[str, Any]:
    """Run a full scan and return the structured scan result payload."""
    ports = ScannerEngine.parse_ports(port_spec)
    prepared = ScannerEngine.prepare_target(target)
    scan_results = seed_scan_results(
        mode=mode,
        target_input=target,
        prepared_target=prepared,
        ports=ports,
        timeout=timeout,
        max_workers=max_workers,
        port_spec=port_spec,
        export_format=export_format,
    )

    engine = ScannerEngine(timeout=timeout, max_workers=max_workers)
    port_results: dict[int, dict[str, Any]] = {}
    started_monotonic = time.perf_counter()

    for event in engine.run_full_scan(target, ports):
        _apply_cli_event(scan_results, port_results, event)
        if event_handler is not None:
            event_handler(event)

    final_status = scan_results.get("status", "running")
    if final_status == "running":
        final_status = "completed"
    finalize_scan_results(
        scan_results,
        status=final_status,
        scan_started_monotonic=started_monotonic,
    )
    return scan_results


def _apply_cli_event(
    scan_results: dict[str, Any],
    port_results: dict[int, dict[str, Any]],
    event: dict[str, Any],
) -> None:
    """Project streamed engine events into the shared scan result structure."""
    event_type = event.get("type")
    if event_type == "port":
        result = event["result"]
        port_results[int(result["port"])] = result
        scan_results["ports"] = [port_results[key] for key in sorted(port_results)]
        return

    if event_type == "dns":
        scan_results["dns"] = event["result"]
        return

    if event_type == "web":
        scan_results["web"] = event["result"]
        if event["result"].get("status") == "error":
            append_scan_error(scan_results, event["result"].get("message", "Web checks failed."))
        return

    if event_type == "tls":
        scan_results["tls"] = event["result"]
        return

    if event_type == "error":
        append_scan_error(scan_results, event.get("message", "An unknown scanner error occurred."))
        return

    if event_type == "cancelled":
        append_scan_error(scan_results, event.get("message", "Scan cancelled."))
        scan_results["status"] = "cancelled"
        return

    if event_type == "complete":
        scan_results["status"] = "completed"


def _print_event(event: dict[str, Any]) -> None:
    """Render a concise live event line for the CLI."""
    event_type = event.get("type")
    if event_type == "status":
        print(event.get("message", "Status update received."))
        return

    if event_type == "port":
        result = event["result"]
        if result.get("status") == "open":
            print(
                f"Open port {result['port']} | "
                f"{result.get('service', 'Unknown')} | {result.get('banner', '')}"
            )
        return

    if event_type == "dns":
        print("DNS intelligence updated.")
        return

    if event_type == "web":
        print("Web posture analysis updated.")
        return

    if event_type == "tls":
        print("TLS posture analysis updated.")
        return

    if event_type in {"error", "cancelled", "complete"}:
        print(event.get("message", "Scanner event received."))


def _print_summary(scan_results: dict[str, Any]) -> None:
    """Print a dissertation-friendly final scan summary."""
    snapshot = build_scan_snapshot(scan_results)
    findings = collect_findings(scan_results)
    print(
        "Scan summary: "
        f"target={scan_results.get('target', '')} | "
        f"status={scan_results.get('status', '')} | "
        f"open_ports={snapshot.get('open_ports_count', 0)} | "
        f"findings={len(findings)} | "
        f"risk={snapshot.get('highest_severity', 'info').upper()} | "
        f"tls={snapshot.get('tls_grade', 'Unavailable')} | "
        f"duration={scan_results.get('duration_seconds', 0.0)}s"
    )


def _resolve_export_format(output_path: Path | None, export_format: str | None) -> str | None:
    """Resolve the desired export format from explicit flags or file extension."""
    if export_format:
        return export_format.upper()

    if output_path is None or not output_path.suffix:
        return None

    suffix = output_path.suffix.lower()
    return {
        ".json": "JSON",
        ".csv": "CSV",
        ".html": "HTML",
        ".pdf": "PDF",
    }.get(suffix)


def _resolve_output_path(output_path: Path | None, export_format: str | None) -> Path | None:
    """Normalize the output path and ensure parent directories exist."""
    if output_path is None:
        return None

    normalized_output = output_path.expanduser().resolve()
    normalized_output.parent.mkdir(parents=True, exist_ok=True)
    if normalized_output.suffix or export_format is None:
        return normalized_output
    return normalized_output.with_suffix(f".{export_format.lower()}")


if __name__ == "__main__":
    raise SystemExit(main())
