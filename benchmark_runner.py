"""Benchmark runner for VulnScan Pro and optional baseline tools."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmark_metrics import load_targets, write_evaluation_summary
from scanner_cli import run_scan
from scanner_engine import ScannerEngine

SUPPORTED_TOOLS = ("vulnscan", "nmap", "zap")


def parse_requested_tools(raw_tools: str) -> list[str]:
    """Parse a comma-separated tool list into normalized names."""
    tools = [item.strip().lower() for item in raw_tools.split(",") if item.strip()]
    if not tools:
        raise ValueError("At least one benchmark tool must be selected.")
    invalid = sorted(set(tools) - set(SUPPORTED_TOOLS))
    if invalid:
        raise ValueError(f"Unsupported benchmark tools: {', '.join(invalid)}")
    return tools


def build_nmap_command(target: dict[str, Any], output_path: Path) -> list[str]:
    """Build an Nmap command for the supplied benchmark target."""
    host = target.get("host") or target.get("url")
    if not host:
        raise ValueError(f"Target '{target.get('id', 'unknown')}' is missing a host.")
    port_argument = ",".join(str(port) for port in ScannerEngine.parse_ports(target.get("port_spec", "common")))
    return ["nmap", "-Pn", "-sV", "-p", port_argument, "-oX", str(output_path), str(host)]


def build_zap_command(target: dict[str, Any], output_path: Path) -> list[str]:
    """Build a ZAP baseline command for the supplied benchmark target."""
    url = target.get("url")
    if not url:
        raise ValueError(f"Target '{target.get('id', 'unknown')}' is missing a URL for ZAP.")
    zap_binary = shutil.which("zap-baseline.py") or shutil.which("zap-baseline")
    if zap_binary is None:
        raise FileNotFoundError("zap-baseline.py was not found on PATH.")
    return [zap_binary, "-t", str(url), "-J", str(output_path), "-m", "1", "-I"]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the benchmark runner."""
    parser = argparse.ArgumentParser(
        prog="vulnscan-benchmark",
        description="Run VulnScan Pro and optional baseline tools against benchmark targets.",
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path("benchmarks/targets.json"),
        help="Benchmark target definition file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmarks/results"),
        help="Directory that will receive timestamped benchmark runs.",
    )
    parser.add_argument(
        "--tools",
        default="vulnscan,nmap,zap",
        help="Comma-separated list of tools to run.",
    )
    parser.add_argument(
        "--target-ids",
        default="",
        help="Optional comma-separated subset of benchmark target IDs.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout forwarded to VulnScan Pro runs.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        help="Worker count forwarded to VulnScan Pro runs.",
    )
    parser.add_argument(
        "--skip-missing-tools",
        action="store_true",
        help="Skip optional baseline tools when their binaries are not installed.",
    )
    args = parser.parse_args(argv)

    result = run_benchmark(
        targets_path=args.targets.resolve(),
        output_dir=args.output_dir.resolve(),
        tools=parse_requested_tools(args.tools),
        target_ids=args.target_ids,
        timeout=args.timeout,
        workers=args.workers,
        skip_missing_tools=args.skip_missing_tools,
    )
    print(f"Benchmark run saved to {result['run_dir']}")
    print(f"Run metadata: {result['metadata_path']}")
    print(f"Evaluation summary: {result['evaluation_path']}")
    return 0


def run_benchmark(
    *,
    targets_path: Path,
    output_dir: Path,
    tools: list[str],
    target_ids: str = "",
    timeout: float = 2.0,
    workers: int = 32,
    skip_missing_tools: bool = False,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Run a benchmark pass and return the output paths and metadata."""
    targets_payload = load_targets(targets_path)
    selected_targets = _select_targets(targets_payload.get("targets", []), target_ids)
    run_dir = _create_run_directory(output_dir)
    run_metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "targets_file": str(targets_path),
        "results_dir": str(run_dir),
        "tools_requested": tools,
        "targets": [],
    }

    for target in selected_targets:
        target_record = {
            "id": target["id"],
            "name": target.get("name", target["id"]),
            "tool_runs": {},
        }
        if progress_callback is not None:
            progress_callback(
                {
                    "type": "target_started",
                    "target_id": target["id"],
                    "target_name": target.get("name", target["id"]),
                }
            )
        for tool_name in tools:
            if progress_callback is not None:
                progress_callback(
                    {
                        "type": "tool_started",
                        "target_id": target["id"],
                        "tool": tool_name,
                    }
                )
            try:
                result = _run_tool(
                    tool_name,
                    target,
                    run_dir,
                    timeout=timeout,
                    workers=workers,
                    skip_missing_tools=skip_missing_tools,
                )
            except Exception as exc:
                result = {
                    "status": "failed",
                    "error": str(exc),
                    "duration_seconds": None,
                    "output_path": "",
                }
            target_record["tool_runs"][tool_name] = result
            if progress_callback is not None:
                progress_callback(
                    {
                        "type": "tool_finished",
                        "target_id": target["id"],
                        "tool": tool_name,
                        "result": result,
                    }
                )
        run_metadata["targets"].append(target_record)

    metadata_path = run_dir / "run-metadata.json"
    metadata_path.write_text(json.dumps(run_metadata, indent=2), encoding="utf-8")
    evaluation_path = write_evaluation_summary(run_dir, targets_path)
    return {
        "run_dir": run_dir,
        "metadata_path": metadata_path,
        "evaluation_path": evaluation_path,
        "run_metadata": run_metadata,
    }


def _run_tool(
    tool_name: str,
    target: dict[str, Any],
    run_dir: Path,
    *,
    timeout: float,
    workers: int,
    skip_missing_tools: bool,
) -> dict[str, Any]:
    """Run one benchmark tool against one target."""
    tool_dir = run_dir / tool_name
    tool_dir.mkdir(parents=True, exist_ok=True)
    target_id = str(target["id"])
    started = time.perf_counter()

    if tool_name == "vulnscan":
        output_path = tool_dir / f"{target_id}.json"
        scan_results = run_scan(
            str(target.get("url") or target.get("host")),
            port_spec=str(target.get("port_spec", "common")),
            timeout=timeout,
            max_workers=workers,
            mode="benchmark",
            export_format="JSON",
        )
        output_path.write_text(json.dumps(scan_results, indent=2), encoding="utf-8")
        return {
            "status": "completed",
            "duration_seconds": round(time.perf_counter() - started, 4),
            "output_path": str(output_path),
        }

    if tool_name == "nmap":
        if shutil.which("nmap") is None:
            return _missing_tool_result("nmap", started, skip_missing_tools)
        output_path = tool_dir / f"{target_id}.xml"
        command = build_nmap_command(target, output_path)
        subprocess.run(command, check=True)
        return {
            "status": "completed",
            "duration_seconds": round(time.perf_counter() - started, 4),
            "output_path": str(output_path),
        }

    if tool_name == "zap":
        try:
            output_path = tool_dir / f"{target_id}.json"
            command = build_zap_command(target, output_path)
        except FileNotFoundError:
            return _missing_tool_result("zap-baseline.py", started, skip_missing_tools)
        subprocess.run(command, check=True)
        return {
            "status": "completed",
            "duration_seconds": round(time.perf_counter() - started, 4),
            "output_path": str(output_path),
        }

    raise ValueError(f"Unsupported benchmark tool '{tool_name}'.")


def _missing_tool_result(tool_name: str, started: float, skip_missing_tools: bool) -> dict[str, Any]:
    """Return a standardized missing-tool result or raise."""
    if not skip_missing_tools:
        raise FileNotFoundError(f"Required benchmark tool '{tool_name}' was not found on PATH.")
    return {
        "status": "skipped",
        "duration_seconds": round(time.perf_counter() - started, 4),
        "output_path": "",
        "error": f"Tool '{tool_name}' was not found on PATH.",
    }


def _create_run_directory(output_dir: Path) -> Path:
    """Create a timestamped benchmark results directory."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _select_targets(targets: list[dict[str, Any]], raw_target_ids: str) -> list[dict[str, Any]]:
    """Filter benchmark targets by optional ID selection."""
    if not raw_target_ids.strip():
        return list(targets)
    selected_ids = {item.strip() for item in raw_target_ids.split(",") if item.strip()}
    return [target for target in targets if str(target.get("id")) in selected_ids]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
