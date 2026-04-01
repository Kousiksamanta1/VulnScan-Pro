"""Local benchmark lab management helpers."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def list_targets(targets_path: Path) -> list[dict[str, Any]]:
    """Load the configured benchmark targets."""
    payload = json.loads(targets_path.read_text(encoding="utf-8"))
    return list(payload.get("targets", []))


def run_lab_command(command: str, compose_file: Path) -> str:
    """Run a lab lifecycle command and return any console output."""
    resolved_compose_file = compose_file.resolve()
    docker_command = ["docker", "compose", "-f", str(resolved_compose_file)]
    if command == "up":
        docker_command.extend(["up", "-d", "--build"])
    elif command == "down":
        docker_command.append("down")
    elif command == "ps":
        docker_command.append("ps")
    else:
        raise ValueError(f"Unsupported lab command '{command}'.")

    completed = subprocess.run(
        docker_command,
        check=True,
        capture_output=True,
        text=True,
    )
    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    return output or f"Lab command '{command}' completed successfully."


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for benchmark lab management."""
    parser = argparse.ArgumentParser(
        prog="vulnscan-benchmark-lab",
        description="Start, stop, and inspect the local controlled benchmark lab.",
    )
    parser.add_argument(
        "command",
        choices=("up", "down", "ps", "targets"),
        help="Lab management command.",
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=Path("benchmarks/docker-compose.yml"),
        help="Compose file used for the benchmark lab.",
    )
    parser.add_argument(
        "--targets",
        type=Path,
        default=Path("benchmarks/targets.json"),
        help="Benchmark targets file used by the lab.",
    )
    args = parser.parse_args(argv)

    if args.command == "targets":
        for target in list_targets(args.targets):
            print(
                f"{target['id']}: {target.get('name', target['id'])} | "
                f"host={target.get('host', '')} | url={target.get('url', '')} | "
                f"ports={target.get('port_spec', '')}"
            )
        return 0

    output = run_lab_command(args.command, args.compose_file)
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
