"""Build the desktop application with PyInstaller."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Run a PyInstaller build for the scanner desktop application."""
    root = Path(__file__).resolve().parent
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        "VulnScanPro",
        "--collect-data",
        "customtkinter",
        str(root / "main.py"),
    ]
    subprocess.run(command, check=True, cwd=root)


if __name__ == "__main__":
    main()
