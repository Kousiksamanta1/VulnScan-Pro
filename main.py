"""Entry point for the CustomTkinter vulnerability scanner."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    """Launch the desktop application or delegate to the CLI scan runner."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        from scanner_cli import main as cli_main

        return cli_main(args)

    try:
        from scanner_app import ScannerApp
    except ModuleNotFoundError as exc:
        print(
            f"Missing dependency '{exc.name}'. Install the packages in requirements.txt "
            "and run the application again."
        )
        return 1

    app = ScannerApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
