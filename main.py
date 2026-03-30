"""Entry point for the CustomTkinter vulnerability scanner."""

from __future__ import annotations


def main() -> None:
    """Launch the desktop application or print a missing dependency message."""
    try:
        from scanner_app import ScannerApp
    except ModuleNotFoundError as exc:
        print(
            f"Missing dependency '{exc.name}'. Install the packages in requirements.txt "
            "and run the application again."
        )
        return

    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
