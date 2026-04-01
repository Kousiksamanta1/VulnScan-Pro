"""Controlled TCP banner benchmark fixture."""

from __future__ import annotations

import socket
from contextlib import closing


def main() -> None:
    """Expose a single banner-speaking TCP service."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 2525))
        server.listen()
        while True:
            connection, _ = server.accept()
            with closing(connection):
                connection.sendall(b"220 VulnBench SMTP ready\r\n")


if __name__ == "__main__":
    main()
