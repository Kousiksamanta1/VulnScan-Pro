"""Controlled SQL injection heuristic benchmark fixture."""

from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


BASELINE_BODY = "<html><body><h1>Inventory</h1><p>3 results returned.</p></body></html>"
DENIED_BODY = "<html><body><h1>Access denied</h1></body></html>"
ERROR_BODY = "<html><body><p>SQL syntax error near malformed input.</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    """Simulate several SQLi detection behaviors for the scanner."""

    server_version = "VulnBenchSQLi/1.0"

    def do_GET(self) -> None:  # noqa: N802 - standard library method name.
        """Respond with baseline, error, boolean, or delayed content."""
        parsed = urlsplit(self.path)
        if parsed.path != "/items":
            self._respond(200, "<html><body><h1>SQLi Lab</h1></body></html>")
            return

        parameters = parse_qs(parsed.query, keep_blank_values=True)
        item_id = parameters.get("id", ["1"])[0]
        lowered = item_id.lower()

        if any(marker in lowered for marker in ("sleep(5)", "waitfor delay", "select(sleep(5))")):
            time.sleep(5)
            self._respond(200, BASELINE_BODY)
            return

        if "or 1=1" in lowered or "' or '1'='1" in lowered:
            self._respond(200, BASELINE_BODY)
            return

        if "and 1=2" in lowered or "' and '1'='2" in lowered:
            self._respond(403, DENIED_BODY)
            return

        if any(marker in item_id for marker in ("'", "\"", "`", "')")):
            self._respond(500, ERROR_BODY)
            return

        self._respond(200, BASELINE_BODY)

    def _respond(self, status_code: int, body: str) -> None:
        """Write a simple HTML response."""
        payload = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Silence fixture request logging."""
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8082), Handler).serve_forever()
