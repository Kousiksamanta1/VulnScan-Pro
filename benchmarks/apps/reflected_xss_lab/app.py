"""Controlled reflected XSS benchmark fixture."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    """Return a deliberately unsafe reflected response for benchmark scans."""

    server_version = "VulnBenchXSS/1.0"

    def do_GET(self) -> None:  # noqa: N802 - standard library method name.
        """Reflect the query value into the response body and attribute context."""
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        search_value = query.get("q", [""])[0]
        body = f"""<!DOCTYPE html>
<html lang="en">
  <body>
    <h1>Reflected XSS Lab</h1>
    <form method="GET" action="/">
      <input name="q" value="{search_value}">
      <button type="submit">Search</button>
    </form>
    <div class="results">{search_value}</div>
  </body>
</html>
"""
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Silence fixture request logging."""
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
