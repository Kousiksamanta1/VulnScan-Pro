"""Controlled header and cookie posture benchmark fixture."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    """Return weak cookies and omit modern defensive headers."""

    server_version = "VulnBenchHeaders/1.0"

    def do_GET(self) -> None:  # noqa: N802 - standard library method name.
        """Serve a minimal HTML page with intentionally weak cookie flags."""
        body = """<!DOCTYPE html>
<html lang="en">
  <body>
    <h1>Header and Cookie Lab</h1>
    <p>This endpoint intentionally omits defensive headers.</p>
    <form method="GET" action="/">
      <input name="name" value="guest">
      <button type="submit">Submit</button>
    </form>
  </body>
</html>
"""
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sessionid=unsafe-cookie")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        """Silence fixture request logging."""
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8083), Handler).serve_forever()
