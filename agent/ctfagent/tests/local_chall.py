"""Local smoke-test CTF challenge used to validate the agent end-to-end.

Run (inside WSL or any Linux/macOS):
    python3 local_chall.py
Then point the agent at http://127.0.0.1:8899
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse

FLAG = "nex{l0c4l_sm0ke_t3st_0k}"
TOKEN = "2026"

HOME = """<!DOCTYPE html>
<html><head><title>NEX Internal</title></head>
<body>
<h1>NEX Internal Console</h1>
<p>员工入口维护中。</p>
<!-- TODO: 迁移到 /api/flag，token 校验别忘了 -->
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "NEX-Internal/1.0"

    def _send(self, code, body, extra_headers=None, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self._send(200, HOME)
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /internal/\n", ctype="text/plain")
        elif path == "/internal/" or path == "/internal":
            self._send(
                403,
                "<h1>403 Forbidden</h1><p>仅限内网访问。</p>",
                extra_headers={"X-Internal-Note": f"token=<REDACTED>"},
            )
        elif path == "/api/flag":
            if query.get("token", [""])[0] == TOKEN=<REDACTED> f"<code>{FLAG}</code>")
            else:
                self._send(401, '{"error":"token required","success":false}', ctype="application/json")
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 8899), Handler)
    print("local challenge on http://127.0.0.1:8899")
    srv.serve_forever()
