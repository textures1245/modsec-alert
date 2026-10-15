#!/usr/bin/env python3
"""Backend for verification boxes: drains the body, answers 200 "ok" to any
method. So any non-200 seen through nginx came from the WAF (or nginx), never
from the app. 501 = method this stub does not implement (still past the WAF)."""
import http.server

class H(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        n = int(self.headers.get("Content-Length") or 0)
        while n > 0:
            b = self.rfile.read(min(n, 1 << 20))
            if not b:
                break
            n -= len(b)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_PROPFIND = do_MKCOL = do_MOVE = do_COPY = _ok

    def log_message(self, *a):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", 9000), H).serve_forever()
