# Stands in for the Discord webhook: appends each POST body as one line to
# /tmp/notify.json and answers 204 like Discord does.
import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open("/tmp/notify.json", "ab") as fh:
            fh.write(body.rstrip() + b"\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass

http.server.HTTPServer(("127.0.0.1", 9099), H).serve_forever()
