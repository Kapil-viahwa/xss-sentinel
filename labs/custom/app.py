from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs, urlsplit


class LabHandler(SimpleHTTPRequestHandler):
    stored_entries = []
    callback_hits = []
    state_lock = Lock()

    def _send(self, status, body, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        request = urlsplit(self.path)
        if request.path == "/callback":
            marker = parse_qs(request.query).get("xs", [""])[0]
            with self.state_lock:
                self.callback_hits.append(marker)
            self._send(204, b"", content_type=None)
            return
        if request.path == "/wall":
            with self.state_lock:
                entries = list(self.stored_entries)
            body = ("<!doctype html><html><meta charset='utf-8'><title>Stored XSS lab wall</title>"
                    "<h1>Stored message wall</h1><p>Test entries are held in memory until cleared or the container restarts.</p>"
                    + "".join(f"<article>{entry}</article>" for entry in entries)
                    + "<form method='post' action='/clear'><button>Clear lab entries</button></form></html>").encode("utf-8")
            self._send(200, body)
            return
        if request.path != "/":
            return super().do_GET()

        query = parse_qs(request.query, keep_blank_values=True)
        value = query.get("q", [""])[0]
        body = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Local XSS Lab</title></head>
<body>
  <h1>Local XSS assessment lab</h1>
  <form method="get"><label>Search <input name="q" value=""></label><button>Search</button></form>
  <a href="/?q=hello">Open reflected case</a>
  <p>Reflected value: {value}</p>
  <a href="/dom.html?message=hello">Open DOM-based case</a>
  <form method="post" action="/stored"><label>Store a message <input name="message" value="hello"></label><button>Store</button></form>
  <a href="/wall">Visit the stored-message wall</a>
</body>
</html>""".encode("utf-8")
        self._send(200, body)

    def do_POST(self):
        request = urlsplit(self.path)
        if request.path == "/clear":
            with self.state_lock:
                self.stored_entries.clear()
            self.send_response(303)
            self.send_header("Location", "/wall")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if request.path != "/stored":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if size < 0 or size > 16_384:
            self.close_connection = True
            self.send_error(413)
            return
        form = parse_qs(self.rfile.read(size).decode("utf-8", errors="replace"), keep_blank_values=True)
        message = form.get("message", [""])[0][:4096]
        with self.state_lock:
            self.stored_entries.append(message)
        self.send_response(303)
        self.send_header("Location", "/wall")
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8084), LabHandler).serve_forever()
