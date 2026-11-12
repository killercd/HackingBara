"""Operator-owned local smoke target; never deploy this fixture on a public interface."""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://203.0.113.1/')
            self.end_headers()
            return
        if self.path == '/protected' and self.headers.get('Authorization') != 'Basic bGFiOmxvY2FsLWZpeHR1cmUtb25seQ==':
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Owned lab"')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<!doctype html><html><body style="background:#122338;color:#7de2bb;font:32px sans-serif;padding:60px"><h1>HackingBara local lab</h1><p>Operator-owned smoke target</p></body></html>')

    def log_message(self, *args):
        pass


HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
