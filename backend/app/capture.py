"""EyeWitness with a run-local, DNS-pinning scope proxy for all browser requests."""

import os
import select
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from PIL import Image

from .config import settings
from .network import pinned_socket
from .scanners import ToolError, run_tool
from .scope import normalize_url


class ScopeProxy(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, scope, url):
        self.scope = scope
        self.allowed_origin = self.origin(url)
        super().__init__(("127.0.0.1", 0), ProxyHandler)

    @staticmethod
    def origin(url):
        u = urlsplit(normalize_url(url))
        return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)

    def connect(self, url):
        if self.origin(url) != self.allowed_origin:
            raise ValueError("Unapproved screenshot origin")
        return pinned_socket(self.scope, url)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    timeout = 10

    def log_message(self, *args):
        pass  # Upstream headers and URL query strings must not enter logs.

    def tunnel(self, upstream):
        self.connection.settimeout(10)
        with upstream:
            for _ in range(600):  # Bound lifetime and aggregate bytes.
                ready, _, _ = select.select([self.connection, upstream], [], [], 0.5)
                if not ready:
                    continue
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    destination = upstream if source is self.connection else self.connection
                    destination.sendall(data)

    def do_CONNECT(self):
        try:
            # CONNECT is approved only for the endpoint's HTTPS origin.
            url = normalize_url("https://" + self.path + "/")
            upstream = self.server.connect(url)
        except (ValueError, OSError):
            self.send_error(403, "Destination denied")
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        try:
            self.tunnel(upstream)
        except OSError:
            pass

    def do_GET(self):
        try:
            url = normalize_url(self.path)
            u = urlsplit(url)
            if u.scheme != "http":
                raise ValueError("Use CONNECT for HTTPS")
            upstream = self.server.connect(url)
            path = u.path + ("?" + u.query if u.query else "")
            # Only read-only fetches; no browser credentials/cookies are forwarded.
            headers = (
                f"GET {path} HTTP/1.0\r\nHost: {u.netloc}\r\n"
                "User-Agent: HackingBara/0.1\r\nConnection: close\r\n\r\n"
            )
            upstream.sendall(headers.encode("ascii"))
            self.tunnel(upstream)
        except (ValueError, OSError, UnicodeError):
            self.send_error(403, "Destination denied")


def capture(scope, url, run_id, screenshot_id, tick):
    if not settings.eyewitness_enabled:
        raise ToolError("EyeWitness is disabled by administrator configuration")
    scope.resolve(url)
    destination = settings.evidence_dir / run_id
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="capture-", dir=destination) as temp:
        proxy = ScopeProxy(scope, url)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        env = {
            **os.environ,
            "HB_CAPTURE_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "no_proxy": "",
            "NO_PROXY": "",
        }
        # The image patches EyeWitness's browser options to require this proxy.
        output = Path(temp) / "output"
        try:
            result = run_tool(
                [
                    "eyewitness",
                    "--web",
                    "--single",
                    url,
                    "-d",
                    str(output),
                    "--threads",
                    "1",
                    "--timeout",
                    "15",
                    "--no-prompt",
                ],
                settings.scanner_timeout,
                tick,
                env,
            )
            if result.exit_code:
                raise ToolError(f"EyeWitness exited with code {result.exit_code}")
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=2)
        images = list((output / "screens").glob("*.png"))
        if not images:
            raise ToolError("EyeWitness produced no screenshot")
        image = images[0]
        if image.stat().st_size > settings.max_artifact_bytes:
            raise ToolError("Screenshot exceeds artifact limit")
        with Image.open(image) as raw:
            if raw.width * raw.height > 20_000_000:
                raise ToolError("Screenshot dimensions exceed limit")
            raw.load()
            width, height = raw.size
            path = destination / f"{screenshot_id}.png"
            raw.convert("RGB").save(path)
            thumb = raw.copy()
            thumb.thumbnail((320, 200))
            thumbnail = destination / f"{screenshot_id}-thumb.png"
            thumb.save(thumbnail)
        return (
            str(path.relative_to(settings.evidence_dir)),
            str(thumbnail.relative_to(settings.evidence_dir)),
            width,
            height,
        )
