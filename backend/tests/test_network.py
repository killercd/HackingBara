import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.capture import ScopeProxy
from app.network import basic_auth
from app.scope import Scope


class Target(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        self.requests.append((self.path, self.headers.get("Authorization")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://203.0.113.1/")
        elif self.path == "/blocked":
            self.send_response(429)
        elif self.path == "/public":
            self.send_response(200)
        elif self.headers.get("Authorization") == "Basic dXNlcjpwYXNz":
            self.send_response(200)
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Lab"')
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def target():
    Target.requests = []
    server = HTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(2)


def test_basic_challenge_proof_and_defensive_abort(target):
    scope = Scope(["127.0.0.1"])
    assert basic_auth(scope, target + "/protected", "user", "pass")[0] == "successful"
    assert basic_auth(scope, target + "/protected", "user", "wrong")[0] == "failed"
    assert basic_auth(scope, target + "/blocked", "user", "pass")[0] == "blocked"
    assert basic_auth(scope, target + "/public", "user", "pass")[0] == "not_supported"
    Target.requests = []
    assert basic_auth(scope, target + "/redirect", "user", "pass")[0] == "not_supported"
    assert Target.requests == [("/redirect", None)]


def test_proxy_rejects_other_origins_before_connect(target):
    proxy = ScopeProxy(Scope(["127.0.0.1"]), target + "/")
    with pytest.raises(ValueError):
        proxy.connect("http://203.0.113.1/")
    with pytest.raises(ValueError):
        proxy.connect("http://127.0.0.1:1/")
    with proxy.connect(target + "/anything") as connection:
        assert connection.getpeername()[0] == "127.0.0.1"
    proxy.server_close()


def test_pinned_http_preserves_hostname_without_second_dns(target, monkeypatch):
    from urllib.parse import urlsplit

    import app.network as network

    u = urlsplit(target)
    queries = []

    def resolve(hostname, port, *args, **kwargs):
        queries.append(hostname)
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    scope = Scope(["127.0.0.1"])
    status, _ = network.request(scope, f"http://lab.example:{u.port}/public")
    assert status == 200
    assert queries == ["lab.example"]
