"""Connections pin the checked address while preserving HTTP Host and TLS SNI."""

import base64
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit

from .scope import normalize_url


def pinned_socket(scope, url, timeout=10):
    addresses, port = scope.resolve(url)
    # Connect to the numeric address: never allow a second implicit DNS lookup.
    family = socket.AF_INET6 if ipaddress.ip_address(addresses[0]).version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    try:
        connection.connect((addresses[0], port))
        return connection
    except Exception:
        connection.close()
        raise


def request(scope, url, authorization=None):
    url = normalize_url(url)
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    connection = http.client.HTTPConnection(u.hostname, port, timeout=10)
    sock = pinned_socket(scope, url)
    if u.scheme == "https":
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        except Exception:
            sock.close()
            raise
    connection.sock = sock
    try:
        headers = {"Host": u.netloc, "User-Agent": "HackingBara/0.1", "Connection": "close"}
        if authorization:
            headers["Authorization"] = authorization
        connection.request("GET", u.path + ("?" + u.query if u.query else ""), headers=headers)
        response = connection.getresponse()
        # No redirects are ever followed by credential adapters.
        return response.status, {k.lower(): v for k, v in response.getheaders()}
    finally:
        connection.close()


def basic_auth(scope, url, username, password):
    # Require an unauthenticated Basic challenge so a public 200 cannot imply success.
    status, headers = request(scope, url)
    if status in (423, 429) or "retry-after" in headers:
        return "blocked", "Defensive response; validation aborted"
    if status != 401 or not headers.get("www-authenticate", "").lower().startswith("basic "):
        return "not_supported", "Endpoint does not present an HTTP Basic challenge"
    # Credentials are never passed in subprocess argv, redirects, or response metadata.
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    status, headers = request(scope, url, "Basic " + token)
    if status in (403, 423, 429) or "retry-after" in headers:
        return "blocked", "Defensive response; validation aborted"
    if 200 <= status < 300:
        return "successful", "HTTP Basic challenge accepted"
    if status == 401:
        return "failed", "HTTP Basic challenge rejected"
    return "unknown", "Unexpected response; no success inferred"
