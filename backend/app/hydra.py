"""Single approved credential pairs through the installed Hydra modules."""

import ipaddress
import json
import os
import re
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from . import scanners
from .capture import ProxyHandler, ScopeProxy
from .config import settings
from .network import request
from .scope import hostname_url, normalize_url


def expand_module(value):
    match = re.search(r"\{([^{}]+)\}", value)
    if match:
        return [
            module
            for part in match[1].split("|")
            for module in expand_module(value[: match.start()] + part + value[match.end() :])
        ]
    match = re.search(r"\[([^\[\]]+)\]", value)
    if match:
        return [
            module
            for part in ("", match[1])
            for module in expand_module(value[: match.start()] + part + value[match.end() :])
        ]
    return [value] if re.fullmatch(r"[a-z][a-z0-9-]*", value) else []


@lru_cache(maxsize=1)
def modules():
    try:
        result = subprocess.run(["hydra", "-h"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return []
    match = re.search(r"Supported services:\s*([^\r\n]+)", result.stdout + result.stderr)
    return sorted({item for token in match[1].split() for item in expand_module(token)}) if match else []


def module_help(module):
    if module not in modules():
        raise ValueError("Module unavailable in this Hydra installation")
    result = subprocess.run(["hydra", "-U", module], capture_output=True, text=True, timeout=5)
    return (result.stdout + result.stderr)[:16000]


class HydraHTTPHandler(ProxyHandler):
    def forward(self):
        try:
            url = normalize_url(self.path)
            parsed = urlsplit(url)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Unsupported request body")
            body = self.rfile.read(length) if length else b""
            upstream = self.server.connect(url)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            headers = [f"{self.command} {path} HTTP/1.0", f"Host: {parsed.netloc}", "Connection: close"]
            headers += [
                f"{key}: {value}"
                for key, value in self.headers.items()
                if key.lower() not in {"host", "connection", "proxy-authorization", "proxy-connection"}
            ]
            upstream.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1") + body)
            self.tunnel(upstream)
        except (OSError, ValueError, UnicodeError):
            self.send_error(403, "Destination denied")

    do_GET = do_HEAD = do_POST = forward


class HydraHTTPProxy(ScopeProxy):
    handler = HydraHTTPHandler


@contextmanager
def http_proxy(scope, target, address, env):
    web_modules = {
        scheme + "-" + method
        for scheme in ("http", "https")
        for method in ("get", "head", "post", "get-form", "post-form")
    }
    if target.module not in web_modules:
        yield address
        return
    from .scope import EndpointScope

    scheme = "https" if target.tls or target.module.startswith("https-") else "http"
    host = f"[{target.host}]" if ":" in target.host else target.host
    proxy_scope = scope if isinstance(scope, EndpointScope) else EndpointScope(scope, address)
    proxy = HydraHTTPProxy(proxy_scope, f"{scheme}://{host}:{target.port}/")
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    env["HYDRA_PROXY_HTTP"] = f"http://127.0.0.1:{proxy.server_port}/"
    try:
        yield target.host
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=2)


def validate(scope, target, username, password, tick=lambda: None):
    if target.module not in modules():
        return "not_supported", "Hydra module unavailable in this installation"
    if any(char in username for char in "\r\n\x00") or (
        target.module != "sshkey" and any(char in password for char in "\r\n\x00")
    ):
        return "not_supported", "Hydra credential files cannot represent newline or NUL characters"
    addresses, _ = scope.resolve(hostname_url(target.host))
    address = addresses[0]
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("HYDRA_")}
    with tempfile.TemporaryDirectory(prefix="hb-hydra-") as directory:
        root = Path(directory)
        sent_password = password
        if target.module == "sshkey":
            if "PRIVATE KEY-----" not in password or "\x00" in password:
                return (
                    "not_supported",
                    "SSH key validation requires private key material in the credential secret",
                )
            key = root / "private-key"
            key.write_text(password.rstrip() + "\n")
            key.chmod(0o600)
            sent_password = str(key)
        for name, value in (("login", username), ("password", sent_password)):
            path = root / name
            path.write_text(value + "\n")
            path.chmod(0o600)
        output = root / "result.json"
        argv = [
            "hydra",
            "-I",
            "-K",
            "-t",
            "1",
            "-f",
            "-L",
            str(root / "login"),
            "-P",
            str(root / "password"),
            "-s",
            str(target.port),
            "-w",
            "10",
            "-o",
            str(output),
            "-b",
            "jsonv1",
        ]
        if ipaddress.ip_address(address).version == 6:
            argv.append("-6")
        if target.tls:
            argv.append("-S")
        if target.options:
            argv += ["-m", target.options]
        try:
            with http_proxy(scope, target, address, env) as destination:
                result = scanners.run_tool(
                    argv + [f"[{destination}]" if ":" in destination else destination, target.module],
                    settings.scanner_timeout,
                    tick,
                    env,
                    cwd=directory,
                )
        except scanners.Interrupted:
            raise
        except Exception:
            return "unknown", "Hydra execution interrupted or failed; no automatic retry"
        # Hydra output and reports contain passwords: persist only normalized outcomes.
        diagnostic = "\n".join(
            line
            for line in (result.stdout + result.stderr).splitlines()
            if line.startswith(("[ERROR]", "[WARNING]"))
        ).lower()
        if any(
            term in diagnostic for term in ("429", "account locked", "account is locked", "too many attempts")
        ):
            return "blocked", "Hydra reported a defensive response; service validation aborted"
        try:
            if output.stat().st_size > settings.max_output_bytes:
                raise ValueError("Oversized report")
            report = json.loads(output.read_text())
            if not isinstance(report, dict):
                raise ValueError("Invalid report structure")
            matches = report.get("results", [])
            if not isinstance(matches, list):
                raise ValueError("Invalid report")
            if (
                report.get("errormessages")
                or "[error]" in diagnostic
                or result.exit_code != 0
                or report.get("success") is not True
            ):
                return "unknown", "Hydra could not establish a conclusive result; see target configuration"
            for match in matches:
                if not isinstance(match, dict):
                    raise ValueError("Invalid result entry")
                if (
                    str(match.get("host")).strip("[]") in {address, target.host}
                    and int(match.get("port", 0)) == target.port
                    and (
                        match.get("login") == username
                        or target.module
                        in {"cisco", "cisco-enable", "redis", "snmp", "vnc", "s7-300", "oracle-listener"}
                    )
                    and match.get("password") == sent_password
                ):
                    return "successful", f"Hydra {target.module}: approved credential accepted"
            if matches:
                return "unknown", "Hydra report did not match the approved credential and destination"
            return "failed", f"Hydra {target.module}: approved credential rejected"
        except (OSError, ValueError, TypeError):
            return "unknown", "Hydra returned no valid report; no automatic retry"


def http_auth(scope, url, username, password, tick=lambda: None):
    from .scope import HydraService

    status, headers = request(scope, url)
    if status in (423, 429) or "retry-after" in headers:
        return "blocked", "Defensive response; validation aborted"
    if status != 401 or not headers.get("www-authenticate", "").lower().startswith("basic "):
        return "not_supported", "Endpoint does not present an HTTP Basic challenge"
    parsed = urlsplit(url)
    target = HydraService(
        module="https-get" if parsed.scheme == "https" else "http-get",
        host=parsed.hostname,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        options=parsed.path + ("?" + parsed.query if parsed.query else ""),
    )
    return validate(scope, target, username, password, tick)


def detected_service(service):
    """Select a module from Nmap's service identification, never the port number."""
    from .scope import HydraService

    if service.details.get("method") == "table" or (
        service.details.get("method") != "probed" and getattr(service, "confidence", 0) < 7
    ):
        return None
    name = service.name.lower().removeprefix("ssl/")
    aliases = {
        "ldap": "ldap3",
        "ldaps": "ldap3s",
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "ms-sql-s": "mssql",
        "postgresql": "postgres",
        "mongod": "mongodb",
        "ms-wbt-server": "rdp",
        "rfb": "vnc",
        "vmware-auth": "vmauthd",
        "xmpp-client": "xmpp",
        "jabber": "xmpp",
        "oracle-tns": "oracle-listener",
    }
    module = aliases.get(name, name)
    # Web forms, proxy tests and enumeration require explicit module configuration.
    manual = {
        "http",
        "https",
        "http-proxy",
        "http-proxy-urlenum",
        "smtp-enum",
        "oracle-sid",
        "unknown",
        "tcpwrapped",
        "sshkey",
    }
    if module in manual or module.startswith(("http-", "https-")):
        return None
    available = modules()
    tls = service.name.lower().startswith("ssl/") or service.details.get("tunnel") == "ssl"
    if tls and module + "s" in available:
        module += "s"
    if module not in available:
        return None
    return HydraService(module=module, host=service.ip, port=service.port, tls=tls)
