"""Bounded subprocess adapters. Scanner output is always untrusted."""

import ipaddress
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

from .config import settings
from .scope import ScanInput, ScopePreparationError, port_set


class Interrupted(Exception):
    pass


class ToolError(Exception):
    def __init__(self, message, metadata=None):
        super().__init__(message)
        self.metadata = metadata or {}


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    version: str = "unknown"


def kill_group(process):
    for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
    # Kill descendants even if the process leader exited first.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_tool(argv, timeout, tick=lambda: None, env=None, *, on_stdout=None, capture_stdout=True):
    start = time.monotonic()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    guarded = [sys.executable, str(Path(__file__).with_name("process_guard.py")), str(os.getpid()), *argv]
    with subprocess.Popen(
        guarded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
    ) as process:
        selector = selectors.DefaultSelector()
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                tick()
                if timeout is not None and time.monotonic() - start > timeout:
                    raise ToolError(
                        "Scanner timeout",
                        {
                            "argv": argv,
                            "timeout": True,
                            "stderr": output["stderr"].decode(errors="replace")[:2000],
                        },
                    )
                for key, _ in selector.select(0.2):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data != "stdout" or capture_stdout:
                        output[key.data].extend(data)
                    if key.data == "stdout" and on_stdout is not None:
                        on_stdout(data)
                    if sum(map(len, output.values())) > settings.max_output_bytes:
                        raise ToolError("Scanner output exceeded limit", {"argv": argv, "output_limit": True})
            process.wait(timeout=3)
        finally:
            selector.close()
            kill_group(process)
    return ToolResult(
        output["stdout"].decode(errors="replace"),
        output["stderr"].decode(errors="replace"),
        process.returncode,
        round(time.monotonic() - start, 3),
    )


def parse_rustscan(output, address, selected_ports):
    approved = port_set(selected_ports)
    found = set()
    # Greppable output: 192.0.2.1 -> [22,80] (also handles IPv6).
    for host, values in re.findall(r"^\s*(\S+)\s*->\s*\[([\d,\s]*)\]", output, re.MULTILINE):
        if ipaddress.ip_address(host) != ipaddress.ip_address(address):
            raise ToolError("Scanner returned an unexpected address")
        found.update(int(x.strip()) for x in values.split(",") if x.strip())
    if not found <= approved:
        raise ToolError("Scanner returned an unapproved port")
    return sorted(found)


def rustscan(address, selected_ports, request_timeout, tick, max_threads=10):
    argv = [
        "rustscan",
        "-a",
        address,
        "-p",
        ",".join(map(str, sorted(port_set(selected_ports)))),
        "-g",
        "-n",
        "-b",
        str(max_threads),
        "-t",
        str(max(1, round(request_timeout * 1000))),
        "--tries",
        "1",
    ]
    result = run_tool(argv, None, tick)
    if result.exit_code:
        raise ToolError(
            f"RustScan exited with code {result.exit_code}",
            {"argv": argv, "exit_code": result.exit_code, "stderr": result.stderr[:2000]},
        )
    result.version = tool_version("rustscan", tick)
    return parse_rustscan(result.stdout, address, selected_ports), result, argv


def parse_nmap(xml, address, discovered_ports):
    root = ElementTree.fromstring(xml)
    observations = []
    for host in root.findall("host"):
        addresses = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")]
        if any(ipaddress.ip_address(a) != ipaddress.ip_address(address) for a in addresses):
            raise ToolError("Nmap returned an unexpected address")
        for port in host.findall("./ports/port"):
            number = int(port.get("portid"))
            if number not in discovered_ports or port.get("protocol") != "tcp":
                raise ToolError("Nmap returned an unapproved port or transport")
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            attrs = service.attrib if service is not None else {}
            observations.append(
                {
                    "port": number,
                    "transport": "tcp",
                    "state": "open",
                    "name": attrs.get("name", "unknown"),
                    "product": attrs.get("product", ""),
                    "version": attrs.get("version", ""),
                    "banner": attrs.get("extrainfo", ""),
                    "confidence": int(attrs.get("conf", "0")),
                    "details": {
                        "tunnel": attrs.get("tunnel"),
                        "cpe": [c.text for c in service.findall("cpe")] if service is not None else [],
                    },
                }
            )
    return observations


def nmap(address, discovered_ports, request_timeout, tick, max_threads=10, timing=3):
    if not discovered_ports:
        return [], None, []
    argv = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "-sV",
        "--version-light",
        "--max-retries",
        "1",
        f"-T{timing}",
        "--max-parallelism",
        str(max_threads),
        "--min-rtt-timeout",
        f"{min(100, max(1, round(request_timeout * 1000)))}ms",
        "--initial-rtt-timeout",
        f"{min(1000, max(1, round(request_timeout * 1000)))}ms",
        "--max-rtt-timeout",
        f"{max(1, round(request_timeout * 1000))}ms",
        "--host-timeout",
        "0",
        "-p",
        ",".join(map(str, sorted(discovered_ports))),
        "-oX",
        "-",
    ]
    if ipaddress.ip_address(address).version == 6:
        argv += ["-6"]
    argv.append(address)
    result = run_tool(argv, None, tick)
    if result.exit_code:
        raise ToolError(
            f"Nmap exited with code {result.exit_code}",
            {"argv": argv, "exit_code": result.exit_code, "stderr": result.stderr[:2000]},
        )
    result.version = tool_version("nmap", tick)
    return parse_nmap(result.stdout, address, discovered_ports), result, argv


def tool_version(tool, tick):
    result = run_tool([tool, "version" if tool == "gobuster" else "--version"], 5, tick)
    return result.stdout.splitlines()[0][:200] if result.stdout else "unknown"


def parse_gobuster_record(line, approved):
    line = line.replace("\x1b[2K", "").strip()
    if not line:
        return None
    match = re.fullmatch(r"(Found|Missed): ([a-zA-Z0-9_.-]+)(?: \[([^\]]+)\])?", line)
    if not match:
        raise ToolError("Unexpected Gobuster DNS output")
    hostname = match[2].lower().rstrip(".")
    if hostname not in approved:
        raise ToolError("Gobuster returned an unapproved subdomain")
    if match[1] == "Missed":
        if match[3]:
            raise ToolError("Unexpected negative Gobuster DNS result")
        return hostname, None
    if not match[3]:
        raise ToolError("Gobuster returned a positive result without addresses")
    try:
        addresses = sorted({str(ipaddress.ip_address(ip.strip())) for ip in match[3].split(",")})
    except ValueError:
        raise ToolError("Gobuster returned an invalid IP address") from None
    return hostname, {"hostname": hostname, "addresses": addresses}


def parse_gobuster_dns(output, domain, words):
    approved = {f"{word}.{domain}" for word in words}
    found = {}
    for line in output.splitlines():
        record = parse_gobuster_record(line, approved)
        if record and record[1] is not None:
            found[record[0]] = record[1]
    return [found[hostname] for hostname in sorted(found)]


class GobusterDNSStream:
    def __init__(self, domain, words, on_update):
        self.approved = {f"{word}.{domain}" for word in words}
        self.seen = set()
        self.found = {}
        self.pending = bytearray()
        self.on_update = on_update

    def line(self, data):
        record = parse_gobuster_record(data.decode(errors="replace"), self.approved)
        if record is None:
            return
        hostname, observation = record
        if hostname in self.seen:
            return
        self.seen.add(hostname)
        if observation is not None:
            self.found[hostname] = observation
        self.on_update(len(self.seen), observation)

    def feed(self, data):
        self.pending.extend(data)
        lines = self.pending.split(b"\n")
        self.pending = lines.pop()
        for line in lines:
            self.line(line)
        if len(self.pending) > settings.max_output_bytes:
            raise ToolError("Gobuster DNS output line exceeded limit")

    def finish(self):
        if self.pending:
            self.line(bytes(self.pending))
            self.pending.clear()
        if self.seen != self.approved:
            raise ToolError("Gobuster did not report every wordlist candidate")
        return [self.found[name] for name in sorted(self.found)]


def gobuster_dns(domain, words, request_timeout, tick, max_threads=10, on_update=lambda count, row: None):
    # Validate at the adapter boundary as well as the API. Never accept a server path.
    config = ScanInput(
        name="DNS",
        mode="subdomain",
        domain=domain,
        subdomains=words,
        request_timeout=request_timeout,
        max_threads=max_threads,
    )
    with tempfile.TemporaryDirectory(prefix="gobuster-dns-") as directory:
        wordlist = Path(directory) / "subdomains.txt"
        wordlist.write_text("\n".join(config.subdomains) + "\n", encoding="ascii")
        argv = [
            "gobuster",
            "dns",
            "--domain",
            config.domain,
            "--wordlist",
            str(wordlist),
            "--show-ips",
            "--verbose",
            "--threads",
            str(config.max_threads),
            "--timeout",
            f"{config.request_timeout:g}s",
            "--quiet",
            "--no-progress",
            "--no-color",
        ]
        stream = GobusterDNSStream(config.domain, config.subdomains, on_update)
        result = run_tool(argv, None, tick, on_stdout=stream.feed, capture_stdout=False)
        if result.exit_code:
            raise ToolError(
                f"Gobuster exited with code {result.exit_code}",
                {"argv": argv, "exit_code": result.exit_code, "stderr": result.stderr[:2000]},
            )
        observations = stream.finish()
        result.version = tool_version("gobuster", tick)
        return observations, result, argv


def prepare_scope(config, tick):
    # DNS resolution must not hold an HTTP request or a database transaction open.
    # The process guard keeps heartbeat/stop effective even inside getaddrinfo().
    with tempfile.TemporaryDirectory(prefix="prepare-scope-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(config.model_dump_json())
        result = run_tool([sys.executable, "-m", "app.prepare_scope", str(path)], None, tick)
        if result.exit_code:
            raise ToolError("Scope resolver process failed", {"stderr": result.stderr[:2000]})
        data = json.loads(result.stdout)
        if data.get("error"):
            raise ScopePreparationError(data["error"], data["issues"])
        return ScanInput.model_validate(data["config"]), data["issues"]
