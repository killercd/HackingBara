"""Bounded subprocess adapters. Scanner output is always untrusted."""

import ipaddress
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

from .config import settings
from .scope import port_set


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


def run_tool(argv, timeout, tick=lambda: None, env=None):
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
                if time.monotonic() - start > timeout:
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
                    output[key.data].extend(data)
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


def rustscan(address, selected_ports, timeout, tick):
    argv = [
        "rustscan",
        "-a",
        address,
        "-p",
        ",".join(map(str, sorted(port_set(selected_ports)))),
        "-g",
        "-n",
        "-b",
        "32",
        "-t",
        "1500",
        "--tries",
        "1",
    ]
    result = run_tool(argv, timeout, tick)
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


def nmap(address, discovered_ports, timeout, tick):
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
        "--max-rate",
        "20",
        "--host-timeout",
        f"{timeout}s",
        "-p",
        ",".join(map(str, sorted(discovered_ports))),
        "-oX",
        "-",
    ]
    if ipaddress.ip_address(address).version == 6:
        argv += ["-6"]
    argv.append(address)
    result = run_tool(argv, timeout + 5, tick)
    if result.exit_code:
        raise ToolError(
            f"Nmap exited with code {result.exit_code}",
            {"argv": argv, "exit_code": result.exit_code, "stderr": result.stderr[:2000]},
        )
    result.version = tool_version("nmap", tick)
    return parse_nmap(result.stdout, address, discovered_ports), result, argv


def tool_version(tool, tick):
    result = run_tool([tool, "--version"], 5, tick)
    return result.stdout.splitlines()[0][:200] if result.stdout else "unknown"
