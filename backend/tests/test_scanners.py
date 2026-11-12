import sys
import time
from pathlib import Path

import pytest

from app.scanners import Interrupted, ToolError, parse_nmap, parse_rustscan, run_tool

XML = """<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.26" conf="10"><cpe>cpe:/a:nginx:nginx:1.26</cpe></service></port></ports></host></nmaprun>"""


def test_rustscan_parser():
    assert parse_rustscan("192.0.2.1 -> [22,80]\n", "192.0.2.1", "22,80") == [22, 80]
    assert parse_rustscan("2001:db8::1 -> [443]", "2001:db8::1", "443") == [443]
    with pytest.raises(ToolError):
        parse_rustscan("203.0.113.1 -> [80]", "192.0.2.1", "80")
    with pytest.raises(ToolError):
        parse_rustscan("192.0.2.1 -> [443]", "192.0.2.1", "80")


def test_nmap_xml_scope():
    result = parse_nmap(XML, "192.0.2.1", [80])
    assert result[0]["product"] == "nginx" and result[0]["confidence"] == 10
    with pytest.raises(ToolError):
        parse_nmap(XML, "192.0.2.1", [22])
    with pytest.raises(ToolError):
        parse_nmap(XML, "203.0.113.1", [80])
    with pytest.raises(Exception):
        parse_nmap(
            '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>', "192.0.2.1", [80]
        )


def test_process_timeout_and_cancellation(tmp_path):
    marker = tmp_path / "pid"
    argv = [
        sys.executable,
        "-c",
        f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));time.sleep(30)",
    ]
    start = time.monotonic()
    with pytest.raises(ToolError, match="timeout"):
        run_tool(argv, 0.5)
    assert time.monotonic() - start < 6
    pid = int(marker.read_text())
    # An exited zombie may briefly remain until its guardian is reaped; it cannot scan.
    if Path(f"/proc/{pid}/stat").exists():
        assert Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z"

    def cancel():
        raise Interrupted()

    with pytest.raises(Interrupted):
        run_tool(argv, 20, cancel)


def test_output_limit(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "max_output_bytes", 100)
    with pytest.raises(ToolError, match="limit"):
        run_tool([sys.executable, "-c", 'print("x"*10000)'], 5)
