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


def test_tool_without_total_deadline_still_supports_stop():
    assert run_tool([sys.executable, "-c", 'print("finished")'], None).stdout.strip() == "finished"

    def cancel():
        raise Interrupted()

    with pytest.raises(Interrupted):
        run_tool([sys.executable, "-c", "import time; time.sleep(30)"], None, cancel)


def test_network_request_timing_and_parallelism(monkeypatch):
    from app import scanners
    from app.scanners import ToolResult

    calls = []

    def tool(argv, timeout, tick):
        assert timeout is None
        calls.append(argv)
        if argv[0] == "rustscan":
            return ToolResult("192.0.2.1 -> [80]", "", 0, 0.1)
        return ToolResult(XML, "", 0, 0.1)

    monkeypatch.setattr(scanners, "run_tool", tool)
    monkeypatch.setattr(scanners, "tool_version", lambda *a: "test")
    assert scanners.rustscan("192.0.2.1", "80", 0.375, lambda: None, max_threads=45)[0] == [80]
    assert calls[0][calls[0].index("-b") + 1] == "45"
    assert calls[0][calls[0].index("-t") + 1] == "375"
    assert scanners.nmap("192.0.2.1", [80], 0.375, lambda: None, max_threads=45, timing=5)[0]
    argv = calls[1]
    assert "-T5" in argv
    assert argv[argv.index("--max-parallelism") + 1] == "45"
    assert argv[argv.index("--max-rtt-timeout") + 1] == "375ms"
    # Explicit zero overrides the host deadline that Nmap's T5 would otherwise add.
    assert argv[argv.index("--host-timeout") + 1] == "0"


def test_streaming_stdout_is_delivered_before_process_exit_without_accumulating_output(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "max_output_bytes", 100)
    received = []
    code = 'import sys,time; print("x"*5000,flush=True); time.sleep(30)'

    def stream(data):
        received.append(data)
        raise Interrupted()

    start = time.monotonic()
    with pytest.raises(Interrupted):
        run_tool([sys.executable, "-c", code], None, on_stdout=stream, capture_stdout=False)
    assert received and b"x" in received[0]
    assert time.monotonic() - start < 6
