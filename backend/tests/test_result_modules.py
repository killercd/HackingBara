import csv
import io
import json
import socket

import pytest
from test_pipeline import fake_tools, launch  # noqa: F401, F811

from app import models as m
from app import pipeline, scanners
from app.pipeline import Runner, claim
from app.scanners import ToolResult


def test_searchsploit_adapter_handles_banner_and_cve(monkeypatch):
    calls = []

    def tool(argv, timeout, tick):
        calls.append(argv)
        return ToolResult(
            json.dumps(
                {
                    "RESULTS_EXPLOIT": [
                        {"EDB-ID": "123", "Title": "Example", "Codes": "CVE-2020-1234"},
                        {"EDB-ID": "456", "Title": "No CVE"},
                    ]
                }
            ),
            "",
            0,
            0,
        )

    monkeypatch.setattr(scanners, "run_tool", tool)
    query, rows = scanners.searchsploit("nginx/1.2 --update; $(id)", lambda: None)
    assert all(not term.startswith("-") for term in calls[0][3:])
    assert rows[0]["cve"] == "CVE-2020-1234"
    assert rows[1]["cve"] == ""
    assert rows[0]["url"] == "https://www.exploit-db.com/exploits/123"
    assert scanners.searchsploit("", lambda: None) == ("", [])


def test_result_hostnames_headers_cve_sort_and_csv(auth, db_factory, fake_tools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))]
    )
    monkeypatch.setattr(
        pipeline,
        "request",
        lambda *a, **k: (200, [("Server", "nginx/1.2"), ("X-Test", "first"), ("X-Test", "second")]),
    )
    calls = []

    def lookup(banner, tick):
        calls.append(banner)
        return banner, [
            {
                "edb_id": "123",
                "cve": "CVE-2020-1234",
                "title": "=candidate",
                "url": "https://www.exploit-db.com/exploits/123",
                "status": "candidate",
            }
        ]

    monkeypatch.setattr(scanners, "searchsploit", lookup)
    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Named host", "hostnames": ["web.example"], "ports": "80", "searchsploit": True},
    ).json()
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    base = f"/api/v1/runs/{identity}"
    assert auth.get(base).json()["status"] == "completed"
    assert calls == ["nginx 1.26"]
    services = auth.get(base + "/services?sort_by=hostname&sort_order=asc").json()["items"]
    assert services[0]["hostname"] == "web.example"
    assert services[0]["details"]["response_headers"][-1] == ["X-Test", "second"]
    for collection, fields in {
        "hosts": ["hostname", "open_ports", "services", "first_seen_at", "last_seen_at"],
        "services": ["transport", "banner", "confidence", "details", "first_seen_at"],
        "endpoints": ["hostname", "details", "screenshot"],
        "cve": ["hostname", "cve", "query", "title", "port", "details"],
        "events": ["details", "level", "stage"],
    }.items():
        for field in fields:
            response = auth.get(base + f"/{collection}?sort_by={field}")
            assert response.status_code == 200, response.text
    rows = auth.get(base + "/cve").json()["items"]
    assert rows[0]["cve"] == "CVE-2020-1234", (rows, auth.get(base + "/events?status=error").json())
    assert rows[0]["details"] == services[0]["details"]
    export = auth.get(base + "/cve/export.csv?status=candidate&sort_by=port&sort_order=asc")
    assert export.status_code == 200
    exported = list(csv.DictReader(io.StringIO(export.content.decode("utf-8-sig"))))
    assert exported[0]["title"] == "'=candidate"
    assert exported[0]["hostname"] == "web.example"
    assert exported[0]["details"] == "Server: nginx/1.2\nX-Test: first\nX-Test: second"
    assert auth.get(base + "/cve/export.csv?status=error").status_code == 200
    assert auth.get(base + "/services/export.csv?sort_by=password_hash").status_code == 422


def test_csv_exports_all_pages_and_requires_login(auth, client, scan, db_factory):
    identity = launch(auth, scan)
    with db_factory() as db:
        for n in range(105):
            db.add(m.Event(run_id=identity, stage="test", event_type="test", message=f"row {n:03}"))
        db.commit()
    response = auth.get(
        f"/api/v1/runs/{identity}/events/export.csv?search=row&sort_by=message&sort_order=asc"
    )
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert len(rows) == 105
    assert rows[0]["message"] == "row 000" and rows[-1]["message"] == "row 104"
    client.cookies.clear()
    assert client.get(f"/api/v1/runs/{identity}/events/export.csv").status_code == 401


def test_capture_retries_missing_image_and_preserves_artifact(monkeypatch, tmp_path):
    from PIL import Image

    import app.capture as capture_module
    from app.config import settings
    from app.scope import Scope

    monkeypatch.setattr(settings, "eyewitness_enabled", True)
    monkeypatch.setattr(settings, "evidence_dir", tmp_path)
    calls = []

    def tool(argv, timeout, tick, env):
        from pathlib import Path

        calls.append(argv)
        if len(calls) == 2:
            screens = Path(argv[argv.index("-d") + 1]) / "screens"
            screens.mkdir(parents=True)
            Image.new("RGB", (640, 480), "white").save(screens / "capture.png")
        return ToolResult("", "", 0, 0)

    monkeypatch.setattr(capture_module, "run_tool", tool)
    path, thumbnail, width, height = capture_module.capture(
        Scope(["192.0.2.1"]), "https://192.0.2.1/", "run", "shot", lambda: None
    )
    assert len(calls) == 2
    assert (tmp_path / path).is_file() and (tmp_path / thumbnail).is_file()
    assert (width, height) == (640, 480)


@pytest.mark.parametrize(
    "product,version", [("Apache", ""), ("", "2.4.49"), ("", ""), ("  ", "2.4.49"), ("Apache", "  ")]
)
def test_searchsploit_skips_incomplete_identity(auth, scan, fake_tools, monkeypatch, product, version):  # noqa: F811
    original = scanners.nmap

    def incomplete(*args, **kwargs):
        observations, result, argv = original(*args, **kwargs)
        for observation in observations:
            observation.update(product=product, version=version, banner="Apache 2.4.49")
        return observations, result, argv

    monkeypatch.setattr(scanners, "nmap", incomplete)
    monkeypatch.setattr(pipeline, "request", lambda *a, **k: (200, [("Server", "Apache/2.4.49")]))
    assert auth.patch(f"/api/v1/scans/{scan['id']}", json={"searchsploit": True}).status_code == 200
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    base = f"/api/v1/runs/{identity}"
    assert auth.get(base).json()["status"] == "completed"
    rows = auth.get(base + "/cve").json()["items"]
    assert len(rows) == 1
    assert rows[0]["status"] == "skipped"
    assert rows[0]["query"] == "" and rows[0]["edb_id"] == ""
    assert "product name and version are required" in rows[0]["title"]
