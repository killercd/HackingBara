from datetime import timedelta

import pytest
from sqlalchemy import select
from test_scanners import XML

from app import models as m
from app import pipeline, scanners
from app.db import now
from app.pipeline import Runner, claim
from app.scanners import ToolResult


def launch(auth, scan):
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202, response.text
    return response.json()["id"]


@pytest.fixture
def fake_tools(monkeypatch):
    calls = []

    def rust(address, ports, timeout, tick, **options):
        tick()
        calls.append(("rustscan", address, ports))
        return [80], ToolResult("192.0.2.1 -> [80]", "", 0, 0.1), ["rustscan", "-a", address]

    def nmap(address, discovered, timeout, tick, **options):
        tick()
        calls.append(("nmap", address, discovered))
        assert discovered == [80]
        return (
            scanners.parse_nmap(XML, address, discovered),
            ToolResult(XML, "", 0, 0.1),
            ["nmap", "-p", "80", address],
        )

    monkeypatch.setattr(scanners, "rustscan", rust)
    monkeypatch.setattr(scanners, "nmap", nmap)
    monkeypatch.setattr(
        pipeline, "basic_auth", lambda *a, **k: pytest.fail("Credential validation must be opt-in")
    )
    monkeypatch.setattr(pipeline, "capture", lambda *a, **k: pytest.fail("Screenshots must be opt-in"))
    return calls


def test_pipeline_partial_results_history_and_rerun(auth, scan, db_factory, fake_tools, monkeypatch):
    identity = launch(auth, scan)
    owner = claim(identity)
    assert owner and claim(identity) is None
    Runner(identity, owner).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed", run
    assert run["counts"]["hosts"] == 1 and run["counts"]["services"] == 1
    assert [x[0] for x in fake_tools] == ["rustscan", "nmap"]
    assert auth.get(f"/api/v1/runs/{identity}/services?status=open").json()["total"] == 1
    assert auth.get(f"/api/v1/runs/{identity}/services?status=no-longer-observed").json()["total"] == 0
    assert auth.get(f"/api/v1/runs/{identity}/events?status=error").json()["total"] == 0
    assert auth.get(f"/api/v1/runs/{identity}/services").json()["items"][0]["change"] == "new"
    second = launch(auth, scan)
    Runner(second, claim(second)).run()
    assert auth.get(f"/api/v1/runs/{second}/services").json()["items"][0]["change"] == "unchanged"
    monkeypatch.setattr(scanners, "rustscan", lambda *a, **k: ([], ToolResult("", "", 0, 0.1), ["rustscan"]))
    third = launch(auth, scan)
    Runner(third, claim(third)).run()
    services = auth.get(f"/api/v1/runs/{third}/services").json()["items"]
    assert services[0]["change"] == "no-longer-observed"
    assert services[0]["state"] == "no-longer-observed"
    assert auth.get(f"/api/v1/runs/{identity}/services").json()["items"][0]["change"] == "new"


def test_pause_resume_checkpoint_does_not_repeat_discovery(auth, scan, db_factory, fake_tools, monkeypatch):
    identity = launch(auth, scan)
    owner = claim(identity)
    original = scanners.rustscan

    def pause(*args, **options):
        result = original(*args, **options)
        assert auth.post(f"/api/v1/runs/{identity}/pause").json()["status"] == "pausing"
        return result

    monkeypatch.setattr(scanners, "rustscan", pause)
    Runner(identity, owner).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "paused"
    assert auth.get(f"/api/v1/runs/{identity}/ports").json()["total"] == 1
    assert auth.post(f"/api/v1/runs/{identity}/resume").status_code == 200
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert [x[0] for x in fake_tools].count("rustscan") == 1
    assert auth.get(f"/api/v1/runs/{identity}/services").json()["total"] == 1


def test_stop_during_tool_preserves_results(auth, scan, db_factory, fake_tools, monkeypatch):
    identity = launch(auth, scan)
    owner = claim(identity)

    def stop(address, discovered, timeout, tick, **options):
        auth.post(f"/api/v1/runs/{identity}/stop")
        tick(True)

    monkeypatch.setattr(scanners, "nmap", stop)
    Runner(identity, owner).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "stopped"
    assert auth.get(f"/api/v1/runs/{identity}/ports").json()["total"] == 1


def test_individual_scanner_failure_does_not_destroy_ports(auth, scan, db_factory, fake_tools, monkeypatch):
    def error(*args):
        raise scanners.ToolError("Error")

    monkeypatch.setattr(scanners, "nmap", error)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed" and run["counts"]["errors"] == 1
    assert auth.get(f"/api/v1/runs/{identity}/ports").json()["total"] == 1


def test_lease_reconciliation(auth, scan, db_factory, monkeypatch):
    import app.tasks as tasks
    from app.tasks import reconcile

    class Broker:
        def llen(self, *a):
            return 100

    monkeypatch.setattr(tasks.Redis, "from_url", lambda *a, **k: Broker())
    identity = launch(auth, scan)
    claim(identity)
    with db_factory() as db:
        db.get(m.Run, identity).heartbeat_at = now() - timedelta(minutes=5)
        db.commit()
    reconcile.run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "failed"


def test_global_capacity(auth, scan, db_factory, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "max_concurrent_runs", 1)
    first = launch(auth, scan)
    second_scan = auth.post("/api/v1/scans", json={"name": "Other", "targets": ["192.0.2.2"]}).json()
    second = launch(auth, second_scan)
    assert claim(first) and claim(second) is None


def test_password_first_pair_order_budgets_and_immutability(auth, db_factory, fake_tools, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "spray_account_budget", 1)
    ids = []
    for username, password in [("alice", "alpha"), ("alice", "beta"), ("bob", "alpha"), ("bob", "beta")]:
        ids.append(
            auth.post(
                "/api/v1/credentials", json={"label": username, "username": username, "password": password}
            ).json()["id"]
        )
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Approved lab",
            "targets": ["192.0.2.1"],
            "ports": "80",
            "urls": ["http://192.0.2.1/"],
            "credential_endpoints": ["http://192.0.2.1/"],
            "password_spray": True,
            "credential_ids": ids,
        },
    ).json()
    calls = []

    def attempt(scope, url, username, password):
        calls.append((password, username))
        return "failed", "Challenge rejected"

    monkeypatch.setattr(pipeline, "basic_auth", attempt)
    identity = launch(auth, scan)
    # Removing current definition references must not permit changing a historic approval.
    assert (
        auth.patch(
            f"/api/v1/scans/{scan['id']}", json={"credential_ids": [], "password_spray": False}
        ).status_code
        == 200
    )
    assert auth.patch(f"/api/v1/credentials/{ids[0]}", json={"password": "new"}).status_code == 409
    assert auth.delete(f"/api/v1/credentials/{ids[0]}").status_code == 409
    Runner(identity, claim(identity)).run()
    assert calls == [("alpha", "alice"), ("alpha", "bob")]
    results = auth.get(f"/api/v1/runs/{identity}/credentials").json()
    assert results["total"] == 4
    assert "alpha" not in str(results) and "beta" not in str(results)


def test_blocked_service_aborts_later_accounts(auth, db_factory, fake_tools, monkeypatch):
    credentials = [
        auth.post("/api/v1/credentials", json={"label": u, "username": u, "password": "approved"}).json()[
            "id"
        ]
        for u in ["alice", "bob"]
    ]
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Lab",
            "targets": ["192.0.2.1"],
            "ports": "80",
            "urls": ["http://192.0.2.1/"],
            "credential_endpoints": ["http://192.0.2.1/"],
            "password_spray": True,
            "credential_ids": credentials,
        },
    ).json()
    attempts = []

    def attempt(*args):
        attempts.append(1)
        return "blocked", "Defensive response"

    monkeypatch.setattr(pipeline, "basic_auth", attempt)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert len(attempts) == 1


def test_screenshot_evidence_is_private(auth, scan, db_factory, fake_tools, monkeypatch):
    from app.config import settings

    def screenshot(scope, url, run_id, shot_id, tick):
        tick()
        root = settings.evidence_dir / run_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "shot.png").write_bytes(b"fake-png")
        return f"{run_id}/shot.png", f"{run_id}/shot.png", 320, 200

    monkeypatch.setattr(pipeline, "capture", screenshot)
    auth.patch(f"/api/v1/scans/{scan['id']}", json={"screenshots": True})
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    shot = auth.get(f"/api/v1/runs/{identity}/screenshots").json()["items"][0]
    assert "path" not in shot
    assert auth.get(shot["content_url"]).content == b"fake-png"
    auth.post("/api/v1/auth/logout")
    assert auth.get(shot["content_url"]).status_code == 401


def test_unknown_attempt_is_journaled_and_never_retried(auth, db_factory, fake_tools, monkeypatch):
    credential = auth.post(
        "/api/v1/credentials", json={"label": "Approved", "username": "alice", "password": "approved"}
    ).json()["id"]
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Journal test",
            "targets": ["192.0.2.1"],
            "ports": "80",
            "urls": ["http://192.0.2.1/"],
            "credential_endpoints": ["http://192.0.2.1/"],
            "password_spray": True,
            "credential_ids": [credential],
        },
    ).json()
    identity = launch(auth, scan)
    calls = []

    def uncertain(*args):
        with db_factory() as db:
            journal = db.scalar(select(m.Attempt).where(m.Attempt.run_id == identity))
            assert journal.status == "unknown" and journal.attempted_at is not None
        calls.append(1)
        assert auth.post(f"/api/v1/runs/{identity}/pause").status_code == 200
        raise TimeoutError("No credentials in persisted exception evidence")

    monkeypatch.setattr(pipeline, "basic_auth", uncertain)
    owner = claim(identity)
    runner = Runner(identity, owner)
    runner.run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "paused"
    assert auth.post(f"/api/v1/runs/{identity}/resume").status_code == 200
    Runner(identity, claim(identity)).run()
    assert calls == [1]
    assert auth.get(f"/api/v1/runs/{identity}/credentials").json()["items"][0]["status"] == "unknown"


def test_account_budget_is_global_across_paths(auth, db_factory, fake_tools, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "spray_account_budget", 1)
    credential = auth.post(
        "/api/v1/credentials", json={"label": "Approved", "username": "alice", "password": "approved"}
    ).json()["id"]
    urls = ["http://192.0.2.1/one", "http://192.0.2.1/two"]
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Global budget",
            "targets": ["192.0.2.1"],
            "ports": "80",
            "urls": urls,
            "credential_endpoints": urls,
            "password_spray": True,
            "credential_ids": [credential],
        },
    ).json()
    calls = []

    def attempt(*args):
        calls.append(1)
        return "failed", "Rejected"

    monkeypatch.setattr(pipeline, "basic_auth", attempt)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert len(calls) == 1


def test_scanner_metadata_and_banners_redact_selected_secrets(auth, db_factory, fake_tools, monkeypatch):
    credential = auth.post(
        "/api/v1/credentials", json={"label": "Secret", "username": "alice", "password": "do-not-leak"}
    ).json()["id"]
    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Redaction", "targets": ["192.0.2.1"], "ports": "80", "credential_ids": [credential]},
    ).json()
    original = scanners.nmap

    def banner(*args, **options):
        rows, result, argv = original(*args, **options)
        rows[0]["banner"] = "a banner with do-not-leak"
        result.stderr = "untrusted output do-not-leak"
        return rows, result, argv

    monkeypatch.setattr(scanners, "nmap", banner)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert "do-not-leak" not in auth.get(f"/api/v1/runs/{identity}/services").text
    assert "do-not-leak" not in auth.get(f"/api/v1/runs/{identity}/events").text


def test_url_only_run_derives_ips_without_mutating_definition(auth, db_factory, fake_tools, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80))])
    response = auth.post(
        "/api/v1/scans", json={"name": "URL only pipeline", "urls": ["http://lab.example/"], "ports": "80"}
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["config"]["targets"] == []
    identity = launch(auth, scan)
    snapshot = auth.get(f"/api/v1/runs/{identity}").json()
    assert snapshot["config_snapshot"]["targets"] == []
    assert snapshot["status"] == "queued"
    assert auth.get(f"/api/v1/scans/{scan['id']}").json()["config"]["targets"] == []
    Runner(identity, claim(identity)).run()
    result = auth.get(f"/api/v1/runs/{identity}").json()
    assert result["status"] == "completed"
    assert result["config_snapshot"]["targets"] == ["192.0.2.1"]
    assert result["total"] == 1
    assert result["counts"]["services"] == 1
    assert ("rustscan", "192.0.2.1", "80") in fake_tools
    assert auth.get(f"/api/v1/runs/{identity}/endpoints?search=lab.example").json()["total"] == 1


def test_explicit_ip_scope_still_restricts_urls(auth, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 80))])
    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Restricted", "targets": ["192.0.2.1"], "urls": ["http://lab.example/"]},
    ).json()
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202
    identity = response.json()["id"]
    Runner(identity, claim(identity)).run()
    result = auth.get(f"/api/v1/runs/{identity}").json()
    assert result["status"] == "failed"
    assert "outside the authorized scope" in result["error_summary"]
    assert auth.get(f"/api/v1/runs/{identity}/hosts").json()["total"] == 0


def test_unresolvable_url_only_run_fails_in_scope_stage_without_scanning(auth, monkeypatch):
    import socket

    def no_dns(*a, **k):
        raise socket.gaierror("No DNS answer")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    scan = auth.post("/api/v1/scans", json={"name": "Unresolved", "urls": ["http://missing.example/"]}).json()
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202
    identity = response.json()["id"]
    Runner(identity, claim(identity)).run()
    result = auth.get(f"/api/v1/runs/{identity}").json()
    assert result["status"] == "failed"
    assert "None of the supplied URLs" in result["error_summary"]
    assert auth.get(f"/api/v1/runs/{identity}/hosts").json()["total"] == 0


def test_dns_failures_are_partial_results_and_optional_modules_skip_failed_urls(
    auth, db_factory, fake_tools, monkeypatch
):
    import socket

    def resolve(host, *args, **kwargs):
        if host == "missing.example":
            raise socket.gaierror(socket.EAI_NONAME, "No IP address")
        return [(2, 1, 6, "", ("192.0.2.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    credential = auth.post(
        "/api/v1/credentials", json={"label": "Approved", "username": "test", "password": "approved-pair"}
    ).json()["id"]
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Mixed DNS",
            "urls": ["http://working.example/", "http://missing.example/"],
            "ports": "80",
            "screenshots": True,
            "password_spray": True,
            "credential_ids": [credential],
            "credential_endpoints": ["http://missing.example/"],
        },
    ).json()
    identity = launch(auth, scan)
    captures = []

    def capture(scope, url, *args):
        assert "missing.example" not in url
        captures.append(url)
        raise RuntimeError("Expected mock capture failure")

    monkeypatch.setattr(pipeline, "capture", capture)
    Runner(identity, claim(identity)).run()
    initial = auth.get(f"/api/v1/runs/{identity}").json()
    assert initial["config_snapshot"]["targets"] == ["192.0.2.1"]
    assert initial["config_snapshot"]["urls"] == ["http://working.example/", "http://missing.example/"]
    failed = [
        item
        for item in auth.get(f"/api/v1/runs/{identity}/endpoints?status=error").json()["items"]
        if item["details"].get("code") == "dns_resolution_failed"
    ]
    assert len(failed) == 1 and failed[0]["url"] == "http://missing.example/"
    assert failed[0]["details"]["code"] == "dns_resolution_failed"
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert captures == ["http://working.example/"]
    assert auth.get(f"/api/v1/runs/{identity}/credentials").json()["total"] == 0
    assert auth.get(f"/api/v1/runs/{identity}/endpoints?search=missing.example").json()["total"] == 1
    events = auth.get(f"/api/v1/runs/{identity}/events?search=missing.example").json()
    assert events["total"] == 1 and events["items"][0]["event_type"] == "dns_resolution_failed"


def test_all_dns_failures_report_every_url_in_failed_run(auth, monkeypatch):
    import socket

    def resolve(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "No IP address")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    urls = ["https://missing-one.example/", "https://missing-two.example/"]
    scan = auth.post("/api/v1/scans", json={"name": "All unresolved", "urls": urls}).json()
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202
    identity = response.json()["id"]
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "failed"
    assert "None of the supplied URLs" in run["error_summary"]
    failed = auth.get(f"/api/v1/runs/{identity}/endpoints?status=error").json()["items"]
    assert {item["url"] for item in failed} == set(urls)
    assert all(item["details"]["code"] == "dns_resolution_failed" for item in failed)


def test_out_of_scope_is_reported_separately_from_dns_failure(auth, monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 80))])
    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Outside scope", "targets": ["192.0.2.1"], "urls": ["http://outside.example/"]},
    ).json()
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202
    identity = response.json()["id"]
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "failed"
    assert "outside the authorized scope" in run["error_summary"]
    assert auth.get(f"/api/v1/runs/{identity}/events?search=scope_rejected").json()["total"] == 1
    assert auth.get(f"/api/v1/runs/{identity}/events?search=dns_resolution_failed").json()["total"] == 0


def test_network_timing_settings_reach_both_tools(auth, scan, fake_tools, monkeypatch):
    assert (
        auth.patch(
            f"/api/v1/scans/{scan['id']}",
            json={"request_timeout": 1.25, "max_threads": 48, "network_timing": 4},
        ).status_code
        == 200
    )
    rust, nmap = scanners.rustscan, scanners.nmap

    def discover(address, ports, request_timeout, tick, **options):
        assert request_timeout == 1.25 and options["max_threads"] == 48
        return rust(address, ports, request_timeout, tick, **options)

    def enumerate_services(address, ports, request_timeout, tick, **options):
        assert request_timeout == 1.25 and options == {"max_threads": 48, "timing": 4}
        return nmap(address, ports, request_timeout, tick, **options)

    monkeypatch.setattr(scanners, "rustscan", discover)
    monkeypatch.setattr(scanners, "nmap", enumerate_services)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed" and run["counts"]["errors"] == 0
    assert "timeout" not in run["config_snapshot"]
    assert [call[0] for call in fake_tools] == ["rustscan", "nmap"]


@pytest.mark.parametrize("target", ["web.example", "https://web.example/"])
@pytest.mark.parametrize("fail_first", [False, True])
def test_eyewitness_attempts_every_http_port_with_original_hostname(auth, monkeypatch, target, fail_first):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80))])
    response = auth.post(
        "/api/v1/scans",
        json={"name": "Multiple web ports", "urls": [target], "ports": "22,80,443,8080", "screenshots": True},
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert "web.example" in scan["target_summary"]
    captures = []

    def rustscan(*args, **kwargs):
        return [22, 80, 443, 8080], ToolResult("", "", 0, 0.1), ["rustscan"]

    def nmap(*args, **kwargs):
        observations = []
        for port, name, details in [
            (22, "ssh", {}),
            (80, "http", {}),
            (443, "http", {"tunnel": "ssl"}),
            (8080, "http-proxy", {}),
        ]:
            observations.append(
                {
                    "port": port,
                    "name": name,
                    "details": details,
                    "transport": "tcp",
                    "state": "open",
                    "product": "",
                    "version": "",
                    "banner": "",
                    "confidence": 10,
                }
            )
        return observations, ToolResult("", "", 0, 0.1), ["nmap"]

    def capture(scope, url, *args):
        assert scope.resolve(url)[0] == ["192.0.2.1"]
        captures.append(url)
        if fail_first and url == "http://web.example/":
            raise RuntimeError("Mock capture failure on port 80")
        return "mock.png", "mock-thumb.png", 320, 200

    monkeypatch.setattr(scanners, "rustscan", rustscan)
    monkeypatch.setattr(scanners, "nmap", nmap)
    monkeypatch.setattr(pipeline, "capture", capture)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert set(captures) == {"http://web.example/", "https://web.example/", "http://web.example:8080/"}
    assert len(captures) == 3
    endpoints = auth.get(f"/api/v1/runs/{identity}/endpoints").json()
    assert endpoints["total"] == 3
    assert {item["port"] for item in endpoints["items"]} == {80, 443, 8080}
    shots = auth.get(f"/api/v1/runs/{identity}/screenshots").json()
    assert shots["total"] == 3
    assert sum(row["status"] == "captured" for row in shots["items"]) == (2 if fail_first else 3)
    snapshot = auth.get(f"/api/v1/runs/{identity}").json()["config_snapshot"]
    assert snapshot["targets"] == ["192.0.2.1"]
    if target == "web.example":
        assert snapshot["hostnames"] == ["web.example"] and snapshot["urls"] == []


def test_unresolvable_hostname_is_reported_without_creating_fake_http_endpoint(auth, monkeypatch, fake_tools):
    import socket

    def resolve(host, *a, **k):
        if host == "missing.example":
            raise socket.gaierror(socket.EAI_NONAME, "No IP address")
        return [(2, 1, 6, "", ("192.0.2.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    response = auth.post(
        "/api/v1/scans",
        json={"name": "Mixed names", "urls": ["working.example", "missing.example"], "ports": "80"},
    )
    assert response.status_code == 201, response.text
    identity = launch(auth, response.json())
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed"
    endpoints = auth.get(f"/api/v1/runs/{identity}/endpoints").json()["items"]
    assert [item["url"] for item in endpoints] == ["http://working.example/"]
    assert auth.get(f"/api/v1/runs/{identity}/events?search=missing.example").json()["total"] == 1


def test_screenshot_uses_ip_where_nmap_identified_http_server(auth, monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80)), (2, 1, 6, "", ("192.0.2.2", 80))],
    )
    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Multiple addresses", "urls": ["web.example"], "ports": "8080", "screenshots": True},
    ).json()

    def rust(address, *a, **k):
        return ([8080] if address == "192.0.2.2" else []), ToolResult("", "", 0, 0.1), ["rustscan"]

    def nmap(address, discovered, *a, **k):
        if not discovered:
            return [], None, []
        return (
            [
                {
                    "port": 8080,
                    "name": "http-alt",
                    "details": {},
                    "product": "",
                    "version": "",
                    "banner": "",
                    "confidence": 10,
                }
            ],
            ToolResult("", "", 0, 0.1),
            ["nmap"],
        )

    attempts = []

    def capture(scope, url, *a):
        attempts.append((url, scope.resolve(url)[0]))
        return "mock.png", "mock-thumb.png", 320, 200

    monkeypatch.setattr(scanners, "rustscan", rust)
    monkeypatch.setattr(scanners, "nmap", nmap)
    monkeypatch.setattr(pipeline, "capture", capture)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert attempts == [("http://web.example:8080/", ["192.0.2.2"])]
    assert auth.get(f"/api/v1/runs/{identity}/endpoints").json()["items"][0]["ip"] == "192.0.2.2"


def test_launch_queues_without_waiting_for_hostname_resolution(auth, monkeypatch):
    import socket

    scan = auth.post(
        "/api/v1/scans",
        json={"name": "Imported DNS names", "urls": [f"name-{i}.example.test" for i in range(44)]},
    ).json()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("Launch must not perform DNS"))
    monkeypatch.setattr(
        scanners, "prepare_scope", lambda *a: pytest.fail("HTTP must not wait for scope preparation")
    )
    identity = launch(auth, scan)
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "queued" and run["current_stage"] == "scope"
    assert run["config_snapshot"]["targets"] == []
    assert len(run["config_snapshot"]["hostnames"]) == 44


def test_stop_during_scope_preparation_does_not_start_scanners(auth, monkeypatch):
    scan = auth.post("/api/v1/scans", json={"name": "Stop resolution", "urls": ["slow.example.test"]}).json()
    identity = launch(auth, scan)

    def prepare(config, tick):
        run = auth.get(f"/api/v1/runs/{identity}").json()
        assert run["status"] == "running" and run["current_stage"] == "scope"
        assert auth.post(f"/api/v1/runs/{identity}/stop").status_code == 200
        tick(True)
        pytest.fail("Scope preparation must be interrupted")

    monkeypatch.setattr(scanners, "prepare_scope", prepare)
    monkeypatch.setattr(
        scanners, "rustscan", lambda *a, **k: pytest.fail("No scanning before the IP scope is frozen")
    )
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "stopped"
    assert auth.get(f"/api/v1/runs/{identity}/hosts").json()["total"] == 0


def test_prepared_scope_is_not_resolved_again_after_pause(auth, scan, fake_tools, monkeypatch):
    calls = []
    prepare = scanners.prepare_scope
    rustscan = scanners.rustscan

    def resolver(config, tick):
        calls.append(1)
        return prepare(config, tick)

    def pause(*args, **options):
        result = rustscan(*args, **options)
        assert auth.post(f"/api/v1/runs/{identity}/pause").status_code == 200
        return result

    monkeypatch.setattr(scanners, "prepare_scope", resolver)
    monkeypatch.setattr(scanners, "rustscan", pause)
    identity = launch(auth, scan)
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "paused"
    assert auth.post(f"/api/v1/runs/{identity}/resume").status_code == 200
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert calls == [1]
