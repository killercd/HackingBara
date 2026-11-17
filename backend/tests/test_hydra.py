import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_pipeline import fake_tools, launch  # noqa: F401, F811

from app import hydra, pipeline
from app.scanners import Interrupted, ToolResult
from app.scope import HydraService, Scope


def test_catalog_expands_installed_modules(monkeypatch):
    hydra.modules.cache_clear()
    monkeypatch.setattr(
        hydra.subprocess,
        "run",
        lambda *a, **k: type(
            "Result",
            (),
            {
                "stdout": "Supported services: ssh ftp[s] http[s]-{head|get|post} ldap3[-{cram|digest}md5][s]\n\nNot compiled: oracle",
                "stderr": "",
            },
        )(),
    )
    names = hydra.modules()
    assert {"ssh", "ftp", "ftps", "https-post", "ldap3-digestmd5s"} <= set(names)
    assert "oracle" not in names
    hydra.modules.cache_clear()


@pytest.mark.parametrize(
    "report,expected",
    [
        ({"success": True, "results": []}, "failed"),
        ({"success": False, "results": []}, "unknown"),
        ({"success": True, "errormessages": ["Connection lost"], "results": []}, "unknown"),
        (
            {
                "success": True,
                "results": [{"host": "203.0.113.1", "port": 22, "login": "alice", "password": "secret"}],
            },
            "unknown",
        ),
        (
            {
                "success": True,
                "results": [{"host": "192.0.2.1", "port": 22, "login": "alice", "password": "secret"}],
            },
            "successful",
        ),
    ],
)
def test_single_pair_adapter_keeps_secrets_private(monkeypatch, report, expected):
    monkeypatch.setattr(hydra, "modules", lambda: ["ssh"])
    paths = []

    def run(argv, timeout, tick, env, cwd):
        assert "alice" not in argv and "secret" not in argv
        assert argv[argv.index("-t") + 1] == "1"
        assert argv[-2:] == ["192.0.2.1", "ssh"]
        login, password = Path(argv[argv.index("-L") + 1]), Path(argv[argv.index("-P") + 1])
        assert login.read_text() == "alice\n" and password.read_text() == "secret\n"
        assert password.stat().st_mode & 0o777 == 0o600
        paths.extend([login, password])
        Path(argv[argv.index("-o") + 1]).write_text(json.dumps(report))
        return ToolResult("contains secret", "", 0, 0)

    monkeypatch.setattr(hydra.scanners, "run_tool", run)
    outcome, evidence = hydra.validate(
        Scope(["192.0.2.1"]), HydraService(module="ssh", host="192.0.2.1", port=22), "alice", "secret"
    )
    assert outcome == expected
    assert "secret" not in evidence
    assert all(not path.exists() for path in paths)


def test_adapter_handles_unsupported_scope_and_stop(monkeypatch):
    target = HydraService(module="ssh", host="192.0.2.1", port=22)
    monkeypatch.setattr(hydra, "modules", lambda: [])
    assert hydra.validate(Scope(["192.0.2.1"]), target, "u", "p")[0] == "not_supported"
    monkeypatch.setattr(hydra, "modules", lambda: ["ssh"])
    with pytest.raises(ValueError):
        hydra.validate(Scope(["192.0.2.2"]), target, "u", "p")
    monkeypatch.setattr(hydra.scanners, "run_tool", lambda *a, **k: (_ for _ in ()).throw(Interrupted()))
    with pytest.raises(Interrupted):
        hydra.validate(Scope(["192.0.2.1"]), target, "u", "p")


@pytest.mark.parametrize("host", ["outside/path", "user@host", "http://host", "host?query", "host#fragment"])
def test_service_rejects_unsafe_host(host):
    with pytest.raises(ValidationError):
        HydraService(module="ssh", host=host, port=22)


def test_pipeline_runs_explicit_hydra_services_only(auth, db_factory, fake_tools, monkeypatch):  # noqa: F811
    credential = auth.post(
        "/api/v1/credentials", json={"label": "Lab", "username": "alice", "password": "secret"}
    ).json()["id"]
    service = {"module": "ssh", "host": "192.0.2.1", "port": 22, "options": "", "tls": False}
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Hydra lab",
            "targets": ["192.0.2.1"],
            "ports": "22,80",
            "password_spray": True,
            "credential_ids": [credential],
            "credential_services": [service],
        },
    ).json()
    calls = []

    def attempt(scope, target, username, password, tick):
        assert scope.resolve("http://192.0.2.1/")[0] == ["192.0.2.1"]
        calls.append((target.module, target.port, username, password))
        return "successful", "Hydra approved pair accepted"

    monkeypatch.setattr(pipeline, "hydra_auth", attempt)
    identity = launch(auth, scan)
    pipeline.Runner(identity, pipeline.claim(identity)).run()
    assert calls == [("ssh", 22, "alice", "secret")]
    results = auth.get(f"/api/v1/runs/{identity}/credentials").json()
    assert results["items"][0]["status"] == "successful"
    assert results["items"][0]["url"].startswith("ssh://192.0.2.1:22/")
    assert "secret" not in str(results)


def test_auto_detection_uses_identified_service_and_actual_port(auth, monkeypatch):
    from app.scanners import ToolResult

    credential = auth.post(
        "/api/v1/credentials", json={"label": "Lab", "username": "alice", "password": "secret"}
    ).json()["id"]
    scan = auth.post(
        "/api/v1/scans",
        json={
            "name": "Detected services",
            "targets": ["192.0.2.1"],
            "ports": "21,22,2222",
            "password_spray": True,
            "credential_auto_detect": True,
            "credential_ids": [credential],
        },
    ).json()
    monkeypatch.setattr(hydra, "modules", lambda: ["ssh", "ftp"])
    monkeypatch.setattr(
        pipeline.scanners,
        "rustscan",
        lambda *a, **k: ([21, 22, 2222], ToolResult("", "", 0, 0), ["rustscan"]),
    )

    def enumerate_services(*args, **kwargs):
        observations = []
        for port, name in [(21, "unknown"), (22, "ftp"), (2222, "ssh")]:
            observations.append(
                {
                    "port": port,
                    "name": name,
                    "transport": "tcp",
                    "state": "open",
                    "product": "",
                    "version": "",
                    "banner": "",
                    "details": {},
                    "confidence": 10,
                }
            )
        return observations, ToolResult("", "", 0, 0), ["nmap"]

    monkeypatch.setattr(pipeline.scanners, "nmap", enumerate_services)
    calls = []
    monkeypatch.setattr(
        pipeline,
        "hydra_auth",
        lambda scope, target, *args: (
            calls.append((target.module, target.port)) or ("failed", "Lab rejection")
        ),
    )
    identity = launch(auth, scan)
    pipeline.Runner(identity, pipeline.claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert calls == [("ftp", 22), ("ssh", 2222)]


def test_tls_service_mapping(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(hydra, "modules", lambda: ["ftp", "ftps", "ssh"])
    service = SimpleNamespace(name="ftp", details={"tunnel": "ssl"}, ip="192.0.2.1", port=2121, confidence=10)
    target = hydra.detected_service(service)
    assert target.module == "ftps" and target.port == 2121 and target.tls
    service.name = "unknown"
    assert hydra.detected_service(service) is None


def test_port_table_guess_is_not_service_identification(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(hydra, "modules", lambda: ["ssh"])
    service = SimpleNamespace(name="ssh", details={"method": "table"}, confidence=3, ip="192.0.2.1", port=22)
    assert hydra.detected_service(service) is None
