from pathlib import Path

import pytest

from app import scanners
from app.pipeline import Runner, claim
from app.scanners import ToolError, ToolResult
from app.scope import ScanInput, prepare_run_config


def test_dns_config_normalizes_names_and_preserves_network_default():
    assert ScanInput(name="Existing", targets=["192.0.2.1"]).mode == "network"
    config = ScanInput(
        name="DNS", mode="subdomain", domain="EXAMPLE.test.", subdomains=["WWW", "www", "dev.api"]
    )
    assert config.domain == "example.test"
    assert config.subdomains == ["www", "dev.api"]
    assert "timeout" not in config.model_dump()
    assert prepare_run_config(config) == config


@pytest.mark.parametrize(
    "options",
    [
        {"domain": ""},
        {"domain": "192.0.2.1"},
        {"domain": "https://example.test"},
        {"domain": "-bad.test"},
        {"subdomains": []},
        {"subdomains": ["../etc/passwd"]},
        {"subdomains": ["a\nwww"]},
        {"subdomains": ["*"]},
        {"subdomains": ["a" * 64]},
        {"targets": ["192.0.2.1"]},
        {"screenshots": True},
        {"mode": "unknown"},
    ],
)
def test_invalid_dns_configuration(options):
    with pytest.raises(ValueError):
        ScanInput.model_validate(
            {"name": "DNS", "mode": "subdomain", "domain": "example.test", "subdomains": ["www"], **options}
        )


def test_gobuster_parser_checks_exact_candidates_and_addresses():
    assert scanners.parse_gobuster_dns(
        "\r\x1b[2KFound: api.example.test [192.0.2.1,2001:db8::1]\n", "example.test", ["api"]
    ) == [{"hostname": "api.example.test", "addresses": ["192.0.2.1", "2001:db8::1"]}]
    assert scanners.parse_gobuster_dns("", "example.test", ["api"]) == []
    assert scanners.parse_gobuster_dns(
        "Missed: www.example.test\nFound: api.example.test [192.0.2.1]\n",
        "example.test",
        ["www", "api"],
    ) == [{"hostname": "api.example.test", "addresses": ["192.0.2.1"]}]
    for output in (
        "Found: www.example.test [192.0.2.1]",
        "Found: api.other.test [192.0.2.1]",
        "Found: api.example.test [bad]",
        "unexpected output",
    ):
        with pytest.raises(ToolError):
            scanners.parse_gobuster_dns(output, "example.test", ["api"])


def test_gobuster_adapter_uses_temporary_wordlist_and_fixed_flags(monkeypatch):
    paths = []

    def tool(argv, timeout, tick, **options):
        assert argv[:2] == ["gobuster", "dns"]
        path = Path(argv[argv.index("--wordlist") + 1])
        assert path.read_text() == "www\napi\n"
        paths.append(path)
        assert timeout is None
        assert argv[argv.index("--timeout") + 1] == "0.75s"
        assert argv[argv.index("--threads") + 1] == "37"
        assert "--show-ips" in argv and "--wildcard" not in argv
        assert "--verbose" in argv
        assert argv[argv.index("--domain") + 1] == "example.test"
        assert options["capture_stdout"] is False
        options["on_stdout"](b"Missed: www.example.test\nFound: api.example.test [192.0.2.1]\n")
        return ToolResult("", "", 0, 0.1)

    monkeypatch.setattr(scanners, "run_tool", tool)
    monkeypatch.setattr(scanners, "tool_version", lambda *a, **k: "3.6")
    results, _, _ = scanners.gobuster_dns("example.test", ["www", "api"], 0.75, lambda: None, max_threads=37)
    assert results[0]["hostname"] == "api.example.test"
    assert not paths[0].exists()


def create_dns_run(auth):
    response = auth.post(
        "/api/v1/scans",
        json={
            "name": "DNS lab",
            "mode": "subdomain",
            "domain": "example.test",
            "subdomains": ["www", "api"],
            "request_timeout": 0.75,
            "max_threads": 37,
        },
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["target_summary"] == "example.test (2 DNS candidates)"
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202, response.text
    assert response.json()["total"] == 2
    return scan, response.json()["id"]


def test_dns_run_results_and_immutable_snapshot(auth, monkeypatch):
    scan, identity = create_dns_run(auth)
    assert auth.patch(f"/api/v1/scans/{scan['id']}", json={"subdomains": ["mail"]}).status_code == 200

    def dns(domain, words, timeout, tick, **options):
        assert domain == "example.test" and words == ["www", "api"]
        assert timeout == 0.75 and options["max_threads"] == 37
        tick()
        return (
            [{"hostname": "api.example.test", "addresses": ["192.0.2.1"]}],
            ToolResult("", "", 0, 0.1, "3.6"),
            ["gobuster", "dns"],
        )

    monkeypatch.setattr(scanners, "gobuster_dns", dns)
    monkeypatch.setattr(scanners, "rustscan", lambda *a, **k: pytest.fail("DNS mode must not scan ports"))
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed", run
    assert run["processed"] == 2 and run["counts"]["subdomains"] == 1
    assert run["counts"]["hosts"] == 0 and run["counts"]["errors"] == 0
    results = auth.get(f"/api/v1/runs/{identity}/subdomains?search=api").json()
    assert results["total"] == 1
    assert results["items"][0]["evidence"]["addresses"] == ["192.0.2.1"]
    assert auth.get(f"/api/v1/runs/{identity}/subdomains?search=mail").json()["total"] == 0


def test_dns_tool_error_fails_run_with_diagnostics(auth, monkeypatch):
    _, identity = create_dns_run(auth)

    def dns(*a, **options):
        raise ToolError("Gobuster failed", {"exit_code": 1, "stderr": "Wildcard DNS detected"})

    monkeypatch.setattr(scanners, "gobuster_dns", dns)
    Runner(identity, claim(identity)).run()
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "failed" and run["counts"]["subdomains"] == 0
    events = auth.get(f"/api/v1/runs/{identity}/events?search=scanner_error").json()["items"]
    assert events[0]["details"]["stderr"] == "Wildcard DNS detected"
    assert auth.get(f"/api/v1/runs/{identity}/targets").json()["items"][0]["status"] == "error"


def test_dns_pause_resume_preserves_checkpoint(auth, monkeypatch):
    _, identity = create_dns_run(auth)
    calls = []

    def dns(*a, **options):
        calls.append(1)
        assert auth.post(f"/api/v1/runs/{identity}/pause").status_code == 200
        return [], ToolResult("", "", 0, 0.1), ["gobuster", "dns"]

    monkeypatch.setattr(scanners, "gobuster_dns", dns)
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "paused"
    assert auth.post(f"/api/v1/runs/{identity}/resume").status_code == 200
    Runner(identity, claim(identity)).run()
    assert auth.get(f"/api/v1/runs/{identity}").json()["status"] == "completed"
    assert calls == [1]


def test_multipart_wordlist_over_64kb_is_saved_and_preserved_on_edit(auth):
    import json

    words = [f"subdomain-{number:04d}" for number in range(12000)]
    content = ("\n".join(words) + "\n").encode()
    assert len(content) > 65536
    response = auth.post(
        "/api/v1/scans",
        data={"config": json.dumps({"name": "Uploaded list", "mode": "subdomain", "domain": "example.test"})},
        files={"wordlist": ("words.txt", content, "text/plain")},
    )
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["config"]["wordlist_filename"] == "words.txt"
    assert scan["config"]["subdomains"] == words
    response = auth.patch(f"/api/v1/scans/{scan['id']}", json={"name": "Renamed upload"})
    assert response.status_code == 200
    assert response.json()["config"]["subdomains"] == words
    response = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True})
    assert response.status_code == 202, response.text
    snapshot = response.json()["config_snapshot"]
    assert snapshot["wordlist_filename"] == "words.txt" and snapshot["subdomains"] == words
    replacement = auth.patch(
        f"/api/v1/scans/{scan['id']}",
        data={"config": json.dumps({"domain": "other.test"})},
        files={"wordlist": ("replacement.txt", b"api\r\nwww\r\napi\r\n", "text/plain")},
    )
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["config"]["subdomains"] == ["api", "www"]
    assert replacement.json()["config"]["wordlist_filename"] == "replacement.txt"
    # Replacing a definition's list must not change its existing run snapshot.
    assert auth.get(f"/api/v1/runs/{response.json()['id']}").json()["config_snapshot"] == snapshot


@pytest.mark.parametrize(
    "content,status",
    [
        (b"", 422),
        (b"../bad", 422),
        (b"\xff", 422),
        (b"a" * (3 * 1024 * 1024 + 1), 413),
    ],
)
def test_multipart_wordlist_validation(auth, content, status):
    import json

    response = auth.post(
        "/api/v1/scans",
        data={"config": json.dumps({"name": "Upload", "mode": "subdomain", "domain": "example.test"})},
        files={"wordlist": ("words.txt", content, "text/plain")},
    )
    assert response.status_code == status, response.text
    assert auth.get("/api/v1/scans").json()["total"] == 0


def test_multipart_upload_keeps_authentication_and_csrf(client, auth):
    import json

    auth.headers.pop("X-CSRF-Token")
    response = auth.post(
        "/api/v1/scans",
        data={"config": json.dumps({"name": "Upload", "mode": "subdomain", "domain": "example.test"})},
        files={"wordlist": ("words.txt", b"api", "text/plain")},
    )
    assert response.status_code == 403


def test_uploaded_wordlist_skips_invalid_rows_and_reports_line_numbers(auth, monkeypatch):
    import json
    import socket

    # Validate the reported domain locally; creating a scan must not query it.
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("No DNS during wordlist import"))
    content = (
        "# Sample list\r\n; comment\r\n// comment\r\n\r\nwww\r\n"
        "API.AMPLIFON.COM.\r\napi\r\n*.amplifon.com\r\n"
        "https://amplifon.com\r\n../invalid\r\n"
        "amplifon.com\r\ndev.api\r\n"
    )
    response = auth.post(
        "/api/v1/scans",
        data={"config": json.dumps({"name": "Import test", "mode": "subdomain", "domain": "amplifon.com"})},
        files={"wordlist": ("words.txt", content.encode(), "text/plain")},
    )
    assert response.status_code == 201, response.text
    config = response.json()["config"]
    assert config["domain"] == "amplifon.com"
    assert config["subdomains"] == ["www", "api", "dev.api"]
    report = config["wordlist_import"]
    assert report["skipped_invalid"] == 4
    assert report["skipped_comments"] == 3
    assert report["duplicates"] == 1
    assert report["examples"][0].startswith("Line 8:")
    assert "*.amplifon.com" in report["examples"][0]
    assert "Line 11:" in report["examples"][-1]


def test_all_invalid_uploaded_names_explain_the_problem(auth):
    import json

    response = auth.post(
        "/api/v1/scans",
        data={
            "config": json.dumps({"name": "Invalid import", "mode": "subdomain", "domain": "amplifon.com"})
        },
        files={"wordlist": ("words.txt", b"# comment\n*\nhttps://amplifon.com\n", "text/plain")},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["message"] == "Wordlist contains no valid subdomain names"
    assert "Line 2:" in error["details"][0]["message"]
    assert auth.get("/api/v1/scans").json()["total"] == 0


def test_manual_wordlist_error_identifies_the_invalid_row(auth):
    response = auth.post(
        "/api/v1/scans",
        json={"name": "Manual", "mode": "subdomain", "domain": "amplifon.com", "subdomains": ["www", "*"]},
    )
    assert response.status_code == 422
    assert "line 2" in response.json()["error"]["details"][0]["message"]


def test_dns_wordlist_accepts_underscores_and_hyphens_without_loosening_base_domains():
    from app.scope import import_wordlist

    words = ["c1_arvofgagit", "default._bimi", "computer-repairs-", "--wildcard"]
    config = ScanInput(name="DNS labels", mode="subdomain", domain="example.test", subdomains=words)
    assert config.subdomains == words
    imported, report = import_wordlist("\n".join(words) + "\npo\\197\\161ta", "example.test")
    assert imported == words and report.skipped_invalid == 1
    with pytest.raises(ValueError):
        ScanInput(name="Invalid base", mode="subdomain", domain="_bad.test", subdomains=["api"])
    assert scanners.parse_gobuster_dns(
        "Found: c1_arvofgagit.example.test [192.0.2.1]\n", "example.test", words
    ) == [{"hostname": "c1_arvofgagit.example.test", "addresses": ["192.0.2.1"]}]


def test_dns_stream_counts_negative_answers_without_storing_them():
    from app.scanners import GobusterDNSStream

    updates = []
    stream = GobusterDNSStream(
        "example.test", ["www", "api"], lambda count, row: updates.append((count, row))
    )
    stream.feed(b"\r\x1b[")
    stream.feed(b"2KMissed: www.example.test\n\r\x1b[2KFound: api.exam")
    assert updates == [(1, None)]
    stream.feed(b"ple.test [192.0.2.1,2001:db8::1]\n")
    assert updates[-1] == (2, {"hostname": "api.example.test", "addresses": ["192.0.2.1", "2001:db8::1"]})
    assert stream.finish() == [updates[-1][1]]
    stream.feed(b"Missed: www.example.test\n")
    assert len(updates) == 2


def test_dns_progress_and_results_are_visible_before_completion_and_survive_stop(auth, monkeypatch):
    _, identity = create_dns_run(auth)

    def dns(domain, words, timeout, tick, **options):
        options["on_update"](1, {"hostname": "api.example.test", "addresses": ["192.0.2.1"]})
        running = auth.get(f"/api/v1/runs/{identity}").json()
        assert running["status"] == "running"
        assert running["processed"] == 1 and running["total"] == 2
        assert running["counts"]["subdomains"] == 1
        rows = auth.get(f"/api/v1/runs/{identity}/subdomains").json()
        assert rows["total"] == 1 and rows["items"][0]["identity"] == "api.example.test"
        # Even a throttled negative progress update must be saved on stop.
        options["on_update"](2, None)
        assert auth.post(f"/api/v1/runs/{identity}/stop").status_code == 200
        tick(True)
        pytest.fail("Stop must interrupt the scanner")

    monkeypatch.setattr(scanners, "gobuster_dns", dns)
    Runner(identity, claim(identity)).run()
    stopped = auth.get(f"/api/v1/runs/{identity}").json()
    assert stopped["status"] == "stopped"
    assert stopped["processed"] == 2 and stopped["total"] == 2
    assert stopped["counts"]["subdomains"] == 1
    assert auth.get(f"/api/v1/runs/{identity}/subdomains").json()["total"] == 1


def test_dns_stream_rejects_out_of_scope_and_incomplete_output():
    from app.scanners import GobusterDNSStream

    stream = GobusterDNSStream("example.test", ["api"], lambda *a: None)
    with pytest.raises(ToolError, match="unapproved"):
        stream.feed(b"Missed: api.other.test\n")
    with pytest.raises(ToolError, match="every wordlist"):
        stream.finish()
