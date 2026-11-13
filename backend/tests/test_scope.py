import socket

import pytest

from app.scope import ScanInput, Scope, normalize_url, ports


@pytest.mark.parametrize("value", ["0", "65536", "80;id", "80,80", "90-80", "80-90,85", "-1", "1-65535"])
def test_invalid_ports(value):
    with pytest.raises(ValueError):
        ports(value)


def test_default_and_canonical_ports():
    assert ports("") == "1-1024"
    assert ports("443,22,80-81") == "22,80-81,443"


@pytest.mark.parametrize(
    "targets",
    [
        ["0.0.0.0/0"],
        ["192.0.2.1/24"],
        ["example.org"],
        ["192.0.2.0/30", "192.0.2.1"],
        ["::/0"],
        ["224.0.0.1"],
    ],
)
def test_invalid_targets(targets):
    with pytest.raises(ValueError):
        ScanInput(name="Test", targets=targets)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://u:p@example.org/",
        "http://example.org/#x",
        "http://example.org/\r\nx",
        "http://example.org\\@evil.org/",
        "http://example.org:0/",
    ],
)
def test_unsafe_urls(url):
    with pytest.raises(ValueError):
        normalize_url(url)


def test_url_normalization():
    assert normalize_url("HTTPS://EXAMPLE.ORG:443") == "https://example.org/"
    assert normalize_url("http://[2001:db8::1]:80/") == "http://[2001:db8::1]/"
    config = ScanInput(name=" Test ", targets=["192.0.2.1"], urls=["http://192.0.2.1", "http://192.0.2.1/"])
    assert config.urls == ["http://192.0.2.1/"]
    assert not config.password_spray


def test_scope_rejects_mixed_dns_and_rebinding(monkeypatch):
    scope = Scope(["192.0.2.0/24"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80)), (2, 1, 6, "", ("203.0.113.1", 80))],
    )
    with pytest.raises(ValueError, match="outside"):
        scope.resolve("http://lab.example/")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80))])
    assert scope.resolve("http://lab.example/")[0] == ["192.0.2.1"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 80))])
    with pytest.raises(ValueError):
        scope.resolve("http://lab.example/")


def test_explicit_credential_scope_required():
    with pytest.raises(ValueError):
        ScanInput(name="Test", targets=["192.0.2.1"], password_spray=True, credential_ids=["x"])


@pytest.mark.parametrize("targets", [None, []])
def test_urls_can_replace_explicit_ip_targets(targets, monkeypatch):
    from app.scope import prepare_run_config

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (2, 1, 6, "", ("192.0.2.1", 80)),
            (2, 1, 6, "", ("192.0.2.1", 80)),
            (10, 1, 6, "", ("2001:db8::1", 80)),
        ],
    )
    data = {"name": "URL only", "urls": ["https://lab.example/", "https://lab.example/path"]}
    if targets is not None:
        data["targets"] = targets
    definition = ScanInput.model_validate(data)
    snapshot = prepare_run_config(definition)
    assert definition.targets == []
    assert snapshot.targets == ["192.0.2.1", "2001:db8::1"]
    assert snapshot.urls == definition.urls
    assert snapshot.ports == "1-1024"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 80))])
    with pytest.raises(ValueError, match="outside"):
        Scope(snapshot.targets).resolve(snapshot.urls[0])


def test_no_targets_and_no_urls_is_invalid():
    with pytest.raises(ValueError, match="at least one"):
        ScanInput(name="Empty")


def test_url_only_literal_ips_need_no_dns(monkeypatch):
    from app.scope import prepare_run_config

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("Literal URLs require no DNS"))
    config = prepare_run_config(
        ScanInput(name="Literal", urls=["http://192.0.2.1:8080/", "https://[2001:db8::1]/"])
    )
    assert config.targets == ["192.0.2.1", "2001:db8::1"]


def test_url_only_resolution_obeys_target_limit(monkeypatch):
    from app.config import settings
    from app.scope import prepare_run_config

    monkeypatch.setattr(settings, "max_targets", 1)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80)), (2, 1, 6, "", ("192.0.2.2", 80))],
    )
    with pytest.raises(ValueError, match="administrator limit"):
        prepare_run_config(ScanInput(name="Limit", urls=["http://lab.example/"]))


@pytest.mark.parametrize("address", ["0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1"])
def test_url_only_rejects_unsupported_dns_addresses(address, monkeypatch):
    from app.scope import prepare_run_config

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", (address, 80))])
    with pytest.raises(ValueError, match="unsupported"):
        prepare_run_config(ScanInput(name="Unsafe", urls=["http://lab.example/"]))


@pytest.mark.parametrize("error", [socket.EAI_AGAIN, socket.EAI_NONAME])
def test_dns_diagnostics_distinguish_temporary_failure(error, monkeypatch):
    from app.scope import ScopePreparationError, prepare_run_config

    def resolve(*args, **kwargs):
        raise socket.gaierror(error, "Untrusted resolver detail")

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(ScopePreparationError) as caught:
        prepare_run_config(ScanInput(name="DNS diagnostics", urls=["https://missing.example/"]))
    message = caught.value.issues[0]["message"]
    assert ("temporarily unavailable" in message) == (error == socket.EAI_AGAIN)
    assert "Untrusted resolver detail" not in message


def test_network_targets_accept_hostnames_without_schemes(monkeypatch):
    from app.scope import prepare_run_config

    config = ScanInput(
        name="Names", urls=["LAB.EXAMPLE", "lab.example/", "lab.example:8080/path", "lab.example:443/login"]
    )
    assert config.hostnames == ["lab.example"]
    assert config.urls == ["http://lab.example:8080/path", "https://lab.example/login"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 80))])
    prepared = prepare_run_config(config)
    assert prepared.targets == ["192.0.2.1"]
    assert prepared.hostnames == ["lab.example"]
    assert config.targets == []


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "//evil.example",
        "user:secret@example.test",
        "example.test/#fragment",
        "example.test\\@evil.example",
        "example.test:0",
    ],
)
def test_schemeless_input_does_not_accept_unsafe_urls(target):
    with pytest.raises(ValueError):
        ScanInput(name="Unsafe", urls=[target])


def test_hostname_targets_cannot_expand_explicit_scope(monkeypatch):
    from app.scope import prepare_run_config

    config = ScanInput(name="Restricted", targets=["192.0.2.1"], urls=["lab.example"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 80))])
    with pytest.raises(ValueError, match="outside"):
        prepare_run_config(config)


def test_screenshot_scope_uses_observed_address_and_rejects_rebinding(monkeypatch):
    from app.scope import EndpointScope

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 8080)), (2, 1, 6, "", ("192.0.2.2", 8080))],
    )
    scope = EndpointScope(Scope(["192.0.2.1", "192.0.2.2"]), "192.0.2.2")
    assert scope.resolve("http://web.example:8080/") == (["192.0.2.2"], 8080)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.1", 8080))])
    with pytest.raises(ValueError, match="observed address"):
        scope.resolve("http://web.example:8080/")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("203.0.113.1", 8080))])
    with pytest.raises(ValueError, match="outside"):
        scope.resolve("http://web.example:8080/")
