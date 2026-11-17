from sqlalchemy import select
from test_pipeline import fake_tools, launch  # noqa: F401, F811

from app import models as m
from app import pipeline
from app.security import cipher


def list_scan(auth):
    response = auth.post(
        "/api/v1/scans",
        json={
            "name": "User/password lists",
            "targets": ["192.0.2.1"],
            "ports": "80",
            "password_spray": True,
            "hydra_usernames": ["bob", "alice"],
            "hydra_passwords": ["z-first-secret", "a-second-secret"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_list_pairs_are_encrypted_and_auto_detected(auth, db_factory):
    scan = list_scan(auth)
    config = scan["config"]
    assert config["credential_auto_detect"] is True
    assert config["credential_services"] == [] and config["credential_endpoints"] == []
    assert config["hydra_usernames"] == ["bob", "alice"] and config["hydra_password_count"] == 2
    assert "hydra_passwords" not in config and "z-first-secret" not in str(scan)
    assert len(config["credential_ids"]) == 4
    assert auth.get("/api/v1/credentials").json()["total"] == 0
    with db_factory() as db:
        rows = db.scalars(select(m.Credential)).all()
        assert len(rows) == 4 and all(row.generated for row in rows)
        assert {(row.username, cipher().decrypt(row.encrypted_secret.encode()).decode()) for row in rows} == {
            ("bob", "z-first-secret"),
            ("alice", "z-first-secret"),
            ("bob", "a-second-secret"),
            ("alice", "a-second-secret"),
        }
        assert all("secret" not in row.encrypted_secret for row in rows)


def test_list_execution_preserves_order_and_historic_secrets(auth, db_factory, fake_tools, monkeypatch):  # noqa: F811
    scan = list_scan(auth)
    identity = launch(auth, scan)
    old_ids = scan["config"]["credential_ids"]
    updated = auth.patch(f"/api/v1/scans/{scan['id']}", json={"hydra_passwords": ["replacement-secret"]})
    assert updated.status_code == 200, updated.text
    assert set(updated.json()["config"]["credential_ids"]).isdisjoint(old_ids)
    calls = []

    def attempt(scope, url, username, password, tick):
        calls.append((password, username))
        return "failed", "Lab rejection"

    monkeypatch.setattr(pipeline, "basic_auth", attempt)
    pipeline.Runner(identity, pipeline.claim(identity)).run()
    assert calls == [
        ("z-first-secret", "bob"),
        ("z-first-secret", "alice"),
        ("a-second-secret", "bob"),
        ("a-second-secret", "alice"),
    ]
    run = auth.get(f"/api/v1/runs/{identity}").json()
    assert run["status"] == "completed"
    assert "z-first-secret" not in str(run) and "hydra_passwords" not in run["config_snapshot"]
    rows = auth.get(f"/api/v1/runs/{identity}/credentials").json()["items"]
    assert {row["credential_label"] for row in rows} == {"Hydra password #1", "Hydra password #2"}
    assert "a-second-secret" not in str(rows)
    assert auth.delete(f"/api/v1/scans/{scan['id']}").status_code == 204
    with db_factory() as db:
        assert db.scalars(select(m.Credential).where(m.Credential.generated.is_(True))).all() == []


def test_edit_retains_passwords_without_returning_them(auth):
    scan = list_scan(auth)
    original = scan["config"]["credential_ids"]
    updated = auth.patch(
        f"/api/v1/scans/{scan['id']}", json={"description": "Edited", "hydra_passwords": None}
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["config"]["credential_ids"] == original
    assert updated.json()["config"]["hydra_password_count"] == 2
    assert "z-first-secret" not in updated.text
    changed_users = auth.patch(f"/api/v1/scans/{scan['id']}", json={"hydra_usernames": ["carol"]})
    assert changed_users.status_code == 200
    assert len(changed_users.json()["config"]["credential_ids"]) == 2


def test_list_validation_does_not_echo_passwords(auth):
    response = auth.post(
        "/api/v1/scans",
        json={
            "name": "Bad list",
            "targets": ["192.0.2.1"],
            "password_spray": True,
            "hydra_usernames": ["alice"],
            "hydra_passwords": ["secret\nextra"],
        },
    )
    assert response.status_code == 422
    assert "secret" not in response.text and "extra" not in response.text


def test_auto_credentials_stay_on_selected_scan_ports(auth, db_factory, fake_tools, monkeypatch):  # noqa: F811
    scan = list_scan(auth)
    assert (
        auth.patch(f"/api/v1/scans/{scan['id']}", json={"urls": ["http://192.0.2.1:8080/"]}).status_code
        == 200
    )
    calls = []
    monkeypatch.setattr(
        pipeline, "basic_auth", lambda scope, url, *args: calls.append(url) or ("failed", "Lab rejection")
    )
    identity = launch(auth, scan)
    pipeline.Runner(identity, pipeline.claim(identity)).run()
    assert set(calls) == {"http://192.0.2.1/"}
