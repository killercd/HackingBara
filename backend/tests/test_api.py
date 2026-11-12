from datetime import timedelta

import pytest
from sqlalchemy import select

from app import models as m
from app.db import now


@pytest.mark.parametrize(
    "path",
    [
        "/scans",
        "/credentials",
        "/runs/anything",
        "/runs/anything/events",
        "/screenshots/anything/content",
        "/openapi.json",
        "/docs",
    ],
)
def test_requires_authentication(client, path):
    assert client.get("/api/v1" + path).status_code == 401


def test_login_csrf_logout(auth):
    token = auth.headers.pop("X-CSRF-Token")
    assert auth.post("/api/v1/scans", json={"name": "x", "targets": ["192.0.2.1"]}).status_code == 403
    auth.headers["X-CSRF-Token"] = token
    assert auth.post("/api/v1/auth/logout").status_code == 204
    assert auth.get("/api/v1/auth/me").status_code == 401


def test_expired_session(auth, db_factory):
    with db_factory() as db:
        session = db.scalar(select(m.Session))
        session.expires_at = now() - timedelta(seconds=1)
        db.commit()
    assert auth.get("/api/v1/scans").status_code == 401


def test_throttling_and_no_reflected_password(client):
    for _ in range(10):
        assert (
            client.post("/api/v1/auth/login", json={"username": "bad", "password": "secret"}).status_code
            == 401
        )
    assert (
        client.post("/api/v1/auth/login", json={"username": "bad", "password": "secret"}).status_code == 429
    )
    response = client.post("/api/v1/auth/login", json={"username": "x", "password": "q" * 1001})
    assert "q" * 100 not in response.text


def test_scan_crud_pagination(auth):
    for i in range(7):
        assert (
            auth.post("/api/v1/scans", json={"name": f"Lab {i}", "targets": [f"192.0.2.{i + 1}"]}).status_code
            == 201
        )
    data = auth.get("/api/v1/scans?page=2&page_size=3&sort_by=name&sort_order=asc").json()
    assert [x["name"] for x in data["items"]] == ["Lab 3", "Lab 4", "Lab 5"]
    assert data["total"] == 7 and data["total_pages"] == 3
    assert auth.get("/api/v1/scans?search=192.0.2.2").json()["total"] == 1
    assert auth.get("/api/v1/scans?page_size=101").status_code == 422
    identity = data["items"][0]["id"]
    assert auth.patch(f"/api/v1/scans/{identity}", json={"name": "Changed"}).status_code == 200
    assert auth.get(f"/api/v1/scans/{identity}").json()["name"] == "Changed"
    assert auth.delete(f"/api/v1/scans/{identity}").status_code == 204


def test_snapshots_and_state_conflicts(auth, scan):
    path = f"/api/v1/scans/{scan['id']}/runs"
    assert auth.post(path, json={"authorized_scope_confirmed": False}).status_code == 422
    run = auth.post(path, json={"authorized_scope_confirmed": True}).json()
    assert run["status"] == "queued"
    assert auth.post(path, json={"authorized_scope_confirmed": True}).status_code == 409
    assert auth.delete(f"/api/v1/scans/{scan['id']}").status_code == 409
    auth.patch(f"/api/v1/scans/{scan['id']}", json={"name": "New name"})
    assert auth.get(f"/api/v1/runs/{run['id']}").json()["config_snapshot"]["name"] == "Local lab"
    assert auth.post(f"/api/v1/runs/{run['id']}/pause").status_code == 409
    assert auth.post(f"/api/v1/runs/{run['id']}/stop").json()["status"] == "stopped"
    assert auth.post(f"/api/v1/runs/{run['id']}/resume").status_code == 409
    assert auth.delete(f"/api/v1/scans/{scan['id']}").status_code == 204
    assert auth.get(f"/api/v1/runs/{run['id']}").status_code == 404


def test_credential_encryption_and_serialization(auth, db_factory):
    response = auth.post(
        "/api/v1/credentials", json={"label": "Lab", "username": "user", "password": "super-secret"}
    )
    assert response.status_code == 201
    assert "super-secret" not in response.text and "encrypted_secret" not in response.text
    identity = response.json()["id"]
    with db_factory() as db:
        assert "super-secret" not in db.get(m.Credential, identity).encrypted_secret
    assert auth.get("/api/v1/credentials?sort_by=encrypted_secret").status_code == 422
    assert auth.patch(f"/api/v1/credentials/{identity}", json={"label": "Renamed"}).status_code == 200
    assert auth.delete(f"/api/v1/credentials/{identity}").status_code == 204


def test_all_run_collections_are_paginated(auth, scan):
    run = auth.post(f"/api/v1/scans/{scan['id']}/runs", json={"authorized_scope_confirmed": True}).json()
    from app.api import COLLECTIONS

    for collection in COLLECTIONS:
        response = auth.get(f"/api/v1/runs/{run['id']}/{collection}?page_size=1")
        assert response.status_code == 200, response.text
        assert set(response.json()) == {"items", "page", "page_size", "total", "total_pages"}


def test_successful_login_resets_failure_budget(client, db_factory):
    for _ in range(3):
        assert (
            client.post("/api/v1/auth/login", json={"username": "operator", "password": "wrong"}).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "operator", "password": "a-long-test-password"}
        ).status_code
        == 200
    )
    with db_factory() as db:
        assert db.scalar(select(m.LoginThrottle)).count == 0
