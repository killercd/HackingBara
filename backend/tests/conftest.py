import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["PUBLIC_ORIGIN"] = "http://testserver"
os.environ["SECURE_COOKIES"] = "false"
os.environ["SPRAY_DELAY_SECONDS"] = "0"
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as database
from app import pipeline
from app.config import settings
from app.db import Base, get_db
from app.main import app
from app.models import User
from app.security import hasher


@pytest.fixture
def db_factory(monkeypatch, tmp_path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(pipeline, "SessionLocal", factory)
    import app.tasks as tasks

    monkeypatch.setattr(tasks, "SessionLocal", factory)
    monkeypatch.setattr(tasks.execute_run, "delay", lambda *args: None)
    key = tmp_path / "key"
    key.write_bytes(Fernet.generate_key())
    monkeypatch.setattr(settings, "secret_key_file", str(key))
    monkeypatch.setattr(settings, "evidence_dir", tmp_path / "evidence")

    def dependency():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = dependency
    with factory() as db:
        db.add(User(username="operator", password_hash=hasher.hash("a-long-test-password")))
        db.commit()
    yield factory
    app.dependency_overrides.clear()
    engine.dispose()


@pytest.fixture
def client(db_factory):
    with TestClient(app, headers={"Origin": settings.public_origin}) as client:
        yield client


@pytest.fixture
def auth(client):
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "operator", "password": "a-long-test-password"}
        ).status_code
        == 200
    )
    client.headers["X-CSRF-Token"] = client.cookies["hb_csrf"]
    return client


@pytest.fixture
def scan(auth):
    response = auth.post(
        "/api/v1/scans", json={"name": "Local lab", "targets": ["192.0.2.1"], "ports": "22,80"}
    )
    assert response.status_code == 201, response.text
    return response.json()
