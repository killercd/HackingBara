import uuid

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, now

J = JSON().with_variant(JSONB(), "postgresql")
ACTIVE = ("queued", "running", "pausing", "paused", "stopping")


class Entity:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[object] = mapped_column(DateTime, default=now, index=True)


class User(Entity, Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    last_login_at: Mapped[object | None] = mapped_column(DateTime)


class Session(Entity, Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[object] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[object | None] = mapped_column(DateTime)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    reset_at: Mapped[object] = mapped_column(DateTime)


class Credential(Entity, Base):
    __tablename__ = "credentials"
    label: Mapped[str] = mapped_column(String(200))
    username: Mapped[str] = mapped_column(String(200))
    encrypted_secret: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[object] = mapped_column(DateTime, default=now, onupdate=now)


class Scan(Entity, Base):
    __tablename__ = "scan_definitions"
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    config: Mapped[dict] = mapped_column(J)
    target_summary: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[object] = mapped_column(DateTime, default=now, onupdate=now, index=True)
    last_run_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    last_status: Mapped[str] = mapped_column(String(32), default="never")


class ScanCredential(Base):
    __tablename__ = "scan_credentials"
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scan_definitions.id", ondelete="CASCADE"), primary_key=True
    )
    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.id", ondelete="RESTRICT"), primary_key=True
    )


class Run(Entity, Base):
    __tablename__ = "scan_runs"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scan_definitions.id", ondelete="CASCADE"), index=True)
    config_snapshot: Mapped[dict] = mapped_column(J)
    initiated_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    current_stage: Mapped[str] = mapped_column(String(64), default="scope")
    processed: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    counts: Mapped[dict] = mapped_column(J, default=dict)
    started_at: Mapped[object | None] = mapped_column(DateTime)
    ended_at: Mapped[object | None] = mapped_column(DateTime)
    heartbeat_at: Mapped[object | None] = mapped_column(DateTime, index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(36))
    error_summary: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (
        Index(
            "one_active_run_per_scan",
            "scan_id",
            unique=True,
            postgresql_where=text("status IN ('queued','running','pausing','paused','stopping')"),
            sqlite_where=text("status IN ('queued','running','pausing','paused','stopping')"),
        ),
    )


class RunCredential(Base):
    __tablename__ = "run_credentials"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), primary_key=True)
    credential_id: Mapped[str] = mapped_column(
        ForeignKey("credentials.id", ondelete="RESTRICT"), primary_key=True
    )


class RunTarget(Entity, Base):
    __tablename__ = "run_targets"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    identity: Mapped[str] = mapped_column(String(2048))
    target_type: Mapped[str] = mapped_column(String(16), default="ip")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    __table_args__ = (UniqueConstraint("run_id", "identity"),)


class Host(Entity, Base):
    __tablename__ = "hosts"
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(253))
    last_seen_at: Mapped[object] = mapped_column(DateTime, default=now)


class RunHost(Entity, Base):
    __tablename__ = "run_hosts"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    source: Mapped[str] = mapped_column(String(64), default="rustscan")
    status: Mapped[str] = mapped_column(String(32), default="new")
    last_seen_at: Mapped[object] = mapped_column(DateTime, default=now)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    services: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("run_id", "host_id"),)


class Service(Entity, Base):
    __tablename__ = "services"
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"))
    port: Mapped[int] = mapped_column(Integer)
    transport: Mapped[str] = mapped_column(String(8), default="tcp")
    last_seen_at: Mapped[object] = mapped_column(DateTime, default=now)
    __table_args__ = (UniqueConstraint("host_id", "port", "transport"),)


class ServiceObservation(Entity, Base):
    __tablename__ = "service_observations"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    transport: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(32), default="open")
    name: Mapped[str] = mapped_column(String(200), default="unknown", index=True)
    product: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[str] = mapped_column(Text, default="")
    banner: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict] = mapped_column(J, default=dict)
    change: Mapped[str] = mapped_column(String(32), default="new")
    __table_args__ = (UniqueConstraint("run_id", "service_id"),)


class Endpoint(Entity, Base):
    __tablename__ = "web_endpoints"
    url: Mapped[str] = mapped_column(String(2048), unique=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id"))
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"))
    last_seen_at: Mapped[object] = mapped_column(DateTime, default=now)


class EndpointObservation(Entity, Base):
    __tablename__ = "endpoint_observations"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("web_endpoints.id"))
    url: Mapped[str] = mapped_column(String(2048))
    ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="discovered")
    details: Mapped[dict] = mapped_column(J, default=dict)
    __table_args__ = (UniqueConstraint("run_id", "endpoint_id"),)


class Attempt(Entity, Base):
    __tablename__ = "credential_attempts"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[str | None] = mapped_column(ForeignKey("services.id"))
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("web_endpoints.id"))
    credential_id: Mapped[str] = mapped_column(ForeignKey("credentials.id", ondelete="RESTRICT"))
    username: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(32), default="not_attempted", index=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    attempted_at: Mapped[object | None] = mapped_column(DateTime)
    __table_args__ = (UniqueConstraint("run_id", "endpoint_id", "credential_id"),)


class Screenshot(Entity, Base):
    __tablename__ = "screenshots"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("web_endpoints.id"))
    url: Mapped[str] = mapped_column(String(2048))
    path: Mapped[str | None] = mapped_column(Text)
    thumbnail_path: Mapped[str | None] = mapped_column(Text)
    mime: Mapped[str] = mapped_column(String(32), default="image/png")
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
    captured_at: Mapped[object | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    error: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("run_id", "endpoint_id"),)


class Event(Entity, Base):
    __tablename__ = "scan_events"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(64))
    level: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(J, default=dict)
    __table_args__ = (Index("events_run_level_created", "run_id", "level", "created_at"),)


class Checkpoint(Entity, Base):
    __tablename__ = "scan_checkpoints"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(64))
    target_key: Mapped[str] = mapped_column(String(2048))
    state: Mapped[str] = mapped_column(String(32), default="done")
    updated_at: Mapped[object] = mapped_column(DateTime, default=now, onupdate=now)
    __table_args__ = (UniqueConstraint("run_id", "stage", "target_key"),)


class Finding(Entity, Base):
    __tablename__ = "findings"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    identity: Mapped[str] = mapped_column(String(2048))
    kind: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), default="info")
    evidence: Mapped[dict] = mapped_column(J, default=dict)
    source: Mapped[str | None] = mapped_column(String(200))
    published_at: Mapped[object | None] = mapped_column(DateTime)
    updated_at: Mapped[object] = mapped_column(DateTime, default=now, onupdate=now)
    __table_args__ = (UniqueConstraint("run_id", "kind", "identity"),)


class FollowUp(Entity, Base):
    __tablename__ = "follow_up_candidates"
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(2048))
    reason: Mapped[str] = mapped_column(Text)
    approval_status: Mapped[str] = mapped_column(String(32), default="pending")
