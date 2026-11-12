import time
import uuid
from collections import defaultdict
from urllib.parse import urlsplit

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from . import models as m
from . import scanners
from .capture import capture
from .config import settings
from .db import SessionLocal, now
from .network import basic_auth
from .scope import ScanInput, Scope, normalize_url
from .security import cipher

TERMINAL = ("completed", "failed", "stopped")


def get_or_create(db, model, defaults=None, **identity):
    item = db.scalar(select(model).filter_by(**identity))
    if item is None:
        try:
            with db.begin_nested():
                item = model(**identity, **(defaults or {}))
                db.add(item)
                db.flush()
        except IntegrityError:
            item = db.scalar(select(model).filter_by(**identity))
            if item is None:
                raise
    return item


def event(db, run, kind, message, level="info", details=None):
    db.add(
        m.Event(
            run_id=run.id,
            stage=run.current_stage,
            event_type=kind,
            message=message,
            level=level,
            details=details or {},
        )
    )


def finding(db, run, kind, identity, evidence):
    return get_or_create(
        db, m.Finding, run_id=run.id, kind=kind, identity=identity, defaults={"evidence": evidence}
    )


def spray_order(credentials):
    # Approved pairs only. Never manufacture the Cartesian product of accounts and secrets.
    groups = defaultdict(list)
    for credential in credentials:
        groups[cipher().decrypt(credential.encrypted_secret.encode()).decode()].append(credential)
    return [
        (credential, password)
        for password in sorted(groups)
        for credential in sorted(groups[password], key=lambda c: (c.username, c.id))
    ]


class Runner:
    def __init__(self, run_id, owner):
        self.run_id, self.owner = run_id, owner
        self.last_tick = 0
        self.secret_values = []

    def redact(self, value):
        if isinstance(value, dict):
            return {key: self.redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            for secret in self.secret_values:
                value = value.replace(secret, "[REDACTED]")
        return value

    def tick(self, force=False):
        if not force and time.monotonic() - self.last_tick < 0.5:
            return
        with SessionLocal() as db:
            run = db.scalar(select(m.Run).where(m.Run.id == self.run_id).with_for_update())
            if not run or run.lease_owner != self.owner or run.status not in ("running", "pausing"):
                raise scanners.Interrupted()
            # Pause waits for the current subprocess; stop cancels it immediately.
            run.heartbeat_at = now()
            db.commit()
        self.last_tick = time.monotonic()

    def boundary(self, db, run, stage):
        self.tick(True)
        db.refresh(run)
        if run.status == "pausing":
            run.status, run.lease_owner = "paused", None
            db.get(m.Scan, run.scan_id).last_status = "paused"
            event(db, run, "paused", "Paused at a persisted stage boundary")
            db.commit()
            raise scanners.Interrupted()
        run.current_stage = stage
        db.commit()

    def wait(self, seconds):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            self.tick()
            time.sleep(min(0.2, max(0, until - time.monotonic())))

    def checkpoint(self, db, run, stage, key):
        return (
            db.scalar(
                select(m.Checkpoint.id).where(
                    m.Checkpoint.run_id == run.id, m.Checkpoint.stage == stage, m.Checkpoint.target_key == key
                )
            )
            is not None
        )

    def done(self, db, run, stage, key):
        get_or_create(db, m.Checkpoint, run_id=run.id, stage=stage, target_key=key)
        db.commit()
        self.summarize(db, run)

    def error(self, db, run, key, exc):
        # Exceptions from adapters may include response data or secrets; record type only.
        message = f"{key}: {type(exc).__name__}; stage item failed"
        event(db, run, "scanner_error", message, "error", self.redact(getattr(exc, "metadata", {})))
        finding(db, run, "scanner_error", f"{run.current_stage}:{key}", {"message": message})
        db.commit()

    def tool_event(self, db, run, result, argv):
        event(
            db,
            run,
            "tool_finished",
            "Scanner completed",
            details={
                "argv": argv,
                "exit_code": result.exit_code,
                "duration_seconds": result.duration,
                "stderr": self.redact(result.stderr[:2000]),
                "tool_version": result.version,
            },
        )

    def persist_ports(self, db, run, ip, discovered):
        if not discovered:
            return
        host = db.scalar(select(m.Host).where(m.Host.ip == ip))
        new = host is None
        host = get_or_create(db, m.Host, ip=ip)
        host.last_seen_at = now()
        runhost = get_or_create(
            db,
            m.RunHost,
            run_id=run.id,
            host_id=host.id,
            defaults={"ip": ip, "status": "new" if new else "unchanged"},
        )
        runhost.open_ports = len(discovered)
        if new:
            finding(db, run, "new_host", ip, {"ip": ip})
            get_or_create(
                db,
                m.FollowUp,
                run_id=run.id,
                kind="host",
                target=ip,
                defaults={"reason": "New host observed; follow-up requires approval"},
            )
        for port in discovered:
            old = db.scalar(
                select(m.Service).where(
                    m.Service.host_id == host.id, m.Service.port == port, m.Service.transport == "tcp"
                )
            )
            service = get_or_create(db, m.Service, host_id=host.id, port=port, transport="tcp")
            service.last_seen_at = now()
            get_or_create(
                db,
                m.ServiceObservation,
                run_id=run.id,
                service_id=service.id,
                defaults={"ip": ip, "port": port, "change": "new" if old is None else "unchanged"},
            )
            if old is None:
                finding(db, run, "new_port", f"{ip}:{port}/tcp", {"ip": ip, "port": port})
        db.commit()

    def enumerate(self, db, run, ip, discovered, timeout):
        observations, result, argv = scanners.nmap(ip, discovered, timeout, self.tick)
        if result:
            self.tool_event(db, run, result, argv)
        for data in observations:
            for field in ("name", "product", "version", "banner", "details"):
                data[field] = self.redact(data[field])
            row = db.scalar(
                select(m.ServiceObservation).where(
                    m.ServiceObservation.run_id == run.id,
                    m.ServiceObservation.ip == ip,
                    m.ServiceObservation.port == data["port"],
                )
            )
            previous = db.scalar(
                select(m.ServiceObservation)
                .where(
                    m.ServiceObservation.service_id == row.service_id,
                    m.ServiceObservation.run_id != run.id,
                    m.ServiceObservation.state == "open",
                )
                .order_by(m.ServiceObservation.created_at.desc())
                .limit(1)
            )
            if previous:
                fields = ("name", "product", "version", "banner", "details")
                row.change = (
                    "changed" if any(getattr(previous, f) != data[f] for f in fields) else "unchanged"
                )
            for key, value in data.items():
                setattr(row, key, value)
            if row.change in ("new", "changed"):
                finding(
                    db,
                    run,
                    f"{row.change}_service",
                    row.service_id,
                    {
                        "ip": ip,
                        "port": row.port,
                        "name": row.name,
                        "product": row.product,
                        "version": row.version,
                    },
                )
        host = db.scalar(select(m.RunHost).where(m.RunHost.run_id == run.id, m.RunHost.ip == ip))
        if host:
            host.services = len(observations)
        db.commit()

    def endpoints(self, db, run, config, scope):
        urls = {u: ("explicit", None) for u in config.urls}
        for service in db.scalars(select(m.ServiceObservation).where(m.ServiceObservation.run_id == run.id)):
            if "http" not in service.name:
                continue
            scheme = "https" if service.details.get("tunnel") == "ssl" or "https" in service.name else "http"
            host = f"[{service.ip}]" if ":" in service.ip else service.ip
            url = normalize_url(f"{scheme}://{host}:{service.port}/")
            urls.setdefault(url, ("nmap", service.service_id))
        for url, (source, service_id) in urls.items():
            self.boundary(db, run, "endpoints")
            if self.checkpoint(db, run, "endpoints", url):
                continue
            try:
                addresses, port = scope.resolve(url)
                endpoint = get_or_create(db, m.Endpoint, url=url, defaults={"service_id": service_id})
                endpoint.last_seen_at = now()
                get_or_create(
                    db,
                    m.EndpointObservation,
                    run_id=run.id,
                    endpoint_id=endpoint.id,
                    defaults={"url": url, "ip": addresses[0], "port": port, "source": source},
                )
            except (ValueError, OSError) as exc:
                self.error(db, run, "Endpoint scope rejected", exc)
            self.done(db, run, "endpoints", url)

    def credentials(self, db, run, config, scope):
        if not config.password_spray:
            return
        approved = db.scalars(select(m.Credential).where(m.Credential.id.in_(config.credential_ids))).all()
        if len(approved) > settings.max_credentials:
            raise ValueError("Credential limit exceeded")
        # Precreate durable intentions: an interrupted network attempt becomes unknown, never retried.
        endpoints = db.scalars(
            select(m.EndpointObservation).where(
                m.EndpointObservation.run_id == run.id,
                m.EndpointObservation.url.in_(config.credential_endpoints),
                m.EndpointObservation.status != "error",
            )
        ).all()
        for endpoint in endpoints:
            for cred in approved:
                get_or_create(
                    db,
                    m.Attempt,
                    run_id=run.id,
                    endpoint_id=endpoint.endpoint_id,
                    credential_id=cred.id,
                    defaults={
                        "url": endpoint.url,
                        "username": cred.username,
                        "service_id": db.get(m.Endpoint, endpoint.endpoint_id).service_id,
                    },
                )
        db.commit()
        # Derive budgets from persisted attempts, including unknown outcomes after a crash.
        attempts = db.scalars(select(m.Attempt).where(m.Attempt.run_id == run.id)).all()
        accounts = defaultdict(int)
        services = defaultdict(int)
        blocked = set()
        for a in attempts:
            if a.attempted_at:
                accounts[a.username] += 1
                services[urlsplit(a.url).netloc] += 1
            if a.status in ("blocked", "unknown"):
                blocked.add(urlsplit(a.url).netloc)
        # Password-first across all approved services; each account gets only its approved pairs.
        for cred, password in spray_order(approved):
            for endpoint in endpoints:
                self.boundary(db, run, "credentials")
                a = db.scalar(
                    select(m.Attempt).filter_by(
                        run_id=run.id, endpoint_id=endpoint.endpoint_id, credential_id=cred.id
                    )
                )
                if a.status != "not_attempted":
                    continue
                if (
                    urlsplit(endpoint.url).netloc in blocked
                    or accounts[a.username] >= settings.spray_account_budget
                    or services[urlsplit(a.url).netloc] >= settings.spray_service_budget
                ):
                    a.evidence = "Skipped by defensive response or attempt budget"
                    db.commit()
                    continue
                # Always wait before each attempt, including the first after resume/recovery.
                self.wait(settings.spray_delay_seconds)
                self.boundary(db, run, "credentials")
                a.status, a.attempted_at = "unknown", now()
                a.evidence = "Attempt started; outcome unknown until confirmed"
                db.commit()
                accounts[a.username] += 1
                services[urlsplit(a.url).netloc] += 1
                try:
                    a.status, a.evidence = basic_auth(scope, endpoint.url, cred.username, password)
                except Exception:
                    a.status, a.evidence = "unknown", "Connection or TLS validation error; no retry"
                if a.status in ("blocked", "unknown"):
                    blocked.add(urlsplit(a.url).netloc)
                if a.status == "successful":
                    finding(
                        db,
                        run,
                        "credential_success",
                        a.id,
                        {"credential_id": cred.id, "username": cred.username, "url": endpoint.url},
                    )
                    get_or_create(
                        db,
                        m.FollowUp,
                        run_id=run.id,
                        kind="credential",
                        target=cred.id,
                        defaults={"reason": "Verified credential; no automatic reuse"},
                    )
                event(db, run, "credential_validation", f"Approved credential validation outcome: {a.status}")
                db.commit()
                self.summarize(db, run)

    def screenshots(self, db, run, config, scope):
        if not config.screenshots:
            return
        for endpoint in db.scalars(
            select(m.EndpointObservation).where(
                m.EndpointObservation.run_id == run.id, m.EndpointObservation.status != "error"
            )
        ):
            self.boundary(db, run, "screenshots")
            if self.checkpoint(db, run, "screenshots", endpoint.id):
                continue
            shot = get_or_create(
                db,
                m.Screenshot,
                run_id=run.id,
                endpoint_id=endpoint.endpoint_id,
                defaults={"url": endpoint.url},
            )
            db.commit()
            try:
                shot.path, shot.thumbnail_path, shot.width, shot.height = capture(
                    scope, endpoint.url, run.id, shot.id, self.tick
                )
                shot.status, shot.captured_at = "captured", now()
                endpoint.status = "captured"
                finding(db, run, "screenshot", shot.id, {"url": endpoint.url, "screenshot_id": shot.id})
            except scanners.Interrupted:
                raise
            except Exception as exc:
                shot.status, shot.error = "error", "Screenshot capture failed; see stage events"
                endpoint.status = "error"
                self.error(db, run, "Screenshot", exc)
            self.done(db, run, "screenshots", endpoint.id)

    def consolidate(self, db, run):
        # Compare to the previous completed run of this definition, not another scan's scope.
        previous = db.scalar(
            select(m.Run)
            .where(m.Run.scan_id == run.scan_id, m.Run.status == "completed", m.Run.id != run.id)
            .order_by(m.Run.created_at.desc())
            .limit(1)
        )
        if previous:
            seen_services = set(
                db.scalars(
                    select(m.ServiceObservation.service_id).where(
                        m.ServiceObservation.run_id == run.id, m.ServiceObservation.state == "open"
                    )
                )
            )
            for old in db.scalars(
                select(m.ServiceObservation).where(
                    m.ServiceObservation.run_id == previous.id, m.ServiceObservation.state == "open"
                )
            ):
                if old.service_id not in seen_services:
                    get_or_create(
                        db,
                        m.ServiceObservation,
                        run_id=run.id,
                        service_id=old.service_id,
                        defaults={
                            "ip": old.ip,
                            "port": old.port,
                            "transport": old.transport,
                            "state": "no-longer-observed",
                            "change": "no-longer-observed",
                        },
                    )
                    finding(db, run, "no_longer_observed", old.service_id, {"ip": old.ip, "port": old.port})
            seen_hosts = set(db.scalars(select(m.RunHost.host_id).where(m.RunHost.run_id == run.id)))
            for old in db.scalars(select(m.RunHost).where(m.RunHost.run_id == previous.id)):
                if old.host_id not in seen_hosts:
                    get_or_create(
                        db,
                        m.RunHost,
                        run_id=run.id,
                        host_id=old.host_id,
                        defaults={"ip": old.ip, "status": "no-longer-observed"},
                    )
        db.commit()

    def run(self):
        with SessionLocal() as db:
            run = db.get(m.Run, self.run_id)
            config = ScanInput.model_validate(run.config_snapshot)
            scope = Scope(config.targets)
            selected = db.scalars(
                select(m.Credential).where(m.Credential.id.in_(config.credential_ids))
            ).all()
            self.secret_values = [cipher().decrypt(c.encrypted_secret.encode()).decode() for c in selected]
            try:
                self.boundary(db, run, "scope")
                for address in scope.addresses():
                    get_or_create(db, m.RunTarget, run_id=run.id, identity=address)
                db.commit()
                for target in db.scalars(
                    select(m.RunTarget).where(m.RunTarget.run_id == run.id).order_by(m.RunTarget.identity)
                ):
                    address = target.identity
                    self.boundary(db, run, "discovery")
                    if not scope.allows(address):
                        raise ValueError("Target outside scope")
                    if not self.checkpoint(db, run, "discovery", address):
                        try:
                            found, result, argv = scanners.rustscan(
                                address, config.ports, config.timeout, self.tick
                            )
                            self.tool_event(db, run, result, argv)
                            self.persist_ports(db, run, address, found)
                            target.status = "discovered"
                        except scanners.Interrupted:
                            raise
                        except Exception as exc:
                            target.status = "error"
                            self.error(db, run, address, exc)
                        self.done(db, run, "discovery", address)
                    self.boundary(db, run, "enumeration")
                    if not self.checkpoint(db, run, "enumeration", address):
                        discovered = db.scalars(
                            select(m.ServiceObservation.port).where(
                                m.ServiceObservation.run_id == run.id, m.ServiceObservation.ip == address
                            )
                        ).all()
                        try:
                            self.enumerate(db, run, address, discovered, config.timeout)
                            if target.status != "error":
                                target.status = "completed"
                        except scanners.Interrupted:
                            raise
                        except Exception as exc:
                            target.status = "error"
                            self.error(db, run, address, exc)
                        self.done(db, run, "enumeration", address)
                    run.processed = db.scalar(
                        select(func.count())
                        .select_from(m.Checkpoint)
                        .where(m.Checkpoint.run_id == run.id, m.Checkpoint.stage == "enumeration")
                    )
                    db.commit()
                    self.summarize(db, run)
                self.endpoints(db, run, config, scope)
                self.credentials(db, run, config, scope)
                self.screenshots(db, run, config, scope)
                self.boundary(db, run, "consolidation")
                self.consolidate(db, run)
                self.tick(True)
                db.refresh(run, with_for_update=True)
                if run.lease_owner != self.owner or run.status == "stopping":
                    raise scanners.Interrupted()
                if run.status == "pausing":
                    run.status, run.lease_owner = "paused", None
                    db.get(m.Scan, run.scan_id).last_status = "paused"
                    event(db, run, "paused", "Paused after consolidation")
                    db.commit()
                    raise scanners.Interrupted()
                run.status, run.ended_at, run.lease_owner = "completed", now(), None
                db.get(m.Scan, run.scan_id).last_status = "completed"
                event(db, run, "completed", "Run completed; individual item errors remain in results")
                self.summarize(db, run)
                db.commit()
            except scanners.Interrupted:
                db.rollback()
                db.refresh(run)
                if run.lease_owner == self.owner and run.status == "stopping":
                    run.status, run.ended_at, run.lease_owner = "stopped", now(), None
                    db.get(m.Scan, run.scan_id).last_status = "stopped"
                    for target in db.scalars(
                        select(m.RunTarget).where(
                            m.RunTarget.run_id == run.id, m.RunTarget.status.notin_(("completed", "error"))
                        )
                    ):
                        target.status = "interrupted"
                    event(db, run, "stopped", "Scanner process groups terminated; partial results preserved")
                    self.summarize(db, run)
                    db.commit()
            except Exception as exc:
                db.rollback()
                db.refresh(run)
                if run.lease_owner == self.owner:
                    run.status, run.ended_at, run.lease_owner = "failed", now(), None
                    run.error_summary = f"Execution failed: {type(exc).__name__}"
                    db.get(m.Scan, run.scan_id).last_status = "failed"
                    event(db, run, "failed", run.error_summary, "error")
                    self.summarize(db, run)
                    db.commit()

    @staticmethod
    def summarize(db, run):
        counts = {}
        for name, model in (
            ("hosts", m.RunHost),
            ("open_ports", m.ServiceObservation),
            ("services", m.ServiceObservation),
            ("endpoints", m.EndpointObservation),
            ("credentials", m.Attempt),
            ("screenshots", m.Screenshot),
            ("findings", m.Finding),
            ("errors", m.Event),
        ):
            query = select(func.count()).select_from(model).where(model.run_id == run.id)
            if name == "credentials":
                query = query.where(m.Attempt.status == "successful")
            elif name == "screenshots":
                query = query.where(m.Screenshot.status == "captured")
            elif name == "errors":
                query = query.where(m.Event.level == "error")
            elif name in ("services", "open_ports"):
                query = query.where(m.ServiceObservation.state == "open")
                if name == "services":
                    query = query.where(m.ServiceObservation.name != "unknown")
            elif name == "hosts":
                query = query.where(m.RunHost.status != "no-longer-observed")
            counts[name] = db.scalar(query)
        run.counts = counts
        db.commit()


def claim(run_id):
    with SessionLocal() as db:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(71003)"))
        run = db.scalar(select(m.Run).where(m.Run.id == run_id).with_for_update())
        if not run or run.status != "queued":
            return None
        active = db.scalar(
            select(func.count())
            .select_from(m.Run)
            .where(m.Run.status.in_(("running", "pausing", "stopping")))
        )
        if active >= settings.max_concurrent_runs:
            return None
        owner = str(uuid.uuid4())
        run.status, run.lease_owner, run.heartbeat_at = "running", owner, now()
        run.started_at = run.started_at or now()
        db.get(m.Scan, run.scan_id).last_status = "running"
        event(db, run, "running", "Worker acquired run lease")
        db.commit()
        return owner
