import json
import math
import shutil
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import String, cast, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession
from starlette.datastructures import UploadFile

from . import models as m
from .config import settings
from .db import get_db, now
from .scope import ScanInput, Scope, import_wordlist
from .security import DUMMY_HASH, cipher, create_session, current_user, digest, verify

router = APIRouter(prefix="/api/v1")
DB = Annotated[DBSession, Depends(get_db)]
User = Annotated[m.User, Depends(current_user)]


def serialize(row):
    hidden = {"password_hash", "encrypted_secret", "token_hash", "csrf_hash", "path", "thumbnail_path"}
    result = {}
    for column in row.__table__.columns:
        if column.name in hidden:
            continue
        value = getattr(row, column.name)
        result[column.name] = value.isoformat() + "Z" if isinstance(value, datetime) else value
    if isinstance(row, m.Credential):
        result["secret"] = "••••••••"
    if isinstance(row, m.Screenshot) and row.status == "captured":
        result["content_url"] = f"/api/v1/screenshots/{row.id}/content"
        result["thumbnail_url"] = result["content_url"] + "?thumbnail=true"
    return result


def serialize_inventory(db, row):
    item = serialize(row)
    persistent = None
    if isinstance(row, m.ServiceObservation):
        persistent = db.get(m.Service, row.service_id)
    elif isinstance(row, m.RunHost):
        persistent = db.get(m.Host, row.host_id)
    if persistent:
        item["first_seen_at"] = persistent.created_at.isoformat() + "Z"
        item["last_seen_at"] = persistent.last_seen_at.isoformat() + "Z"
    return item


class Page(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(25, ge=1, le=100)
    search: str = Field("", max_length=200)
    sort_by: str = "created_at"
    sort_order: str = Field("desc", pattern="^(asc|desc)$")
    status: str | None = None
    ip: str | None = None


def paginate(db, model, query, args):
    allowed_sort = {
        c.name
        for c in model.__table__.columns
        if isinstance(c.type, (String,))
        or c.name in {"created_at", "updated_at", "last_run_at", "port", "attempted_at", "captured_at"}
    }
    allowed_sort -= {"encrypted_secret", "password_hash", "path", "thumbnail_path"}
    if args.sort_by not in allowed_sort:
        raise HTTPException(422, "Unsupported sort field")
    if args.search:
        fields = [
            getattr(model, c.name)
            for c in model.__table__.columns
            if c.name
            in {
                "name",
                "description",
                "target_summary",
                "ip",
                "url",
                "username",
                "label",
                "kind",
                "message",
                "product",
                "version",
                "identity",
                "event_type",
                "evidence",
            }
        ]
        if fields:
            term = args.search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            query = query.where(or_(*(cast(c, String).ilike(f"%{term}%", escape="\\") for c in fields)))
    if args.status:
        if model is m.Scan:
            column = "last_status"
        elif model is m.ServiceObservation:
            column = (
                "change" if args.status in {"new", "changed", "unchanged", "no-longer-observed"} else "state"
            )
        elif model is m.Event:
            column = "level"
        elif model is m.Finding:
            column = "kind"
        else:
            column = "status" if hasattr(model, "status") else None
        if column:
            query = query.where(getattr(model, column) == args.status)
        else:
            raise HTTPException(422, "This collection does not support status filtering")
    if args.ip and hasattr(model, "ip"):
        query = query.where(model.ip == args.ip)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    column = getattr(model, args.sort_by)
    order = column.asc() if args.sort_order == "asc" else column.desc()
    items = db.scalars(
        query.order_by(order.nulls_last(), model.id.asc())
        .offset((args.page - 1) * args.page_size)
        .limit(args.page_size)
    ).all()
    return {
        "items": [serialize_inventory(db, i) for i in items],
        "page": args.page,
        "page_size": args.page_size,
        "total": total,
        "total_pages": math.ceil(total / args.page_size),
    }


def get_or_404(db, model, identity):
    row = db.get(model, identity)
    if not row:
        raise HTTPException(404, "Resource not found")
    return row


def lock_run(db, run_id):
    row = db.scalar(select(m.Run).where(m.Run.id == run_id).with_for_update())
    if not row:
        raise HTTPException(404, "Run not found")
    return row


def audit(db, run, user, action):
    db.add(
        m.Event(
            run_id=run.id,
            stage=run.current_stage,
            event_type=action,
            message=f"{action.capitalize()} requested by {user.username}",
        )
    )


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1000)


@router.post("/auth/login")
def login(body: LoginInput, request: Request, response: Response, db: DB):
    if request.headers.get("origin") != settings.public_origin:
        raise HTTPException(403, "Origin verification failed")
    # PostgreSQL advisory lock serializes attempts even across API replicas.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(71001)"))
    key = digest(request.client.host if request.client else "unknown")
    throttle = db.get(m.LoginThrottle, key)
    if not throttle:
        throttle = m.LoginThrottle(key=key, count=0, reset_at=now() + timedelta(minutes=15))
        db.add(throttle)
    if throttle.reset_at <= now():
        throttle.count, throttle.reset_at = 0, now() + timedelta(minutes=15)
    if throttle.count >= 10:
        raise HTTPException(429, "Too many login attempts; retry later")
    throttle.count += 1
    db.commit()
    user = db.scalar(select(m.User).where(m.User.username == body.username))
    valid = verify(body.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid:
        raise HTTPException(401, "Invalid username or password")
    throttle.count = 0
    token, csrf = create_session(db, user)
    for name, value, httponly in (("hb_session", token, True), ("hb_csrf", csrf, False)):
        response.set_cookie(
            name,
            value,
            httponly=httponly,
            secure=settings.secure_cookies,
            samesite="strict",
            max_age=settings.session_hours * 3600,
            path="/",
        )
    return {"id": user.id, "username": user.username}


@router.get("/auth/me")
def me(user: User):
    return {"id": user.id, "username": user.username}


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, user: User, db: DB):
    db.get(m.Session, request.state.session_id).revoked_at = now()
    db.commit()
    response.delete_cookie("hb_session")
    response.delete_cookie("hb_csrf")


@router.get("/scans")
def scans(user: User, db: DB, args: Annotated[Page, Query()]):
    data = paginate(db, m.Scan, select(m.Scan), args)
    for item in data["items"]:
        latest = db.scalar(
            select(m.Run).where(m.Run.scan_id == item["id"]).order_by(m.Run.created_at.desc()).limit(1)
        )
        item["latest_run"] = serialize(latest) if latest else None
    return data


def save_scan(db, scan, body):
    ids = body.credential_ids
    if len(db.scalars(select(m.Credential.id).where(m.Credential.id.in_(ids))).all()) != len(ids):
        raise HTTPException(422, "Unknown credential reference")
    scan.name, scan.description = body.name, body.description
    scan.config = body.model_dump()
    scan.target_summary = (
        f"{body.domain} ({len(body.subdomains)} DNS candidates)"
        if body.mode == "subdomain"
        else ", ".join(body.targets + body.hostnames + body.urls)
    )
    db.add(scan)
    db.flush()
    db.query(m.ScanCredential).filter_by(scan_id=scan.id).delete()
    for credential_id in ids:
        db.add(m.ScanCredential(scan_id=scan.id, credential_id=credential_id))
    db.commit()
    return serialize(scan)


MAX_WORDLIST_BYTES = 3 * 1024 * 1024
MAX_SCAN_REQUEST_BYTES = 4 * 1024 * 1024


async def scan_input(request: Request, existing=None):
    if int(request.headers.get("content-length", "0")) > MAX_SCAN_REQUEST_BYTES:
        raise HTTPException(413, "Scan request must be at most 4 MiB; wordlist files at most 3 MiB")
    try:
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            async with request.form(max_files=1, max_fields=1, max_part_size=65536) as form:
                if set(form) != {"config", "wordlist"} or not isinstance(form["wordlist"], UploadFile):
                    raise HTTPException(422, "Provide config and one wordlist file")
                body = json.loads(form["config"])
                if not isinstance(body, dict):
                    raise HTTPException(422, "Scan configuration must be an object")
                upload = form["wordlist"]
                content = await upload.read(MAX_WORDLIST_BYTES + 1)
                if len(content) > MAX_WORDLIST_BYTES:
                    raise HTTPException(413, "Wordlist must be at most 3 MiB")
                try:
                    text_content = content.decode("utf-8-sig")
                except UnicodeDecodeError:
                    raise HTTPException(422, "Wordlist must be a UTF-8 text file") from None
                raw_domain = body.get("domain", (existing or {}).get("domain", ""))
                if not isinstance(raw_domain, str):
                    raise HTTPException(422, "Base domain must be a string")
                domain = ScanInput.clean_domain(raw_domain)
                if not domain:
                    raise HTTPException(422, "Provide a base domain before importing the wordlist")
                words, report = import_wordlist(text_content, domain)
                if not words:
                    raise HTTPException(
                        422,
                        {
                            "message": "Wordlist contains no valid subdomain names",
                            "details": [
                                {"field": "wordlist", "message": sample} for sample in report.examples
                            ],
                        },
                    )
                body = {
                    **body,
                    "subdomains": words,
                    "wordlist_import": report.model_dump(),
                    "wordlist_filename": (upload.filename or "wordlist.txt")
                    .replace("\\", "/")
                    .split("/")[-1][:200],
                }
        else:
            body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(422, "Scan configuration must be an object")
        return ScanInput.model_validate({**(existing or {}), **body})
    except ValidationError as exc:
        raise HTTPException(
            422,
            {
                "message": "Invalid scan configuration",
                "details": [
                    {"field": ".".join(map(str, error["loc"])), "message": error["msg"]}
                    for error in exc.errors()
                ],
            },
        ) from None
    except (ValueError, TypeError):
        raise HTTPException(422, "Invalid scan configuration or multipart upload") from None


@router.post("/scans", status_code=201)
async def create_scan(request: Request, user: User, db: DB):
    return save_scan(db, m.Scan(), await scan_input(request))


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: str, user: User, db: DB):
    return serialize(get_or_404(db, m.Scan, scan_id))


@router.patch("/scans/{scan_id}")
async def update_scan(scan_id: str, request: Request, user: User, db: DB):
    scan = get_or_404(db, m.Scan, scan_id)
    return save_scan(db, scan, await scan_input(request, scan.config))


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, user: User, db: DB):
    scan = db.scalar(select(m.Scan).where(m.Scan.id == scan_id).with_for_update())
    if not scan:
        raise HTTPException(404, "Scan not found")
    runs = db.scalars(select(m.Run).where(m.Run.scan_id == scan_id)).all()
    if any(r.status in m.ACTIVE for r in runs):
        raise HTTPException(409, "Stop all active runs before deleting this scan")
    db.delete(scan)
    db.commit()
    for run in runs:
        shutil.rmtree(settings.evidence_dir / run.id, ignore_errors=True)


@router.get("/scans/{scan_id}/runs")
def scan_runs(scan_id: str, user: User, db: DB, args: Annotated[Page, Query()]):
    get_or_404(db, m.Scan, scan_id)
    return paginate(db, m.Run, select(m.Run).where(m.Run.scan_id == scan_id), args)


class Launch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorized_scope_confirmed: bool


@router.post("/scans/{scan_id}/runs", status_code=202)
def start_run(scan_id: str, body: Launch, user: User, db: DB):
    if not body.authorized_scope_confirmed:
        raise HTTPException(422, "Explicit authorization of the target scope is required")
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(71002)"))
    scan = db.scalar(select(m.Scan).where(m.Scan.id == scan_id).with_for_update())
    if not scan:
        raise HTTPException(404, "Scan not found")
    if db.scalar(select(m.Run.id).where(m.Run.scan_id == scan_id, m.Run.status.in_(m.ACTIVE))):
        raise HTTPException(409, "This scan already has an active run")
    if (
        db.scalar(select(func.count()).select_from(m.Run).where(m.Run.status.in_(m.ACTIVE)))
        >= settings.max_queue
    ):
        raise HTTPException(429, "Run queue is full")
    config = ScanInput.model_validate(scan.config)
    run = m.Run(
        scan_id=scan_id,
        config_snapshot=config.model_dump(),
        initiated_by=user.id,
        total=len(config.subdomains)
        if config.mode == "subdomain"
        else len(Scope(config.targets).addresses()),
    )
    db.add(run)
    db.flush()
    scan.last_run_at, scan.last_status = run.created_at, "queued"
    for credential_id in config.credential_ids:
        db.add(m.RunCredential(run_id=run.id, credential_id=credential_id))
    audit(db, run, user, "start")
    db.commit()
    # The independent scheduler publishes this durable outbox row.
    return serialize(run)


@router.get("/runs/{run_id}")
def run_detail(run_id: str, user: User, db: DB):
    return serialize(get_or_404(db, m.Run, run_id))


@router.get("/runs/{run_id}/network-draft")
def network_draft(run_id: str, user: User, db: DB):
    run = get_or_404(db, m.Run, run_id)
    if run.config_snapshot.get("mode") != "subdomain":
        raise HTTPException(422, "Only DNS recon results can be used for this action")
    # Query the full run, independently of pagination and filters in the results table.
    names = db.scalars(
        select(m.Finding.identity)
        .where(
            m.Finding.run_id == run.id,
            m.Finding.kind == "subdomain",
        )
        .distinct()
        .order_by(m.Finding.identity)
    ).all()
    if not names:
        raise HTTPException(422, "This DNS run has no discovered subdomains")
    domain = run.config_snapshot["domain"]
    return {
        "config": {
            "mode": "network",
            "name": f"Network - {domain}"[:200],
            "description": f"Discovered subdomains from DNS run {run.id} ({domain}).",
            "targets": [],
            "hostnames": [],
            "urls": list(names),
        },
        "source": {
            "run_id": run.id,
            "scan_id": run.scan_id,
            "domain": domain,
            "status": run.status,
            "target_count": len(names),
        },
    }


@router.post("/runs/{run_id}/{action}")
def control_run(run_id: str, action: str, user: User, db: DB):
    run = lock_run(db, run_id)
    transitions = {
        "pause": {"running": "pausing"},
        "resume": {"paused": "queued"},
        "stop": {"queued": "stopped", "running": "stopping", "pausing": "stopping", "paused": "stopped"},
    }
    if action not in transitions:
        raise HTTPException(404, "Unknown run action")
    target = transitions[action].get(run.status)
    if not target:
        raise HTTPException(409, f"Cannot {action} a {run.status} run")
    run.status = target
    if target == "stopped":
        run.ended_at = now()
    audit(db, run, user, action)
    db.get(m.Scan, run.scan_id).last_status = target
    db.commit()
    return serialize(run)


COLLECTIONS = {
    "subdomains": m.Finding,
    "hosts": m.RunHost,
    "ports": m.ServiceObservation,
    "services": m.ServiceObservation,
    "endpoints": m.EndpointObservation,
    "credentials": m.Attempt,
    "credential-attempts": m.Attempt,
    "screenshots": m.Screenshot,
    "findings": m.Finding,
    "events": m.Event,
    "targets": m.RunTarget,
    "checkpoints": m.Checkpoint,
    "follow-up-candidates": m.FollowUp,
}


@router.get("/runs/{run_id}/{collection}")
def run_collection(run_id: str, collection: str, user: User, db: DB, args: Annotated[Page, Query()]):
    get_or_404(db, m.Run, run_id)
    model = COLLECTIONS.get(collection)
    if not model:
        raise HTTPException(404, "Unknown collection")
    query = select(model).where(model.run_id == run_id)
    if collection == "subdomains":
        query = query.where(m.Finding.kind == "subdomain")
    return paginate(db, model, query, args)


@router.get("/screenshots/{screenshot_id}/content")
def screenshot(screenshot_id: str, user: User, db: DB, thumbnail: bool = False):
    shot = get_or_404(db, m.Screenshot, screenshot_id)
    relative = shot.thumbnail_path if thumbnail else shot.path
    if shot.status != "captured" or not relative:
        raise HTTPException(404, "Screenshot not available")
    root = settings.evidence_dir.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(404, "Evidence not found")
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "private, no-store"})


class CredentialInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=1, max_length=200, pattern=r"^[^:\r\n\x00]+$")
    password: str = Field(min_length=1, max_length=1000)


class CredentialPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str | None = Field(None, min_length=1, max_length=200)
    username: str | None = Field(None, min_length=1, max_length=200, pattern=r"^[^:\r\n\x00]+$")
    password: str | None = Field(None, min_length=1, max_length=1000)


@router.get("/credentials")
def credentials(user: User, db: DB, args: Annotated[Page, Query()]):
    return paginate(db, m.Credential, select(m.Credential), args)


@router.post("/credentials", status_code=201)
def create_credential(body: CredentialInput, user: User, db: DB):
    row = m.Credential(
        label=body.label,
        username=body.username,
        encrypted_secret=cipher().encrypt(body.password.encode()).decode(),
    )
    db.add(row)
    db.commit()
    return serialize(row)


@router.get("/credentials/{credential_id}")
def credential_detail(credential_id: str, user: User, db: DB):
    return serialize(get_or_404(db, m.Credential, credential_id))


@router.patch("/credentials/{credential_id}")
def update_credential(credential_id: str, body: CredentialPatch, user: User, db: DB):
    row = get_or_404(db, m.Credential, credential_id)
    # References form part of an immutable run approval. Do not change secrets underneath a run.
    referenced = db.scalar(select(m.ScanCredential.scan_id).where(m.ScanCredential.credential_id == row.id))
    attempted = db.scalar(select(m.Attempt.id).where(m.Attempt.credential_id == row.id))
    run_reference = db.scalar(select(m.RunCredential.run_id).where(m.RunCredential.credential_id == row.id))
    if referenced or attempted or run_reference:
        raise HTTPException(409, "Referenced credentials are immutable; create a new entry")
    for key, value in body.model_dump(exclude_none=True).items():
        if key == "password":
            row.encrypted_secret = cipher().encrypt(value.encode()).decode()
        else:
            setattr(row, key, value)
    db.commit()
    return serialize(row)


@router.delete("/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: str, user: User, db: DB):
    row = get_or_404(db, m.Credential, credential_id)
    # Also protect credential IDs referenced in immutable runs before attempts exist.
    if db.scalar(select(m.RunCredential.run_id).where(m.RunCredential.credential_id == credential_id)):
        raise HTTPException(409, "Credential is referenced by run history")
    db.delete(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Credential is referenced by a scan or run") from None
