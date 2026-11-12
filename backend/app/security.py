import hashlib
import secrets
from datetime import timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from .config import settings
from .db import get_db, now
from .models import Session, User

hasher = PasswordHasher()
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def cipher():
    return Fernet(Path(settings.secret_key_file).read_bytes().strip())


def verify(password, hashed):
    try:
        return hasher.verify(hashed, password)
    except VerificationError:
        return False


def create_session(db, user):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.add(
        Session(
            token_hash=digest(token),
            csrf_hash=digest(csrf),
            user_id=user.id,
            expires_at=now() + timedelta(hours=settings.session_hours),
        )
    )
    user.last_login_at = now()
    db.commit()
    return token, csrf


def current_user(request: Request, db: DBSession = Depends(get_db)):
    token = request.cookies.get("hb_session", "")
    session = db.scalar(
        select(Session).where(
            Session.token_hash == digest(token), Session.revoked_at.is_(None), Session.expires_at > now()
        )
    )
    if not session:
        raise HTTPException(401, "Authentication required")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        csrf = request.headers.get("X-CSRF-Token", "")
        origin = request.headers.get("origin")
        if not secrets.compare_digest(digest(csrf), session.csrf_hash) or origin != settings.public_origin:
            raise HTTPException(403, "CSRF verification failed")
    request.state.session_id = session.id
    return db.get(User, session.user_id)
