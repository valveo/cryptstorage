"""
auth.py - Password hashing, JWT access tokens and refresh token rotation.

Access token:   short-lived JWT (default 60 min), used for API calls.
Refresh token:  long-lived opaque token stored in DB (default 7 days).
                Rotation: each use issues a new token and revokes the old.
                Theft detection: presenting a revoked token revokes the
                entire family and triggers a security alert email.

Refresh token storage:
  - Raw token: returned to client (cryptographically random, 32 bytes)
  - DB stores SHA256(token) so the plaintext never touches the database
"""

import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jwt import PyJWTError
from sqlalchemy.orm import Session

import config
from database import get_db
from models import User, RefreshToken, SecurityEvent

# --- Configuration ---
SECRET_KEY = config.require("JWT_SECRET_KEY", min_len=32)
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS   = int(os.getenv("JWT_REFRESH_EXPIRE_DAYS", "7"))

bearer_scheme = HTTPBearer()


# --- Password ---
# Argon2id for new hashes. bcrypt hashes from older versions still verify and are
# upgraded transparently at the next successful login (password_needs_rehash).

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        if hashed.startswith("$argon2"):
            return _hasher.verify(hashed, plain)
        if hashed.startswith("$2"):
            # bcrypt only looks at the first 72 bytes
            return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("ascii"))
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False
    return False


def password_needs_rehash(hashed: str) -> bool:
    return not hashed.startswith("$argon2") or _hasher.check_needs_rehash(hashed)


# Verified when the username does not exist, so login takes the same time either way
DUMMY_HASH = hash_password("dummy password used only for constant-time login")


# --- Access token (JWT) ---

# A web UI session: signed in with a passkey alone, or handed over by the app, so the password
# was never typed into a page this server serves. It manages the account but never gets what opens
# the storage (get_full_user), and it confirms sensitive actions with a recent sign-in, not a password.
WEB_SCOPE = "web"


def create_access_token(user_id: str, token_version: int = 0, second_factor_at: Optional[int] = None,
                        web: bool = False) -> str:
    """second_factor_at: when this login passed the second factor (Unix time). Sensitive actions
    accept it for a few minutes instead of asking for another code (main.STEP_UP_WINDOW).
    web: a web UI session (WEB_SCOPE); "auth" records when it signed in."""
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "type": "access",
        "tv": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    if second_factor_at is not None:
        claims["mfa"] = second_factor_at
    if web:
        claims["scope"] = WEB_SCOPE
        claims["auth"] = int(now.timestamp())
    return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_claims(token: str) -> Optional[dict]:
    """Returns the claims or None if the token is invalid / wrong type."""
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM],
            options={"require": ["exp", "sub", "iat"]},
        )
    except PyJWTError:
        return None
    if payload.get("type") != "access" or not isinstance(payload.get("sub"), str):
        return None
    return payload


def decode_access_token(token: str) -> Optional[str]:
    """Returns user_id or None if token is invalid / wrong type."""
    claims = decode_access_claims(token)
    return claims["sub"] if claims else None


# --- Refresh token (opaque, DB-backed) ---

# Server-side HMAC key for refresh token hashing.
# Prevents offline brute-force if the DB leaks: attacker needs this key
# to compute valid hashes. Required: a per-start random key would invalidate
# every refresh token on restart.
_TOKEN_HMAC_KEY: bytes = bytes.fromhex(
    config.require("REFRESH_TOKEN_HMAC_KEY", hex_bytes=32)
)


def _hash_token(raw: str) -> str:
    """HMAC-SHA256 of the raw token. Stored in DB instead of plaintext."""
    return hmac.new(_TOKEN_HMAC_KEY, raw.encode(), hashlib.sha256).hexdigest()


def create_refresh_token(user_id: str, db: Session, family_id: str | None = None) -> str:
    """
    Generate a new refresh token, persist it and return the raw value.
    Pass family_id to continue an existing rotation family (used in rotate_refresh_token).
    """
    raw    = secrets.token_urlsafe(32)
    tok_id = str(uuid.uuid4())
    fam_id = family_id or str(uuid.uuid4())

    db.add(RefreshToken(
        id         = tok_id,
        token_hash = _hash_token(raw),
        user_id    = user_id,
        family_id  = fam_id,
        revoked    = False,
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    ))
    db.commit()
    # Return token in format  <id>.<raw>  so we can look up the record efficiently
    return f"{tok_id}.{raw}"


def rotate_refresh_token(token: str, db: Session) -> tuple[str, str] | None:
    """
    Validate, revoke and replace a refresh token.

    Returns (user_id, new_raw_token) on success.
    Returns None if the token is unknown or expired.

    Theft detection: if the token is already revoked (reuse), the entire
    family is revoked so all sessions using that family become invalid.
    A SecurityEvent is logged for alerting.
    """
    try:
        tok_id, raw = token.split(".", 1)
    except ValueError:
        return None

    record = db.query(RefreshToken).filter(RefreshToken.id == tok_id).first()

    if record is None:
        return None

    # Verify hash matches
    if record.token_hash != _hash_token(raw):
        return None

    # Check expiry
    if datetime.utcnow() > record.expires_at:
        return None

    # Theft detection: token already revoked → revoke entire family
    if record.revoked:
        _revoke_family(record.family_id, db)
        db.add(SecurityEvent(
            user_id    = record.user_id,
            event_type = "refresh_token_reuse",
            detail     = f"Revoked token {tok_id} was presented. Family {record.family_id} revoked.",
        ))
        db.commit()
        return None

    # Revoke old token and issue new one in the same family
    record.revoked = True
    db.flush()

    new_raw   = create_refresh_token(record.user_id, db, family_id=record.family_id)
    new_tok_id = new_raw.split(".")[0]
    record.replaced_by = new_tok_id
    db.commit()

    return record.user_id, new_raw


def revoke_all_refresh_tokens(user_id: str, db: Session) -> None:
    """Revoke all refresh tokens for a user (e.g. on password change or logout)."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False,
    ).update({"revoked": True})
    db.commit()


def _revoke_family(family_id: str, db: Session) -> None:
    db.query(RefreshToken).filter(
        RefreshToken.family_id == family_id,
    ).update({"revoked": True})
    db.commit()


# --- FastAPI dependency ---

def get_user_for_enrolment(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """The signed-in user, even one who still has to set up a required second factor.
    Only the endpoints needed for that setup use this; everything else uses get_current_user."""
    claims = decode_access_claims(credentials.credentials)
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.id == claims["sub"], User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )
    if claims.get("tv", 0) != (user.token_version or 0):
        # The password was changed after this token was issued
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Not a column: lets sensitive endpoints see when this session passed the second factor
    user.auth_claims = claims
    return user


SECOND_FACTOR_SETUP_REQUIRED = "SECOND_FACTOR_SETUP_REQUIRED"


def get_current_user(user: User = Depends(get_user_for_enrolment)) -> User:
    """The signed-in user. Refused while the server requires a second factor the account lacks,
    so a password alone reaches nothing but the setup of that factor."""
    if config.totp_required() and not user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SECOND_FACTOR_SETUP_REQUIRED)
    return user


# --- Handing a sign-in of the app over to the web UI ---

WEB_TICKET_SECONDS = 120
_tickets_lock = threading.Lock()
_tickets_used: dict[str, float] = {}     # jti -> expiry: a ticket works once


def create_web_ticket(user_id: str, token_version: int) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user_id, "type": "web-ticket", "tv": token_version, "jti": secrets.token_hex(16),
                       "iat": now, "exp": now + WEB_TICKET_SECONDS}, SECRET_KEY, algorithm=ALGORITHM)


def redeem_web_ticket(ticket: str) -> Optional[tuple[str, int]]:
    """(user id, token version) of an unused, unexpired ticket, which is then used up."""
    try:
        claims = jwt.decode(ticket, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "jti"]})
    except PyJWTError:
        return None
    if claims.get("type") != "web-ticket" or not isinstance(claims.get("sub"), str):
        return None
    now = time.time()
    with _tickets_lock:
        for jti, exp in list(_tickets_used.items()):
            if exp < now:
                del _tickets_used[jti]
        if claims["jti"] in _tickets_used:
            return None
        _tickets_used[claims["jti"]] = claims["exp"]
    return claims["sub"], int(claims.get("tv", 0))


def is_web_session(user: User) -> bool:
    return (getattr(user, "auth_claims", None) or {}).get("scope") == WEB_SCOPE


WEB_SESSION_REFUSED = "WEB_SESSION_REFUSED"


def get_full_user(user: User = Depends(get_current_user)) -> User:
    """The signed-in user of the app: refused for a web UI session. Anything that opens the storage,
    changes a key or the password, or hands out a new session needs the app's full sign-in."""
    if is_web_session(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=WEB_SESSION_REFUSED)
    return user
