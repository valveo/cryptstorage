"""
main.py - FastAPI application entry point (end-to-end encrypted storage).

The client derives the login key and the volume key from one password and encrypts everything
itself; this server stores the login-key hash and the ciphertext's SFTP account, never a key
that opens the data (docs/design-e2ee.md).

Routes:
    GET  /server-info             - What the client needs before creating a volume (public)
    POST /auth/register           - Register a new user (sends verification email)
    POST /auth/verify-email       - Verify email address
    POST /auth/login              - Login -> JWT access token + refresh token
    POST /auth/refresh            - Refresh access token using refresh token
    POST /auth/recover-e2ee       - New login key with the recovery proof
    GET  /users/me                - Current user
    PUT  /users/me/ssh-key        - Replace the SSH public key (waits CHANGE_DELAY_HOURS)
    GET/DELETE /users/me/pending-changes - Waiting key changes and deletions; cancel one
    POST /auth/cancel-change      - Cancel a waiting change with the link from the e-mail
    POST /users/me/password       - Change the login key
    PUT  /users/me/recovery-verifier, PUT/GET /users/me/escrow
    POST /users/me/totp/*         - Second factor
    /users/me/sticks*             - The server's half of the stick's key (sticks.py); lock, unlock, delayed removal
    GET  /storage/e2ee            - Where the client connects (SFTP)
    GET  /storage/usage           - Storage usage bytes
    DELETE /storage               - Delete storage and account (waits CHANGE_DELAY_HOURS)
"""

import base64
import logging
import os
import threading
from typing import Optional
import uuid
from datetime import datetime
from pydantic import BaseModel

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from auth import (
    create_access_token,
    create_refresh_token,
    rotate_refresh_token,
    revoke_all_refresh_tokens,
    get_current_user,
    get_full_user,
    get_user_for_enrolment,
    hash_password,
    verify_password,
    create_web_ticket,
    redeem_web_ticket,
    is_web_session,
    WEB_TICKET_SECONDS,
)
from database import SessionLocal, get_db, init_db
from models import PendingChange, StickLock, StickSecret, User, WebAuthnCredential
import passkeys
import sticks
import version
from schemas import (
    PasskeyDeleteRequest,
    PasskeyLoginBegin,
    PasskeyLoginFinish,
    PasskeyOptions,
    PasskeyRegisterBegin,
    PasskeyRegisterFinish,
    PasskeyResponse,
    CancelChangeRequest,
    ChangeResponse,
    DeleteRequest,
    LoginRequest,
    MessageResponse,
    StickCreateRequest,
    StickDeleteRequest,
    StickResponse,
    StickSecretResponse,
    PendingChangeResponse,
    PasswordChangeRequest,
    RegisterRequest,
    SSHKeyUpdate,
    TokenResponse,
    UserResponse,
)
from socket_client import (
    DaemonError,
    daemon_e2ee_provision,
    daemon_e2ee_usage,
)
from email_verification import (
    generate_verification_token,
    send_verification_email,
    verify_email_token,
    EmailError,
)
from audit import log as audit_log, get_client_ip
import config
from auth import DUMMY_HASH, password_needs_rehash
from email_verification import send_enrolment_code_email, send_security_notice_email
import pending
import time
from throttle import FailureTracker
from schemas import (
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpSetupRequest,
    TotpSetupResponse,
)
import totp
from schemas import E2EERecoverRequest, E2EEStorageResponse, EscrowRequest, RecoveryVerifierRequest, ServerInfo
from schemas import SyncLockRequest, SyncLockResponse
from schemas import WebPasskeyBegin, WebTicketRedeem, WebTicketResponse
from models import EscrowSeal, SyncLock
import escrow_state
from datetime import timedelta
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limits are per real client IP (see audit.get_client_ip); keying on the socket
# address would put every user behind the proxy / web UI into one shared bucket.
limiter = Limiter(key_func=get_client_ip)

# Brute-force protection beyond the per-IP request limit. The password also protects
# the master key, so repeated guessing is throttled per (IP, username) and, with a
# higher threshold, per username across all IPs.
_login_by_ip_user = FailureTracker(limit=5, window=900)
_login_by_user = FailureTracker(limit=30, window=3600)
_pw_failures = FailureTracker(limit=5, window=900)   # password re-checks by a logged-in user
# Second-factor guesses, per account. A 6-digit code is only safe because guesses are limited.
_totp_failures = FailureTracker(limit=5, window=900)

TOTP_ISSUER = os.getenv("TOTP_ISSUER", "CryptStorage")


def _too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many failed attempts. Try again later.",
        headers={"Retry-After": str(retry_after)},
    )


# A web UI session confirms a sensitive action with a sign-in this recent instead of the password, which
# the web UI no longer asks for. After that the user signs in again.
REAUTH_WINDOW = 600
REAUTH_REQUIRED = "REAUTH_REQUIRED"


def _confirm_identity(request: Request, db: Session, user: User, password: str, event: str) -> None:
    """Before a sensitive action: the password from the app, a recent sign-in from a web UI session."""
    if is_web_session(user):
        signed_in = (getattr(user, "auth_claims", None) or {}).get("auth")
        if isinstance(signed_in, int) and 0 <= time.time() - signed_in <= REAUTH_WINDOW:
            return
        audit_log(db, f"{event}_reauth_required", user_id=user.id, ip_address=get_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=REAUTH_REQUIRED)
    _verify_password_or_fail(request, db, user, password, event)


def _verify_password_or_fail(request: Request, db: Session, user: User, password: str, event: str) -> None:
    """Re-check the password of a logged-in user (throttled, audited)."""
    retry = _pw_failures.blocked(user.id)
    if retry:
        raise _too_many(retry)
    if not verify_password(password, user.password_hash):
        _pw_failures.record_failure(user.id)
        audit_log(db, f"{event}_bad_password", user_id=user.id, ip_address=get_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password.")
    _pw_failures.reset(user.id)


def _notify_all(what: str) -> None:
    """Mail every user in the background, so a slow mail server does not hold up the start."""
    def run():
        with SessionLocal() as db:
            for user in db.query(User).filter(User.is_active == True, User.email_verified == True).all():
                _notify(user, what)
    threading.Thread(target=run, daemon=True).start()


def _notify(user: User, what: str) -> None:
    """Best-effort security notice by e-mail; never fails the request."""
    try:
        send_security_notice_email(user.email, user.username, what)
    except Exception as e:
        logger.error(f"Could not send security notice to user {user.id}: {e}")
SSH_PORT = int(os.getenv("SFTP_PORT", "2222"))
SERVER_HOST = os.getenv("SERVER_HOST", "your-server.example.com")
# Public host keys of the SFTP service (comma-separated .pub files). The client gets them over the
# pinned TLS connection and pins the SFTP host key without asking the user.
SFTP_HOST_KEY_FILES = [p.strip() for p in os.getenv("SFTP_HOST_KEY_FILES", "").split(",") if p.strip()]
_HOST_KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}
REQUIRE_EMAIL_VERIFICATION = os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").lower() == "true"

# The interactive docs describe every endpoint to anyone who can reach the API;
# enable them only for development (ENABLE_DOCS=true).
_ENABLE_DOCS = config.env_bool("ENABLE_DOCS", False)

app = FastAPI(
    title="CryptStorage API",
    description="Encrypted personal cloud storage API",
    version=version.VERSION,
    docs_url="/docs" if _ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _ENABLE_DOCS else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# The web UI talks to the API server-side and the Go client is not a browser, so
# CORS is off unless origins are listed explicitly. Tokens travel in the
# Authorization header, never in cookies, hence no credentials mode.
_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

def _second_factor_unavailable() -> HTTPException:
    return HTTPException(status_code=503,
                         detail="Two-factor authentication is not configured on this server.")


def _accept_second_factor(db: Session, user: User, code: str) -> bool:
    """True if `code` is a valid TOTP code or an unused backup code; consumes it atomically."""
    if not totp.is_configured():
        raise _second_factor_unavailable()
    try:
        secret = totp.decrypt_secret(user.totp_secret_enc, user.id)
    except Exception as e:     # wrong or rotated TOTP_ENCRYPTION_KEY, damaged data: fail closed
        logger.error(f"Cannot read the TOTP secret of user {user.id}: {e}")
        raise _second_factor_unavailable()

    step = totp.verify(secret, code, user.totp_last_step)
    if step is not None:
        # Only the request that moves last_step forward wins, so one code cannot be used
        # by two requests at the same time.
        changed = db.query(User).filter(
            User.id == user.id,
            or_(User.totp_last_step.is_(None), User.totp_last_step < step),
        ).update({User.totp_last_step: step}, synchronize_session=False)
        db.commit()
        return changed == 1

    remaining = totp.consume_backup_code(user.totp_backup_hashes, code)
    if remaining is not None:
        changed = db.query(User).filter(
            User.id == user.id,
            User.totp_backup_hashes == user.totp_backup_hashes,
        ).update({User.totp_backup_hashes: remaining}, synchronize_session=False)
        db.commit()
        if changed == 1:
            audit_log(db, "totp_backup_code_used", user_id=user.id)
        return changed == 1
    return False


def _check_second_factor(request: Request, db: Session, user: User, code: Optional[str]) -> None:
    """Login step after the password: nothing if the account has no second factor."""
    if not user.totp_enabled:
        return
    if not code:
        # Reached only with the right password, so this does not reveal accounts to guessers.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP_REQUIRED")
    ip = get_client_ip(request)
    retry = _totp_failures.blocked(user.id)
    if retry:
        audit_log(db, "login_totp_throttled", user_id=user.id, ip_address=ip)
        raise _too_many(retry)
    if _accept_second_factor(db, user, code):
        _totp_failures.reset(user.id)
        return
    _totp_failures.record_failure(user.id)
    audit_log(db, "login_totp_failed", user_id=user.id, ip_address=ip)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code.")


# A login that passed the second factor this recently counts for sensitive actions too, so the
# client can sign in and change the password without asking for a second code.
STEP_UP_WINDOW = 300


def _check_second_factor_again(request: Request, db: Session, user: User, code: Optional[str], event: str) -> None:
    """Sensitive action by a signed-in user: the second factor again, when the account has one."""
    if not user.totp_enabled:
        return
    if not code:
        mfa_at = (getattr(user, "auth_claims", None) or {}).get("mfa")
        if isinstance(mfa_at, int) and 0 <= time.time() - mfa_at <= STEP_UP_WINDOW:
            return
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="TOTP_REQUIRED")
    retry = _totp_failures.blocked(user.id)
    if retry:
        raise _too_many(retry)
    if not _accept_second_factor(db, user, code):
        _totp_failures.record_failure(user.id)
        audit_log(db, f"{event}_totp_failed", user_id=user.id, ip_address=get_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code.")
    _totp_failures.reset(user.id)
    db.refresh(user)


def _schedule(db: Session, user: User, kind: str, request: Request, ssh_public_key: Optional[str] = None):
    try:
        change = pending.schedule(db, user, kind, get_client_ip(request), ssh_public_key)
    except pending.NoticeFailed:
        raise HTTPException(status_code=503, detail="Could not send the confirmation e-mail. Try again later.")
    if config.change_delay_hours() == 0 and pending.apply_due(db, user.id):
        return None
    return change



@app.on_event("startup")
def on_startup():
    config.validate()
    init_db()
    logger.info("Database initialized.")
    with SessionLocal() as db:
        escrow_state.check_at_startup(db, _notify_all)
    pending.start_worker(SessionLocal, float(os.getenv("CHANGE_WORKER_INTERVAL", "300")))


@app.get("/health")
def health():
    """Liveness probe for compose/Ansible and the client's TLS pin discovery."""
    return {"status": "ok", "version": version.VERSION}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=MessageResponse, status_code=201)
@limiter.limit("5/minute")
def register(request: Request, req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user. The "password" is the login key the client derived; the server never
    sees the password or any key that opens the data. The storage account is created on the
    first call to /storage/e2ee.
    """

    if config.max_users() and db.query(User).count() >= config.max_users():
        raise HTTPException(status_code=503, detail="This server has reached its user limit. Try again later.")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=409, detail="Username already taken.")
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=409, detail="Email already registered.")

    user = User(
        id=str(uuid.uuid4()),
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        ssh_public_key=req.ssh_public_key,
        storage_created=False,
        email_verified=not REQUIRE_EMAIL_VERIFICATION,
        quota_bytes=config.default_quota_bytes(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    message = f"User '{req.username}' registered successfully."
    if REQUIRE_EMAIL_VERIFICATION:
        token = generate_verification_token(user.id)
        try:
            send_verification_email(req.email, req.username, token)
        except EmailError as e:
            logger.error(f"Failed to send verification email to {req.email}: {e}")
            db.delete(user)
            db.commit()
            raise HTTPException(status_code=500, detail="Failed to send verification email.")
        message = f"Registered. Check your email ({req.email}) to verify your account."

    audit_log(db, "register", user_id=user.id,
              detail=f"username={req.username} email={req.email}",
              ip_address=get_client_ip(request))
    return {"message": message}


class VerifyEmailRequest(BaseModel):
    token: str


@app.post("/auth/verify-email", response_model=MessageResponse)
@limiter.limit("10/minute")
def verify_email(request: Request, req: VerifyEmailRequest, db: Session = Depends(get_db)):
    """Verify the email address."""
    user_id = verify_email_token(req.token)
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.email_verified:
        return {"message": "Email already verified."}

    user.email_verified = True
    db.commit()
    audit_log(db, "email_verified", user_id=user.id,
              ip_address=get_client_ip(request))
    return {"message": "Email verified. You can now log in."}


@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, req: LoginRequest, db: Session = Depends(get_db)):
    """Login with the derived login key. Returns a JWT access token and a refresh token."""
    user = _password_login(request, db, req.username, req.password)
    _check_second_factor(request, db, user, req.totp_code)
    second_factor_at = int(time.time()) if user.totp_enabled else None

    audit_log(db, "login_success", user_id=user.id,
              ip_address=get_client_ip(request))
    user.last_login = datetime.utcnow()
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(req.password)   # bcrypt -> Argon2id upgrade
    db.commit()

    if req.web:
        return _web_session(user, second_factor_at)
    return {
        "access_token":  create_access_token(user.id, user.token_version or 0, second_factor_at),
        "refresh_token": create_refresh_token(user.id, db),
    }


def _web_session(user: User, second_factor_at: Optional[int]) -> dict:
    """A web UI session: no refresh token, so it ends with its access token."""
    return {"access_token": create_access_token(user.id, user.token_version or 0, second_factor_at, web=True)}


def _password_login(request: Request, db: Session, username: str, password: str) -> User:
    """The first login step (throttled, audited): the user, if the login key is right."""
    ip = get_client_ip(request)
    name_key = username.strip().lower()
    ip_key = f"{ip}|{name_key}"

    retry = max(_login_by_ip_user.blocked(ip_key), _login_by_user.blocked(name_key))
    if retry:
        audit_log(db, "login_throttled", detail=f"attempted_username={username}", ip_address=ip)
        raise _too_many(retry)

    user = db.query(User).filter(
        User.username == username,
        User.is_active == True,
    ).first()

    # Always hash-verify (against a dummy hash if the user does not exist) so the
    # response time does not reveal whether a username is registered.
    password_ok = verify_password(password, user.password_hash if user else DUMMY_HASH)

    # Do not log user_id on login_failed to avoid leaking username existence.
    if not user or not password_ok:
        _login_by_ip_user.record_failure(ip_key)
        _login_by_user.record_failure(name_key)
        audit_log(db, "login_failed",
                  detail=f"attempted_username={username}",
                  ip_address=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    _login_by_ip_user.reset(ip_key)

    if REQUIRE_EMAIL_VERIFICATION and not user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Check your inbox.")
    return user


# ---------------------------------------------------------------------------
# Passkeys (WebAuthn): the second factor without typing a code (passkeys.py)
# ---------------------------------------------------------------------------

def _passkeys_or_fail() -> None:
    if not passkeys.is_configured():
        raise HTTPException(status_code=503, detail="Passkeys are not configured on this server (WEBAUTHN_RP_ID / BASE_URL).")


def _user_passkeys(db: Session, user_id: str) -> list[WebAuthnCredential]:
    return (db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user_id)
            .order_by(WebAuthnCredential.created_at).all())


@app.post("/auth/passkey/begin", response_model=PasskeyOptions)
@limiter.limit("10/minute")
def passkey_login_begin(request: Request, req: PasskeyLoginBegin, db: Session = Depends(get_db)):
    """Login step 2 with a passkey instead of a code: the password first, then the browser's options."""
    _passkeys_or_fail()
    user = _password_login(request, db, req.username, req.password)
    creds = _user_passkeys(db, user.id)
    if not creds or not user.totp_enabled:
        # Reached only with the right password, so this does not reveal accounts to guessers.
        raise HTTPException(status_code=404, detail="NO_PASSKEY")
    options, session = passkeys.authentication_options(user.id, [c.credential_id for c in creds])
    return {"options": options, "session": session, "approve_url": passkeys.approve_url()}


@app.post("/auth/passkey/finish", response_model=TokenResponse)
@limiter.limit("10/minute")
def passkey_login_finish(request: Request, req: PasskeyLoginFinish, db: Session = Depends(get_db)):
    """The browser's answer to /auth/passkey/begin. Gives the same tokens as /auth/login."""
    _passkeys_or_fail()
    ip = get_client_ip(request)
    try:
        user_id, challenge = passkeys.open_login_session(req.session)
    except passkeys.PasskeyError as e:
        raise HTTPException(status_code=401, detail=str(e))
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    retry = _totp_failures.blocked(user.id)
    if retry:
        audit_log(db, "login_passkey_throttled", user_id=user.id, ip_address=ip)
        raise _too_many(retry)
    cid = passkeys.answer_credential_id(req.credential)
    cred = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.credential_hash == passkeys.credential_hash(cid or ""),
    ).first() if cid else None
    try:
        if not cred:
            raise passkeys.PasskeyError("This passkey is not registered for this account.")
        count = passkeys.verify_authentication(challenge, req.credential, cred.public_key, cred.sign_count or 0)
    except passkeys.PasskeyError as e:
        _totp_failures.record_failure(user.id)
        audit_log(db, "login_passkey_failed", user_id=user.id, ip_address=ip)
        raise HTTPException(status_code=401, detail=str(e))
    _totp_failures.reset(user.id)
    cred.sign_count = count
    cred.last_used_at = datetime.utcnow()
    user.last_login = datetime.utcnow()
    db.commit()
    audit_log(db, "login_success", user_id=user.id, detail="passkey", ip_address=ip)
    if req.web:
        return _web_session(user, int(time.time()))
    return {
        "access_token":  create_access_token(user.id, user.token_version or 0, int(time.time())),
        "refresh_token": create_refresh_token(user.id, db),
    }


# ---------------------------------------------------------------------------
# Web UI sign-in without the password. The server also serves the web UI's scripts, so a password
# typed there is only as safe as the server. These two ways never put it into the page: the passkey
# alone, or a sign-in the app hands over. Both give a web session (auth.WEB_SCOPE).
# ---------------------------------------------------------------------------

@app.post("/auth/web/passkey/begin", response_model=PasskeyOptions)
@limiter.limit("10/minute")
def web_passkey_begin(request: Request, req: WebPasskeyBegin, db: Session = Depends(get_db)):
    """The browser's options for the account's passkeys. An unknown name or an account without passkeys
    gets options too (for a passkey that does not exist), so the answer does not reveal accounts."""
    _passkeys_or_fail()
    user = db.query(User).filter(User.username == req.username, User.is_active == True).first()
    creds = _user_passkeys(db, user.id) if user and user.totp_enabled else []
    if not creds:
        options, session = passkeys.web_authentication_options("-", [passkeys.b64url(os.urandom(32))])
        return {"options": options, "session": session}
    options, session = passkeys.web_authentication_options(user.id, [c.credential_id for c in creds])
    return {"options": options, "session": session}


@app.post("/auth/web/passkey/finish", response_model=TokenResponse)
@limiter.limit("10/minute")
def web_passkey_finish(request: Request, req: PasskeyLoginFinish, db: Session = Depends(get_db)):
    """The browser's answer to /auth/web/passkey/begin: a web session."""
    _passkeys_or_fail()
    ip = get_client_ip(request)
    try:
        user_id, challenge = passkeys.open_web_session(req.session)
    except passkeys.PasskeyError as e:
        raise HTTPException(status_code=401, detail=str(e))
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user or not user.totp_enabled:
        raise HTTPException(status_code=401, detail="This passkey is not registered for this account.")
    retry = _totp_failures.blocked(user.id)
    if retry:
        audit_log(db, "web_login_passkey_throttled", user_id=user.id, ip_address=ip)
        raise _too_many(retry)
    cid = passkeys.answer_credential_id(req.credential)
    cred = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.credential_hash == passkeys.credential_hash(cid or ""),
    ).first() if cid else None
    try:
        if not cred:
            raise passkeys.PasskeyError("This passkey is not registered for this account.")
        count = passkeys.verify_authentication(challenge, req.credential, cred.public_key, cred.sign_count or 0,
                                               require_user_verification=True)
    except passkeys.PasskeyError as e:
        _totp_failures.record_failure(user.id)
        audit_log(db, "web_login_passkey_failed", user_id=user.id, ip_address=ip)
        raise HTTPException(status_code=401, detail=str(e))
    _totp_failures.reset(user.id)
    cred.sign_count = count
    cred.last_used_at = datetime.utcnow()
    user.last_login = datetime.utcnow()
    db.commit()
    audit_log(db, "login_success", user_id=user.id, detail="web passkey", ip_address=ip)
    return _web_session(user, int(time.time()))


@app.post("/auth/web/ticket", response_model=WebTicketResponse)
@limiter.limit("10/minute")
def web_ticket(request: Request, current_user: User = Depends(get_full_user), db: Session = Depends(get_db)):
    """The app hands its sign-in over to the web UI: a one-time ticket, valid for two minutes, that the
    web UI exchanges for a web session. Only right after a full sign-in (the second factor recently)."""
    _check_second_factor_again(request, db, current_user, None, "web_ticket")
    ticket = create_web_ticket(current_user.id, current_user.token_version or 0)
    base = passkeys.web_url()
    audit_log(db, "web_ticket_issued", user_id=current_user.id, ip_address=get_client_ip(request))
    # after "#": the browser keeps it out of the request, so it never reaches the access log
    return {"ticket": ticket, "url": f"{base}/index.php#ticket={ticket}" if base else None,
            "expires_in": WEB_TICKET_SECONDS}


@app.post("/auth/web/ticket/redeem", response_model=TokenResponse)
@limiter.limit("10/minute")
def web_ticket_redeem(request: Request, req: WebTicketRedeem, db: Session = Depends(get_db)):
    """The web UI's half: a valid ticket, once, gives a web session."""
    found = redeem_web_ticket(req.ticket)
    user = db.query(User).filter(User.id == found[0], User.is_active == True).first() if found else None
    if not user or found[1] != (user.token_version or 0):
        audit_log(db, "web_ticket_refused", ip_address=get_client_ip(request))
        raise HTTPException(status_code=401, detail="This sign-in link is invalid, used or expired. Start again in the app.")
    user.last_login = datetime.utcnow()
    db.commit()
    audit_log(db, "login_success", user_id=user.id, detail="web ticket", ip_address=get_client_ip(request))
    return _web_session(user, int(time.time()) if user.totp_enabled else None)


@app.get("/users/me/passkeys", response_model=list[PasskeyResponse])
def list_passkeys(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _user_passkeys(db, current_user.id)


@app.post("/users/me/passkeys/register/begin", response_model=PasskeyOptions)
@limiter.limit("5/minute")
def passkey_register_begin(
    request: Request,
    req: PasskeyRegisterBegin,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a passkey: the password and the second factor first. TOTP stays as the fallback, so it
    must be on (a lost phone must not lock the owner out)."""
    _passkeys_or_fail()
    if not current_user.totp_enabled:
        raise HTTPException(status_code=409, detail="Turn on the authenticator app first; it stays as the fallback.")
    _confirm_identity(request, db, current_user, req.password, "passkey_add")
    _check_second_factor_again(request, db, current_user, req.totp_code, "passkey_add")
    creds = _user_passkeys(db, current_user.id)
    if len(creds) >= passkeys.MAX_PER_USER:
        raise HTTPException(status_code=409, detail=f"At most {passkeys.MAX_PER_USER} passkeys per account.")
    options, session = passkeys.registration_options(current_user.id, current_user.username,
                                                     [c.credential_id for c in creds])
    return {"options": options, "session": session}


@app.post("/users/me/passkeys/register/finish", response_model=PasskeyResponse, status_code=201)
@limiter.limit("5/minute")
def passkey_register_finish(
    request: Request,
    req: PasskeyRegisterFinish,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _passkeys_or_fail()
    try:
        new = passkeys.verify_registration(current_user.id, req.session, req.credential)
    except passkeys.PasskeyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    h = passkeys.credential_hash(new["id"])
    if db.query(WebAuthnCredential).filter(WebAuthnCredential.credential_hash == h).first():
        raise HTTPException(status_code=409, detail="This passkey is already registered.")
    cred = WebAuthnCredential(user_id=current_user.id, credential_id=new["id"], credential_hash=h,
                              public_key=new["public_key"], sign_count=new["sign_count"],
                              transports=new["transports"] or None, name=req.name.strip()[:64])
    db.add(cred)
    db.commit()
    db.refresh(cred)
    audit_log(db, "passkey_added", user_id=current_user.id, ip_address=get_client_ip(request))
    _notify(current_user, f"A passkey ({cred.name}) was added to your account.")
    return cred


@app.delete("/users/me/passkeys/{passkey_id}", response_model=MessageResponse)
@limiter.limit("5/minute")
def passkey_delete(
    request: Request,
    passkey_id: str,
    req: PasskeyDeleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a passkey. TOTP remains, so this never removes the last second factor."""
    _confirm_identity(request, db, current_user, req.password, "passkey_remove")
    _check_second_factor_again(request, db, current_user, req.totp_code, "passkey_remove")
    cred = db.query(WebAuthnCredential).filter(WebAuthnCredential.id == passkey_id,
                                               WebAuthnCredential.user_id == current_user.id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="No such passkey.")
    name = cred.name
    db.delete(cred)
    db.commit()
    audit_log(db, "passkey_removed", user_id=current_user.id, ip_address=get_client_ip(request))
    _notify(current_user, f"A passkey ({name}) was removed from your account.")
    return {"message": "Passkey removed."}


# --- The server's half of the stick's key (sticks.py) ---

def _sticks_or_fail() -> None:
    if not sticks.is_configured():
        raise HTTPException(status_code=503, detail="Stick secrets are not configured on this server (TOTP_ENCRYPTION_KEY).")


def _user_sticks(db: Session, user_id: str) -> list[StickSecret]:
    return db.query(StickSecret).filter(StickSecret.user_id == user_id).order_by(StickSecret.created_at).all()


@app.post("/users/me/sticks", response_model=StickSecretResponse, status_code=201)
@limiter.limit("5/minute")
def stick_create(
    request: Request,
    req: StickCreateRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """A new stick secret, for the client to seal the stick's key with. A session that passed the full
    login can create one; the secret is useless without the stick and the password."""
    _sticks_or_fail()
    # a secret the client never used (the write to the stick failed) does not count for long
    cutoff = datetime.utcnow() - timedelta(hours=1)
    db.query(StickSecret).filter(StickSecret.user_id == current_user.id, StickSecret.last_used_at.is_(None),
                                 StickSecret.created_at < cutoff).delete(synchronize_session=False)
    if len(_user_sticks(db, current_user.id)) >= sticks.MAX_PER_USER:
        raise HTTPException(status_code=409, detail=f"At most {sticks.MAX_PER_USER} sticks per account. Remove one you no longer use.")
    secret = sticks.new_secret()
    stick = StickSecret(id=str(uuid.uuid4()), user_id=current_user.id, name=req.name.strip()[:64], secret_enc="")
    stick.secret_enc = sticks.encrypt(secret, current_user.id, stick.id)
    db.add(stick)
    db.commit()
    audit_log(db, "stick_sealed", user_id=current_user.id, detail=f"stick={stick.id}", ip_address=get_client_ip(request))
    return {"stick_id": stick.id, "secret": secret.hex()}


@app.post("/users/me/sticks/{stick_id}/secret", response_model=StickSecretResponse)
@limiter.limit("20/minute")
def stick_secret(
    request: Request,
    stick_id: str,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """The stick secret, after the full login. POST so that nothing on the way caches it."""
    _sticks_or_fail()
    stick = db.query(StickSecret).filter(StickSecret.id == stick_id, StickSecret.user_id == current_user.id).first()
    if not stick:
        audit_log(db, "stick_unknown", user_id=current_user.id, detail=f"stick={stick_id[:36]}",
                  ip_address=get_client_ip(request))
        raise HTTPException(status_code=404, detail="STICK_REVOKED")
    if db.query(StickLock).filter(StickLock.stick_id == stick.id).first():
        audit_log(db, "stick_locked_refused", user_id=current_user.id, detail=f"stick={stick.id}",
                  ip_address=get_client_ip(request))
        raise HTTPException(status_code=403, detail=STICK_LOCKED)
    try:
        secret = sticks.decrypt(stick.secret_enc, current_user.id, stick.id)
    except Exception as e:     # wrong or rotated TOTP_ENCRYPTION_KEY, damaged data: fail closed
        logger.error(f"Cannot read the secret of stick {stick.id}: {e}")
        raise HTTPException(status_code=503, detail="The stick secret cannot be read on this server.")
    stick.last_used_at = datetime.utcnow()
    db.commit()
    audit_log(db, "stick_unlocked", user_id=current_user.id, detail=f"stick={stick.id}", ip_address=get_client_ip(request))
    return {"stick_id": stick.id, "secret": secret.hex()}


@app.get("/users/me/sticks", response_model=list[StickResponse])
def stick_list(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    locks = {l.stick_id: l for l in db.query(StickLock).filter(StickLock.user_id == current_user.id).all()}
    removals = {c.id: c.due_at for c in pending.list_pending(db, current_user.id) if c.kind == "stick"}
    out = []
    for s in _user_sticks(db, current_user.id):
        lock = locks.get(s.id)
        out.append({"id": s.id, "name": s.name, "created_at": s.created_at, "last_used_at": s.last_used_at,
                    "locked_at": lock.locked_at if lock else None,
                    "removal_due": removals.get(lock.removal_change_id) if lock else None})
    return out


# A lost stick is locked at once; unlocking needs the app's full sign-in, and removing it for good waits
# CHANGE_DELAY_HOURS like other destructive changes. So someone with a passkey alone (a web session)
# can at most lock a stick, which the owner undoes with the password, and never removes it unnoticed.
STICK_LOCKED = "STICK_LOCKED"


def _own_stick(db: Session, user: User, stick_id: str) -> StickSecret:
    stick = db.query(StickSecret).filter(StickSecret.id == stick_id, StickSecret.user_id == user.id).first()
    if not stick:
        raise HTTPException(status_code=404, detail="No such stick.")
    return stick


def _lock(db: Session, user: User, stick: StickSecret, request: Request) -> tuple[StickLock, bool]:
    """Lock the stick unless it already is; returns the lock and whether it was new."""
    lock = db.query(StickLock).filter(StickLock.stick_id == stick.id).first()
    if lock:
        return lock, False
    lock = StickLock(stick_id=stick.id, user_id=user.id)
    db.add(lock)
    db.commit()
    audit_log(db, "stick_locked", user_id=user.id, detail=f"stick={stick.id}", ip_address=get_client_ip(request))
    return lock, True


@app.post("/users/me/sticks/{stick_id}/lock", response_model=MessageResponse)
@limiter.limit("10/minute")
def stick_lock(
    request: Request,
    stick_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Lock a stick at once, e.g. a lost one: its key cannot be opened until it is unlocked from the app.
    The safe direction, so a session is enough, a web session included."""
    stick = _own_stick(db, current_user, stick_id)
    _, new = _lock(db, current_user, stick, request)
    if new:
        _notify(current_user, f"A USB stick ({stick.name}) was locked: its key cannot be opened until you unlock "
                              "it, by connecting with it in the app (password and second factor).")
    return {"message": "Stick locked. To unlock it, connect with it in the app."}


@app.post("/users/me/sticks/{stick_id}/unlock", response_model=MessageResponse)
@limiter.limit("5/minute")
def stick_unlock(
    request: Request,
    stick_id: str,
    req: StickDeleteRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Unlock a stick: only the app's full sign-in, never a web session. Also stops a waiting removal."""
    _check_second_factor_again(request, db, current_user, req.totp_code, "stick_unlock")
    stick = _own_stick(db, current_user, stick_id)
    lock = db.query(StickLock).filter(StickLock.stick_id == stick.id).first()
    if not lock:
        return {"message": "The stick is not locked."}
    if lock.removal_change_id:
        pending.cancel(db, current_user.id, lock.removal_change_id, get_client_ip(request))
    db.delete(lock)
    db.commit()
    audit_log(db, "stick_lock_removed", user_id=current_user.id, detail=f"stick={stick.id}",
              ip_address=get_client_ip(request))
    _notify(current_user, f"The USB stick ({stick.name}) was unlocked and can be used again.")
    return {"message": "Stick unlocked."}


@app.delete("/users/me/sticks/{stick_id}", response_model=ChangeResponse)
@limiter.limit("5/minute")
def stick_delete(
    request: Request,
    stick_id: str,
    req: StickDeleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove a stick for good: its key can never be opened again, whoever has the stick and the password.
    It is locked at once; the removal waits CHANGE_DELAY_HOURS and can be cancelled until then (it then
    stays locked)."""
    _confirm_identity(request, db, current_user, req.password, "stick_remove")
    _check_second_factor_again(request, db, current_user, req.totp_code, "stick_remove")
    stick = _own_stick(db, current_user, stick_id)
    lock, _ = _lock(db, current_user, stick, request)
    if lock.removal_change_id:
        waiting = db.query(PendingChange).filter(PendingChange.id == lock.removal_change_id,
                                                 PendingChange.state == "pending").first()
        if waiting:
            return {"message": f"The stick is locked and will be removed on {waiting.due_at:%Y-%m-%d %H:%M} UTC.",
                    "pending": True, "change_id": waiting.id, "effective_at": waiting.due_at}
    try:
        change = pending.schedule(db, current_user, "stick", get_client_ip(request))
    except pending.NoticeFailed:
        raise HTTPException(status_code=503, detail="Could not send the confirmation e-mail. Try again later.")
    lock.removal_change_id = change.id
    db.commit()
    if config.change_delay_hours() == 0 and pending.apply_due(db, current_user.id):
        return {"message": "Stick removed."}
    return {"message": f"The stick is locked now and will be removed for good on {change.due_at:%Y-%m-%d %H:%M} UTC. "
                       "An e-mail with a cancel link was sent.",
            "pending": True, "change_id": change.id, "effective_at": change.due_at}


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
def refresh_token(request: Request, req: RefreshRequest, db: Session = Depends(get_db)):
    """Issue a new access + refresh token pair via refresh token rotation."""
    result = rotate_refresh_token(req.refresh_token, db)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    user_id, new_refresh = result
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    return {
        "access_token":  create_access_token(user.id, user.token_version or 0),
        "refresh_token": new_refresh,
    }


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

@app.get("/users/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_user_for_enrolment)):
    return current_user


@app.put("/users/me/ssh-key", response_model=ChangeResponse)
@limiter.limit("5/minute")
def update_ssh_key(
    request: Request,
    req: SSHKeyUpdate,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """
    Set the SSH public key. The first key takes effect at once. Replacing a key needs the
    password and the second factor and waits CHANGE_DELAY_HOURS, during which the old key keeps
    working and the owner can cancel from the e-mail. Repeating a request is harmless.
    """
    _verify_password_or_fail(request, db, current_user, req.password, "ssh_key_update")
    _check_second_factor_again(request, db, current_user, req.totp_code, "ssh_key_update")
    if current_user.ssh_public_key and current_user.ssh_public_key != req.ssh_public_key:
        waiting = [c for c in pending.list_pending(db, current_user.id)
                   if c.kind == "ssh_key" and c.ssh_public_key == req.ssh_public_key]
        change = waiting[0] if waiting else _schedule(db, current_user, "ssh_key", request, req.ssh_public_key)
        if change is not None:
            return {"message": f"The new SSH key takes effect on {change.due_at:%Y-%m-%d %H:%M} UTC. "
                               "Until then the old key keeps working. An e-mail with a cancel link was sent.",
                    "pending": True, "change_id": change.id, "effective_at": change.due_at}
        return {"message": "SSH public key updated."}
    # No key yet (a new account), or the same key again: nothing to take over, so no delay.
    # The key must reach the SFTP server before we report success
    try:
        daemon_e2ee_provision(current_user.username, req.ssh_public_key, current_user.quota_bytes)
    except DaemonError as e:
        raise HTTPException(status_code=500, detail=str(e))
    added = current_user.ssh_public_key is None
    current_user.storage_created = True
    current_user.ssh_public_key = req.ssh_public_key
    db.commit()
    if not added:
        return {"message": "This SSH key is already active."}
    audit_log(db, "ssh_key_updated", user_id=current_user.id,
              ip_address=get_client_ip(request))
    _notify(current_user, "An SSH public key was added to your account.")
    return {"message": "SSH public key added."}


@app.get("/users/me/pending-changes", response_model=list[PendingChangeResponse])
def list_pending_changes(
    current_user: User = Depends(get_user_for_enrolment),
    db: Session = Depends(get_db),
):
    """Waiting key changes and deletions. Visible even before a required second factor is set
    up, so the owner can always see and stop them."""
    return pending.list_pending(db, current_user.id)


@app.delete("/users/me/pending-changes/{change_id}", response_model=MessageResponse)
@limiter.limit("10/minute")
def cancel_pending_change(
    request: Request,
    change_id: str,
    current_user: User = Depends(get_user_for_enrolment),
    db: Session = Depends(get_db),
):
    """Cancelling is always the safe direction, so a session is enough."""
    if not pending.cancel(db, current_user.id, change_id, get_client_ip(request)):
        raise HTTPException(status_code=404, detail="No such waiting change.")
    _notify(current_user, "A waiting change on your account was cancelled.")
    return {"message": "Cancelled."}


@app.post("/auth/cancel-change", response_model=MessageResponse)
@limiter.limit("10/minute")
def cancel_change_by_link(request: Request, req: CancelChangeRequest, db: Session = Depends(get_db)):
    """Cancel a waiting change with the link from the e-mail; no sign-in needed."""
    if not pending.cancel_by_token(db, req.token, get_client_ip(request)):
        raise HTTPException(status_code=404, detail="This link is invalid, or the change already happened or was cancelled.")
    return {"message": "Cancelled. Nothing was changed. If you did not ask for it, change your password now."}


@app.post("/users/me/password", response_model=MessageResponse)
@limiter.limit("5/minute")
def change_password(
    request: Request,
    req: PasswordChangeRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Change the login key and revoke all sessions. The client re-wraps gocryptfs.conf itself."""
    _verify_password_or_fail(request, db, current_user, req.current_password, "password_change")
    _check_second_factor_again(request, db, current_user, req.totp_code, "password_change")
    current_user.password_hash = hash_password(req.new_password)
    revoke_all_refresh_tokens(current_user.id, db)
    # Access tokens issued before this change are rejected from now on
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    audit_log(db, "password_changed", user_id=current_user.id,
              ip_address=get_client_ip(request))
    _notify(current_user, "The password of your account was changed.")
    return {"message": "Password changed successfully. All sessions have been logged out; log in again."}


# ---------------------------------------------------------------------------
# Account recovery
# ---------------------------------------------------------------------------

_recover_by_ip_user = FailureTracker(limit=5, window=900)
_recover_by_user = FailureTracker(limit=10, window=3600)

@app.post("/users/me/totp/setup", response_model=TotpSetupResponse)
@limiter.limit("5/minute")
def totp_setup(
    request: Request,
    req: TotpSetupRequest,
    current_user: User = Depends(get_user_for_enrolment),
    db: Session = Depends(get_db),
):
    """Start enrolling a second factor. Needs the password; nothing is active until
    /users/me/totp/enable confirms a code from the authenticator app and the code sent by e-mail."""
    if not totp.is_configured():
        raise _second_factor_unavailable()
    _confirm_identity(request, db, current_user, req.password, "totp_setup")
    if current_user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled.")
    secret = totp.generate_secret()
    current_user.totp_secret_enc = totp.encrypt_secret(secret, current_user.id)
    current_user.totp_last_step = None
    try:
        send_enrolment_code_email(current_user.email, current_user.username,
                                  totp.enrolment_code(current_user.id, current_user.totp_secret_enc))
    except Exception as e:
        db.rollback()
        logger.error(f"Could not send the two-factor setup code to user {current_user.id}: {e}")
        raise HTTPException(status_code=503, detail="Could not send the setup code by e-mail. Try again later.")
    db.commit()
    audit_log(db, "totp_setup_started", user_id=current_user.id, ip_address=get_client_ip(request))
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, current_user.username, TOTP_ISSUER),
        "message": "Add the secret to your authenticator app, then confirm with its code and the code we e-mailed you.",
    }


@app.post("/users/me/totp/enable", response_model=TotpEnableResponse)
@limiter.limit("10/minute")
def totp_enable(
    request: Request,
    req: TotpEnableRequest,
    current_user: User = Depends(get_user_for_enrolment),
    db: Session = Depends(get_db),
):
    """Confirm the authenticator app works, switch the second factor on and return the
    backup codes (shown once)."""
    if not totp.is_configured():
        raise _second_factor_unavailable()
    if current_user.totp_enabled or not current_user.totp_secret_enc:
        raise HTTPException(status_code=409, detail="Start the setup first.")
    retry = _totp_failures.blocked(current_user.id)
    if retry:
        raise _too_many(retry)
    try:
        secret = totp.decrypt_secret(current_user.totp_secret_enc, current_user.id)
    except Exception as e:
        logger.error(f"Cannot read the TOTP secret of user {current_user.id}: {e}")
        raise _second_factor_unavailable()
    step = totp.verify(secret, req.code)
    if not totp.check_enrolment_code(current_user.id, current_user.totp_secret_enc, req.email_code):
        step = None
    if step is None:
        _totp_failures.record_failure(current_user.id)
        audit_log(db, "totp_enable_failed", user_id=current_user.id, ip_address=get_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid verification code or e-mail code.")
    _totp_failures.reset(current_user.id)
    codes = totp.generate_backup_codes()
    current_user.totp_enabled = True
    current_user.totp_last_step = step
    current_user.totp_backup_hashes = totp.hash_backup_codes(codes)
    db.commit()
    audit_log(db, "totp_enabled", user_id=current_user.id, ip_address=get_client_ip(request))
    _notify(current_user, "Two-factor authentication was turned on for your account.")
    return {"message": "Two-factor authentication is on. Store the backup codes safely; they are shown only once.",
            "backup_codes": codes}


@app.post("/users/me/totp/disable", response_model=MessageResponse)
@limiter.limit("5/minute")
def totp_disable(
    request: Request,
    req: TotpDisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Turn the second factor off. Needs the password and a valid code (or backup code)."""
    _confirm_identity(request, db, current_user, req.password, "totp_disable")
    if not current_user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is not enabled.")
    if config.totp_required():
        raise HTTPException(status_code=409, detail="This server requires two-factor authentication.")
    if _user_passkeys(db, current_user.id):
        # Passkeys never stand alone here: the authenticator app is their fallback
        raise HTTPException(status_code=409, detail="Remove your passkeys first.")
    retry = _totp_failures.blocked(current_user.id)
    if retry:
        raise _too_many(retry)
    if not _accept_second_factor(db, current_user, req.code):
        _totp_failures.record_failure(current_user.id)
        audit_log(db, "totp_disable_failed", user_id=current_user.id, ip_address=get_client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid verification code.")
    _totp_failures.reset(current_user.id)
    db.refresh(current_user)
    current_user.totp_enabled = False
    current_user.totp_secret_enc = None
    current_user.totp_last_step = None
    current_user.totp_backup_hashes = None
    db.commit()
    audit_log(db, "totp_disabled", user_id=current_user.id, ip_address=get_client_ip(request))
    _notify(current_user, "Two-factor authentication was turned off for your account.")
    return {"message": "Two-factor authentication is off."}


@app.get("/storage/usage")
def storage_usage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _e2ee_usage(current_user)


@app.delete("/storage", response_model=ChangeResponse)
@limiter.limit("5/minute")
def delete_account(
    request: Request,
    req: DeleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete storage and account after CHANGE_DELAY_HOURS; the owner can cancel until then."""
    _confirm_identity(request, db, current_user, req.password, "account_delete")
    _check_second_factor_again(request, db, current_user, req.totp_code, "account_delete")
    change = _schedule(db, current_user, "delete", request)
    if change is None:
        return {"message": "Account and storage permanently deleted."}
    return {"message": f"Your account and all data will be deleted on {change.due_at:%Y-%m-%d %H:%M} UTC. "
                       "An e-mail with a cancel link was sent.",
            "pending": True, "change_id": change.id, "effective_at": change.due_at}


# ---------------------------------------------------------------------------
# End-to-end encrypted mode
# ---------------------------------------------------------------------------

def _e2ee_usage(user: User) -> dict:
    try:
        return daemon_e2ee_usage(user.username, user.quota_bytes)
    except DaemonError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/server-info", response_model=ServerInfo)
def server_info():
    """What the client needs before it can create a volume. Public, contains no secrets."""
    policy, fingerprint = escrow_state.current()
    return {
        "storage_mode": "e2ee",
        "version": version.VERSION,
        "recovery_policy": policy,
        "escrow_public_key": config.escrow_public_key() if policy != "user" else None,
        "escrow_key_fingerprint": fingerprint,
        "account_lifetime_hours": config.account_lifetime_hours() or None,
        "server_id": sticks.server_id(),
    }


@app.get("/storage/e2ee", response_model=E2EEStorageResponse)
@limiter.limit("30/minute")
def e2ee_storage(
    request: Request,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Where the client connects (SFTP, ciphertext only). Creates the account on first use."""
    if REQUIRE_EMAIL_VERIFICATION and not current_user.email_verified:
        raise HTTPException(status_code=403, detail="Email not verified. Check your inbox.")
    # A key change whose delay has just passed should work now, not at the next worker run
    if pending.apply_due(db, current_user.id):
        db.refresh(current_user)
    try:
        ssh_user = daemon_e2ee_provision(current_user.username, current_user.ssh_public_key,
                                         current_user.quota_bytes)
    except DaemonError as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not current_user.storage_created:
        current_user.storage_created = True
        db.commit()
    used = _e2ee_usage(current_user).get("used_bytes", 0)
    return {"ssh_host": SERVER_HOST, "ssh_port": SSH_PORT, "ssh_user": ssh_user,
            "ssh_host_keys": _sftp_host_keys(),
            "quota_bytes": current_user.quota_bytes, "used_bytes": used}


@app.post("/storage/sync-lock", response_model=SyncLockResponse,
          responses={409: {"description": "Another device holds the lock"}})
# Generous: the limit is per address, and an office behind one NAT renews every user's lock from it
@limiter.limit("600/minute")
def acquire_sync_lock(
    request: Request,
    req: SyncLockRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Take or renew the volume's sync lock. Free, lapsed or already ours: taken until now + TTL.
    Held by another device: 409 with its name and how long it still lasts."""
    now = datetime.utcnow()
    ttl = config.sync_lock_seconds()
    fields = {"holder": req.holder, "holder_name": req.holder_name, "expires_at": now + timedelta(seconds=ttl)}
    try:
        db.add(SyncLock(user_id=current_user.id, volume=req.volume, **fields))
        db.commit()
        taken = True
    except IntegrityError:
        db.rollback()
        # One conditional UPDATE, so two devices racing for a lapsed lock cannot both win
        taken = db.query(SyncLock).filter(
            SyncLock.user_id == current_user.id, SyncLock.volume == req.volume,
            or_(SyncLock.holder == req.holder, SyncLock.expires_at < now),
        ).update(fields, synchronize_session=False) == 1
        db.commit()
    if not taken:
        lock = db.get(SyncLock, (current_user.id, req.volume))
        left = max(0, int((lock.expires_at - now).total_seconds())) if lock else 0
        return JSONResponse(status_code=409, content={
            "detail": "SYNC_LOCKED", "holder_name": lock.holder_name if lock else None, "expires_in": left})
    return {"expires_at": fields["expires_at"], "ttl_seconds": ttl}


@app.delete("/storage/sync-lock", response_model=MessageResponse)
@limiter.limit("600/minute")
def release_sync_lock(
    request: Request,
    holder: str,
    volume: str = "personal",
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Release the lock if this device holds it; anything else is left alone (and is not an error)."""
    db.query(SyncLock).filter(
        SyncLock.user_id == current_user.id, SyncLock.volume == volume, SyncLock.holder == holder,
    ).delete(synchronize_session=False)
    db.commit()
    return {"message": "Released."}


def _sftp_host_keys() -> list[str]:
    """The SFTP service's public host keys as "type base64", read on every call so a rotated key shows up.
    A missing or malformed file is logged and skipped: the client then falls back to asking the user."""
    keys = []
    for path in SFTP_HOST_KEY_FILES:
        try:
            with open(path, encoding="ascii") as f:
                parts = f.readline().split()
            if len(parts) < 2 or parts[0] not in _HOST_KEY_TYPES:
                raise ValueError("not an OpenSSH public key")
            base64.b64decode(parts[1], validate=True)
            keys.append(f"{parts[0]} {parts[1]}")
        except (OSError, ValueError, UnicodeDecodeError) as e:
            logger.error(f"SFTP host key {path} not usable: {e}")
    return keys


_DUMMY_PROOF_HASH = hash_password("00" * 32)


@app.put("/users/me/recovery-verifier", response_model=MessageResponse)
@limiter.limit("10/minute")
def put_recovery_verifier(
    request: Request,
    req: RecoveryVerifierRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Store a slow hash of the recovery proof, so a forgotten password can be reset later.
    Replacing one makes the old recovery code useless, so it needs a sign-in with the second factor in
    the last few minutes and the owner is told (the client does it only when a new volume is created,
    right after signing in)."""
    replaced = bool(current_user.recovery_encrypted_master_key)
    if replaced:
        _check_second_factor_again(request, db, current_user, None, "recovery_verifier_replace")
    current_user.recovery_encrypted_master_key = hash_password(req.proof)
    db.commit()
    audit_log(db, "recovery_verifier_replaced" if replaced else "recovery_verifier_stored",
              user_id=current_user.id, ip_address=get_client_ip(request))
    if replaced:
        _notify(current_user, "The recovery code of your account was replaced: the previous recovery code no "
                              "longer works. If you did not just create your storage again, change your password now.")
    return {"message": "Recovery verifier stored."}


@app.post("/auth/recover-e2ee", response_model=MessageResponse)
@limiter.limit("5/minute")
def recover_e2ee(request: Request, req: E2EERecoverRequest, db: Session = Depends(get_db)):
    """
    Set a new login key after a forgotten password, proving possession of the recovery code.
    The data is untouched: the client re-wraps gocryptfs.conf itself afterwards.
    """
    ip = get_client_ip(request)
    name_key = req.username.strip().lower()
    ip_key = f"{ip}|{name_key}"
    retry = max(_recover_by_ip_user.blocked(ip_key), _recover_by_user.blocked(name_key))
    if retry:
        audit_log(db, "recovery_throttled", detail=f"attempted_username={req.username}", ip_address=ip)
        raise _too_many(retry)

    user = db.query(User).filter(User.username == req.username, User.is_active == True).first()
    usable = bool(user and user.email_verified and user.recovery_encrypted_master_key)
    stored = user.recovery_encrypted_master_key if usable else _DUMMY_PROOF_HASH
    ok = verify_password(req.proof, stored)       # always one slow hash, whatever the account state
    if not (ok and usable):
        _recover_by_ip_user.record_failure(ip_key)
        _recover_by_user.record_failure(name_key)
        audit_log(db, "recovery_failed", detail=f"attempted_username={req.username}", ip_address=ip)
        raise HTTPException(status_code=401, detail="Invalid username or recovery code.")
    _recover_by_ip_user.reset(ip_key)
    # The recovery code replaces the password, not the second factor
    _check_second_factor(request, db, user, req.totp_code)

    user.password_hash = hash_password(req.new_password)
    user.token_version = (user.token_version or 0) + 1
    revoke_all_refresh_tokens(user.id, db)
    db.commit()
    audit_log(db, "account_recovered", user_id=user.id, ip_address=ip)
    _notify(user, "Your account was recovered with the recovery code and the login key was changed.")
    return {"message": "Login key changed. Log in again."}


@app.put("/users/me/escrow", response_model=MessageResponse)
@limiter.limit("10/minute")
def put_escrow(
    request: Request,
    req: EscrowRequest,
    current_user: User = Depends(get_full_user),
    db: Session = Depends(get_db),
):
    """Store the master key sealed to the organisation's escrow key. The server cannot read it."""
    if config.recovery_policy() == "user":
        raise HTTPException(status_code=409, detail="Escrow is not enabled on this server.")
    current_user.escrow_blob = req.blob
    _, fingerprint = escrow_state.current()
    db.merge(EscrowSeal(user_id=current_user.id, key_fingerprint=fingerprint, sealed_at=datetime.utcnow()))
    db.commit()
    audit_log(db, "escrow_stored", user_id=current_user.id, ip_address=get_client_ip(request))
    _notify(current_user, "A sealed copy of your storage key was stored for your organisation's escrow key. "
                          "Its administrators can now read your files.")
    return {"message": "Escrow blob stored."}


@app.get("/users/me/escrow")
def get_escrow(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """This user's escrow state (not just the server setting), for the web UI. The client keeps its
    own record on the stick, because the operator controls what this answers."""
    policy, fingerprint = escrow_state.current()
    seal = db.get(EscrowSeal, current_user.id)
    return {
        "has_escrow": bool(current_user.escrow_blob),
        "sealed_key_fingerprint": seal.key_fingerprint if seal else None,
        "sealed_at": seal.sealed_at if seal else None,
        "recovery_policy": policy,
        "escrow_key_fingerprint": fingerprint,
        "settings_changed_at": escrow_state.status["changed_at"],
        "settings_log_ok": escrow_state.status["chain_ok"],
    }
