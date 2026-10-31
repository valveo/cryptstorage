"""
email_verification.py - Email verification for new registrations.

Flow:
  1. User registers → generate_verification_token(user_id) → send_verification_email()
  2. User clicks link → POST /auth/verify-email { token: "..." }
     → verify_email_token(token) returns user_id
     → storage is created, email_verified set to True

Tokens:
  - Signed JWT, expire in 24 hours
  - Single-use enforced by checking user.email_verified in the endpoint

Email sending:
  - Uses SMTP with STARTTLS (configurable via env vars)
  - Set SMTP_HOST='' to disable sending (tokens are logged instead, for dev)
"""

import logging
import os
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

import jwt
from jwt import PyJWTError

import config

logger = logging.getLogger(__name__)

# --- Config ---
SECRET_KEY  = config.require("JWT_SECRET_KEY", min_len=32)
ALGORITHM   = "HS256"
TOKEN_TTL_H = 24  # hours

SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "noreply@cryptstorage.example.com")
# "starttls" (port 587) or "ssl" (TLS from the first byte, port 465). Default: ssl on 465.
SMTP_SECURITY = (os.getenv("SMTP_SECURITY", "") or ("ssl" if SMTP_PORT == 465 else "starttls")).strip().lower()
BASE_URL      = os.getenv("BASE_URL", "https://your-server.example.com")


class EmailError(Exception):
    pass


def generate_verification_token(user_id: str) -> str:
    """Generate a signed JWT verification token that expires in 24 hours."""
    expire = datetime.utcnow() + timedelta(hours=TOKEN_TTL_H)
    return jwt.encode(
        {"sub": user_id, "type": "email_verify", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def verify_email_token(token: str) -> Optional[str]:
    """
    Validate a verification token.
    Returns user_id if valid, None otherwise.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "email_verify":
            return None
        return payload.get("sub")
    except PyJWTError:
        return None


def send_verification_email(email: str, username: str, token: str):
    """
    Send a verification email to the user.
    If SMTP_HOST is not configured, logs the link instead (development mode).
    """
    verify_url = f"{BASE_URL}/verify-email.php?token={token}"

    if not SMTP_HOST:
        # Dev mode: log the link
        logger.info(
            f"[DEV] Email verification for {username} <{email}>:\n"
            f"  {verify_url}"
        )
        return

    # Build email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "CryptStorage – Verify your email"
    msg["From"]    = SMTP_FROM
    msg["To"]      = email

    text_body = f"""Hello {username},

Welcome to CryptStorage!

Please verify your email address by visiting:
{verify_url}

This link expires in {TOKEN_TTL_H} hours.

If you did not create this account, you can ignore this email.

— CryptStorage
"""

    html_body = f"""<!DOCTYPE html>
<html>
<body style="font-family:sans-serif;background:#0a0a0f;color:#e8e8f0;padding:2rem;">
  <div style="max-width:480px;margin:0 auto;background:#111118;border:1px solid #1e1e2e;padding:2rem;">
    <h2 style="color:#00e5a0;font-family:monospace;letter-spacing:0.1em;">CryptStorage</h2>
    <p>Hello <strong>{username}</strong>,</p>
    <p>Welcome! Please verify your email address to activate your encrypted storage.</p>
    <p style="margin:2rem 0;">
      <a href="{verify_url}"
         style="background:#00e5a0;color:#000;padding:0.75rem 1.5rem;
                text-decoration:none;font-family:monospace;font-weight:bold;
                letter-spacing:0.1em;">
        VERIFY EMAIL →
      </a>
    </p>
    <p style="color:#5a5a72;font-size:0.8rem;">
      This link expires in {TOKEN_TTL_H} hours.<br>
      If you did not create this account, ignore this email.
    </p>
  </div>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    _deliver(msg, email)
    logger.info(f"Verification email sent to {email}")


def _connect() -> smtplib.SMTP:
    # Without an explicit context smtplib does NOT verify the certificate
    context = ssl.create_default_context()
    if SMTP_SECURITY == "ssl":
        return smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=context)
    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
    server.ehlo()
    server.starttls(context=context)
    return server


def _deliver(msg, email: str) -> None:
    """Send over SMTP with STARTTLS or implicit TLS (SMTP_SECURITY). The server certificate is verified."""
    try:
        with _connect() as server:
            server.ehlo()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [email], msg.as_string())
    except Exception as e:
        raise EmailError(f"SMTP error: {e}") from e


def send_security_notice_email(email: str, username: str, what: str, action: str = "") -> None:
    """
    Tell the user that something security-relevant changed on their account
    (e.g. "Your SSH public key was changed."). `action` is an optional paragraph such as a
    cancel link. Dev mode (no SMTP_HOST) only logs.
    """
    if not SMTP_HOST:
        logger.info(f"[DEV] Security notice for {username} <{email}>: {what} {action}")
        return
    extra = f"{action}\n\n" if action else ""
    _send_plain(
        email, "CryptStorage – Security notice",
        f"Hello {username},\n\n{what}\n\n{extra}"
        "If this was you, no action is needed. If it was not, change your password "
        "immediately and contact the administrator.\n\n— CryptStorage\n",
    )


def send_enrolment_code_email(email: str, username: str, code: str) -> None:
    """The e-mail half of turning on two-factor: someone who only knows the password cannot do it."""
    if not SMTP_HOST:
        logger.info(f"[DEV] Two-factor setup code for {username} <{email}>: {code}")
        return
    _send_plain(
        email, "CryptStorage – Two-factor setup code",
        f"Hello {username},\n\nSomeone is turning on two-factor authentication for your account.\n"
        f"If it is you, enter this code on the setup page:\n\n    {code}\n\n"
        "If it is not you, someone knows your password: change it now and contact the administrator.\n\n"
        "— CryptStorage\n",
    )


def _send_plain(email: str, subject: str, body: str) -> None:
    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = email
    _deliver(msg, email)
