"""
passkeys.py - Passkeys (WebAuthn) as a second factor, with py_webauthn (BSD-3-Clause).

A passkey replaces the 6-digit code at login and works on phones without an app (Face ID, fingerprint,
or a QR code the phone scans). It is an authentication factor only: the volume key is still derived
from the password (docs/design-factors.md). On this server TOTP stays required next to it, as the
fallback when the passkey's device is lost (decided 2026-10-26), so an account cannot hold passkeys
without TOTP.

A ceremony takes two requests. The begin request returns the browser's options and a short-lived signed
"session" token that carries the challenge, so the server keeps no state between the two. The finish
request verifies the browser's answer against that challenge; each session token works once.

Settings:
  WEBAUTHN_RP_ID   the domain the passkeys are bound to (default: the host of BASE_URL). Passkeys stop
                   working if it changes, so set it to the final domain before users register any.
  WEBAUTHN_ORIGIN  the web UI's origin(s), comma-separated (default: BASE_URL without its path)
  WEBAUTHN_RP_NAME the name the browser shows (default "CryptStorage")
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

import jwt
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth import ALGORITHM, SECRET_KEY

SESSION_SECONDS = 300
MAX_PER_USER = 10


class PasskeyError(Exception):
    """The browser's answer did not verify, or the session is invalid."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def credential_hash(credential_id: str) -> str:
    """Fixed-length unique key for a credential id (ids can be up to 1023 bytes)."""
    return hashlib.sha256(credential_id.encode("ascii")).hexdigest()


def _base_url() -> str:
    return os.getenv("BASE_URL", "").strip()


def rp_id() -> str:
    return os.getenv("WEBAUTHN_RP_ID", "").strip() or (urlsplit(_base_url()).hostname or "")


def origins() -> list[str]:
    raw = os.getenv("WEBAUTHN_ORIGIN", "").strip()
    if raw:
        return [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    u = urlsplit(_base_url())
    return [f"{u.scheme}://{u.netloc}"] if u.scheme and u.netloc else []


def rp_name() -> str:
    return os.getenv("WEBAUTHN_RP_NAME", "CryptStorage").strip() or "CryptStorage"


def web_url() -> Optional[str]:
    """The web UI's address, from BASE_URL (else the first WebAuthn origin)."""
    base = _base_url().rstrip("/")
    if not base:
        o = origins()
        base = o[0] if o else ""
    return base or None


def approve_url() -> Optional[str]:
    """The web UI page that approves a sign-in of the cryptclient app (webui/passkey-approve.php)."""
    base = _base_url().rstrip("/")
    if not base:
        o = origins()
        base = o[0] if o else ""
    return f"{base}/passkey-approve.php" if base else None


def is_configured() -> bool:
    return bool(rp_id() and origins())


# --- One-time session tokens ---

_used_lock = threading.Lock()
_used: dict[str, float] = {}     # jti -> expiry; a finished ceremony cannot be replayed


def _make_session(user_id: str, purpose: str, challenge: bytes) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user_id, "type": f"webauthn-{purpose}", "chl": b64url(challenge),
                       "jti": secrets.token_hex(16), "iat": now, "exp": now + SESSION_SECONDS},
                      SECRET_KEY, algorithm=ALGORITHM)


def _open_session(token: str, purpose: str) -> tuple[str, bytes]:
    """Returns (user id, challenge) and marks the session used."""
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM],
                            options={"require": ["exp", "sub", "jti", "chl"]})
    except jwt.PyJWTError:
        raise PasskeyError("The passkey request expired. Try again.")
    if claims.get("type") != f"webauthn-{purpose}":
        raise PasskeyError("Wrong kind of passkey request.")
    now = time.time()
    with _used_lock:
        for jti, exp in list(_used.items()):
            if exp < now:
                del _used[jti]
        if claims["jti"] in _used:
            raise PasskeyError("This passkey request was already used. Try again.")
        _used[claims["jti"]] = claims["exp"]
    return claims["sub"], unb64url(claims["chl"])


# --- Ceremonies ---

def registration_options(user_id: str, username: str, existing_ids: list[str]) -> tuple[dict, str]:
    challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=rp_id(), rp_name=rp_name(), user_id=user_id.encode(), user_name=username,
        challenge=challenge,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=unb64url(c)) for c in existing_ids],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    return json.loads(options_to_json(options)), _make_session(user_id, "register", challenge)


def verify_registration(user_id: str, session: str, credential: dict) -> dict:
    """Returns the new credential: id, public_key (base64url), sign_count, transports."""
    sub, challenge = _open_session(session, "register")
    if sub != user_id:
        raise PasskeyError("This passkey request belongs to another session.")
    try:
        v = verify_registration_response(credential=credential, expected_challenge=challenge,
                                         expected_rp_id=rp_id(), expected_origin=origins())
    except Exception as e:      # the library raises several types for a bad answer
        raise PasskeyError(f"The passkey could not be verified: {e}")
    transports = (credential.get("response") or {}).get("transports") or []
    return {"id": b64url(v.credential_id), "public_key": b64url(v.credential_public_key),
            "sign_count": v.sign_count,
            "transports": ",".join(t for t in transports if isinstance(t, str))[:255]}


def authentication_options(user_id: str, credential_ids: list[str]) -> tuple[dict, str]:
    challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=rp_id(), challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=unb64url(c)) for c in credential_ids],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(options)), _make_session(user_id, "login", challenge)


def open_login_session(session: str) -> tuple[str, bytes]:
    return _open_session(session, "login")


def web_authentication_options(user_id: str, credential_ids: list[str]) -> tuple[dict, str]:
    """A web UI sign-in with the passkey alone. The passkey is then the only factor, so the
    device must verify the user (PIN, fingerprint, face), not just that someone touched it."""
    challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=rp_id(), challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=unb64url(c)) for c in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(options)), _make_session(user_id, "web", challenge)


def open_web_session(session: str) -> tuple[str, bytes]:
    return _open_session(session, "web")


def verify_authentication(challenge: bytes, credential: dict, public_key: str, sign_count: int,
                          require_user_verification: bool = False) -> int:
    """Returns the new sign count."""
    try:
        v = verify_authentication_response(
            credential=credential, expected_challenge=challenge, expected_rp_id=rp_id(),
            expected_origin=origins(), credential_public_key=unb64url(public_key),
            credential_current_sign_count=sign_count,
            require_user_verification=require_user_verification)
    except Exception as e:
        raise PasskeyError(f"The passkey could not be verified: {e}")
    return v.new_sign_count


def answer_credential_id(credential: dict) -> Optional[str]:
    cid = credential.get("id") if isinstance(credential, dict) else None
    return cid if isinstance(cid, str) and 0 < len(cid) <= 1400 else None
