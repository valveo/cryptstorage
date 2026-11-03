"""
kdf.py - The server's part of the password key derivation (docs/design-e2ee.md, section 5a).

The client turns the password into the login key and the volume passphrase with Argon2id. Version 1
(v0.1.0) salted it with the username only, so a guesser could prepare for a known username before
getting hold of any server's data, and the same username had the same salt on every server.
Version 2 adds a random 32-byte value this server creates once (`kdf_salt`, public in /server-info):

    salt = SHA-256("cryptstorage/kdf/v2" 0x00 || kdf_salt (32 bytes) || lower(trim(username)))

The salt still needs no round trip per user, so login does not reveal whether a user exists.
The server never derives anything itself: it stores which version each account's login key is
(user_kdf), and during the change-over accepts the version 1 key next to the version 2 one at login.

kdf_salt must never change: every version 2 key depends on it. It lives in the database, so it is in
the database backup with the accounts that use it.
"""

import secrets
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import ServerSetting, UserKdf

CURRENT = 2          # what new accounts and changed passwords use
LEGACY = 1           # no row in user_kdf
_SALT_NAME = "kdf_salt"

_salt_cache: Optional[str] = None


def ensure_salt(db: Session) -> str:
    """The server's kdf_salt (64 hex), created on first use. Several workers may start at once:
    the one that loses the race reads the winner's value."""
    global _salt_cache
    if _salt_cache:
        return _salt_cache
    row = db.get(ServerSetting, _SALT_NAME)
    if row is None:
        db.add(ServerSetting(name=_SALT_NAME, value=secrets.token_hex(32)))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        row = db.get(ServerSetting, _SALT_NAME)
    _salt_cache = row.value
    return _salt_cache


def version_of(db: Session, user_id: str) -> int:
    row = db.get(UserKdf, user_id)
    return row.version if row else LEGACY


def set_version(db: Session, user_id: str, version: int) -> None:
    """Record the version of the login key just stored; the caller commits."""
    row = db.get(UserKdf, user_id)
    if version == LEGACY:
        if row:
            db.delete(row)
        return
    if row:
        row.version = version
    else:
        db.add(UserKdf(user_id=user_id, version=version))


def login_key_for(version: int, password: str, legacy_password: Optional[str]) -> str:
    """The key to check against an account of this version. A version 2 client sends its version 1
    key as legacy_password; an older client sends only the version 1 key, as password."""
    if version == LEGACY and legacy_password:
        return legacy_password
    return password


def _reset_cache_for_tests() -> None:
    global _salt_cache
    _salt_cache = None
